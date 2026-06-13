/*
 * WTPDataTunnel.c
 *
 * Milestone-3: openCAPWAP -> NSS CAPWAP data-plane offload integration.
 * See WTPDataTunnel.h. Built on the nss_nlcapwap userspace netlink lib
 * (nss_nlcapwap_api.c + nss_nlsock.c) validated standalone in milestone 2.
 */

#include "WTPDataTunnel.h"

/* openCAPWAP logging (CWLog) and core types */
#include "CWWTP.h"

/*
 * kernel shorthand macros used by the NSS headers; force-define them for the
 * userspace build (undef first in case a system header defined them
 * incompatibly).
 */
#ifdef __packed
#undef __packed
#endif
#define __packed __attribute__((packed))
#ifdef __aligned
#undef __aligned
#endif
#define __aligned(x) __attribute__((aligned(x)))

#include <nss_nlbase.h>          /* pulls in nss_nlcapwap_* + libnl */
#include <nss_capwap_user.h>     /* struct nss_capwap_metaheader, versions */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
/* meta_header_type enum lives in the kernel-only nss_nlcapwap.h, not the
/* shared if.h the WTP sees. Define the value M2 used (IPV4_DATA = 0). */
#ifndef NSS_NLCAPWAP_META_HEADER_TYPE_IPV4_DATA
#define NSS_NLCAPWAP_META_HEADER_TYPE_IPV4_DATA 0
#endif

#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

/* netlink-level constants (kernel-private header not included in userspace) */
#ifndef NSS_NLCAPWAP_IP_VERS_4
#define NSS_NLCAPWAP_IP_VERS_4 4
#endif

/*
 * One shared socket context for the WTP's tunnel operations. Opened lazily.
 */
static struct nss_nlcapwap_ctx gTunCtx;
static int gTunCtxOpen = 0;

static int tun_ctx_ensure_open(void)
{
        int err;

        if (gTunCtxOpen)
                return 0;

        err = nss_nlcapwap_sock_open(&gTunCtx, NULL, NULL);
        if (err) {
                CWLog("[DATATUN] nss_nlcapwap_sock_open failed: %d", err);
                return err;
        }

        /*
         * Milestone-2 fix: the regular open path leaves auto-ack enabled, so
         * nl_send_sync waits for an ACK the NSS netlink side does not deliver
         * (=> NLE_AGAIN). Disable seq-check + auto-ack as the mcast path does.
         */
        nl_socket_disable_seq_check(gTunCtx.sock.nl_sk);
        nl_socket_disable_auto_ack(gTunCtx.sock.nl_sk);

        gTunCtxOpen = 1;
        return 0;
}

/*
 * Resolve the egress interface name and MAC for reaching dest_ip_host.
 * Uses a connected UDP socket so the kernel picks the egress per the
 * routing table, then matches the chosen source IP to an interface.
 * Returns 0 on success (fills ifname[>=IFNAMSIZ] and mac[6]), -1 on failure.
 */
static int CWResolveEgressForDest(uint32_t dest_ip_host, char *ifname_out, uint8_t mac_out[6])
{
	int s, ret = -1;
	struct sockaddr_in dst, src;
	socklen_t slen = sizeof(src);
	struct ifconf ifc;
	struct ifreq ifrbuf[32];
	int i, n;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(dest_ip_host);
	dst.sin_port = htons(9);   /* discard; no packet is actually sent */

	if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) != 0)
		goto out;
	if (getsockname(s, (struct sockaddr *)&src, &slen) != 0)
		goto out;

	memset(&ifc, 0, sizeof(ifc));
	ifc.ifc_len = sizeof(ifrbuf);
	ifc.ifc_req = ifrbuf;
	if (ioctl(s, SIOCGIFCONF, &ifc) != 0)
		goto out;

	n = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < n; i++) {
		struct sockaddr_in *a = (struct sockaddr_in *)&ifrbuf[i].ifr_addr;
		if (ifrbuf[i].ifr_addr.sa_family != AF_INET)
			continue;
		if (a->sin_addr.s_addr != src.sin_addr.s_addr)
			continue;
		strncpy(ifname_out, ifrbuf[i].ifr_name, IFNAMSIZ - 1);
		ifname_out[IFNAMSIZ - 1] = '\0';
		{
			struct ifreq mreq;
			memset(&mreq, 0, sizeof(mreq));
			strncpy(mreq.ifr_name, ifname_out, IFNAMSIZ - 1);
			if (ioctl(s, SIOCGIFHWADDR, &mreq) == 0) {
				memcpy(mac_out, mreq.ifr_hwaddr.sa_data, 6);
				ret = 0;
			}
		}
		break;
	}
out:
	close(s);
	return ret;
}

int CWWTPCreateDataTunnel(uint32_t ac_ip_host,
                          uint32_t ap_ip_host,
                          uint16_t data_port,
                          uint32_t path_mtu,
                          const char *wan_ifname,
                          const uint8_t wan_ifmac[6],
                          const uint8_t bssid[6],
                          uint8_t *out_tun_id)
{
        struct nss_nlcapwap_rule rule;
        struct nss_nlcapwap_create_tun *c;
        int err;

        if (tun_ctx_ensure_open())
                return -1;

        /* ---- CREATE_TUN ---- */
        memset(&rule, 0, sizeof(rule));
        nss_nlcapwap_init_rule(&rule, NSS_NLCAPWAP_CMD_TYPE_CREATE_TUN);
        c = &rule.msg.create;

        {
                char resolved_if[IFNAMSIZ];
                uint8_t resolved_mac[6];
                const char *use_if = wan_ifname;
                const uint8_t *use_mac = wan_ifmac;
                if (use_if == NULL || use_if[0] == '\0') {
                        if (CWResolveEgressForDest(ac_ip_host, resolved_if, resolved_mac) == 0) {
                                use_if = resolved_if;
                                use_mac = resolved_mac;
                                CWLog("[DATATUN] resolved egress: %s %02x:%02x:%02x:%02x:%02x:%02x",
                                      resolved_if, resolved_mac[0], resolved_mac[1], resolved_mac[2],
                                      resolved_mac[3], resolved_mac[4], resolved_mac[5]);
                        } else {
                                CWLog("[DATATUN] egress resolution FAILED for dest 0x%08x", ac_ip_host);
                                return -1;
                        }
                }
                strncpy(c->gmac_ifname, use_if, sizeof(c->gmac_ifname) - 1);
                memcpy(c->gmac_ifmac, use_mac, 6);
        }
        memcpy(c->bssid, bssid, 6);

        /* encap 5-tuple - host byte order (kernel passes these straight) */
        c->rule.encap.src_ip.ip.ipv4  = ap_ip_host;
        c->rule.encap.src_port        = data_port;
        c->rule.encap.dest_ip.ip.ipv4 = ac_ip_host;
        c->rule.encap.dest_port       = data_port;
        c->rule.encap.path_mtu        = path_mtu;

        /* decap defaults (0 => firmware default) */
        c->rule.decap.reassembly_timeout = 0;
        c->rule.decap.max_fragments      = 0;
        c->rule.decap.max_buffer_size    = 0;

        c->rule.stats_timer = 1000;
        c->rule.l3_proto    = NSS_NLCAPWAP_IP_VERS_4;
        c->rule.which_udp   = IPPROTO_UDP;

        err = nss_nlcapwap_sock_send(&gTunCtx, &rule, NULL, NULL);
        if (err) {
                CWLog("[DATATUN] CREATE_TUN send failed: %d", err);
                return err;
        }

        /*
         * The netlink create handler picks the first free tunnel id via
         * find_first_zero_bit, so the first WLAN's tunnel is id 0. We track
         * ids monotonically on our side to match. For phase 1 (single WLAN)
         * this is id 0; a multi-WLAN mapping is a later refinement.
         */
        if (out_tun_id)
                *out_tun_id = 0;

        CWLog("[DATATUN] CREATE_TUN sent: src=0x%08x dst=0x%08x port=%u mtu=%u via=%s",
              ap_ip_host, ac_ip_host, data_port, path_mtu, wan_ifname);
	        /* ---- META_HEADER: store the per-tunnel metaheader blob NSS injects ---- */
        {
                struct nss_nlcapwap_rule mh_rule;
                struct nss_capwap_metaheader *mh;

                memset(&mh_rule, 0, sizeof(mh_rule));
                nss_nlcapwap_init_rule(&mh_rule, NSS_NLCAPWAP_CMD_TYPE_META_HEADER);
                mh_rule.msg.meta_header.tun_id = 0;
                mh_rule.msg.meta_header.type   = NSS_NLCAPWAP_META_HEADER_TYPE_IPV4_DATA;

                mh = (struct nss_capwap_metaheader *)mh_rule.msg.meta_header.meta_header_blob;
                mh->version   = NSS_CAPWAP_VERSION_V2;
                mh->rid       = 1;
                mh->tunnel_id = 0;
                mh->type      = NSS_CAPWAP_PKT_TYPE_DATA;

                err = nss_nlcapwap_sock_send(&gTunCtx, &mh_rule, NULL, NULL);
                if (err) {
                        CWLog("[DATATUN] META_HEADER send failed: %d", err);
                        return err;
                }
                CWLog("[DATATUN] META_HEADER stored: ver=V2 type=IPV4_DATA tun=0");
        }
        return 0;
}

int CWWTPDestroyDataTunnel(uint8_t tun_id)
{
        struct nss_nlcapwap_rule rule;
        int err;

        if (tun_ctx_ensure_open())
                return -1;

        memset(&rule, 0, sizeof(rule));
        nss_nlcapwap_init_rule(&rule, NSS_NLCAPWAP_CMD_TYPE_DESTROY_TUN);
        rule.msg.destroy.tun_id = tun_id;

        err = nss_nlcapwap_sock_send(&gTunCtx, &rule, NULL, NULL);
        if (err) {
                CWLog("[DATATUN] DESTROY_TUN send failed: %d", err);
                return err;
        }

        CWLog("[DATATUN] DESTROY_TUN sent: tun_id=%u", tun_id);
        return 0;
}
