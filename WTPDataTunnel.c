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

        strncpy(c->gmac_ifname, wan_ifname, sizeof(c->gmac_ifname) - 1);
        memcpy(c->gmac_ifmac, wan_ifmac, 6);
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
