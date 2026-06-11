/*
 * WTPDataTunnel.h
 *
 * Milestone-3 integration: drive the IPQ6018 NSS CAPWAP data-plane offload
 * from openCAPWAP. Creates an NSS CAPWAP data tunnel (AP -> AC) bound to a
 * WLAN at ADD_WLAN time, and tears it down at DEL_WLAN / session close.
 *
 * Reuses the exact nss_nlcapwap netlink sequence validated in milestone 2
 * (capwap_tuntest.c): CREATE_TUN (auto change_version + enable_tunnel) and
 * DESTROY_TUN. Sends run with auto-ack/seq-check disabled (the M2 fix).
 */

#ifndef __WTP_DATA_TUNNEL_H
#define __WTP_DATA_TUNNEL_H

#include <stdint.h>

/*
 * Create one IPv4 CAPWAP data tunnel for the given WLAN.
 *
 *   ac_ip_host    : AC IP in HOST byte order (tunnel dest)
 *   ap_ip_host    : AP/local IP in HOST byte order (tunnel src)
 *   data_port     : CAPWAP data UDP port (5247)
 *   path_mtu      : negotiated path MTU (gWTPPathMTU)
 *   wan_ifname    : egress interface name (e.g. "eth1")
 *   wan_ifmac     : egress interface MAC (6 bytes)
 *   bssid         : BSSID of the WLAN (6 bytes)
 *   out_tun_id    : receives the tunnel id chosen (for later destroy)
 *
 * Returns 0 on success (message accepted by kernel), negative on failure.
 *
 * NOTE: success is not visible in dmesg (handler logs are pr_debug); verify
 * via /sys/kernel/debug/nlcapwap/stats. The created tunnel is auto-enabled.
 */
int CWWTPCreateDataTunnel(uint32_t ac_ip_host,
                          uint32_t ap_ip_host,
                          uint16_t data_port,
                          uint32_t path_mtu,
                          const char *wan_ifname,
                          const uint8_t wan_ifmac[6],
                          const uint8_t bssid[6],
                          uint8_t *out_tun_id);

/*
 * Destroy a previously created CAPWAP data tunnel.
 */
int CWWTPDestroyDataTunnel(uint8_t tun_id);

#endif /* __WTP_DATA_TUNNEL_H */
