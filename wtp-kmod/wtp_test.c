/*
 * wtp_test.c — minimal userspace test for wtp-kmod genl interface
 *
 * Sends CMD_LINK → CMD_CREATE → CMD_JOIN_NETDEV to the wtp kmod.
 * After running, check dmesg for:
 *   "wtp-kmod: registered rx_handler on ath1 (radio=1 wlan=1)"
 *
 * Usage: ./wtp_test <ath1_ifindex> <local_ip> <peer_ip>
 * Example: ./wtp_test 14 10.100.15.82 10.100.14.96
 *
 * Build: see Makefile.test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <netlink/route/link.h>
#include "nlsmartcapwap.h"

/* Session ID — 16 bytes, arbitrary for test */
static const uint8_t test_session_id[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};

static struct nl_sock *sock;
static int family_id;

static int send_cmd(int cmd, struct nl_msg *msg)
{
    int ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        fprintf(stderr, "nl_send_auto cmd=%d: %s\n", cmd, nl_geterror(ret));
        return ret;
    }
    /* wait for ACK */
    ret = nl_wait_for_ack(sock);
    if (ret < 0)
        fprintf(stderr, "ACK cmd=%d: %s\n", cmd, nl_geterror(ret));
    return ret;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <ath1_ifindex> <local_ip> <peer_ip> [sta_mac]\n", argv[0]);
        fprintf(stderr, "  Get ifindex: ip link show ath1 | head -1 | awk '{print $1}' | tr -d ':'\n");
        return 1;
    }

    uint32_t ifindex  = atoi(argv[1]);
    const char *local_str = argv[2];
    const char *peer_str  = argv[3];
    const char *sta_mac_str = (argc > 4) ? argv[4] : NULL;  /* optional STA MAC */

    uint8_t sta_mac[6] = {0};
    if (sta_mac_str) {
        if (sscanf(sta_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &sta_mac[0],&sta_mac[1],&sta_mac[2],
                   &sta_mac[3],&sta_mac[4],&sta_mac[5]) != 6) {
            fprintf(stderr, "Invalid STA MAC: %s\n", sta_mac_str);
            return 1;
        }
    }

    /* Build sockaddr_storage for local + peer (IPv4, port 5247) */
    struct sockaddr_storage local_addr, peer_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    memset(&peer_addr,  0, sizeof(peer_addr));
    {
        struct sockaddr_in *l = (struct sockaddr_in *)&local_addr;
        struct sockaddr_in *p = (struct sockaddr_in *)&peer_addr;
        l->sin_family = AF_INET;
        l->sin_port   = htons(5247);
        p->sin_family = AF_INET;
        p->sin_port   = htons(5247);
        if (inet_pton(AF_INET, local_str, &l->sin_addr) != 1 ||
            inet_pton(AF_INET, peer_str,  &p->sin_addr) != 1) {
            fprintf(stderr, "Invalid IP address\n");
            return 1;
        }
    }

    /* Open genl socket */
    sock = nl_socket_alloc();
    if (!sock) { perror("nl_socket_alloc"); return 1; }
    if (genl_connect(sock)) { perror("genl_connect"); return 1; }

    family_id = genl_ctrl_resolve(sock, NLSMARTCAPWAP_GENL_NAME);
    if (family_id < 0) {
        fprintf(stderr, "genl family '%s' not found — is wtp.ko loaded?\n",
                NLSMARTCAPWAP_GENL_NAME);
        return 1;
    }
    printf("found genl family '%s' id=%d\n", NLSMARTCAPWAP_GENL_NAME, family_id);

    /* 1. CMD_LINK */
    {
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                    NLSMARTCAPWAP_CMD_LINK, 1);
        if (send_cmd(NLSMARTCAPWAP_CMD_LINK, msg) < 0) return 1;
        nlmsg_free(msg);
        printf("CMD_LINK OK\n");
    }

    /* 2. CMD_CREATE */
    {
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                    NLSMARTCAPWAP_CMD_CREATE, 1);
        nla_put(msg, NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS,
                sizeof(local_addr), &local_addr);
        nla_put(msg, NLSMARTCAPWAP_ATTR_PEER_ADDRESS,
                sizeof(peer_addr), &peer_addr);
        nla_put(msg, NLSMARTCAPWAP_ATTR_SESSION_ID,
                sizeof(test_session_id), test_session_id);
        nla_put_u16(msg, NLSMARTCAPWAP_ATTR_MTU, 1450);
        if (send_cmd(NLSMARTCAPWAP_CMD_CREATE, msg) < 0) return 1;
        nlmsg_free(msg);
        printf("CMD_CREATE OK (local=%s peer=%s port=5247)\n",
               local_str, peer_str);
    }

    /* 2b. Detach ifindex from its bridge master (if any).
     * netdev_rx_handler_register fails with EBUSY if bridge is present. */
    {
        /* Use RTM_SETLINK with IFLA_MASTER=0 to remove bridge membership */
        struct nl_sock *rtsock = nl_socket_alloc();
        struct nl_msg  *rtmsg  = nlmsg_alloc();
        struct ifinfomsg ifi   = { .ifi_index = (int)ifindex };

        nl_connect(rtsock, NETLINK_ROUTE);
        nlmsg_put(rtmsg, NL_AUTO_PORT, NL_AUTO_SEQ,
                  RTM_SETLINK, 0, NLM_F_REQUEST | NLM_F_ACK);
        nlmsg_append(rtmsg, &ifi, sizeof(ifi), NLMSG_ALIGNTO);
        nla_put_u32(rtmsg, IFLA_MASTER, 0);   /* 0 = no master = leave bridge */
        int r = nl_send_auto(rtsock, rtmsg);
        if (r >= 0) nl_wait_for_ack(rtsock);
        nlmsg_free(rtmsg);
        nl_socket_free(rtsock);
        printf("bridge detach sent for ifindex=%u (errors OK if not bridged)\n",
               ifindex);
    }

    /* 3. CMD_JOIN_NETDEV */
    {
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                    NLSMARTCAPWAP_CMD_JOIN_NETDEV, 1);
        nla_put_u32(msg, NLSMARTCAPWAP_ATTR_IFINDEX,  ifindex);
        nla_put_u8 (msg, NLSMARTCAPWAP_ATTR_RADIOID,  1);
        nla_put_u8 (msg, NLSMARTCAPWAP_ATTR_WLANID,   1);
        nla_put_u8 (msg, NLSMARTCAPWAP_ATTR_BINDING,  2); /* IEEE 802.11 */
        nla_put_u32(msg, NLSMARTCAPWAP_ATTR_FLAGS,
                    NLSMARTCAPWAP_FLAGS_TUNNEL_8023);
        if (send_cmd(NLSMARTCAPWAP_CMD_JOIN_NETDEV, msg) < 0) return 1;
        nlmsg_free(msg);
        printf("CMD_JOIN_NETDEV OK (ifindex=%u)\n", ifindex);
    }

    /* 4. CMD_ADD_STATION (optional, if STA MAC given) */
    if (sta_mac_str) {
        struct nl_msg *msg = nlmsg_alloc();
        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                    NLSMARTCAPWAP_CMD_ADD_STATION, 1);
        nla_put_u8 (msg, NLSMARTCAPWAP_ATTR_RADIOID, 1);
        nla_put_u8 (msg, NLSMARTCAPWAP_ATTR_WLANID,  1);
        nla_put    (msg, NLSMARTCAPWAP_ATTR_MAC, 6, sta_mac);
        nla_put_u32(msg, NLSMARTCAPWAP_ATTR_FLAGS, 0);
        if (send_cmd(NLSMARTCAPWAP_CMD_ADD_STATION, msg) < 0) return 1;
        nlmsg_free(msg);
        printf("CMD_ADD_STATION OK (%s radio=1 wlan=1)\n", sta_mac_str);
    }

    printf("SUCCESS — check dmesg on AP for rx_handler registration\n");
    nl_socket_free(sock);
    return 0;
}
