#ifndef __WTP_NLSMARTCAPWAP_HEADER__
#define __WTP_NLSMARTCAPWAP_HEADER__

/* Generic netlink family name — kept identical to freewtp for
 * compatibility with the userspace kmod.c API */
#define NLSMARTCAPWAP_GENL_NAME         "smartcapwap_wtp"

/* Tunnel mode flag: 802.3 Ethernet frames (not raw 802.11) */
#define NLSMARTCAPWAP_FLAGS_TUNNEL_8023  0x00000001

/* Netlink attributes */
enum nlsmartcapwap_attrs {
        NLSMARTCAPWAP_ATTR_UNSPEC,

        NLSMARTCAPWAP_ATTR_IFINDEX,       /* netdev ifindex (ath1) */
        NLSMARTCAPWAP_ATTR_RADIOID,       /* CAPWAP radio ID */
        NLSMARTCAPWAP_ATTR_WLANID,        /* CAPWAP WLAN ID */
        NLSMARTCAPWAP_ATTR_BINDING,       /* protocol binding (802.11) */

        NLSMARTCAPWAP_ATTR_FLAGS,         /* NLSMARTCAPWAP_FLAGS_* */

        NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK,
        NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK,
        NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK,

        NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS, /* struct sockaddr_storage */
        NLSMARTCAPWAP_ATTR_PEER_ADDRESS,  /* struct sockaddr_storage */
        NLSMARTCAPWAP_ATTR_MTU,

        NLSMARTCAPWAP_ATTR_SESSION_ID,    /* 16-byte CAPWAP session ID */

        NLSMARTCAPWAP_ATTR_DTLS,          /* reserved for future DTLS */

        NLSMARTCAPWAP_ATTR_DATA_FRAME,    /* raw 802.3 frame bytes */
        NLSMARTCAPWAP_ATTR_RSSI,
        NLSMARTCAPWAP_ATTR_SNR,
        NLSMARTCAPWAP_ATTR_RATE,

        NLSMARTCAPWAP_ATTR_MAC,           /* STA MAC address */

        /* last */
        __NLSMARTCAPWAP_ATTR_AFTER_LAST,
        NLSMARTCAPWAP_ATTR_MAX = __NLSMARTCAPWAP_ATTR_AFTER_LAST - 1
};

/* Netlink commands */
enum nlsmartcapwap_commands {
        NLSMARTCAPWAP_CMD_UNSPEC,

        NLSMARTCAPWAP_CMD_LINK,           /* userspace connects */

        NLSMARTCAPWAP_CMD_CREATE,         /* create CAPWAP session */
        NLSMARTCAPWAP_CMD_RESET,          /* destroy CAPWAP session */

        NLSMARTCAPWAP_CMD_SEND_KEEPALIVE, /* userspace → kmod */
        NLSMARTCAPWAP_CMD_RECV_KEEPALIVE, /* kmod → userspace event */

        NLSMARTCAPWAP_CMD_SEND_DATA,      /* userspace → kmod (inject DL frame) */
        NLSMARTCAPWAP_CMD_RECV_DATA,      /* kmod → userspace event (UL frame) */

        /* Replaces freewtp's JOIN_MAC80211_DEVICE.
         * Registers a netdev_rx_handler on the given ifindex (ath1).
         * No mac80211 patch required — qca-wifi already delivers 802.3
         * frames to the bridge layer; we steal them before br-lan. */
        NLSMARTCAPWAP_CMD_JOIN_NETDEV,
        NLSMARTCAPWAP_CMD_LEAVE_NETDEV,

        NLSMARTCAPWAP_CMD_ADD_STATION,    /* STA associated */
        NLSMARTCAPWAP_CMD_DEL_STATION,    /* STA disassociated */

        /* last */
        __NLSMARTCAPWAP_CMD_AFTER_LAST,
        NLSMARTCAPWAP_CMD_MAX = __NLSMARTCAPWAP_CMD_AFTER_LAST - 1
};

#endif /* __WTP_NLSMARTCAPWAP_HEADER__ */
