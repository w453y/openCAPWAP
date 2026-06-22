/*
 * wtp-kmod/netlinkapp.c
 *
 * Kernel-space CAPWAP data plane for openCAPWAP WTP on IPQ6018/qca-wifi.
 *
 * Replaces freewtp's netlinkapp.c (which requires a mac80211 kernel patch
 * and the ieee80211_pcktunnel API). Instead we use netdev_rx_handler_register()
 * on the VAP netdev (ath1), which works with Qualcomm's qca-wifi driver
 * because it already delivers 802.3 Ethernet frames to the bridge layer.
 *
 * Architecture:
 *   UL: STA → ath1 → [rx_handler steals skb] → CAPWAP encap → UDP → AC
 *   DL: AC → UDP → CAPWAP decap → dev_queue_xmit(ath1) → STA
 *
 * The control plane (DTLS handshake, state machine) stays in userspace.
 * After reaching RUN state the WTP userspace sends CREATE + JOIN_NETDEV
 * to this module and the data path moves to kernel space.
 *
 * Based on freewtp (travelping/freewtp) by Massimo Vellucci / Travelping.
 * CAPWAP framing code (capwap.c, capwap_private.c) is reused verbatim.
 */

#include "config.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/rcupdate.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>

#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>

#include "nlsmartcapwap.h"
#include "netlinkapp.h"
#include "capwap.h"

/* ------------------------------------------------------------------ */
/* Per-netdev handle — one per JOIN_NETDEV                             */
/* ------------------------------------------------------------------ */

struct wtp_netdev_handle {
        struct list_head  list;
        struct net_device *dev;        /* ath1 — held with dev_hold()   */
        uint8_t           radioid;
        uint8_t           wlanid;
        uint8_t           binding;
        uint32_t          flags;
        struct net       *net;
};

/* ------------------------------------------------------------------ */
/* Per-net-namespace state                                             */
/* ------------------------------------------------------------------ */

static int sc_net_id __read_mostly;

struct sc_net {
        uint32_t                  sc_netlink_usermodeid;
        struct sc_capwap_session  sc_acsession;
        struct list_head          sc_netlink_dev_list;
};

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static int  sc_netlink_pre_doit(const struct genl_ops *ops,
                                struct sk_buff *skb,
                                struct genl_info *info);
static void sc_netlink_post_doit(const struct genl_ops *ops,
                                 struct sk_buff *skb,
                                 struct genl_info *info);

/* ------------------------------------------------------------------ */
/* UL RX handler — replaces freewtp's ieee80211_pcktunnel handler      */
/*                                                                     */
/* Called by the kernel when a frame arrives on ath1 before br-lan     */
/* sees it. skb->data points to the Ethernet header (802.3).           */
/* We CAPWAP-encapsulate and send to the AC via UDP tunnel socket.     */
/* ------------------------------------------------------------------ */

static rx_handler_result_t wtp_rx_handler(struct sk_buff **pskb)
{
        struct sk_buff           *skb = *pskb;
        struct wtp_netdev_handle *nldev;
        struct sc_net            *sc;
        int                       ret;

        TRACEKMOD("### wtp_rx_handler ifindex=%d len=%d\n",
                  skb->dev->ifindex, skb->len);

        nldev = rcu_dereference(skb->dev->rx_handler_data);
        if (!nldev)
                return RX_HANDLER_PASS;

        sc = net_generic(nldev->net, sc_net_id);
        if (!sc || !sc->sc_acsession.socket)
                return RX_HANDLER_PASS;

        /* Make sure skb is linear — sc_capwap_send_data needs contiguous data */
        if (skb_linearize(skb)) {
                TRACEKMOD("*** wtp_rx_handler: skb_linearize failed\n");
                kfree_skb(skb);
                *pskb = NULL;
                return RX_HANDLER_CONSUMED;
        }

        /* CAPWAP-encapsulate the 802.3 frame and send to AC via
         * sc_capwap_forwarddata() which builds the CAPWAP header and
         * sends over the UDP tunnel socket. We need to give it an skb
         * with CAPWAP_HEADER_MAX_LENGTH headroom for the header. */
        {
                struct sk_buff *fwdskb;
                int len = skb->len;

                fwdskb = alloc_skb(len + CAPWAP_HEADER_MAX_LENGTH, GFP_ATOMIC);
                if (!fwdskb) {
                        kfree_skb(skb);
                        *pskb = NULL;
                        return RX_HANDLER_CONSUMED;
                }
                skb_reserve(fwdskb, CAPWAP_HEADER_MAX_LENGTH);
                memcpy(skb_put(fwdskb, len), skb->data, len);

                ret = sc_capwap_forwarddata(&sc->sc_acsession,
                                            nldev->radioid,
                                            nldev->binding,
                                            fwdskb,
                                            NLSMARTCAPWAP_FLAGS_TUNNEL_8023,
                                            NULL, 0, NULL, 0);
                if (ret)
                        TRACEKMOD("*** wtp_rx_handler: forwarddata ret=%d\n", ret);

                kfree_skb(fwdskb);
        }

        kfree_skb(skb);
        *pskb = NULL;
        return RX_HANDLER_CONSUMED;
}

/* ------------------------------------------------------------------ */
/* DL inject — deliver a decapsulated 802.3 frame to ath1 → STA        */
/* Called from the UDP RX path (capwap.c sc_capwap_parsingpacket).     */
/* ------------------------------------------------------------------ */

int sc_netlink_notify_recv_data(struct net *net,
                                uint8_t *packet, int length)
{
        struct sc_net            *sc;
        struct wtp_netdev_handle *nldev;
        struct sk_buff           *skb;

        TRACEKMOD("### sc_netlink_notify_recv_data len=%d\n", length);

        sc = net_generic(net, sc_net_id);
        if (!sc)
                return -ENODEV;

        /* Find the first registered netdev — in our single-VAP model
         * there's one entry; multi-VAP support can extend this later. */
        if (list_empty(&sc->sc_netlink_dev_list))
                return -ENODEV;

        nldev = list_first_entry(&sc->sc_netlink_dev_list,
                                 struct wtp_netdev_handle, list);

        /* Allocate an skb and copy the decapsulated 802.3 frame */
        skb = netdev_alloc_skb(nldev->dev, length + NET_IP_ALIGN);
        if (!skb)
                return -ENOMEM;

        skb_reserve(skb, NET_IP_ALIGN);
        memcpy(skb_put(skb, length), packet, length);

        skb->dev      = nldev->dev;
        skb->protocol = eth_type_trans(skb, nldev->dev);

        /* Send down to ath1 — qca-wifi handles 802.3→802.11 and queuing */
        dev_queue_xmit(skb);
        return 0;
}

/* ------------------------------------------------------------------ */
/* Keepalive notify (called from capwap.c on keepalive receipt)        */
/* ------------------------------------------------------------------ */

int sc_netlink_notify_recv_keepalive(struct net *net,
                                     struct sc_capwap_sessionid_element *sessionid)
{
        TRACEKMOD("### sc_netlink_notify_recv_keepalive\n");
        /* TODO: forward keepalive event to userspace via netlink upcall
         * so the WTP state machine can reset its keepalive timer.
         * For milestone 1 we silently consume it here. */
        return 0;
}

/* ------------------------------------------------------------------ */
/* Helper: find VAP netdev by radioid/wlanid                           */
/* ------------------------------------------------------------------ */

struct net_device *sc_netlink_getdev_from_wlanid(struct net *net,
                                                  uint8_t radioid,
                                                  uint8_t wlanid)
{
        struct sc_net            *sc = net_generic(net, sc_net_id);
        struct wtp_netdev_handle *nldev;

        if (!sc)
                return NULL;

        list_for_each_entry(nldev, &sc->sc_netlink_dev_list, list) {
                if (nldev->radioid == radioid && nldev->wlanid == wlanid)
                        return nldev->dev;
        }
        return NULL;
}

/* ------------------------------------------------------------------ */
/* Netlink command handlers                                            */
/* ------------------------------------------------------------------ */

static int sc_netlink_pre_doit(const struct genl_ops *ops,
                               struct sk_buff *skb,
                               struct genl_info *info)
{
        TRACEKMOD("### sc_netlink_pre_doit\n");
        rtnl_lock();
        return 0;
}

static void sc_netlink_post_doit(const struct genl_ops *ops,
                                  struct sk_buff *skb,
                                  struct genl_info *info)
{
        TRACEKMOD("### sc_netlink_post_doit\n");
        rtnl_unlock();
}

/* CMD_LINK — userspace daemon announces itself */
static int sc_netlink_link(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net *sc = net_generic(genl_info_net(info), sc_net_id);
        TRACEKMOD("### sc_netlink_link\n");
        sc->sc_netlink_usermodeid = info->snd_portid;
        return 0;
}

/* CMD_CREATE — create the CAPWAP UDP tunnel session */
static int sc_netlink_create(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net                *sc;
        struct sockaddr_storage       local, peer;
        uint16_t                      mtu = 1500;
        struct sc_capwap_sessionid_element sessionid;

        TRACEKMOD("### sc_netlink_create\n");

        sc = net_generic(genl_info_net(info), sc_net_id);

        if (!info->attrs[NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS] ||
            !info->attrs[NLSMARTCAPWAP_ATTR_PEER_ADDRESS]  ||
            !info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID])
                return -EINVAL;

        memcpy(&local, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS]),
               sizeof(local));
        memcpy(&peer,  nla_data(info->attrs[NLSMARTCAPWAP_ATTR_PEER_ADDRESS]),
               sizeof(peer));
        memcpy(&sessionid, nla_data(info->attrs[NLSMARTCAPWAP_ATTR_SESSION_ID]),
               sizeof(sessionid));

        if (info->attrs[NLSMARTCAPWAP_ATTR_MTU])
                mtu = nla_get_u16(info->attrs[NLSMARTCAPWAP_ATTR_MTU]);

        /* Populate session config before calling sc_capwap_create */
        memcpy(&sc->sc_acsession.sessionid, &sessionid,
               sizeof(struct sc_capwap_sessionid_element));
        sc->sc_acsession.mtu = mtu;

        {
                struct udp_port_cfg *cfg = &sc->sc_acsession.udp_config;
                struct sockaddr_in *l4 = (struct sockaddr_in *)&local;
                struct sockaddr_in *p4 = (struct sockaddr_in *)&peer;
                cfg->family           = peer.ss_family;
                cfg->local_udp_port   = l4->sin_port;
                cfg->peer_udp_port    = p4->sin_port;
                cfg->use_udp_checksums    = 1;
                cfg->use_udp6_tx_checksums = 1;
                cfg->use_udp6_rx_checksums = 1;
                /* Copy IP addresses into the udp_port_cfg union fields */
                memcpy(&cfg->local_ip, &l4->sin_addr, sizeof(struct in_addr));
                memcpy(&cfg->peer_ip, &p4->sin_addr, sizeof(struct in_addr));
        }

        return sc_capwap_create(&sc->sc_acsession);
}

/* CMD_RESET — destroy the CAPWAP session and deregister all netdevs */
static int sc_netlink_reset(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net            *sc;
        struct wtp_netdev_handle *nldev, *tmp;

        TRACEKMOD("### sc_netlink_reset\n");

        sc = net_generic(genl_info_net(info), sc_net_id);

        /* Deregister all rx_handlers */
        list_for_each_entry_safe(nldev, tmp, &sc->sc_netlink_dev_list, list) {
                netdev_rx_handler_unregister(nldev->dev);
                dev_put(nldev->dev);
                list_del(&nldev->list);
                kfree(nldev);
        }

        sc_capwap_close(&sc->sc_acsession);
        return 0;
}

/* CMD_JOIN_NETDEV — register rx_handler on ath1 (replaces JOIN_MAC80211_DEVICE) */
static int sc_netlink_join_netdev(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net            *sc;
        struct wtp_netdev_handle *nldev;
        struct net_device        *dev;
        uint32_t                  ifindex;
        int                       ret;

        TRACEKMOD("### sc_netlink_join_netdev\n");

        if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX])
                return -EINVAL;

        ifindex = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]);
        sc      = net_generic(genl_info_net(info), sc_net_id);

        dev = dev_get_by_index(genl_info_net(info), ifindex);
        if (!dev) {
                pr_err("wtp-kmod: JOIN_NETDEV: ifindex %u not found\n", ifindex);
                return -ENODEV;
        }

        nldev = kzalloc(sizeof(*nldev), GFP_KERNEL);
        if (!nldev) {
                dev_put(dev);
                return -ENOMEM;
        }

        nldev->dev     = dev;   /* dev_hold already done by dev_get_by_index */
        nldev->net     = genl_info_net(info);
        nldev->binding = info->attrs[NLSMARTCAPWAP_ATTR_BINDING]
                         ? nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_BINDING]) : 0;
        nldev->radioid = info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]
                         ? nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_RADIOID]) : 0;
        nldev->wlanid  = info->attrs[NLSMARTCAPWAP_ATTR_WLANID]
                         ? nla_get_u8(info->attrs[NLSMARTCAPWAP_ATTR_WLANID]) : 0;
        nldev->flags   = info->attrs[NLSMARTCAPWAP_ATTR_FLAGS]
                         ? nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_FLAGS])
                         : NLSMARTCAPWAP_FLAGS_TUNNEL_8023;

        /* Register the rx_handler — this steals frames from ath1 before
         * br-lan sees them. The handler data pointer is the nldev struct. */
        ret = netdev_rx_handler_register(dev, wtp_rx_handler, nldev);
        if (ret) {
                pr_err("wtp-kmod: netdev_rx_handler_register(%s) failed: %d\n",
                       dev->name, ret);
                dev_put(dev);
                kfree(nldev);
                return ret;
        }

        list_add(&nldev->list, &sc->sc_netlink_dev_list);
        pr_info("wtp-kmod: registered rx_handler on %s (radio=%u wlan=%u)\n",
                dev->name, nldev->radioid, nldev->wlanid);
        return 0;
}

/* CMD_LEAVE_NETDEV — deregister rx_handler from ath1 */
static int sc_netlink_leave_netdev(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net            *sc;
        struct wtp_netdev_handle *nldev, *tmp;
        uint32_t                  ifindex;

        TRACEKMOD("### sc_netlink_leave_netdev\n");

        if (!info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX])
                return -EINVAL;

        ifindex = nla_get_u32(info->attrs[NLSMARTCAPWAP_ATTR_IFINDEX]);
        sc      = net_generic(genl_info_net(info), sc_net_id);

        list_for_each_entry_safe(nldev, tmp, &sc->sc_netlink_dev_list, list) {
                if (nldev->dev->ifindex == ifindex) {
                        netdev_rx_handler_unregister(nldev->dev);
                        pr_info("wtp-kmod: unregistered rx_handler on %s\n",
                                nldev->dev->name);
                        dev_put(nldev->dev);
                        list_del(&nldev->list);
                        kfree(nldev);
                        return 0;
                }
        }
        return -ENODEV;
}

/* CMD_SEND_DATA — userspace injects a downlink 802.3 frame into ath1 */
static int sc_netlink_send_data(struct sk_buff *skb, struct genl_info *info)
{
        struct sc_net            *sc;
        struct wtp_netdev_handle *nldev;
        struct sk_buff           *newskb;
        uint8_t                  *data;
        int                       length;

        TRACEKMOD("### sc_netlink_send_data\n");

        if (!info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME])
                return -EINVAL;

        sc     = net_generic(genl_info_net(info), sc_net_id);
        data   = nla_data(info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]);
        length = nla_len(info->attrs[NLSMARTCAPWAP_ATTR_DATA_FRAME]);

        if (list_empty(&sc->sc_netlink_dev_list))
                return -ENODEV;

        nldev = list_first_entry(&sc->sc_netlink_dev_list,
                                 struct wtp_netdev_handle, list);

        newskb = netdev_alloc_skb(nldev->dev, length + NET_IP_ALIGN);
        if (!newskb)
                return -ENOMEM;

        skb_reserve(newskb, NET_IP_ALIGN);
        memcpy(skb_put(newskb, length), data, length);
        newskb->dev      = nldev->dev;
        newskb->protocol = eth_type_trans(newskb, nldev->dev);

        dev_queue_xmit(newskb);
        return 0;
}

/* CMD_ADD_STATION / CMD_DEL_STATION — future: update per-STA state */
static int sc_netlink_add_station(struct sk_buff *skb, struct genl_info *info)
{
        TRACEKMOD("### sc_netlink_add_station\n");
        return 0;
}

static int sc_netlink_del_station(struct sk_buff *skb, struct genl_info *info)
{
        TRACEKMOD("### sc_netlink_del_station\n");
        return 0;
}

/* ------------------------------------------------------------------ */
/* Genl family definition                                              */
/* ------------------------------------------------------------------ */

static const struct nla_policy sc_netlink_policy[NLSMARTCAPWAP_ATTR_MAX + 1] = {
        [NLSMARTCAPWAP_ATTR_IFINDEX]           = { .type = NLA_U32 },
        [NLSMARTCAPWAP_ATTR_RADIOID]           = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_WLANID]            = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_BINDING]           = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_FLAGS]             = { .type = NLA_U32 },
        [NLSMARTCAPWAP_ATTR_MGMT_SUBTYPE_MASK] = { .type = NLA_U16 },
        [NLSMARTCAPWAP_ATTR_CTRL_SUBTYPE_MASK] = { .type = NLA_U16 },
        [NLSMARTCAPWAP_ATTR_DATA_SUBTYPE_MASK] = { .type = NLA_U16 },
        [NLSMARTCAPWAP_ATTR_LOCAL_ADDRESS]     = { .type = NLA_BINARY,
                                                   .len = sizeof(struct sockaddr_storage) },
        [NLSMARTCAPWAP_ATTR_PEER_ADDRESS]      = { .type = NLA_BINARY,
                                                   .len = sizeof(struct sockaddr_storage) },
        [NLSMARTCAPWAP_ATTR_MTU]               = { .type = NLA_U16 },
        [NLSMARTCAPWAP_ATTR_SESSION_ID]        = { .type = NLA_BINARY,
                                                   .len = sizeof(struct sc_capwap_sessionid_element) },
        [NLSMARTCAPWAP_ATTR_DATA_FRAME]        = { .type = NLA_BINARY, .len = 2048 },
        [NLSMARTCAPWAP_ATTR_RSSI]              = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_SNR]               = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_RATE]              = { .type = NLA_U8  },
        [NLSMARTCAPWAP_ATTR_MAC]               = { .type = NLA_BINARY, .len = ETH_ALEN },
};

static const struct genl_ops sc_netlink_ops[] = {
        { .cmd = NLSMARTCAPWAP_CMD_LINK,           .doit = sc_netlink_link           },
        { .cmd = NLSMARTCAPWAP_CMD_CREATE,         .doit = sc_netlink_create         },
        { .cmd = NLSMARTCAPWAP_CMD_RESET,          .doit = sc_netlink_reset          },
        { .cmd = NLSMARTCAPWAP_CMD_JOIN_NETDEV,    .doit = sc_netlink_join_netdev    },
        { .cmd = NLSMARTCAPWAP_CMD_LEAVE_NETDEV,   .doit = sc_netlink_leave_netdev   },
        { .cmd = NLSMARTCAPWAP_CMD_SEND_DATA,      .doit = sc_netlink_send_data      },
        { .cmd = NLSMARTCAPWAP_CMD_ADD_STATION,    .doit = sc_netlink_add_station    },
        { .cmd = NLSMARTCAPWAP_CMD_DEL_STATION,    .doit = sc_netlink_del_station    },
};

static struct genl_family sc_netlink_family = {
        .name       = NLSMARTCAPWAP_GENL_NAME,
        .version    = 1,
        .maxattr    = NLSMARTCAPWAP_ATTR_MAX,
        .policy     = sc_netlink_policy,
        .pre_doit   = sc_netlink_pre_doit,
        .post_doit  = sc_netlink_post_doit,
        .ops        = sc_netlink_ops,
        .n_ops      = ARRAY_SIZE(sc_netlink_ops),
        .netnsok    = true,
};

/* ------------------------------------------------------------------ */
/* Per-net-namespace init/exit                                         */
/* ------------------------------------------------------------------ */

static int __net_init sc_net_init(struct net *net)
{
        struct sc_net *sc = net_generic(net, sc_net_id);
        TRACEKMOD("### sc_net_init\n");
        INIT_LIST_HEAD(&sc->sc_netlink_dev_list);
        sc_capwap_init(&sc->sc_acsession, net);
        return 0;
}

static void __net_exit sc_net_exit(struct net *net)
{
        struct sc_net            *sc = net_generic(net, sc_net_id);
        struct wtp_netdev_handle *nldev, *tmp;

        TRACEKMOD("### sc_net_exit\n");

        list_for_each_entry_safe(nldev, tmp, &sc->sc_netlink_dev_list, list) {
                netdev_rx_handler_unregister(nldev->dev);
                dev_put(nldev->dev);
                list_del(&nldev->list);
                kfree(nldev);
        }
        sc_capwap_close(&sc->sc_acsession);
}

static struct pernet_operations sc_net_ops = {
        .init  = sc_net_init,
        .exit  = sc_net_exit,
        .id    = &sc_net_id,
        .size  = sizeof(struct sc_net),
};

/* ------------------------------------------------------------------ */
/* Module init/exit                                                    */
/* ------------------------------------------------------------------ */

int sc_netlink_init(void)
{
        int ret;

        TRACEKMOD("### sc_netlink_init\n");

        ret = register_pernet_subsys(&sc_net_ops);
        if (ret) {
                pr_err("wtp-kmod: register_pernet_subsys failed: %d\n", ret);
                return ret;
        }

        ret = genl_register_family(&sc_netlink_family);
        if (ret) {
                pr_err("wtp-kmod: genl_register_family failed: %d\n", ret);
                unregister_pernet_subsys(&sc_net_ops);
                return ret;
        }

        pr_info("wtp-kmod: loaded (genl family '%s')\n", NLSMARTCAPWAP_GENL_NAME);
        return 0;
}

void sc_netlink_exit(void)
{
        TRACEKMOD("### sc_netlink_exit\n");
        genl_unregister_family(&sc_netlink_family);
        unregister_pernet_subsys(&sc_net_ops);
        pr_info("wtp-kmod: unloaded\n");
}
