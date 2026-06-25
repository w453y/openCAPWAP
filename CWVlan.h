#ifndef CW_VLAN_H
#define CW_VLAN_H
#include <string.h>

/* 802.1Q tag = 4 bytes after the 12-byte dst+src MAC:
 *   [dst:6][src:6][TPID 0x8100][PCP/DEI/VID:2][ethertype...]
 * Stage-1 VLAN support for split-MAC 802.3 passthrough. */

/* Push an 802.1Q tag (vlan != 0) into a copy of the frame.
 * out must hold len+4 bytes. Returns new length. */
static inline int CWVlanPush(unsigned char *out, const unsigned char *in, int len, int vlan)
{
    if (len < 14 || vlan == 0) { memcpy(out, in, len); return len; }
    memcpy(out, in, 12);                 /* dst+src MAC */
    out[12] = 0x81; out[13] = 0x00;      /* TPID */
    out[14] = (unsigned char)((vlan >> 8) & 0x0F);  /* PCP=0,DEI=0,VID hi */
    out[15] = (unsigned char)(vlan & 0xFF);         /* VID lo */
    memcpy(out + 16, in + 12, len - 12); /* original ethertype + payload */
    return len + 4;
}

/* Strip an 802.1Q tag in place if present. Returns new length. */
static inline int CWVlanStrip(unsigned char *buf, int len)
{
    if (len >= 16 && buf[12] == 0x81 && buf[13] == 0x00) {
        memmove(buf + 12, buf + 16, len - 16);  /* drop the 4 tag bytes */
        return len - 4;
    }
    return len;
}
#endif
