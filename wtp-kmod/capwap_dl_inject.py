#!/usr/bin/env python3
"""
capwap_dl_inject.py — inject a CAPWAP 802.3 data frame to the WTP kmod,
to test the downlink decap -> dev_queue_xmit(ath1) -> STA path.

Run on the AC. Sends to the AP's 5247. The kmod decaps and delivers the
inner 802.3 frame to the associated STA on ath1.

Usage:
  python3 capwap_dl_inject.py <ap_ip> <sta_mac> [src_mac] [count]
Example:
  python3 capwap_dl_inject.py 10.100.15.82 28:3a:4d:4d:c3:41
"""
import socket, struct, sys, time

def mac_to_bytes(s):
    return bytes(int(x, 16) for x in s.split(':'))

def build_capwap_header(hlen=2, rid=1, wbid=1, flag_t=0,
                        flag_k=0, flag_w=0, flag_m=0):
    # byte 0: preamble version(0) type(0)
    b0 = 0x00
    # bytes 1-2: uint16 LE bitfield
    _rid_hi = (rid >> 2) & 0x7
    _rid_lo = rid & 0x3
    val = ((_rid_hi & 0x7)
           | ((hlen   & 0x1f) << 3)
           | ((flag_t & 1)    << 8)
           | ((wbid   & 0x1f) << 9)
           | ((_rid_lo & 0x3) << 14))
    b12 = struct.pack('<H', val)
    # byte 3: flags
    b3 = ((flag_k & 1) << 4) | ((flag_m & 1) << 3) | ((flag_w & 1) << 2)
    # bytes 4-5 frag_id, 6-7 frag_off
    frag = struct.pack('>H', 0) + struct.pack('>H', 0)
    return bytes([b0]) + b12 + bytes([b3]) + frag

def build_inner_8023(dst_mac, src_mac):
    # Ethernet II: dst(6) src(6) ethertype(2) + payload
    eth = mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack('>H', 0x0800)
    # Minimal IPv4 + ICMP echo request payload (just needs to be parseable bytes;
    # the kmod doesn't inspect L3, it just delivers the 802.3 frame to ath1)
    payload = b'WTP-KMOD-DL-TEST-' + b'\x00' * 32
    return eth + payload

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    ap_ip   = sys.argv[1]
    sta_mac = sys.argv[2]
    src_mac = sys.argv[3] if len(sys.argv) > 3 else '56:f9:23:49:c7:6b'  # AC br0
    count   = int(sys.argv[4]) if len(sys.argv) > 4 else 5

    hdr   = build_capwap_header()
    inner = build_inner_8023(sta_mac, src_mac)
    pkt   = hdr + inner

    print(f"CAPWAP header ({len(hdr)}B): {hdr.hex()}")
    print(f"inner 802.3  ({len(inner)}B): dst={sta_mac} src={src_mac} ethertype=0x0800")
    print(f"total UDP payload: {len(pkt)}B -> {ap_ip}:5247")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind to source port 5247 so it looks like AC->WTP data channel
    try:
        s.bind(('0.0.0.0', 5247))
    except OSError as e:
        print(f"(could not bind 5247: {e} — using ephemeral source port)")
    for i in range(count):
        s.sendto(pkt, (ap_ip, 5247))
        print(f"sent {i+1}/{count}")
        time.sleep(0.3)
    s.close()
    print("done")

if __name__ == '__main__':
    main()
