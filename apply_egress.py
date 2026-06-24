#!/usr/bin/env python3
# Whitespace-robust patcher for WTPDataTunnel.c + caller.
# Run from the openCAPWAP dir, with egress_helper.c alongside this script.
import os, re

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = open(os.path.join(HERE, "egress_helper.c")).read().rstrip("\n") + "\n\n"

# ---------- WTPDataTunnel.c ----------
p = "WTPDataTunnel.c"
src = open(p).read()

# 1. headers (insert after <string.h>)
if "#include <net/if.h>" not in src:
    anchor_h = "#include <string.h>"
    assert anchor_h in src, "string.h not found"
    hdrs = (anchor_h + "\n"
            "#include <unistd.h>\n"
            "#include <sys/socket.h>\n"
            "#include <sys/ioctl.h>\n"
            "#include <netinet/in.h>\n"
            "#include <arpa/inet.h>\n"
            "#include <net/if.h>")
    src = src.replace(anchor_h, hdrs, 1)
    print("headers: inserted")
else:
    print("headers: present")

# 2. helper before the function
fn = "int CWWTPCreateDataTunnel(uint32_t ac_ip_host,"
assert src.count(fn) == 1, f"fn anchor {src.count(fn)}"
if "CWResolveEgressForDest" not in src:
    src = src.replace(fn, HELPER + fn, 1)
    print("helper: inserted")
else:
    print("helper: present")

# 3. body replacement - match the 3 lines regardless of leading whitespace.
# Capture the leading whitespace of the first matched line to reuse it.
body_re = re.compile(
    r'([ \t]*)strncpy\(c->gmac_ifname, wan_ifname, sizeof\(c->gmac_ifname\) - 1\);\n'
    r'[ \t]*memcpy\(c->gmac_ifmac, wan_ifmac, 6\);\n'
    r'[ \t]*memcpy\(c->bssid, bssid, 6\);'
)
m = body_re.search(src)
assert m, "body anchor not found by regex"
ind = m.group(1)              # leading whitespace (spaces or tabs)
i2 = ind + ind.replace('\t','\t').replace('        ','        ')  # not used; build below
# Build replacement using the SAME base indent unit. We just use `ind` + one extra level.
# Use a 1-tab (or 8-space) sub-indent matching the file's style:
sub = '\t' if '\t' in ind else '        '
def L(line, extra=0):
    return ind + sub*extra + line
new_body = "\n".join([
    L("{"),
    L("char resolved_if[IFNAMSIZ];", 1),
    L("uint8_t resolved_mac[6];", 1),
    L("const char *use_if = wan_ifname;", 1),
    L("const uint8_t *use_mac = wan_ifmac;", 1),
    L("if (use_if == NULL || use_if[0] == '\\0') {", 1),
    L("if (CWResolveEgressForDest(ac_ip_host, resolved_if, resolved_mac) == 0) {", 2),
    L("use_if = resolved_if;", 3),
    L("use_mac = resolved_mac;", 3),
    L('CWLog("[DATATUN] resolved egress: %s %02x:%02x:%02x:%02x:%02x:%02x",', 3),
    L("      resolved_if, resolved_mac[0], resolved_mac[1], resolved_mac[2],", 3),
    L("      resolved_mac[3], resolved_mac[4], resolved_mac[5]);", 3),
    L("} else {", 2),
    L('CWLog("[DATATUN] egress resolution FAILED for dest 0x%08x", ac_ip_host);', 3),
    L("return -1;", 3),
    L("}", 2),
    L("}", 1),
    L("strncpy(c->gmac_ifname, use_if, sizeof(c->gmac_ifname) - 1);", 1),
    L("memcpy(c->gmac_ifmac, use_mac, 6);", 1),
    L("}"),
    L("memcpy(c->bssid, bssid, 6);"),
])
src = src[:m.start()] + new_body + src[m.end():]
print("create-tun body: updated")
open(p, "w").write(src)

# ---------- WTPIEEEConfigurationState.c ----------
p2 = "WTPIEEEConfigurationState.c"
s2 = open(p2).read()
# Remove the wanMac declaration line (any leading ws)
s2new, n1 = re.subn(r'[ \t]*uint8_t wanMac\[6\] = \{0x58,0x61,0x63,0xf3,0x8f,0xf4\};[^\n]*\n', '', s2, count=1)
# Replace the "eth1", wanMac, argument line with NULL, NULL,
s2new, n2 = re.subn(r'([ \t]*)"eth1", wanMac,', r'\1NULL, NULL,', s2new, count=1)
if n1 and n2:
    open(p2, "w").write(s2new)
    print(f"caller: updated (removed wanMac decl={n1}, args->NULL={n2})")
elif "NULL, NULL," in s2:
    print("caller: already NULL/NULL")
else:
    print(f"caller: WARNING n1={n1} n2={n2} - check manually")

print("DONE")
