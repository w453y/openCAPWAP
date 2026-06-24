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
