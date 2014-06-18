/*
 * Copyright 2011, Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/types.h>
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <linux/if_packet.h>	/* sockaddr_ll */
#include <linux/if.h>		/* IFNAMSIZ */

static int monitor_init(const char *ifname)
{
	struct sockaddr_ll ll;
	int monitor_sock;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = if_nametoindex(ifname);
	if (ll.sll_ifindex == 0) {
		fprintf(stderr, "Monitor interface '%s' does not exist\n", ifname);
		return -1;
	}

	monitor_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (monitor_sock < 0) {
		fprintf(stderr, "socket(PF_PACKET,SOCK_RAW): %s\n", strerror(errno));
		return -1;
	}

	if (bind(monitor_sock, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		fprintf(stderr, "bind(PACKET): %s\n", strerror(errno));
		close(monitor_sock);
		return -1;
	}

	return monitor_sock;
}

static int inject_frame(int s, const void *data, size_t len)
{
#define IEEE80211_RADIOTAP_F_FRAG       0x08
	unsigned char rtap_hdr[] = {
		0x00, 0x00, /* radiotap version */
		0x0e, 0x00, /* radiotap length */
		0x02, 0xc0, 0x00, 0x00, /* bmap: flags, tx and rx flags */
		IEEE80211_RADIOTAP_F_FRAG, /* F_FRAG (fragment if required) */
		0x00,       /* padding */
		0x00, 0x00, /* RX and TX flags to indicate that */
		0x00, 0x00, /* this is the injected frame directly */
	};
	struct iovec iov[2] = {
		{
			.iov_base = &rtap_hdr,
			.iov_len = sizeof(rtap_hdr),
		},
		{
			.iov_base = (void *) data,
			.iov_len = len,
		}
	};
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	int ret;

	ret = sendmsg(s, &msg, 0);
	if (ret < 0)
		perror("sendmsg");
	return ret;
}

static unsigned char wol_magic_tmpl[30 + 6 + 16 * 6] = {
	0x08, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	/* RA */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	/* TA */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	/* SA */
	0x00, 0x00,

	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static void prepare_wol(unsigned char *wol_magic, unsigned char *mac)
{
	int i;

	for (i = 0; i < 16; i++)
		memcpy(&wol_magic[30 + i * 6], mac, 6);
}

void usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\twol -i monitor_dev -m DE:VI:CE:MA:CW:OL -n #num -v\n");

	fprintf(stderr, "\nDescription:\n");
	fprintf(stderr, "\tThis utility generates a WOL packet for the"
			"given [MAC] address and tries to injects"
			"it into [monitor_dev]\n");

	exit(EXIT_FAILURE);
}

#define MAC_STR "%2X:%2X:%2X:%2X:%2X:%2X"

#define M(a, i) ((unsigned int *)&a[i])
#define MAC_ARG(a) M(a, 0), M(a, 1), M(a, 2), M(a, 3), M(a, 4), M(a, 5)

#define M2(a, i) (a[i])
#define MAC_ARG2(a) M2(a, 0), M2(a, 1), M2(a, 2), M2(a, 3), M2(a, 4), M2(a, 5)

int main(int argc, char **args)
{
	int sock, err = 0, opt, num = 10;
	unsigned char mac[ETH_ALEN];
	char dev_name[IFNAMSIZ + 1] = { 0 };
	bool has_mac = false, has_dev = false, verbose = false;

	while ((opt = getopt(argc, args, "m:i:n:v")) != -EXIT_FAILURE) {
		switch (opt) {
		case 'i':
			has_dev = true;
			strncpy(dev_name, optarg, IFNAMSIZ);
			break;
		case 'm':
			has_mac = true;
			err = sscanf(optarg, MAC_STR, MAC_ARG(mac)) != 6;
			if (err)
				fprintf(stderr, "invalid MAC: \"%s\"\n", optarg);
			break;

		case 'n':
			err = sscanf(optarg, "%d", &num) != 1;
			err |= num < 1 | num > 1000;
			if (err)
				fprintf(stderr, "invalid tries: \"%s\"\n", optarg);
			break;

		case 'v':
			verbose = true;
			break;

		default:
			err = -EINVAL;
			break;
		}

		if (err)
			break;
	}

	if (!has_mac || !has_dev || err)
		usage();

	if (verbose)
		fprintf(stdout, "Opening monitor injection interface [%s].\n", dev_name);

	sock = monitor_init(dev_name);
	if (sock < 0)
		return EXIT_FAILURE;

	if (verbose)
		fprintf(stdout, "Generating %d WOL packet for ["MAC_STR"].\n", num, MAC_ARG2(mac));

	prepare_wol(wol_magic_tmpl, mac);

	while (num--) {
		err = inject_frame(sock, wol_magic_tmpl, sizeof(wol_magic_tmpl));
		if (err < 0) {
			fprintf(stderr, "failed to send WOL packet.\n");
			break;
		} else if (verbose) {
			fprintf(stdout, "WOL packet sent.\n");
		}
	}

	close(sock);
	if (err < 0)
		return EXIT_FAILURE;

	return 0;
}
