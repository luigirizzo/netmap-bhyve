/*-
 * Copyright (c) 2014 Vincenzo Maffione <v.maffione@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>		/* u_short etc */
#include <net/ethernet.h>	/* ETHER_ADDR_LEN */
#include <net/if.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <poll.h>
#include <assert.h>


#include "net_backends.h"
#include "dev/virtio/network/virtio_net.h"

#include <sys/linker_set.h>

/*
 * The API for network backends. This might need to be exposed
 * if we implement them in separate files.
 */
struct net_backend {
	const char *name;	/* name of the backend */
	/*
	 * The init and cleanup functions are used internally,
	 * virtio-net should never use it.
	 */
	int (*init)(struct net_backend *be, const char *devname,
				net_backend_cb_t cb, void *param);
	void (*cleanup)(struct net_backend *be);


	/*
	 * Called to serve a guest transmit request. The scatter-gather
	 * vector provided by the caller has 'iovcnt' elements and contains
	 * the packet to send. 'len' is the length of whole packet in bytes.
	 */
	int (*send)(struct net_backend *be, struct iovec *iov,
			int iovcnt, int len, int more);

	/*
	 * Called to serve guest receive request. When the function
	 * returns a positive value, the scatter-gather vector
	 * provided by the caller (having 'iovcnt' elements in it) will
	 * contain a chunk of the received packet. The 'more' flag will
	 * be set if the returned chunk was the last one for the current
	 * packet, and 0 otherwise. The function returns the chunk size
	 * in bytes, or 0 if the backend doesn't have a new packet to
	 * receive.
	 * Note that it may be necessary to call this callback many
	 * times to receive a single packet, depending of how big is
	 * buffers you provide.
	 */
	int (*recv)(struct net_backend *be, struct iovec *iov,
		    int iovcnt, int *more);

	/*
	 * Ask the backend for the virtio-net features it is able to
	 * support. Possible features are TSO, UFO and checksum offloading
	 * in both rx and tx direction and for both IPv4 and IPv6.
	 */
	uint32_t (*get_features)(struct net_backend *be);

	/*
	 * Tell the backend to enable/disable the specified virtio-net
	 * features.
	 */
	uint32_t (*set_features)(struct net_backend *be, uint32_t features);

	int fd;
	void *priv;	/* Pointer to backend-specific data. */
};


SET_DECLARE(net_backend_set, struct net_backend);

#define WPRINTF(params) printf params

/* the null backend */
static int
netbe_null_init(struct net_backend *be, const char *devname,
			net_backend_cb_t cb, void *param)
{
	be->fd = -1;
	return 0;
}

static void
netbe_null_cleanup(struct net_backend *be)
{
}

static uint32_t
netbe_null_get_features(struct net_backend *be)
{
	return 0;
}

static uint32_t
netbe_null_set_features(struct net_backend *be, uint32_t features)
{
	return 0;
}

static int
netbe_null_send(struct net_backend *be, struct iovec *iov,
	int iovcnt, int len, int more)
{
	return 0; /* pretend we send */
}

static int
netbe_null_recv(struct net_backend *be, struct iovec *iov,
	int iovcnt, int *more)
{
	fprintf(stderr, "netbe_null_recv called ?\n");
	return -1; /* never called, i believe */
}

static struct net_backend null_backend = {
	.name = "null",
	.init = netbe_null_init,
	.cleanup = netbe_null_cleanup,
	.send = netbe_null_send,
	.recv = netbe_null_recv,
	.get_features = netbe_null_get_features,
	.set_features = netbe_null_set_features,
};

DATA_SET(net_backend_set, null_backend);


/* the tap backend */

struct tap_priv {
	struct mevent *mevp;
};


static void
tap_cleanup(struct net_backend *be)
{
	// XXX destroy priv->mevp ?
	if (be->fd != -1)
		close(be->fd);
	if (be->priv)
		free(be->priv);
	be->fd = -1;
	be->priv = NULL;
}



static int
tap_init(struct net_backend *be, const char *devname,
			net_backend_cb_t cb, void *param)
{
	char tbuf[80];
	int fd;
	int opt = 1;
	struct tap_priv *priv;

	priv = calloc(1, sizeof(struct tap_priv));
	if (priv == NULL) {
		WPRINTF(("tap_priv alloc failed\n"));
		return -1;
	}

	strcpy(tbuf, "/dev/");
	strlcat(tbuf, devname, sizeof(tbuf));

	fd = open(tbuf, O_RDWR);
	if (fd == -1) {
		WPRINTF(("open of tap device %s failed\n", tbuf));
		goto error;
	}

	/*
	 * Set non-blocking and register for read
	 * notifications with the event loop
	 */
	if (ioctl(fd, FIONBIO, &opt) < 0) {
		WPRINTF(("tap device O_NONBLOCK failed\n"));
		goto error;
	}

	priv->mevp = mevent_add(fd,
			EVF_READ,
			cb,
			param);
	if (priv->mevp == NULL) {
		WPRINTF(("Could not register event\n"));
		goto error;
	}

	be->fd = fd;
	be->priv = priv;

	return 0;

error:
	tap_cleanup(be);
	return -1;
}


/*
 * Called to send a buffer chain out to the tap device
 */
static int
tap_send(struct net_backend *be, struct iovec *iov, int iovcnt, int len,
	int more)
{
	static char pad[60]; /* all zero bytes */

	/* Skip the first descriptor, which contains the virtio-net
	 * header.
	 */
	len -= iov[0].iov_len;
	iov++;
	iovcnt--;

	/*
	 * If the length is < 60, pad out to that and add the
	 * extra zero'd segment to the iov. It is guaranteed that
	 * there is always an extra iov available by the caller.
	 */
	if (len < 60) {
		iov[iovcnt].iov_base = pad;
		iov[iovcnt].iov_len = 60 - len;
		iovcnt++;
	}
	return writev(be->fd, iov, iovcnt);
}

static int
tap_recv(struct net_backend *be, struct iovec *iov, int iovcnt, int *more)
{
	struct virtio_net_hdr_mrg_rxbuf *vrx;
	uint8_t *buf;
	int ret, len = sizeof(*vrx);

	*more = 0;

	/*
	 * Get a pointer to the rx header, and use the
	 * data immediately following it for the packet buffer.
	 */
	vrx = iov[0].iov_base;
	buf = (uint8_t *)(vrx + 1);

	ret = read(be->fd, buf, iov[0].iov_len - len);

	if (ret < 0 && errno == EWOULDBLOCK) {
		return 0;
	}

	/* Insert an empty rx packet header. */
	memset(vrx, 0, len);
	ret += len;

	return ret;
}



static struct net_backend tap_backend = {
	.name = "tap",
	.init = tap_init,
	.cleanup = tap_cleanup,
	.send = tap_send,
	.recv = tap_recv,
	.get_features = netbe_null_get_features,
	.set_features = netbe_null_set_features,
};

DATA_SET(net_backend_set, tap_backend);

/*
 * The netmap backend
 */

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#if (NETMAP_API < 11)
#error "Netmap API version must be >= 11"
#endif

/* The virtio-net features supported by netmap. */
#define NETMAP_FEATURES (VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_TSO4 | \
		VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_HOST_UFO | \
		VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_GUEST_TSO4 | \
		VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_UFO)

#define NETMAP_POLLMASK (POLLIN | POLLRDNORM | POLLRDBAND)

struct netmap_priv {
	char ifname[IFNAMSIZ];
	struct nm_desc *nmd;
	struct netmap_ring *rx;
	struct netmap_ring *tx;
	pthread_t evloop_tid;
	net_backend_cb_t cb;
	void *cb_param;

	/* Support for splitted receives. */
	int rx_continue;
	int rx_idx;
	uint8_t *rx_buf;
	int rx_avail;
	int rx_morefrag;
	int rx_avail_slots;
};

static void *
netmap_evloop_thread(void *param)
{
	struct net_backend *be = param;
	struct netmap_priv *priv = be->priv;
	struct pollfd pfd;
	int ret;

	for (;;) {
		pfd.fd = be->fd;
		pfd.events = NETMAP_POLLMASK;
		ret = poll(&pfd, 1, INFTIM);
		if (ret == -1 && errno != EINTR) {
			WPRINTF(("netmap poll failed, %d\n", errno));
		} else if (ret == 1 && (pfd.revents & NETMAP_POLLMASK)) {
			priv->cb(pfd.fd, EVF_READ, priv->cb_param);
		}
	}

	return NULL;
}

static void
netmap_set_vnet_hdr_len(struct net_backend *be,
				   int vnet_hdr_len)
{
	int err;
	struct nmreq req;
	struct netmap_priv *priv = be->priv;

	memset(&req, 0, sizeof(req));
	strcpy(req.nr_name, priv->ifname);
	req.nr_version = NETMAP_API;
	req.nr_cmd = NETMAP_BDG_VNET_HDR;
	req.nr_arg1 = vnet_hdr_len;
	err = ioctl(be->fd, NIOCREGIF, &req);
	if (err) {
		WPRINTF(("Unable to set vnet header length %d\n",
				vnet_hdr_len));
	}
}

static uint32_t
netmap_get_features(struct net_backend *be)
{
	return NETMAP_FEATURES;
}

static uint32_t
netmap_set_features(struct net_backend *be, uint32_t features)
{
	int vnet_hdr_len = 0;

	if (features & NETMAP_FEATURES) {
		vnet_hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	}

	netmap_set_vnet_hdr_len(be, vnet_hdr_len);
	return 0;
}

static int
netmap_init(struct net_backend *be, const char *devname,
			net_backend_cb_t cb, void *param)
{
	const char *ndname = "/dev/netmap";
	struct netmap_priv *priv = NULL;
	char tname[40];

	priv = calloc(1, sizeof(struct netmap_priv));
	if (priv == NULL) {
		WPRINTF(("Unable alloc netmap private data\n"));
		return -1;
	}

	strncpy(priv->ifname, devname, sizeof(priv->ifname));
	priv->ifname[sizeof(priv->ifname) - 1] = '\0';

	priv->nmd = nm_open(priv->ifname, NULL, NETMAP_NO_TX_POLL, NULL);
	if (priv->nmd == NULL) {
		WPRINTF(("Unable to nm_open(): device '%s', "
				"interface '%s', errno (%s)\n",
				ndname, devname, strerror(errno)));
		goto err_open;
	}

	priv->tx = NETMAP_TXRING(priv->nmd->nifp, 0);
	priv->rx = NETMAP_RXRING(priv->nmd->nifp, 0);

	priv->cb = cb;
	priv->cb_param = param;
	priv->rx_continue = 0;

	be->fd = priv->nmd->fd;
	be->priv = priv;

	/* Create a thread for netmap poll. */
	pthread_create(&priv->evloop_tid, NULL, netmap_evloop_thread, (void *)be);
	snprintf(tname, sizeof(tname), "netmap-evloop-%p", priv);
	pthread_set_name_np(priv->evloop_tid, tname);

	return 0;

err_open:
	free(priv);

	return -1;
}

static void
netmap_cleanup(struct net_backend *be)
{
	struct netmap_priv *priv = be->priv;

	if (priv) {
		nm_close(priv->nmd);
	}
	be->fd = -1;
}

/* A fast copy routine only for multiples of 64 bytes, non overlapped. */
static inline void
pkt_copy(const void *_src, void *_dst, int l)
{
    const uint64_t *src = _src;
    uint64_t *dst = _dst;
    if (l >= 1024) {
        bcopy(src, dst, l);
        return;
    }
    for (; l > 0; l -= 64) {
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
    }
}

static int
netmap_send(struct net_backend *be, struct iovec *iov,
			int iovcnt, int size, int more)
{
	struct netmap_priv *priv = be->priv;
	struct netmap_ring *ring;
	uint32_t last;
	uint32_t idx;
	uint8_t *dst;
	int j;
	uint32_t i;

	if (iovcnt <= 0)
		goto txsync;

	ring = priv->tx;
	last = i = ring->cur;

	if (nm_ring_space(ring) < iovcnt) {
		static int c;
		c++;
		RD(5, "no space, txsync %d", c);
		/* Not enough netmap slots. */
		goto txsync;
	}

	for (j = 0; j < iovcnt; j++) {
		int iov_frag_size = iov[j].iov_len;
		int offset = 0;
		int nm_frag_size;

		/* Split each iovec fragment over more netmap slots, if
		   necessary (without performing data copy). */
		while (iov_frag_size) {
			nm_frag_size = iov_frag_size;
			if (nm_frag_size > ring->nr_buf_size) {
				nm_frag_size = ring->nr_buf_size;
			}

			if (nm_ring_empty(ring)) {
				/* We run out of netmap slots while splitting the
				   iovec fragments. */
				goto txsync;
			}

			idx = ring->slot[i].buf_idx;
			dst = (uint8_t *)NETMAP_BUF(ring, idx);

			ring->slot[i].len = nm_frag_size;
#ifdef USE_INDIRECT_BUFFERS
			ring->slot[i].flags = NS_MOREFRAG | NS_INDIRECT;
			*((const uint8_t **)dst) = iov[j].iov_base + offset;
#else	/* !USE_INDIRECT_BUFFERS */
			ring->slot[i].flags = NS_MOREFRAG;
			pkt_copy(iov[j].iov_base + offset, dst, nm_frag_size);
#endif	/* !USING_INDIRECT_BUFFERS */

			last = i;
			i = nm_ring_next(ring, i);

			offset += nm_frag_size;
			iov_frag_size -= nm_frag_size;
		}
	}
	/* The last slot must not have NS_MOREFRAG set. */
	ring->slot[last].flags &= ~NS_MOREFRAG;

	/* Now update ring->cur and ring->avail. */
	ring->cur = ring->head = i;

txsync:
	if (!more || nm_ring_space(ring) < 64) {
		// IFRATE(vq->vq_vs->rate.cur.var2[vq->vq_num]++);
		netmap_ioctl_counter++;
		ioctl(be->fd, NIOCTXSYNC, NULL);
	}

	return 0;
}

static int netmap_receive(struct net_backend *be, struct iovec *iov,
			  int iovcnt, int *more)
{
	struct netmap_priv *priv = be->priv;
	struct netmap_ring *ring;
	int tot = 0;
	int copylen;
	int iov_avail;
	uint8_t *iov_buf;

	assert(iovcnt);

	ring = priv->rx;

	/* Init iovec pointers. */
	iov_buf = iov->iov_base;
	iov_avail = iov->iov_len;

	if (!priv->rx_continue) {
		/* Init netmap pointers. */
		priv->rx_idx = ring->cur;
		priv->rx_avail_slots = nm_ring_space(ring);
		priv->rx_buf = NETMAP_BUF(ring,
				ring->slot[priv->rx_idx].buf_idx);
		priv->rx_avail = ring->slot[priv->rx_idx].len;
		priv->rx_morefrag = (ring->slot[priv->rx_idx].flags
					& NS_MOREFRAG);

		if (!priv->rx_avail_slots) {
			goto out;
		}
		priv->rx_continue = 1;
	}

	for (;;) {
		copylen = priv->rx_avail;
		if (copylen > iov_avail) {
			copylen = iov_avail;
		}

		/* Copy and update pointers. */
		bcopy(priv->rx_buf, iov_buf, copylen);
		iov_buf += copylen;
		iov_avail -= copylen;
		priv->rx_buf += copylen;
		priv->rx_avail -= copylen;
		tot += copylen;

		if (!priv->rx_avail) {
			priv->rx_avail_slots--;
			if (!priv->rx_morefrag || !priv->rx_avail_slots) {
				priv->rx_continue = 0;
				break;
			}
			/* Go to the next netmap slot. */
			priv->rx_idx = nm_ring_next(ring, priv->rx_idx);
			priv->rx_buf = NETMAP_BUF(ring,
					ring->slot[priv->rx_idx].buf_idx);
			priv->rx_avail = ring->slot[priv->rx_idx].len;
			priv->rx_morefrag =
				(ring->slot[priv->rx_idx].flags
					& NS_MOREFRAG);
		}

		if (!iov_avail) {
			iovcnt--;
			if (!iovcnt) {
				break;
			}
			/* Go to the next iovec descriptor. */
			iov++;
			iov_buf = iov->iov_base;
			iov_avail = iov->iov_len;
		}
	}

	if (!priv->rx_continue) {
		/* End of reception: Update the ring now. */
		ring->cur = ring->head = nm_ring_next(ring, priv->rx_idx);
	}
out:
	*more = priv->rx_continue;

	return tot;
}

static struct net_backend netmap_backend = {
	.name = "netmap|vale",
	.init = netmap_init,
	.cleanup = netmap_cleanup,
	.send = netmap_send,
	.recv = netmap_receive,
	.get_features = netmap_get_features,
	.set_features = netmap_set_features,
};

DATA_SET(net_backend_set, netmap_backend);


/*
 * make sure a backend is properly initialized
 */
static void
netbe_fix(struct net_backend *be)
{
	if (be == NULL)
		return;
	if (be->name == NULL) {
		fprintf(stderr, "missing name for %p\n", be);
		be->name = "unnamed netbe";
	}
	if (be->init == NULL) {
		fprintf(stderr, "missing init for %p %s\n", be, be->name);
		be->init = netbe_null_init;
	}
	if (be->cleanup == NULL) {
		fprintf(stderr, "missing cleanup for %p %s\n", be, be->name);
		be->cleanup = netbe_null_cleanup;
	}
	if (be->send == NULL) {
		fprintf(stderr, "missing send for %p %s\n", be, be->name);
		be->send = netbe_null_send;
	}
	if (be->recv == NULL) {
		fprintf(stderr, "missing recv for %p %s\n", be, be->name);
		be->recv = netbe_null_recv;
	}
	if (be->get_features == NULL) {
		fprintf(stderr, "missing get_features for %p %s\n",
			be, be->name);
		be->get_features = netbe_null_get_features;
	}
	if (be->set_features == NULL) {
		fprintf(stderr, "missing set_features for %p %s\n",
			be, be->name);
		be->set_features = netbe_null_set_features;
	}
}

/*
 * keys is a set of prefixes separated by '|',
 * return 1 if the leftmost part of name matches one prefix.
 */
static const char *
netbe_name_match(const char *keys, const char *name)
{
	const char *n = name, *good = keys;
	char c;

	if (!keys || !name)
		return NULL;
	while ( (c = *keys++) ) {
		if (c == '|') { /* reached the separator */
			if (good)
				break;
			/* prepare for new round */
			n = name;
			good = keys;
		} else if (good && c != *n++) {
			good = NULL; /* drop till next keyword */
		}
	}
	return good;
}

struct net_backend *
netbe_init(const char *devname, net_backend_cb_t cb, void *param)
{
	/*
	 * Choose the network backend depending on the user
	 * provided device name.
	 */
	struct net_backend **pbe, *ret, *be = NULL;
	int err;

	SET_FOREACH(pbe, net_backend_set) {
		netbe_fix(*pbe); /* make sure we have all fields */
		if (netbe_name_match((*pbe)->name, devname)) {
			be = *pbe;
			break;
		}
	}
	if (be == NULL)
		return NULL; /* or null backend ? */
	ret = calloc(1, sizeof(*ret));
	*ret = *be;
	ret->fd = -1;
	ret->priv = NULL;

	err = be->init(ret, devname, cb, param);
	if (err) {
		free(ret);
		ret = NULL;
	}
	return ret;
}


void
netbe_cleanup(struct net_backend *be)
{
	if (be == NULL)
		return;
	be->cleanup(be);
	free(be);
}


uint32_t
netbe_get_features(struct net_backend *be)
{
	if (be == NULL)
		return 0;
	return be->get_features(be);
}


uint32_t
netbe_set_features(struct net_backend *be, uint32_t features)
{
	if (be == NULL)
		return 0;
	return be->set_features(be, features);
}


int
netbe_send(struct net_backend *be, struct iovec *iov, int iovcnt, int len,
	int more)
{
	if (be == NULL)
		return -1;
	return be->send(be, iov, iovcnt, len, more);
}


int
netbe_recv(struct net_backend *be, struct iovec *iov, int iovcnt, int *more)
{
	if (be == NULL)
		return -1;
	return be->recv(be, iov, iovcnt, more);
}
