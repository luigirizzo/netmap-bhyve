/*-
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: stable/10/usr.sbin/bhyve/pci_virtio_net.c 267393 2014-06-12 13:13:15Z jhb $
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: stable/10/usr.sbin/bhyve/pci_virtio_net.c 267393 2014-06-12 13:13:15Z jhb $");

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <md5.h>
#include <pthread.h>
#include <pthread_np.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "mevent.h"
#include "virtio.h"
#include "dev/virtio/network/virtio_net.h"
#include "net_backends.h"

#define VTNET_RINGSZ	1024

#define VTNET_MAXSEGS	32

#define VTNET_S_HOSTCAPS      \
  ( VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF | VIRTIO_NET_F_STATUS | \
    VIRTIO_RING_F_EVENT_IDX | \
    VIRTIO_F_NOTIFY_ON_EMPTY)

/*
 * Queue definitions.
 */
#define VTNET_RXQ	0
#define VTNET_TXQ	1
#define VTNET_CTLQ	2	/* NB: not yet supported */

#define VTNET_MAXQ	3

/*
 * Debug printf
 */
static int pci_vtnet_debug;
#define DPRINTF(params) if (pci_vtnet_debug) printf params
#define WPRINTF(params) printf params

/*
 * Per-device softc
 */
struct pci_vtnet_softc {
	struct virtio_softc vsc_vs;
	struct vqueue_info vsc_queues[VTNET_MAXQ - 1];
	pthread_mutex_t vsc_mtx;

	struct net_backend *vsc_be;
	int		vsc_rx_ready;
	volatile int	resetting;	/* set and checked outside lock */

	uint32_t	vsc_features;
	struct virtio_net_config vsc_config;

	pthread_mutex_t	rx_mtx;
	int		rx_in_progress;

	pthread_t 	tx_tid;
	pthread_mutex_t	tx_mtx;
	pthread_cond_t	tx_cond;
	int		tx_in_progress;
};

static void pci_vtnet_reset(void *);
/* static void pci_vtnet_notify(void *, struct vqueue_info *); */
static int pci_vtnet_cfgread(void *, int, int, uint32_t *);
static int pci_vtnet_cfgwrite(void *, int, int, uint32_t);
static void pci_vtnet_apply_features(void *, uint32_t);

static struct virtio_consts vtnet_vi_consts = {
	"vtnet",		/* our name */
	VTNET_MAXQ - 1,		/* we currently support 2 virtqueues */
	sizeof(struct virtio_net_config), /* config reg size */
	pci_vtnet_reset,	/* reset */
	NULL,			/* device-wide qnotify -- not used */
	pci_vtnet_cfgread,	/* read PCI config */
	pci_vtnet_cfgwrite,	/* write PCI config */
	pci_vtnet_apply_features, /* apply negotiated features */
	VTNET_S_HOSTCAPS,	/* our capabilities */
};

/*
 * If the transmit thread is active then stall until it is done.
 */
static void
pci_vtnet_txwait(struct pci_vtnet_softc *sc)
{

	pthread_mutex_lock(&sc->tx_mtx);
	while (sc->tx_in_progress) {
		pthread_mutex_unlock(&sc->tx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->tx_mtx);
	}
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * If the receive thread is active then stall until it is done.
 */
static void
pci_vtnet_rxwait(struct pci_vtnet_softc *sc)
{

	pthread_mutex_lock(&sc->rx_mtx);
	while (sc->rx_in_progress) {
		pthread_mutex_unlock(&sc->rx_mtx);
		usleep(10000);
		pthread_mutex_lock(&sc->rx_mtx);
	}
	pthread_mutex_unlock(&sc->rx_mtx);
}

static void
pci_vtnet_reset(void *vsc)
{
	struct pci_vtnet_softc *sc = vsc;

	DPRINTF(("vtnet: device reset requested !\n"));

	sc->resetting = 1;

	/*
	 * Wait for the transmit and receive threads to finish their
	 * processing.
	 */
	pci_vtnet_txwait(sc);
	pci_vtnet_rxwait(sc);

	sc->vsc_rx_ready = 0;

	/* now reset rings, MSI-X vectors, and negotiated capabilities */
	vi_reset_dev(&sc->vsc_vs);

	sc->resetting = 0;
}

void
pci_vtnet_rx_discard(struct pci_vtnet_softc *sc, struct iovec *iov)
{
	int more;

	/*
	 * MP note: the dummybuf is only used to discard frames,
	 * so there is no need for it to be per-vtnet or locked.
	 * We only make it large enough for TSO-sized segment.
	 */
	static uint8_t dummybuf[65536+64];

	iov[0].iov_base = dummybuf;
	iov[0].iov_len = sizeof(dummybuf);
	netbe_recv(sc->vsc_be, iov, 1, &more);
}

/*
 * Called when there is read activity on the net backend file descriptor.
 * If TSO/UFO features are not negotiated, each buffer posted by the guest
 * is assumed to be able to containan entire ethernet frame + rx header
 * (no more than 1514 + 12 bytes).
 * Otherwise the guest can post buffers smaller than the maximum TSO packet
 * size (~64KB), and host will merge those buffers and tell the guest
 * about that.
 */
static void
pci_vtnet_rx(struct pci_vtnet_softc *sc)
{
	struct vqueue_info *vq;
	int len;
	struct iovec iov[VTNET_MAXSEGS + 1];
	int n;
	int more;
	int merged = 0;
	struct virtio_net_hdr_mrg_rxbuf *hdr = NULL;

	/*
	 * But, will be called when the rx ring hasn't yet
	 * been set up or the guest is resetting the device.
	 */
	if (!sc->vsc_rx_ready || sc->resetting) {
		/*
		 * Drop the packet and try later.
		 */
		pci_vtnet_rx_discard(sc, iov);
		return;
	}

	/*
	 * Check for available rx buffers
	 */
	vq = &sc->vsc_queues[VTNET_RXQ];
	vq_startchains(vq);
	if (!vq_has_descs(vq)) {
		/*
		 * Since we've run out of virtio buffers we enable the
		 * notifications on the rx queue. No doubleckeck is
		 * necessary here, because we don't have a queue between
		 * the backend and us: We just drop packets.
		 */
		vq_notifications_enable(vq);
		/*
		 * Drop the packet and try later.  Interrupt on
		 * empty, if that's negotiated.
		 */
		pci_vtnet_rx_discard(sc, iov);
		vq_endchains(vq, 1);
		return;
	}

	do {
		/*
		 * Get descriptor chain, which should have just
		 * one descriptor in it.
		 */
		n = vq_getchain(vq, iov, VTNET_MAXSEGS, NULL);
		assert(n >= 1 && n <= VTNET_MAXSEGS);

		if (merged == 0) {
			/*
			 * We are at the beginning of the received
			 * packet, where the backend will copy in the
			 * virtio-net header. We will need a pointer
			 * to it later.
			 */
			hdr = iov->iov_base;
		}

		len = netbe_recv(sc->vsc_be, iov, n, &more);

		if (len == 0) {
			/*
			 * No more packets, but still some avail ring
			 * entries.  Interrupt if needed/appropriate.
			 */
			vq_endchains(vq, 0);
			return;
		}

		merged++;
		if (!more) {
			/*
			 * We have done receiving the packet from
			 * the backend. Store the number of merged
			 * buffers into the virtio-net header.
			 */
			assert(hdr);
			hdr->num_buffers = merged;
			merged = 0;
			hdr = NULL;
		}

		/*
		 * Release this chain and handle more chains.
		 * If we need more virtio buffers to complete
		 * the packet received from the backend, don't
		 * expose to the guest the buffer we are releasing.
		 * Otherwise expose it together with the previously
		 * not exposed ones.
		 */
		vq_relchain(vq, len, !more);
	} while (vq_has_descs(vq));

	/* Interrupt if needed, including for NOTIFY_ON_EMPTY. */
	vq_endchains(vq, 1);
}

static void
pci_vtnet_callback(int fd, enum ev_type type, void *param)
{
	struct pci_vtnet_softc *sc = param;

	pthread_mutex_lock(&sc->rx_mtx);
	sc->rx_in_progress = 1;
	pci_vtnet_rx(sc);
	sc->rx_in_progress = 0;
	pthread_mutex_unlock(&sc->rx_mtx);

}

static void
pci_vtnet_ping_rxq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	if (!vq_has_descs(vq)) {
		return;
	}

	/* Disable rx queue notifications if we have buffers. */
	vq_notifications_disable(vq);

	/*
	 * A qnotify means that the rx process can now begin
	 */
	if (sc->vsc_rx_ready == 0) {
		sc->vsc_rx_ready = 1;
	}
}

static void
pci_vtnet_proctx(struct pci_vtnet_softc *sc, struct vqueue_info *vq)
{
	struct iovec iov[VTNET_MAXSEGS + 1];
	int i, n;
	int tlen;
	int more;

	/*
	 * Obtain chain of descriptors.  The first one is
	 * really the header descriptor, so we need to sum
	 * up two lengths: packet length and transfer length.
	 */
	n = vq_getchain(vq, iov, VTNET_MAXSEGS, NULL);
	assert(n >= 1 && n <= VTNET_MAXSEGS);
	tlen = iov[0].iov_len;
	for (i = 1; i < n; i++) {
		tlen += iov[i].iov_len;
	}
	more = vq_avail_descs(vq) > 1;
	if (more)
		IFRATE(vq->vq_vs->rate.cur.var1[vq->vq_num]++);

	DPRINTF(("virtio: packet send, %d bytes, %d segs\n\r", tlen, n));
	netbe_send(sc->vsc_be, iov, n, tlen, 1 /* more */);
	if (!more) {
		usleep(1);
		more = vq_avail_descs(vq) > 1;
		if (!more)
			netbe_send(sc->vsc_be, iov, 0, 0, 0); // flush
	}
	/* chain is processed, release it and set tlen */
	vq_relchain(vq, tlen, !more);
}

static void
pci_vtnet_ping_txq(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtnet_softc *sc = vsc;

	/*
	 * Any ring entries to process?
	 */
	if (!vq_has_descs(vq))
		return;

	/* Signal the tx thread for processing. */
	/* Disable tx queue notifications when the thread is active. */
	pthread_mutex_lock(&sc->tx_mtx);
	vq_notifications_disable(vq);
	if (sc->tx_in_progress == 0)
		pthread_cond_signal(&sc->tx_cond);
	pthread_mutex_unlock(&sc->tx_mtx);
}

/*
 * Thread which will handle processing of TX desc
 */
static void *
pci_vtnet_tx_thread(void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct vqueue_info *vq;
	int have_work, error;

	vq = &sc->vsc_queues[VTNET_TXQ];

	/*
	 * Let us wait till the tx queue pointers get initialised &
	 * first tx signaled
	 */
	pthread_mutex_lock(&sc->tx_mtx);
	error = pthread_cond_wait(&sc->tx_cond, &sc->tx_mtx);
	assert(error == 0);

	for (;;) {
		/* note - tx mutex is locked here */
		do {
			if (sc->resetting)
				have_work = 0;
			else
				have_work = vq_has_descs(vq);

			if (!have_work) {
				/*
				 * No more avail buffers, so we enable
				 * tx queue notifications.
				 */
				vq_notifications_enable(vq);
				/*
				 * It is mandatory to check again for
				 * more avail buffers, since some may
				 * have come after the last call to
				 * vq_has_descs(vq) returned 0 and
				 * before we enable the notifications.
				 * If we didn't check, some avail buffers
				 * could stall forever.
				 */
				if (!vq_has_descs(vq)) {
					sc->tx_in_progress = 0;
					error = pthread_cond_wait(&sc->tx_cond,
								&sc->tx_mtx);
					assert(error == 0);
				} else {
					/* XXX we lost the race, re-enable.
					 * but it can only happen once.
					 */
					// vq_notifications_disable(vq);
				}
			}
		} while (!have_work);
		sc->tx_in_progress = 1;
		pthread_mutex_unlock(&sc->tx_mtx);

		vq_startchains(vq);
		do {
			/*
			 * Run through entries, placing them into
			 * iovecs and sending when an end-of-packet
			 * is found
			 */
			pci_vtnet_proctx(sc, vq);
		} while (vq_has_descs(vq));

		/*
		 * Generate an interrupt if needed.
		 */
		vq_endchains(vq, 1);

		pthread_mutex_lock(&sc->tx_mtx);
	}
}

#ifdef notyet
static void
pci_vtnet_ping_ctlq(void *vsc, struct vqueue_info *vq)
{

	DPRINTF(("vtnet: control qnotify!\n\r"));
}
#endif

static int
pci_vtnet_parsemac(char *mac_str, uint8_t *mac_addr)
{
        struct ether_addr *ea;
        char *tmpstr;
        char zero_addr[ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };

        tmpstr = strsep(&mac_str,"=");
       
        if ((mac_str != NULL) && (!strcmp(tmpstr,"mac"))) {
                ea = ether_aton(mac_str);

                if (ea == NULL || ETHER_IS_MULTICAST(ea->octet) ||
                    memcmp(ea->octet, zero_addr, ETHER_ADDR_LEN) == 0) {
			fprintf(stderr, "Invalid MAC %s\n", mac_str);
                        return (EINVAL);
                } else
                        memcpy(mac_addr, ea->octet, ETHER_ADDR_LEN);
        }

        return (0);
}

#ifdef RATE
#define RATE_MS	1500
#define RATE_FPRINTF(r, i, x)                                      \
		fprintf(stderr, #x "[%d] %10.6f KHz\n", i,             \
			(float)(r->cur.x[i] - r->prev.x[i])/RATE_MS)

int netmap_ioctl_counter;
static void rate_timer_cb(int fd, enum ev_type type, void *param)
{
	struct pci_vtnet_softc *sc = param;
	struct rate_info *r = &sc->vsc_vs.rate;
	int i;

	fprintf(stderr, "=======================\n");
	for (i = 0; i < 2; i++) {
		RATE_FPRINTF(r, i, intr);
		RATE_FPRINTF(r, i, kick);
		RATE_FPRINTF(r, i, proc);
		RATE_FPRINTF(r, i, var1);
		r->cur.var2[i] = netmap_ioctl_counter;
		RATE_FPRINTF(r, i, var2);
		RATE_FPRINTF(r, i, var3);
		RATE_FPRINTF(r, i, evidx);
		RATE_FPRINTF(r, i, evidxintr);
		RATE_FPRINTF(r, i, guestintr);
		RATE_FPRINTF(r, i, guestintron);
	}
	r->prev = r->cur;
}
#endif /* RATE */

static int
pci_vtnet_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	MD5_CTX mdctx;
	unsigned char digest[16];
	char nstr[80];
	char tname[MAXCOMLEN + 1];
	struct pci_vtnet_softc *sc;
	char *devname;
	char *vtopts;
	int mac_provided;

	sc = calloc(1, sizeof(struct pci_vtnet_softc));

	pthread_mutex_init(&sc->vsc_mtx, NULL);

	vi_softc_linkup(&sc->vsc_vs, &vtnet_vi_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	sc->vsc_queues[VTNET_RXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_RXQ].vq_notify = pci_vtnet_ping_rxq;
	sc->vsc_queues[VTNET_TXQ].vq_qsize = VTNET_RINGSZ;
	sc->vsc_queues[VTNET_TXQ].vq_notify = pci_vtnet_ping_txq;
#ifdef notyet
	sc->vsc_queues[VTNET_CTLQ].vq_qsize = VTNET_RINGSZ;
        sc->vsc_queues[VTNET_CTLQ].vq_notify = pci_vtnet_ping_ctlq;
#endif
 
	/*
	 * Attempt to open the backend device and read the MAC address
	 * if specified
	 */
	mac_provided = 0;
	if (opts != NULL) {
		int err;

		devname = vtopts = strdup(opts);
		(void) strsep(&vtopts, ",");

		if (vtopts != NULL) {
			err = pci_vtnet_parsemac(vtopts, sc->vsc_config.mac);
			if (err != 0) {
				free(devname);
				return (err);
			}
			mac_provided = 1;
		}

		sc->vsc_be = netbe_init(devname, pci_vtnet_callback, sc);
		if (!sc->vsc_be) {
			WPRINTF(("net backend initialization failed\n"));
		} else {
			vtnet_vi_consts.vc_hv_caps |=
				netbe_get_features(sc->vsc_be);
		}
		free(devname);
	}

	/*
	 * The default MAC address is the standard NetApp OUI of 00-a0-98,
	 * followed by an MD5 of the PCI slot/func number and dev name
	 */
	if (!mac_provided) {
		snprintf(nstr, sizeof(nstr), "%d-%d-%s", pi->pi_slot,
		    pi->pi_func, vmname);

		MD5Init(&mdctx);
		MD5Update(&mdctx, nstr, strlen(nstr));
		MD5Final(digest, &mdctx);

		sc->vsc_config.mac[0] = 0x00;
		sc->vsc_config.mac[1] = 0xa0;
		sc->vsc_config.mac[2] = 0x98;
		sc->vsc_config.mac[3] = digest[0];
		sc->vsc_config.mac[4] = digest[1];
		sc->vsc_config.mac[5] = digest[2];
	}

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_NET);

	pci_lintr_request(pi);

	/* link always up */
	sc->vsc_config.status = 1;
	
	/* use BAR 1 to map MSI-X table and PBA, if we're using MSI-X */
	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		return (1);

	/* use BAR 0 to map config regs in IO space */
	vi_set_io_bar(&sc->vsc_vs, 0);

	sc->resetting = 0;

	sc->rx_in_progress = 0;
	pthread_mutex_init(&sc->rx_mtx, NULL); 

	/* 
	 * Initialize tx semaphore & spawn TX processing thread.
	 * As of now, only one thread for TX desc processing is
	 * spawned. 
	 */
	sc->tx_in_progress = 0;
	pthread_mutex_init(&sc->tx_mtx, NULL);
	pthread_cond_init(&sc->tx_cond, NULL);
	pthread_create(&sc->tx_tid, NULL, pci_vtnet_tx_thread, (void *)sc);
	snprintf(tname, sizeof(tname), "vtnet-%d:%d tx", pi->pi_slot,
	    pi->pi_func);
        pthread_set_name_np(sc->tx_tid, tname);

#ifdef RATE
	snprintf(tname, sizeof(tname), "rate-virtio-%d", getpid());
	sc->vsc_vs.rate.mevp = mevent_add(RATE_MS, EVF_TIMER, rate_timer_cb, sc);
#endif /* RATE */
	return (0);
}

static int
pci_vtnet_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	if (offset < 6) {
		assert(offset + size <= 6);
		/*
		 * The driver is allowed to change the MAC address
		 */
		ptr = &sc->vsc_config.mac[offset];
		memcpy(ptr, &value, size);
	} else {
		DPRINTF(("vtnet: write to readonly reg %d\n\r", offset));
		return (1);
	}
	return (0);
}

static int
pci_vtnet_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtnet_softc *sc = vsc;
	void *ptr;

	ptr = (uint8_t *)&sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static void
pci_vtnet_apply_features(void *vsc, uint32_t negotiated_features)
{
	struct pci_vtnet_softc *sc = vsc;

	/* Tell the backend to enable some features it has advertised.
	 */
	netbe_set_features(sc->vsc_be, negotiated_features);
}

struct pci_devemu pci_de_vnet = {
	.pe_emu = 	"virtio-net",
	.pe_init =	pci_vtnet_init,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read
};
PCI_EMUL_SET(pci_de_vnet);
