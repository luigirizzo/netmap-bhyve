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

#ifndef __NET_BACKENDS_H__
#define __NET_BACKENDS_H__

#include <stdint.h>
#include "mevent.h"

extern int netmap_ioctl_counter;

typedef void (*net_backend_cb_t)(int, enum ev_type, void *param);

/* Interface between virtio-net and the network backend. */
struct net_backend;

struct net_backend *netbe_init(const char *devname,
			net_backend_cb_t cb, void *param);
void	netbe_cleanup(struct net_backend *be);
uint32_t netbe_get_features(struct net_backend *be);
uint32_t netbe_set_features(struct net_backend *be, uint32_t features);
int	netbe_send(struct net_backend *be, struct iovec *iov,
                        int iovcnt, int len, int more);
int	netbe_recv(struct net_backend *be, struct iovec *iov,
		    int iovcnt, int *more);

#endif /* __NET_BACKENDS_H__ */
