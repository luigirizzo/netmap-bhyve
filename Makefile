#
# $FreeBSD: head/usr.sbin/bhyve/Makefile 266125 2014-05-15 14:16:55Z jhb $
#

PROG=	bhyve

DEBUG_FLAGS= -g -O0

MAN=	bhyve.8

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	bhyverun.c		\
	block_if.c		\
	consport.c		\
	dbgport.c		\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_uart.c		\
	pm.c			\
	pmtmr.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c

S=/usr/home/luigi/FreeBSD/head
M=/usr/home/luigi/FreeBSD/obj_head${S}/tmp/usr

.PATH:	${.CURDIR}/../../sys/amd64/vmm ${S}/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBUTIL} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lutil -lpthread
CFLAGS = -I${M}/include -I/${S}/sys -L${M}/lib

WARNS?=	2

.include <bsd.prog.mk>
