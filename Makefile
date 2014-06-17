# $FreeBSD: stable/10/usr.sbin/bhyve/Makefile 267450 2014-06-13 21:30:40Z jhb $
#

PROG=	bhyve

DEBUG_FLAGS= -g -O2 -Wall -Werror

MAN=	bhyve.8

#	pci_e1000.c		\
#	pci_82545.c		\

SRCS=	\
	acpi.c			\
	atpic.c			\
	bhyverun.c		\
	block_if.c		\
	consport.c		\
	dbgport.c		\
	elcr.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_uart.c		\
	pit_8254.c		\
	pm.c			\
	pmtmr.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c

BASEDIR=/usr/home/luigi/FreeBSD
S=${BASEDIR}/R10
M=${BASEDIR}/obj_R10${S}/tmp/usr

.PATH:	${.CURDIR}/../../sys/amd64/vmm ${S}/sys/amd64/vmm /usr/src/sys/amd64/vmm 
SRCS+=	vmm_instruction_emul.c

CFLAGS = -I${M}/include -I/${S}/sys -L${M}/lib

# extra headers for e1000 drivers
CFLAGS += -I/usr/src/sys
CFLAGS += -I/usr/src/sys/dev/e1000
CFLAGS += -I/usr/src/sys/dev/mii

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBUTIL} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lutil -lpthread

WARNS?=	2

.include <bsd.prog.mk>
