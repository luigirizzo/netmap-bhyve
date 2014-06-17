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

.PATH:	${.CURDIR}/../../sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

.ifdef CROSS_BUILD
BASEDIR=/usr/home/luigi/FreeBSD
S=${BASEDIR}/head
M=${BASEDIR}/obj_head${S}/tmp/usr
.PATH: ${S}/sys/amd64/vmm
CFLAGS = -I${M}/include -I/${S}/sys -L${M}/lib
.endif

.ifdef WITH_E1000
# extra headers for e1000 drivers
SRCS +=      pci_e1000.c pci_82545.c
CFLAGS += -I/usr/src/sys
CFLAGS += -I/usr/src/sys/dev/e1000
CFLAGS += -I/usr/src/sys/dev/mii
.endif

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBUTIL} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lutil -lpthread

WARNS?=	2

.include <bsd.prog.mk>
