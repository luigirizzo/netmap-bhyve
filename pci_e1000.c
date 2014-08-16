/*-
 * Copyright (c) 2014 Nahanni Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Intel 82580 gig-E NIC emulation
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/linker_set.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pci_emul.h"

#include "e1000_regs.h"
#include "e1000_defines.h"
#include "mii.h"

/*
 * Some 82580-specific bits and registers
 */
#ifndef E1000_STAT_DEV_RST_SET
#define	E1000_STAT_DEV_RST_SET		0x00100000
#define	E1000_82580_PHY_POWER_MGMT	0xE14
#endif

#define	I82580_MAXQ			8

/* 82577 specific PHY registers */
#ifndef I82577_PHY_CTRL_2
#define	I82577_PHY_CTRL_2		18
#define	I82577_PHY_LBK_CTRL		19
#define	I82577_CFG_REG			22
#define	I82577_PHY_STATUS_2		26
#define	I82577_PHY_DIAG_STATUS		31
#endif

/* RAL/RAH start/end defs for legacy/standard/extended areas */
#define	E1000_LRAx_START	0x40
#define	E1000_LRAx_END		(0x40 + 16*8)
#define	E1000_RAx_START		0x5400
#define	E1000_RAx_END		(0x5400 + 16*8)
#define	E1000_HRAx_START	0x54E0
#define	E1000_HRAx_END		(0x54E0 + 8*8)

#define	VID_INTEL			0x8086
#define	E1000_DEV_ID_82580_COPPER	0x150E

/*
 * s/w representation of the RAL/RAH regs
 */
struct  eth_uni {
	int		eu_valid;
	int		eu_addrsel;
	uint8_t		eu_poolsel;
	struct ether_addr eu_eth;
};

struct e82580_softc {
	struct pci_devinst *esc_pi;
	struct ether_addr esc_mac;
	uint16_t	esc_eeprom_mac[3]; /* big-endian MAC for eeprom */

	uint32_t	esc_CTRL;	/* x0000 device ctl */
	uint32_t	esc_STATUS;	/* x0008 device status */
	uint32_t	esc_EECD;	/* x0010 eeprom/flash ctl */
	uint32_t	esc_EERD;	/* x0014 eeprom read reg */
	uint32_t	esc_CTRL_EXT;	/* x0018 extended ctl */
	uint32_t	esc_MDIC;	/* x0020 MDI ctl */
	uint32_t	esc_VET;	/* x0038 VLAN eth type */
	uint32_t	esc_LEDCTL;	/* x0E00 LED ctl */
	uint32_t	esc_RXPBS;	/* x2404 tx packet buf size */
	uint32_t	esc_SWSM;	/* x5B50 s/w semaphore */
	uint32_t	esc_FWSM;	/* x5B54 f/w semaphore */
	uint32_t	esc_SW_FW_SYNC;	/* x5B5C s/w f/w sync */

	/* L2 frame acceptance */
	struct eth_uni	esc_uni[24];    /* 24 x unicast MAC addresses */
	uint32_t	esc_fmcast[128]; /* Multicast filter bit-match */
	uint32_t	esc_fvlan[128];	/* VLAN 4096-bit filter */
	uint32_t	esc_fucast[128]; /* Unicast filter-bit match */

	/* Receive */
	uint32_t	esc_RCTL;	/* x0100 receive ctl */
	uint32_t	esc_RXCSUM;	/* x5000 receive cksum ctl */
	uint32_t	esc_RLPML;	/* x5004 long packet max len */
	uint32_t	esc_RFCTL;	/* x5008 receive filter ctl */
	uint32_t	esc_RPLPSRTYPE;	/* x54C0 replicated pkt split type */
	uint32_t	esc_MRQC;	/* x5818 multiple rxq cmd */
	uint32_t	esc_RETA[32];	/* x5C00 128-entry redirection tbl */
	uint32_t	esc_RSSRK[10];	/* x5C80 40-byte RSS random key */
	struct {
		uint64_t	r_RDBA;	  /* descriptor table addr */
		uint16_t	r_RDLEN;  /* # descriptors */
		uint16_t	r_RDH;	  /* desc table head idx */
		uint16_t	r_RDT;    /* desc table tail idx */
		uint32_t	r_SRRCTL; /* split/replication rx ctl */
		uint32_t	r_PSRTYPE; /* pkt split rx type */
		uint32_t	r_RXDCTL; /* descriptor ctl */
		uint32_t	r_RQDPC;  /* queue drop count */
	} esc_rx[I82580_MAXQ];
};

static void	e82580_reset(struct e82580_softc *sc, int drvr_reset);

uint64_t e82580_reg_writes;
uint64_t e82580_reg_reads;

static void
e82580_eeprom(struct e82580_softc *sc, uint32_t value)
{
	uint16_t eeaddr;
	uint16_t eedata;
	uint16_t sum;

	/* Ignore writes with no start-bit set */
	if (!(value & E1000_NVM_RW_REG_START))
		return;

	eeaddr = (value & 0xffff) >> E1000_NVM_RW_ADDR_SHIFT;

	switch (eeaddr) {
		/*
		 * The MAC address is the first 3 words of the EEPROM.
		 * Big-endian, and with the MSB in the low address.
		 */
	case NVM_MAC_ADDR + 0:
	case NVM_MAC_ADDR + 1:
	case NVM_MAC_ADDR + 2:
		eedata = sc->esc_eeprom_mac[eeaddr];
		break;
	case NVM_COMPAT:
		/*
		 * bit 15, 0: only cksum for LAN0 valid.
		 * bit 11, 1: "LOM" port, no flash attached
		 */
		eedata = (1 << 11);
		break;
	case NVM_ID_LED_SETTINGS:
		/* fine to return 0000b here: default blinking operation */
		eedata = 0;
		break;
	case NVM_INIT_CONTROL2_REG:
		/* PCS parallel detect == 1 since internal phy is used */
		eedata = (1 << 14);
		break;
	case NVM_CHECKSUM_REG:
		/*
		 * The sum of words 0x00-0x3F within a LAN port's region
		 * should sum to 0xBABA. The checksum reg is used to
		 * force this, so create a value that will result in
		 * the simulated region having a correct checksum
		 * XXX a better way to do this would be to call the read
		 * for the 0->3e to get the sum, and then create the value
		 * at the end. So long as there are no side effects this
		 * results in easier expansion.
		 */
		sum = sc->esc_eeprom_mac[0] +
		    sc->esc_eeprom_mac[1] +
		    sc->esc_eeprom_mac[2] +
	      	    (1 << 11) +
		    (1 << 14);
		eedata = NVM_SUM - sum;
		break;
	default:
		eedata = 0;
		break;
	}

	fprintf(stderr, " @@@ eeprom read @%x, %x\n\r", eeaddr, eedata);

	sc->esc_EERD = (eedata << E1000_NVM_RW_REG_DATA) |
	   (eeaddr << E1000_NVM_RW_ADDR_SHIFT) | E1000_NVM_RW_REG_DONE;
}

static void
e82580_intphy(struct e82580_softc *sc, uint32_t val)
{
	uint8_t miiaddr;
	uint16_t miidata;
	int rd;
	int wr;

	rd = (val &  E1000_MDIC_OP_READ) != 0;
	wr = (val &  E1000_MDIC_OP_WRITE) != 0;
	assert(rd || wr);

	miiaddr = (val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT;
	miidata = val & 0xffff;

	fprintf(stderr, "  ** MII %s, addr %d val %x\n\r", rd ? "rd" : "wr",
		miiaddr, miidata);

	if (rd) {
		switch (miiaddr) {
		case MII_BMCR:
			/* XXX return default */
			miidata = 0x3100;
			break;
		case MII_BMSR:
			miidata = BMSR_ACOMP | BMSR_LINK;
			break;
		case MII_ANAR:
			/* XXX sets PAUSE/ASM_DIR to 0 */
			miidata = 0;
			break;
		case MII_ANLPAR:
			/* XXX sets PAUSE/ASM_DIR to 0 */
			miidata = 0;
			break;
		case MII_PHYIDR1:
			miidata = I82580_I_PHY_ID >> 16;
			break;
		case MII_PHYIDR2:
			miidata = (uint16_t)I82580_I_PHY_ID;
			break;
		case MII_100T2CR:
			miidata = GTCR_ADV_1000TFDX;
			break;
		case MII_100T2SR:
			miidata = GTSR_LRS | GTSR_RRS | GTSR_LP_1000TFDX;
			break;
		case I82577_PHY_CTRL_2:
			miidata = 0;
			break;
		case I82577_CFG_REG:
			miidata = 0;
			break;
		case I82577_PHY_STATUS_2:
			/* 1000 Mbps, normal polarity, no MDIX */
			miidata = 0x0200;
			break;
		case I82577_PHY_DIAG_STATUS:
			/* unknown cable length */
			miidata = (0xff << 2);
			break;
		default:
			fprintf(stderr, " ** MII unhandled\n\r");
			break;
		}
	} else {
		switch (miiaddr) {
		case MII_BMCR:
			break;
		case MII_100T2SR:
			break;
		case I82577_PHY_CTRL_2:
			break;
		case I82577_CFG_REG:
			break;
		default:
			fprintf(stderr, " ** MII unhandled\n\r");
			break;
		}
	}

	/*
	 * Signal the operation is done by setting the READY bit and write
	 * back the data for the guest to read.
	 * XXX generate interrupt ?
	 */	
	sc->esc_MDIC = (val & ~0xffff) | E1000_MDIC_READY | miidata;
}

static uint32_t
e82580_read_ra(struct e82580_softc *sc, int reg)
{
	struct eth_uni *eu;
	uint32_t retval;
	int idx;

	idx = reg >> 1;
	assert(idx < 24);

	eu = &sc->esc_uni[idx];

	if (reg & 0x1) {
		/* RAH */
		retval = (eu->eu_valid << 31) |
			(eu->eu_addrsel << 16) |
			(eu->eu_eth.octet[5] << 8) |
			eu->eu_eth.octet[4];
	} else {
		/* RAL */
		retval = (eu->eu_eth.octet[3] << 24) |
			(eu->eu_eth.octet[2] << 16) |
			(eu->eu_eth.octet[1] << 8) |
			eu->eu_eth.octet[0];
	}

	return (retval);
}

static void
e82580_devctl(struct e82580_softc *sc, uint32_t val)
{

	sc->esc_CTRL =  val;

	if (val & E1000_CTRL_RST)
		e82580_reset(sc, 1);

	/* XXX check for bit 31, phy reset ? */
}

static uint32_t
e82580_stat(struct e82580_softc *sc, int reg)
{
	uint32_t retval;

	retval = 0;

	switch (reg) {
		/*
		 * TODO: Allow individual counters to be extracted
		 */
	default:
		break;
	}

	return (retval);	
}

static void
e82580_reset(struct e82580_softc *sc, int drvr)
{
	sc->esc_CTRL = E1000_CTRL_FD | E1000_CTRL_SPD_1000 | E1000_CTRL_RFCE;

	sc->esc_STATUS = E1000_STATUS_FD | E1000_STATUS_LU |
	    E1000_STATUS_SPEED_1000 | E1000_STATUS_PHYRA |
	    E1000_STATUS_GIO_MASTER_ENABLE;
	if (drvr)
		sc->esc_STATUS |= E1000_STAT_DEV_RST_SET;

	sc->esc_CTRL_EXT = 0;

	/*
	 * eeprom: present, 16-bits wide, 16KB
	 */
	sc->esc_EECD = E1000_EECD_PRES | E1000_EECD_AUTO_RD |
	    E1000_EECD_ADDR_BITS | (0x7 <<  E1000_EECD_SIZE_EX_SHIFT);

	sc->esc_EERD = 0;

	sc->esc_VET = (ETHERTYPE_VLAN << 16) | ETHERTYPE_VLAN;

	/* XXX ??? */
	sc->esc_LEDCTL = 0;

	sc->esc_RXPBS = 0;

	/* Clear out RA{HL} regs and copy MAC address into RAHL[0] */
	memset(sc->esc_uni, 0, sizeof(sc->esc_uni));

	sc->esc_uni[0].eu_valid = 1;
	memcpy(sc->esc_uni[0].eu_eth.octet, sc->esc_mac.octet, ETHER_ADDR_LEN);

	/* zero out vlan/mcast/ucast filter arrays */
	memset(sc->esc_fvlan, 0, sizeof(sc->esc_fvlan));
	memset(sc->esc_fmcast, 0, sizeof(sc->esc_fmcast));
	memset(sc->esc_fucast, 0, sizeof(sc->esc_fucast));
}

static int
e82580_cfgwrite(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		int offset, int bytes, uint32_t val)
{

	/* catch writes to actionable regs */
	return (1);
}

static int
e82580_cfgread(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	       int offset, int bytes, uint32_t *retval)
{

	/* catch reads from actionable regs */
	return (1);
}

static void
e82580_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
             uint64_t offset, int size, uint64_t value)
{
	struct e82580_softc *sc;
	uint32_t wval;
	int unhandled;

	sc = pi->pi_arg;

	if (baridx == 3) {
		pci_emul_msix_twrite(pi, offset, size, value);
		return;
	}

	unhandled = 0;
	wval = value;

	switch (offset) {
	case E1000_CTRL:
		e82580_devctl(sc, wval);
		sc->esc_CTRL = wval;
		if (wval & E1000_CTRL_GIO_MASTER_DISABLE)
			sc->esc_STATUS &= ~E1000_STATUS_GIO_MASTER_ENABLE;
		break;
	case E1000_STATUS:
		/* s/w is allowed to clear the phy and device resets */
		sc->esc_STATUS &= ~(wval & (E1000_STATUS_PHYRA | 
					    E1000_STAT_DEV_RST_SET));
		break;
	case E1000_EECD:
		/* Mask off RO bits */
		sc->esc_EECD = wval & ~(E1000_EECD_DO |
					E1000_EECD_PRES |
					E1000_EECD_AUTO_RD |
					E1000_EECD_ADDR_BITS |
					E1000_EECD_SIZE_EX_MASK |
					0xffff0000);
		break;
	case E1000_EERD:
		e82580_eeprom(sc, wval);
		break;
	case E1000_CTRL_EXT:
		sc->esc_CTRL_EXT = wval;
		break;
	case E1000_MDIC:
		e82580_intphy(sc, wval);
		break;
	case E1000_VET:
		sc->esc_VET = wval;
		break;
	case E1000_LEDCTL:
		sc->esc_LEDCTL = wval;
		break;
	case E1000_82580_PHY_POWER_MGMT:
		break;
	case E1000_RXPBS:
		sc->esc_RXPBS = wval & 0xf;
		break;
	case E1000_DMACR:
		break;
	case E1000_SCVPC:
		/* fall through */
	case E1000_CRCERRS ... E1000_LENERRS:
		/* XXX ignore writes to statistics regs ? */
		break;
	case E1000_WUC:
		/* ignore writes */
		break;
	case E1000_MTA ... (E1000_MTA + (127*4)):
		sc->esc_fmcast[offset >> 2] = wval;
		break;
	case E1000_VFTA ... (E1000_VFTA + (127*4)):
		sc->esc_fvlan[offset >> 2] = wval;
		break;
	case E1000_SWSM:
		/* XXX clear rsvd bits ? */
		sc->esc_SWSM = wval;
		break;
	case E1000_FWSM:
		/* XXX allow more than bit 0 to be set ? */
		sc->esc_SWSM = wval & 0x1;
		break;
	case E1000_SW_FW_SYNC:
		sc->esc_SW_FW_SYNC = wval;
		break;
	case E1000_RAx_START ... E1000_RAx_END:		
		break;
	case E1000_HRAx_START ... E1000_HRAx_END:
		break;
	case E1000_MANC:
		break;
	case E1000_PCIEMISC:
		break;
	case E1000_UTA ... (E1000_UTA + (127*4)):
		sc->esc_fucast[offset >> 2] = wval;
		break;
	default:
		unhandled = 1;
		break;
	}

	e82580_reg_writes++;

    if (unhandled)
	fprintf(stderr, "*** e82580: %cwrite 0x%lx: %x (%d)\n\r",
		unhandled ? '#' : ' ',
		offset, wval, size);
}

static uint64_t
e82580_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
            uint64_t offset, int size)
{
	struct e82580_softc *sc;
	uint64_t retval;
	int unhandled;
	int rareg;
	int silent;

	unhandled = 0;
	silent = 0;
	retval = 0;
	sc = pi->pi_arg;

	if (baridx == 3) {
		return (pci_emul_msix_tread(pi, offset, size));
	}

	switch (offset) {
	case E1000_CTRL:
		retval = sc->esc_CTRL;
		break;
	case E1000_STATUS:
		retval = sc->esc_STATUS;
		break;
	case E1000_EECD:
		retval = sc->esc_EECD;
		break;
	case E1000_EERD:
		retval = sc->esc_EERD;
		break;
	case E1000_CTRL_EXT:
		retval = sc->esc_CTRL_EXT;
		break;
	case E1000_MDIC:
		retval = sc->esc_MDIC;
		break;
	case E1000_VET:
		retval = sc->esc_VET;
		break;
	case E1000_LEDCTL:
		retval = sc->esc_LEDCTL;
		break;
	case E1000_82580_PHY_POWER_MGMT:
		break;
	case E1000_EEMNGCTL:
		/* return CFG_DONE 0 always */
		retval = (1 << 18);
		break;
	case E1000_RXPBS:
		retval = sc->esc_RXPBS;
		break;
	case E1000_DMACR:
		break;
	case E1000_SCVPC:
		/* fall through */
	case E1000_CRCERRS ... E1000_LENERRS:
		retval = e82580_stat(sc, offset);
		break;
	case E1000_PCS_LSTAT:
		/* link is up and running, 1000/fd */
		retval = E1000_PCS_LSTS_AN_COMPLETE |
		    E1000_PCS_LSTS_SYNK_OK |
		    E1000_PCS_LSTS_DUPLEX_FULL |
		    E1000_PCS_LSTS_SPEED_1000 |
		    E1000_PCS_LSTS_LINK_OK;
		break;
	case E1000_WUC:
		break;
	case E1000_MTA ... (E1000_MTA + (127*4)):
		retval = sc->esc_fmcast[offset >> 2];
		break;
	case E1000_VFTA ... (E1000_VFTA + (127*4)):
		retval = sc->esc_fvlan[offset >> 2];
		break;
	case E1000_SWSM:
		silent = 1;
		retval = sc->esc_SWSM;
		/* set the SMBI bit after 1st read when clear */
		if ((sc->esc_SWSM & 0x1) != 0x1)
			sc->esc_SWSM |= 0x1;
		break;
	case E1000_FWSM:
		silent = 1;
		retval = sc->esc_FWSM;
		break;
	case E1000_SW_FW_SYNC:
		silent = 1;
		retval = sc->esc_SW_FW_SYNC;
		break;
	case E1000_RAx_START ... E1000_RAx_END:
		/* ra regs 0:15 [ha|hl] */
		rareg = (offset - E1000_RAx_START) >> 2;
		retval = e82580_read_ra(sc, rareg);
		break;
	case E1000_HRAx_START ... E1000_HRAx_END:
		/* adjust ra reg offset to make this regs 16:23 */
		rareg = ((offset - E1000_HRAx_START) >> 2) + (16 << 1);
		retval = e82580_read_ra(sc, offset - E1000_HRAx_START);
		break;
	case E1000_MANC:
		break;
	case E1000_PCIEMISC:
		break;
	case E1000_UTA ... (E1000_UTA + (127*4)):
		retval = sc->esc_fucast[offset >> 2];
		break;
	default:
		unhandled = 1;
		break;
	}

	e82580_reg_reads++;

	if (!silent && unhandled)
		fprintf(stderr, "*** e82580: %cread  0x%lx: %lx (%d)\n\r",
			unhandled ? '#' : ' ',
			offset, retval, size);
	  
	return (retval);
}

static int
e82580_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct e82580_softc *sc;
	struct ether_addr *ea;
	int error;

	sc = malloc(sizeof(struct e82580_softc));
	memset(sc, 0, sizeof(struct e82580_softc));

	pi->pi_arg = sc;
	sc->esc_pi = pi;

	/*
	 * initialize config space
	 */
	pci_set_cfgdata16(pi, PCIR_VENDOR, VID_INTEL);
	pci_set_cfgdata16(pi, PCIR_DEVICE, E1000_DEV_ID_82580_COPPER);
	pci_set_cfgdata8(pi,  PCIR_REVID, 0x01);
	pci_set_cfgdata8(pi,  PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBCLASS, PCIS_NETWORK_ETHERNET);
	pci_set_cfgdata8(pi,  PCIR_HDRTYPE, PCIM_HDRTYPE_NORMAL);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VID_INTEL);
	pci_set_cfgdata8(pi,  PCIR_INTPIN, 0x1); // INTA#

	pci_emul_set_caprnd(16);
	pci_emul_add_pwrcap(pi);

	pci_emul_set_caprnd(32);
	error = pci_emul_add_msicap(pi, 1);
        assert(error == 0);

	/* force 32-bit BAR operation */
	pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, 128*1024);

	/* Disable BAR 2, the i/o BAR */

	/* msi-x, bar 3 32-bit, tbl offset 0, pbr offset 0x400 */
	pci_emul_set_caprnd(48);
	error = pci_emul_add_msixcap(pi, 10, 3);
	assert(error == 0);

	pci_emul_set_caprnd(-1);
	pci_emul_add_pciecap(pi, PCIEM_TYPE_ENDPOINT);

	/* XXX init MAC addr, copy to eeprom */
	ea = ether_aton("c8:2a:14:08:24:f9");
	memcpy(sc->esc_mac.octet, ea->octet, ETHER_ADDR_LEN);

	sc->esc_eeprom_mac[0] = htobe16(*(uint16_t *)&ea->octet[4]);
	sc->esc_eeprom_mac[1] = htobe16(*(uint16_t *)&ea->octet[2]);
	sc->esc_eeprom_mac[2] = htobe16(*(uint16_t *)&ea->octet[0]);

	/* H/w initiated reset */
	e82580_reset(sc, 0);

	return (0);
}

struct pci_devemu pci_de_e82580 = {
	.pe_emu =       "e82580",
	.pe_init =      e82580_init,
	.pe_cfgwrite =  e82580_cfgwrite,
	.pe_cfgread =   e82580_cfgread,
	.pe_barwrite =  e82580_write,
        .pe_barread =   e82580_read
};
PCI_EMUL_SET(pci_de_e82580);
