#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e1000_regs.h"
#include "e1000_defines.h"
#include "mii.h"

#include "bhyverun.h"
//#include "pci_e1000.h"
#include "pci_emul.h"
#include "mevent.h"

/* Hardware/register definitions XXX: move some to common code. */
#define E82545_VENDOR_ID_INTEL			0x8086
#define E82545_DEV_ID_82545EM_COPPER		0x100F
#define E82545_SUBDEV_ID			1008

#define E82545_REVISION_4			4

#define E82545_MDIC_DATA_MASK			0x0000FFFF
#define E82545_MDIC_OP_MASK			0x0c000000
#define E82545_MDIC_IE				0x20000000

#define E82545_EECD_FWE_DIS	0x00000010 /* Flash writes disabled */
#define E82545_EECD_FWE_EN	0x00000020 /* Flash writes enabled */
#define E82545_EECD_FWE_MASK	0x00000030 /* Flash writes mask */

#define E82545_BAR_REGISTER			0
#define E82545_BAR_REGISTER_LEN			(128*1024)
#define E82545_BAR_FLASH			1
#define E82545_BAR_FLASH_LEN			(64*1024)
#define E82545_BAR_IO				2
#define E82545_BAR_IO_LEN			8

#define E82545_IOADDR				0x00000000
#define E82545_IODATA				0x00000004
#define E82545_IO_REGISTER_MAX			0x0001FFFF
#define E82545_IO_FLASH_BASE			0x00080000
#define E82545_IO_FLASH_MAX			0x000FFFFF

#define E82545_ARRAY_ENTRY(reg, offset)		(reg + (offset<<2))
#define E82545_RAR_MAX				15
#define E82545_MTA_MAX				127
#define E82545_VFTA_MAX				127

/* Slightly modified from the driver versions, hardcoded for 3 opcode bits,
 * followed by 6 address bits.
 * TODO: make opcode bits and addr bits configurable?
 * NVM Commands - Microwire */
#define E82545_NVM_OPCODE_BITS	3
#define E82545_NVM_ADDR_BITS	6
#define E82545_NVM_DATA_BITS	16
#define E82545_NVM_OPADDR_BITS	(E82545_NVM_OPCODE_BITS+E82545_NVM_ADDR_BITS)
#define E82545_NVM_ADDR_MASK	((1<<E82545_NVM_ADDR_BITS)-1)
#define E82545_NVM_OPCODE_MASK	(((1<<E82545_NVM_OPCODE_BITS)-1)<<E82545_NVM_ADDR_BITS)
#define E82545_NVM_OPCODE_READ	(0x6<<E82545_NVM_ADDR_BITS)  /* read */
#define E82545_NVM_OPCODE_WRITE	(0x5<<E82545_NVM_ADDR_BITS)  /* write */
#define E82545_NVM_OPCODE_ERASE	(0x7<<E82545_NVM_ADDR_BITS)  /* erase */
#define E82545_NVM_OPCODE_EWEN	(0x4<<E82545_NVM_ADDR_BITS) /* write-enable */

#define E82545_NVM_EEPROM_SIZE	64 /* 64 * 16-bit values == 128K */

/*
 * Debug printf
 */
static int pci_e82545_debug = 1;
#define DPRINTF(msg,params...) if (pci_e82545_debug) fprintf(stderr, "pci_e82545: " msg, params)
#define WPRINTF(msg,params...) fprintf(stderr, "pci_e82545: " msg, params)

struct pci_e82545_softc {
	struct pci_devinst *pi;

	/* IO Port register access */
	uint32_t io_addr;
	/* Interrupt Mask */
	uint32_t intr_mask;
	/* Interrupt Cause */
	uint32_t intr_cause;
	/* Shadow copy of registers */
	uint32_t transmit_control;
	uint32_t receive_control;
	/* Shadow copy of MDIC */
	uint32_t mdi_control;
	/* Shadow copy of EECD */
	uint32_t eeprom_control;
	/* Latest NVM in/out */
	uint16_t nvm_data;
	uint16_t nvm_opaddr;
	/* stats */
	uint32_t missed_pkt_count; /* dropped for no room in rx queue */
	uint32_t pkt_rx_by_size[6];
	uint32_t pkt_tx_by_size[6];
	uint32_t good_pkt_rx_count;
	uint32_t bcast_pkt_rx_count;
	uint32_t mcast_pkt_rx_count;
	uint32_t good_pkt_tx_count;
	uint32_t bcast_pkt_tx_count;
	uint32_t mcast_pkt_tx_count;
	uint32_t oversize_rx_count;
	uint32_t tso_tx_count;
	uint64_t good_octets_rx;
	uint64_t good_octets_tx;
	uint64_t missed_octets; /* counts missed and oversized */

	uint8_t nvm_bits:6; /* number of bits remaining in/out */
	uint8_t nvm_mode:2;
#define E82545_NVM_MODE_OPADDR  0x0
#define E82545_NVM_MODE_DATAIN  0x1
#define E82545_NVM_MODE_DATAOUT 0x2
	/* MAC Address */
        uint8_t mac_addr[6];
        /* EEPROM data */
        uint16_t eeprom_data[E82545_NVM_EEPROM_SIZE];
};

static inline int
pci_e82545_size_stat_index(uint32_t size)
{
	if (size <= 64) {
		return 0;
	} else if (size >= 1024) {
		return 5;
	} else {
		/* should be 1-4 */
		return (ffs(size) - 6);
	}
}

static void
pci_e82545_init_eeprom(struct pci_e82545_softc *sc)
{
	uint16_t checksum, i;

        /* mac addr */
	sc->eeprom_data[NVM_MAC_ADDR] = ((uint16_t)sc->mac_addr[0]) |
		(((uint16_t)sc->mac_addr[1]) << 8);
	sc->eeprom_data[NVM_MAC_ADDR+1] = ((uint16_t)sc->mac_addr[2]) |
		(((uint16_t)sc->mac_addr[3]) << 8);
	sc->eeprom_data[NVM_MAC_ADDR+2] = ((uint16_t)sc->mac_addr[4]) |
		(((uint16_t)sc->mac_addr[5]) << 8);

	/* pci ids */
	sc->eeprom_data[NVM_SUB_DEV_ID] = E82545_SUBDEV_ID;
	sc->eeprom_data[NVM_SUB_VEN_ID] = E82545_VENDOR_ID_INTEL;
	sc->eeprom_data[NVM_DEV_ID] = E82545_DEV_ID_82545EM_COPPER;
	sc->eeprom_data[NVM_VEN_ID] = E82545_VENDOR_ID_INTEL;

	/* fill in the checksum */
        checksum = 0;
	for (i = 0; i < NVM_CHECKSUM_REG; i++) {
		checksum += sc->eeprom_data[i];
	}
	checksum = NVM_SUM - checksum;
	sc->eeprom_data[NVM_CHECKSUM_REG] = checksum;
	DPRINTF("eeprom checksum: 0x%x\r\n", checksum);
}

static int
pci_e82545_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	DPRINTF("Loading with options: %s\r\n", opts);

	MD5_CTX mdctx;
	unsigned char digest[16];
	char nstr[80];
	struct pci_e82545_softc *sc;

	/* Setup our softc */
	sc = malloc(sizeof(*sc));
	memset(sc, 0, sizeof(*sc));
	pi->pi_arg = sc;
	sc->pi = pi;

	sc->eeprom_control = E1000_EECD_PRES | E82545_EECD_FWE_EN;

	pci_set_cfgdata16(pi, PCIR_DEVICE, E82545_DEV_ID_82545EM_COPPER);
	pci_set_cfgdata16(pi, PCIR_VENDOR, E82545_VENDOR_ID_INTEL);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, E82545_SUBDEV_ID);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, E82545_VENDOR_ID_INTEL);

	/* TODO: this card also supports msi, but the freebsd driver for it
	 * does not, so I have not implemented it. */
	pci_lintr_request(pi, -1);

	pci_emul_alloc_bar(pi, E82545_BAR_REGISTER, PCIBAR_MEM32,
		E82545_BAR_REGISTER_LEN);
	pci_emul_alloc_bar(pi, E82545_BAR_FLASH, PCIBAR_MEM32,
		E82545_BAR_FLASH_LEN);
	pci_emul_alloc_bar(pi, E82545_BAR_IO, PCIBAR_IO,
		E82545_BAR_IO_LEN);

	/* Copied from virtio-net, slightly modified */
	/*
	 * The MAC address is the standard NetApp OUI of 00-a0-98,
	 * followed by an MD5 of the vm name. The slot/func number is
	 * prepended to this for slots other than 1:0, so that 
	 * a bootloader can netboot from the equivalent of slot 1.
	 */
	snprintf(nstr, sizeof(nstr), "e82545-%d-%d-%s", pi->pi_slot,
		 pi->pi_func, vmname);

	MD5Init(&mdctx);
	MD5Update(&mdctx, nstr, strlen(nstr));
	MD5Final(digest, &mdctx);

	sc->mac_addr[0] = 0x00;
	sc->mac_addr[1] = 0xa0;
	sc->mac_addr[2] = 0x98;
	sc->mac_addr[3] = digest[0];
	sc->mac_addr[4] = digest[1];
	sc->mac_addr[5] = digest[2] & 0xFE; /* make even */

	/* start nvm in opcode mode. */
	sc->nvm_opaddr = 0;
	sc->nvm_mode = E82545_NVM_MODE_OPADDR;
	sc->nvm_bits = E82545_NVM_OPADDR_BITS;

	pci_e82545_init_eeprom(sc);

	return 0;
}

static void
pci_e82545_write_mdi(struct pci_e82545_softc *sc, uint8_t reg_addr,
			uint8_t phy_addr, uint32_t data)
{
	DPRINTF("Write mdi reg:0x%x phy:0x%x data: 0x%x\r\n", reg_addr, phy_addr, data);
}

static uint32_t
pci_e82545_read_mdi(struct pci_e82545_softc *sc, uint8_t reg_addr,
			uint8_t phy_addr)
{
	//DPRINTF("Read mdi reg:0x%x phy:0x%x\r\n", reg_addr, phy_addr);
	switch (reg_addr) {
	case PHY_STATUS:
		return (MII_SR_LINK_STATUS | MII_SR_AUTONEG_CAPS |
			MII_SR_AUTONEG_COMPLETE);
	case PHY_AUTONEG_ADV:
		return NWAY_AR_SELECTOR_FIELD;
	case PHY_LP_ABILITY:
		return 0;
	case PHY_1000T_STATUS:
		return (SR_1000T_LP_FD_CAPS | SR_1000T_REMOTE_RX_STATUS |
			SR_1000T_LOCAL_RX_STATUS);
	case PHY_ID1:
		return (M88E1011_I_PHY_ID >> 16) & 0xFFFF;
	case PHY_ID2:
		return (M88E1011_I_PHY_ID | E82545_REVISION_4) & 0xFFFF;
	default:
		DPRINTF("Unknown mdi read reg:0x%x phy:0x%x\r\n", reg_addr, phy_addr);
		return 0;
	}
	/* not reached */
}

static void
pci_e82545_eecd_strobe(struct pci_e82545_softc *sc)
{
	/* Microwire state machine */
	/*
	DPRINTF("eeprom state machine srtobe "
		"0x%x 0x%x 0x%x 0x%x\r\n",
		sc->nvm_mode, sc->nvm_bits,
		sc->nvm_opaddr, sc->nvm_data);*/

	if (sc->nvm_bits == 0) {
		DPRINTF("eeprom state machine not expecting data! "
			"0x%x 0x%x 0x%x 0x%x\r\n",
			sc->nvm_mode, sc->nvm_bits,
			sc->nvm_opaddr, sc->nvm_data);
		return;
	}
	sc->nvm_bits--;
	if (sc->nvm_mode == E82545_NVM_MODE_DATAOUT) {
		/* shifting out */
		if (sc->nvm_data & 0x8000) {
			sc->eeprom_control |= E1000_EECD_DO;
		} else {
			sc->eeprom_control &= ~E1000_EECD_DO;
		}
		sc->nvm_data <<= 1;
		if (sc->nvm_bits == 0) {
			/* read done, back to opcode mode. */
			sc->nvm_opaddr = 0;
			sc->nvm_mode = E82545_NVM_MODE_OPADDR;
			sc->nvm_bits = E82545_NVM_OPADDR_BITS;
		}
	} else if (sc->nvm_mode == E82545_NVM_MODE_DATAIN) {
		/* shifting in */
		sc->nvm_data <<= 1;
		if (sc->eeprom_control & E1000_EECD_DI) {
			sc->nvm_data |= 1;
		}
		if (sc->nvm_bits == 0) {
			/* eeprom write */
			uint16_t op = sc->nvm_opaddr & E82545_NVM_OPCODE_MASK;
			uint16_t addr = sc->nvm_opaddr & E82545_NVM_ADDR_MASK;
			if (op != E82545_NVM_OPCODE_WRITE) {
				DPRINTF("Illegal eeprom write op 0x%x\r\n",
					sc->nvm_opaddr);
			} else if (addr >= E82545_NVM_EEPROM_SIZE) {
				DPRINTF("Illegal eeprom write addr 0x%x\r\n",
					sc->nvm_opaddr);
			} else {
				DPRINTF("eeprom write eeprom[0x%x] = 0x%x\r\n",
				addr, sc->nvm_data);
				sc->eeprom_data[addr] = sc->nvm_data;
			}
			/* back to opcode mode */
			sc->nvm_opaddr = 0;
			sc->nvm_mode = E82545_NVM_MODE_OPADDR;
			sc->nvm_bits = E82545_NVM_OPADDR_BITS;
		}
	} else if (sc->nvm_mode == E82545_NVM_MODE_OPADDR) {
		sc->nvm_opaddr <<= 1;
		if (sc->eeprom_control & E1000_EECD_DI) {
			sc->nvm_opaddr |= 1;
		}
		if (sc->nvm_bits == 0) {
			uint16_t op = sc->nvm_opaddr & E82545_NVM_OPCODE_MASK;
			switch (op) {
			case E82545_NVM_OPCODE_EWEN:
				DPRINTF("eeprom write enable: 0x%x\r\n",
					sc->nvm_opaddr);
				/* back to opcode mode */
				sc->nvm_opaddr = 0;
				sc->nvm_mode = E82545_NVM_MODE_OPADDR;
				sc->nvm_bits = E82545_NVM_OPADDR_BITS;
				break;
			case E82545_NVM_OPCODE_READ:
			{
				uint16_t addr = sc->nvm_opaddr &
					E82545_NVM_ADDR_MASK;
				sc->nvm_mode = E82545_NVM_MODE_DATAOUT;
				sc->nvm_bits = E82545_NVM_DATA_BITS;
				if (addr < E82545_NVM_EEPROM_SIZE) {
					sc->nvm_data = sc->eeprom_data[addr];
					DPRINTF("eeprom read: eeprom[0x%x] = 0x%x\r\n",
						addr, sc->nvm_data);
				} else {
					DPRINTF("eeprom illegal read: 0x%x\r\n",
						sc->nvm_opaddr);
					sc->nvm_data = 0;
				}
				break;
			}
			case E82545_NVM_OPCODE_WRITE:
				sc->nvm_mode = E82545_NVM_MODE_DATAIN;
				sc->nvm_bits = E82545_NVM_DATA_BITS;
				sc->nvm_data = 0;
				break;
			default:
				DPRINTF("eeprom unknown op: 0x%x\r\r",
					sc->nvm_opaddr);
				/* back to opcode mode */
				sc->nvm_opaddr = 0;
				sc->nvm_mode = E82545_NVM_MODE_OPADDR;
				sc->nvm_bits = E82545_NVM_OPADDR_BITS;
			}
		}
	} else {
		DPRINTF("eeprom state machine wrong state! "
			"0x%x 0x%x 0x%x 0x%x\r\n",
			sc->nvm_mode, sc->nvm_bits,
			sc->nvm_opaddr, sc->nvm_data);
	}
}

static void
pci_e82545_write_register(struct pci_e82545_softc *sc, uint32_t offset,
                         uint32_t value)
{
	if (offset & 0x3) {
		DPRINTF("Unaligned register write offset:0x%x value:0x%x\r\n", offset, value);
		return;
	}
	//DPRINTF("Register write: 0x%x value: 0x%x\r\n", offset, value);

	/* ignore mac/vlan filtering */
	if ((offset >= E1000_RAL(0) && offset <= E1000_RAH(E82545_RAR_MAX)) ||
	    (offset >= E1000_MTA && offset <=
			E82545_ARRAY_ENTRY(E1000_MTA, E82545_MTA_MAX)) ||
	    (offset >= E1000_VFTA && offset <=
			E82545_ARRAY_ENTRY(E1000_VFTA, E82545_VFTA_MAX))) {
		return;
	}
	switch (offset) {
	case E1000_EECD:
	{
		//DPRINTF("EECD write 0x%x -> 0x%x\r\n", sc->eeprom_control, value);
		/* edge triggered low->high */
		uint32_t eecd_strobe = ((sc->eeprom_control & E1000_EECD_SK) ?
			0 : (value & E1000_EECD_SK));
		uint32_t eecd_mask = (E1000_EECD_SK|E1000_EECD_CS|
					E1000_EECD_DI|E1000_EECD_REQ);
		sc->eeprom_control &= ~eecd_mask;
		sc->eeprom_control |= (value & eecd_mask);
		/* grant/revoke immediately */
		if (value & E1000_EECD_REQ) {
			sc->eeprom_control |= E1000_EECD_GNT;
		} else {
                        sc->eeprom_control &= ~E1000_EECD_GNT;
		}
		if (eecd_strobe && (sc->eeprom_control & E1000_EECD_CS)) {
			pci_e82545_eecd_strobe(sc);
		}
		return;
	}
	case E1000_MDIC:
	{
		uint8_t reg_addr = (uint8_t)((value & E1000_MDIC_REG_MASK) >>
						E1000_MDIC_REG_SHIFT);
		uint8_t phy_addr = (uint8_t)((value & E1000_MDIC_PHY_MASK) >>
						E1000_MDIC_PHY_SHIFT);
		sc->mdi_control =
			(value & ~(E1000_MDIC_ERROR|E1000_MDIC_DEST));
		if ((value & E1000_MDIC_READY) != 0) {
			DPRINTF("Incorrect MDIC ready bit: 0x%x\r\n", value);
			return;
		}
		switch (value & E82545_MDIC_OP_MASK) {
		case E1000_MDIC_OP_READ:
			sc->mdi_control &= ~E82545_MDIC_DATA_MASK;
			sc->mdi_control |= pci_e82545_read_mdi(sc, reg_addr, phy_addr);
			break;
		case E1000_MDIC_OP_WRITE:
			pci_e82545_write_mdi(sc, reg_addr, phy_addr,
				value & E82545_MDIC_DATA_MASK);
			break;
		default:
			DPRINTF("Unknown MDIC op: 0x%x\r\n", value);
			return;
		}
		/* TODO: barrier? */
		sc->mdi_control |= E1000_MDIC_READY;
		if (value & E82545_MDIC_IE) {
			// TODO: generate interrupt
		}
		return;
	}
	case E1000_IMS:
		DPRINTF("Interrupt mask set: 0x%x | 0x%x\r\n", sc->intr_mask, value);
		sc->intr_mask |= value;
		return;
	case E1000_IMC:
		DPRINTF("Interrupt mask clr: 0x%x & (~0x%x)\r\n", sc->intr_mask, value);
		sc->intr_mask &= (~value);
		return;
	case E1000_MANC:
	case E1000_STATUS: 
		return;
	default:
		DPRINTF("Unknown write register: 0x%x value:%x\r\n", offset, value);
		return;
	}
}

static uint32_t
pci_e82545_read_register(struct pci_e82545_softc *sc, uint32_t offset)
{
	if (offset & 0x3) {
		DPRINTF("Unaligned register read offset:0x%x\r\n", offset);
		return 0;
	}
		
	//DPRINTF("Register read: 0x%x\r\n", offset);
	switch (offset) {
	case E1000_EECD:
		//DPRINTF("EECD read %x\r\n", sc->eeprom_control);
		return sc->eeprom_control;
	case E1000_MDIC:
		return sc->mdi_control;
	case E1000_STATUS:
		return E1000_STATUS_FD | E1000_STATUS_LU |
			E1000_STATUS_SPEED_1000;
	case E1000_IMS:
		return sc->intr_mask;
	case E1000_ICS:
		DPRINTF("Read from WO register: 0x%x\r\n", offset);
		return 0;
	case E1000_MANC:
		return 0;
	/* stats that we emulate. */
	case E1000_MPC:
		return sc->missed_pkt_count;
	case E1000_PRC64:
		return sc->pkt_rx_by_size[0];
	case E1000_PRC127:
		return sc->pkt_rx_by_size[1];
	case E1000_PRC255:
		return sc->pkt_rx_by_size[2];
	case E1000_PRC511:
		return sc->pkt_rx_by_size[3];
	case E1000_PRC1023:
		return sc->pkt_rx_by_size[4];
	case E1000_PRC1522:
		return sc->pkt_rx_by_size[5];
	case E1000_GPRC:
		return sc->good_pkt_rx_count;
	case E1000_BPRC:
		return sc->bcast_pkt_rx_count;
	case E1000_MPRC:
		return sc->mcast_pkt_rx_count;
	case E1000_GPTC:
	case E1000_TPT:
		return sc->good_pkt_tx_count;
	case E1000_GORCL:
		return (uint32_t)sc->good_octets_rx;
	case E1000_GORCH:
		return (uint32_t)(sc->good_octets_rx >> 32);
	case E1000_TOTL:
	case E1000_GOTCL:
		return (uint32_t)sc->good_octets_tx;
	case E1000_TOTH:
	case E1000_GOTCH:
		return (uint32_t)(sc->good_octets_tx >> 32);
	case E1000_ROC:
		return sc->oversize_rx_count;
	case E1000_TORL:
		return (uint32_t)(sc->good_octets_rx +
				  sc->missed_octets);
	case E1000_TORH:
		return (uint32_t)((sc->good_octets_rx +
				   sc->missed_octets) >> 32);
	case E1000_TPR:
		return sc->good_pkt_rx_count +
			sc->missed_pkt_count +
			sc->oversize_rx_count;
	case E1000_PTC64:
		return sc->pkt_tx_by_size[0];
	case E1000_PTC127:
		return sc->pkt_tx_by_size[1];
	case E1000_PTC255:
		return sc->pkt_tx_by_size[2];
	case E1000_PTC511:
		return sc->pkt_tx_by_size[3];
	case E1000_PTC1023:
		return sc->pkt_tx_by_size[4];
	case E1000_PTC1522:
		return sc->pkt_tx_by_size[5];
	case E1000_MPTC:
		return sc->mcast_pkt_tx_count;
	case E1000_BPTC:
		return sc->bcast_pkt_tx_count;
	case E1000_TSCTC:
		return sc->tso_tx_count;
	/* stats that are always 0. */
	case E1000_CRCERRS:
	case E1000_ALGNERRC:
	case E1000_SYMERRS:
	case E1000_RXERRC:
	case E1000_SCC:
	case E1000_ECOL:
	case E1000_MCC:
	case E1000_LATECOL:
	case E1000_COLC:
	case E1000_DC:
	case E1000_TNCRS:
	case E1000_SEC:
	case E1000_CEXTERR:
	case E1000_RLEC:
	case E1000_XONRXC:
	case E1000_XONTXC:
	case E1000_XOFFRXC:
	case E1000_XOFFTXC:
	case E1000_FCRUC:
	case E1000_RNBC:
	case E1000_RUC:
	case E1000_RFC:
	case E1000_RJC:
	case E1000_MGTPRC:
	case E1000_MGTPDC:
	case E1000_MGTPTC:
	case E1000_TSCTFC:
		return 0;
	default:
		DPRINTF("Unknown read register: 0x%x\r\n", offset);
		return 0;
	}
	/* not reached */
}

static void
pci_e82545_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		int baridx, uint64_t offset, int size, uint64_t value)
{
	struct pci_e82545_softc *sc = pi->pi_arg;

	//DPRINTF("Write bar:%d offset:0x%lx value:0x%lx size:%d\r\n", baridx, offset, value, size);

	switch (baridx) {
	case E82545_BAR_IO:
		switch (offset) {
		case E82545_IOADDR:
			if (size != 4) {
				DPRINTF("Wrong io addr write size:%d value:0x%lx\r\n", size, value);
				return;
			}
			sc->io_addr = (uint32_t)value;
			break;
		case E82545_IODATA:
			if (size != 4) {
				DPRINTF("Wrong io data write size:%d value:0x%lx\r\n", size, value);
				return;
			}
			if (sc->io_addr > E82545_IO_REGISTER_MAX) {
				DPRINTF("Non-register io write addr:0x%x value:0x%lx\r\n", sc->io_addr, value);
				return;
			}
			pci_e82545_write_register(sc, sc->io_addr, (uint32_t)value);
			return;
		default:
			DPRINTF("Unknown io bar write offset:0x%lx value:0x%lx size:%d\r\n", offset, value, size);
			return;
		}
	case E82545_BAR_REGISTER:
		if (size != 4) {
			DPRINTF("Wrong register write size:%d offset:0x%lx value:0x%lx\r\n", size, offset, value);
			return;
		}
		pci_e82545_write_register(sc, (uint32_t)offset, (uint32_t)value);
		return;
	default:
		DPRINTF("Unknown write bar:%d offset:0x%lx value:0x%lx size:%d\r\n", baridx, offset, value, size);
	}
		
}

static uint64_t
pci_e82545_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	       int baridx, uint64_t offset, int size)
{
	struct pci_e82545_softc *sc = pi->pi_arg;

	//DPRINTF("Read  bar:%d offset:0x%lx size:%d\r\n", baridx, offset, size);

	switch (baridx) {
	case E82545_BAR_IO:
		switch (offset) {
		case E82545_IOADDR:
			if (size != 4) {
				DPRINTF("Wrong io read size:%d\r\n", size);
			}
			return sc->io_addr;
		case E82545_IODATA:
			if (size != 4) {
				DPRINTF("Wrong io data read size:%d\r\n", size);
			}
			if (sc->io_addr > E82545_IO_REGISTER_MAX) {
				DPRINTF("Non-register io read addr:0x%x\r\n", sc->io_addr);
				return 0;
			}
			return pci_e82545_read_register(sc, sc->io_addr);
		default:
			DPRINTF("Unknown io bar read offset:0x%lx size:%d\r\n", offset, size);
			return 0;
		}
	case E82545_BAR_REGISTER:
		if (size != 4) {
			DPRINTF("Wrong register read size:%d offset:0x%lx\r\n", size, offset);
			return 0;
		}
		return pci_e82545_read_register(sc, (uint32_t)offset);
	default:
		DPRINTF("Unknown read bar:%d offset:0x%lx size:%d\r\n", baridx, offset, size);
		return 0;
	}
	/* Not reached */
}

struct pci_devemu pci_de_e82545 = {
	.pe_emu = 	"e82545",
	.pe_init =	pci_e82545_init,
	.pe_barwrite =	pci_e82545_write,
	.pe_barread =	pci_e82545_read
};
PCI_EMUL_SET(pci_de_e82545);

