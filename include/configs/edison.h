/*
 * Copyright (c) 2015 Google, Inc
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#define CONFIG_BOARD_LATE_INIT
#define CONFIG_MD5

/*-----------------------------------------------------------------------
 * Misc
 */

#define CONFIG_CMD_ASKENV
#define CONFIG_CMD_BSP
#define CONFIG_CMD_CACHE
/*
 *#define CONFIG_CMD_DATE
 */
#define CONFIG_CMD_DIAG
#define CONFIG_CMD_ENV_CALLBACK
#define CONFIG_CMD_ENV_FLAGS
/*
 *#define CONFIG_CMD_GETTIME
 */
#define CONFIG_CMD_GREPENV
#define CONFIG_CMD_HASH
/*
 *#define CONFIG_CMD_KGDB
 */
/*
 *#define CONFIG_CMD_MD5SUM
 */
#define CONFIG_CMD_MEMINFO
#define CONFIG_CMD_PORTIO
/*
 *#define CONFIG_CMD_READ
 */
#define CONFIG_CMD_REGINFO
/*
 *#define CONFIG_CMD_I2C
 *#define CONFIG_SYS_I2C_SPEED    50000
 */
/*
 *#define CONFIG_CMD_SPI
 */
#define CONFIG_CMD_TIMER

/*
 *#define CONFIG_CMD_TRACE
 */
/*
 *#define CONFIG_CMD_DATE
 */
/*
 *#define CONFIG_CMD_GPIO
 */
#define CONFIG_CMD_IRQ
#define CONFIG_CMD_PCI
/*
 *#define CONFIG_CMD_TIME
 *#define CONFIG_CMD_GETTIME
 */
/*
 *#define CONFIG_CMD_USB
 */
/*
 *#define EARLY_TRACE
 *#define FTRACE
 */


/*-----------------------------------------------------------------------
 * Boot
 */
#define CONFIG_BOOTCOUNT_LIMIT
#define CONFIG_BOOTCOUNT_ENV
#define CONFIG_ZBOOT_32
#define CONFIG_CMD_ZBOOT
#define CONFIG_BOOTCOMMAND "run bootcmd"

/*-----------------------------------------------------------------------
 * DEBUG
 */

/*
 *#define DEBUG
 */

/*
 *#define CONFIG_PRE_CONSOLE_BUFFER
 *#define CONFIG_PRE_CON_BUF_SZ (1024*1024*2)
 *#define CONFIG_PRE_CON_BUF_ADDR 0x29200000
 */

/*-----------------------------------------------------------------------
 * Serial
 */

#define CONFIG_BAUDRATE                         115200

/*
* MMC
 */
#define CONFIG_MD5
#define CONFIG_CMD_MMC

/************************************************************
 * DISK Partition support
 ************************************************************/
#define CONFIG_EFI_PARTITION
#define CONFIG_DOS_PARTITION
#define CONFIG_MAC_PARTITION

#define CONFIG_FS_FAT
#define CONFIG_CMD_FAT
#define CONFIG_FAT_WRITE

#define CONFIG_CMD_GPT
#define CONFIG_CMD_PART
#define CONFIG_CMD_EXT4
#define CONFIG_CMD_EXT4_WRITE
#define CONFIG_PARTITION_UUIDS
#define CONFIG_RANDOM_UUID
#define CONFIG_CMD_FS_GENERIC
 /*
 * Miscellaneous configurable options
 */
#define CONFIG_SYS_LONGHELP
#define CONFIG_SYS_CBSIZE			2048
#define CONFIG_SYS_PBSIZE			(CONFIG_SYS_CBSIZE + \
						 sizeof(CONFIG_SYS_PROMPT) + \
						 16)
#define CONFIG_SYS_MAXARGS			128
#define CONFIG_SYS_BARGSIZE			CONFIG_SYS_CBSIZE
#define CONFIG_AUTO_COMPLETE

/*-----------------------------------------------------------------------
 * Board Features
 */

#define CONFIG_SYS_NO_FLASH

/*-----------------------------------------------------------------------
 * Memory
 */

#define CONFIG_SYS_LOAD_ADDR                   0x100000
#define CONFIG_PHYSMEM

#define CONFIG_SYS_CACHELINE_SIZE        64

#define CONFIG_NR_DRAM_BANKS                    3

#define CONFIG_SYS_STACK_SIZE			(32 * 1024)

#define CONFIG_SYS_CAR_ADDR			0x19200000

#define CONFIG_SYS_MONITOR_BASE		        CONFIG_SYS_TEXT_BASE
#define CONFIG_SYS_MONITOR_LEN			(256 * 1024)

#define CONFIG_SYS_MALLOC_LEN			( 128 * 1024 * 1024)

#define CONFIG_SYS_MEMTEST_START		0x00100000
#define CONFIG_SYS_MEMTEST_END			0x01000000

/*-----------------------------------------------------------------------
 * CPU Features
 */

#define CONFIG_SYS_NUM_IRQS			16

#define CONFIG_CMD_GETTIME

#define PIT_BASE   0x40

/*-----------------------------------------------------------------------
 * Environment
 */
#define CONFIG_ENV_IS_IN_MMC
/*
#define CONFIG_SYS_MMC_ENV_DEV                  0
#define CONFIG_SYS_MMC_ENV_PART                 0
 */
#define CONFIG_ENV_SIZE                         (64*1024)
/*
#define CONFIG_ENV_OFFSET	(3 * 1024 * 1024)
#define CONFIG_ENV_OFFSET_REDUND (6 * 1024 * 1024)
 */
#define CONFIG_SUPPORT_EMMC_BOOT
#define CONFIG_CMD_SETEXPR

/*-----------------------------------------------------------------------
 * USB
 */
#define iounmap(x)
#define CONFIG_USB_DWC3
#define CONFIG_USB_DWC3_GADGET
#define CONFIG_USB_DEVICE
#define CONFIG_USB_GADGET
#define CONFIG_USB_GADGET_DOWNLOAD
#define CONFIG_USB_GADGET_DUALSPEED
#define CONFIG_USB_GADGET_VBUS_DRAW 2
#define CONFIG_G_DNL_MANUFACTURER "Intel"
#define CONFIG_G_DNL_VENDOR_NUM 0x8087
#define CONFIG_G_DNL_PRODUCT_NUM 0x0a99

#define CONFIG_GENERIC_MMC
#define CONFIG_WATCHDOG

#endif
