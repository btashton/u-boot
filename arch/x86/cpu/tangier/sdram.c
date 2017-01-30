/*
 * Copyright (c) 2011 The Chromium OS Authors.
 * (C) Copyright 2010,2011
 * Graeme Russ, <graeme.russ@gmail.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <malloc.h>
#include <asm/e820.h>
#include <asm/u-boot-x86.h>
#include <asm/global_data.h>
#include <asm/processor.h>
#include <asm/sections.h>
#include <asm/bootparam.h>
#include <asm/sfi.h>

/* Memory type definitions */
enum sfi_mem_type {
	SFI_MEM_RESERVED,
	SFI_LOADER_CODE,
	SFI_LOADER_DATA,
	SFI_BOOT_SERVICE_CODE,
	SFI_BOOT_SERVICE_DATA,
	SFI_RUNTIME_SERVICE_CODE,
	SFI_RUNTIME_SERVICE_DATA,
	SFI_MEM_CONV,
	SFI_MEM_UNUSABLE,
	SFI_ACPI_RECLAIM,
	SFI_ACPI_NVS,
	SFI_MEM_MMIO,
	SFI_MEM_IOPORT,
	SFI_PAL_CODE,
	SFI_MEM_TYPEMAX,
};

#define SFI_BASE_ADDR		0x000E0000
#define SFI_LENGTH		0x00020000
#define SFI_TABLE_LENGTH	16

static int sfi_table_check(struct sfi_table_header *sbh)
{
	char chksum = 0;
	char *pos = (char *)sbh;
	int i;

	if (sbh->len < SFI_TABLE_LENGTH)
		return -1;

	if (sbh->len > SFI_LENGTH)
		return -1;

	for (i = 0; i < sbh->len; i++)
		chksum += *pos++;

	if (chksum)
		error("sfi: Invalid checksum\n");

	/* checksum is ok if zero */
	return chksum;
}

static unsigned long sfi_search_mmap(void)
{
	struct sfi_table_header *sbh;
	struct sfi_table_simple *sb;
	u32 sys_entry_cnt;
	u32 i;

	/* Find SYST table */
	for (i = 0; i < SFI_LENGTH; i += SFI_TABLE_LENGTH) {
		sb = (struct sfi_table_simple *)(SFI_BASE_ADDR + i);
		sbh = (struct sfi_table_header *)sb;
		if (!strncmp(sbh->sig, SFI_SIG_SYST, SFI_SIGNATURE_SIZE) &&
		    !sfi_table_check(sbh))
			break;
	}

	if (i >= SFI_LENGTH) {
		error("failed to locate SFI SYST table\n");
		return 0;
	}

	sys_entry_cnt = (sbh->len - sizeof(struct sfi_table_header)) / 8;

	/* Search through each SYST entry for MMAP table */
	for (i = 0; i < sys_entry_cnt; i++) {
		sbh = (struct sfi_table_header *)(unsigned long)sb->pentry[i];
		if (!strncmp(sbh->sig, SFI_SIG_MMAP, SFI_SIGNATURE_SIZE) &&
		    !sfi_table_check(sbh))
			return (unsigned long)sbh;
	}

	return 0;
}

unsigned sfi_setup_e820(unsigned max_entries, struct e820entry *entries)
{
	struct sfi_table_simple *sb;
	struct sfi_mem_entry *mentry;
	unsigned long long start, end, size;
	int i, num, type, total;

	total = 0;

	/* search for sfi mmap table */
	sb = (struct sfi_table_simple *)sfi_search_mmap();
	if (!sb) {
		error("failed to locate SFI MMAP table\n");
		return 0;
	}
	debug("will use sfi mmap table for e820 table\n");
	num = SFI_GET_NUM_ENTRIES(sb, struct sfi_mem_entry);
	mentry = (struct sfi_mem_entry *)sb->pentry;

	for (i = 0; i < num; i++) {
		start = mentry->phys_start;
		size = mentry->pages << 12;
		end = start + size;

		if (start > end)
			continue;

		/* translate SFI mmap type to E820 map type */
		switch (mentry->type) {
		case SFI_MEM_CONV:
			type = E820_RAM;
			break;
		case SFI_MEM_UNUSABLE:
		case SFI_RUNTIME_SERVICE_DATA:
			mentry++;
			continue;
		default:
			type = E820_RESERVED;
		}

		if (total == E820MAX)
			break;
		entries[total].addr = start;
		entries[total].size = size;
		entries[total++].type = type;

		mentry++;
	}

	return total;
}

phys_size_t sfi_get_ram_size(void)
{
	struct sfi_table_simple *sb;
	struct sfi_mem_entry *mentry;
	unsigned long long start, end, size;
	int i, num;
	phys_size_t ram = 0;

	/* search for sfi mmap table */
	sb = (struct sfi_table_simple *)sfi_search_mmap();
	if (!sb) {
		error("failed to locate SFI MMAP table\n");
		return 0;
	}
	debug("will use sfi mmap table for e820 table\n");
	num = SFI_GET_NUM_ENTRIES(sb, struct sfi_mem_entry);
	mentry = (struct sfi_mem_entry *)sb->pentry;

	for (i = 0; i < num; i++, mentry++) {
		if (mentry->type != SFI_MEM_CONV)
			continue;

		start = mentry->phys_start;
		size = mentry->pages << 12;
		end = start + size;

		if (start > end)
			continue;

		if (ram < end)
			ram = end;
	}

	/* round up to 512mb */
	ram = (ram + (512 * 1024 * 1024 - 1)) & ~(512 * 1024 * 1024 - 1);

	debug("ram size %llu\n", ram);

	return ram;
}

DECLARE_GLOBAL_DATA_PTR;

unsigned install_e820_map(unsigned max_entries, struct e820entry *entries)
{
	return sfi_setup_e820(max_entries, entries);
}

/*
 * This function looks for the highest region of memory lower than 4GB which
 * has enough space for U-Boot where U-Boot is aligned on a page boundary. It
 * overrides the default implementation found elsewhere which simply picks the
 * end of ram, wherever that may be. The location of the stack, the relocation
 * address, and how far U-Boot is moved by relocation are set in the global
 * data structure.
 */
ulong board_get_usable_ram_top(ulong total_size)
{
	uintptr_t dest_addr = 0x000000003F4FFFFF;
/*
 *    int i;
 *
 *    for (i = 0; i < lib_sysinfo.n_memranges; i++) {
 *        struct memrange *memrange = &lib_sysinfo.memrange[i];
 *        [> Force U-Boot to relocate to a page aligned address. <]
 *        uint64_t start = roundup(memrange->base, 1 << 12);
 *        uint64_t end = memrange->base + memrange->size;
 *
 *        [> Ignore non-memory regions. <]
 *        if (memrange->type != CB_MEM_RAM)
 *            continue;
 *
 *        [> Filter memory over 4GB. <]
 *        if (end > 0xffffffffULL)
 *            end = 0x100000000ULL;
 *        [> Skip this region if it's too small. <]
 *        if (end - start < total_size)
 *            continue;
 *
 *        [> Use this address if it's the largest so far. <]
 *        if (end > dest_addr)
 *            dest_addr = end;
 *    }
 *
 *    [> If no suitable area was found, return an error. <]
 *    if (!dest_addr)
 *        panic("No available memory found for relocation");
 */

	return (ulong)dest_addr;
}

int dram_init_f(void)
{
/*
 *    int i;
 *    phys_size_t ram_size = 0;
 *
 *    for (i = 0; i < lib_sysinfo.n_memranges; i++) {
 *        struct memrange *memrange = &lib_sysinfo.memrange[i];
 *        unsigned long long end = memrange->base + memrange->size;
 *
 *        if (memrange->type == CB_MEM_RAM && end > ram_size)
 *            ram_size = end;
 *    }
 *    gd->ram_size = ram_size;
 *    if (ram_size == 0)
 *        return -1;
 */
	gd->ram_size = sfi_get_ram_size();
	return 0;
}

void dram_init_banksize(void)
{
/*
 *    int i, j;
 *
 *    if (CONFIG_NR_DRAM_BANKS) {
 *        for (i = 0, j = 0; i < lib_sysinfo.n_memranges; i++) {
 *            struct memrange *memrange = &lib_sysinfo.memrange[i];
 *
 *            if (memrange->type == CB_MEM_RAM) {
 *                gd->bd->bi_dram[j].start = memrange->base;
 *                gd->bd->bi_dram[j].size = memrange->size;
 *                j++;
 *                if (j >= CONFIG_NR_DRAM_BANKS)
 *                    break;
 *            }
 *        }
 *    }
 */
/*
 *0:      0000000000000000-0000000000097FFF (   0K -  608K) ram
 *3:      0000000000100000-0000000003FFFFFF (   1M -   64M) ram
 *5:      0000000006000000-000000003F4FFFFF (  96M - 1013M) ram
 */
	gd->bd->bi_dram[0].start = 0x0;
	gd->bd->bi_dram[0].size = 0x97FFF;

	gd->bd->bi_dram[1].start = 0x100000;
	gd->bd->bi_dram[1].size = 0x3FFFFFF - gd->bd->bi_dram[1].start;

	gd->bd->bi_dram[2].start = 0x6000000;
	gd->bd->bi_dram[2].size = 0x3F4FFFFF  -  gd->bd->bi_dram[2].start;
}

int dram_init(void)
{
	dram_init_banksize();
	return 0;
}
