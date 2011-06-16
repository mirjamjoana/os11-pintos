#include "devices/block.h"
/* swap pages */

/* global swap table */
static struct hash swap_table;

static struct block* swap_disk;


void init_swap()
{
	swap_disk = block_get_role(BLOCK_SWAP);
}

void swap_out(sup_page)
{
	save_into_swap();
}

void swap_in(sup_page)
{
	load_from_swap();
}

static void save_into_swap()
{
	void block_write (struct block *, block_sector_t, const void *);
}

static void load_from_swap()
{
	void block_read (struct block *, block_sector_t, void *);
}

