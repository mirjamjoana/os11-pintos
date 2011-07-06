#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "lib/kernel/bitmap.h"
#include "lib/string.h"

void cache_evict (void);
void cache_add_readahead_block(block_sector_t next);

struct cache_block
{
	/* block id on disk */
	block_sector_t bid;

	/* corresponding kernel page */
	void * kpage;

	/* fields to check access and if someone wrote to the page */
	bool dirty;
	bool accessed;
	int reader;
	int writer;
};

/* how many blocks fit in one page */
int blocks_per_page = (PGSIZE/BLOCK_SECTOR_SIZE);

/* the cache */
struct cache_block *cache[CACHE_SIZE];

/* bitmap of free cache blocks */
struct bitmap *cache_table;

/* global cache lock */
struct lock cache_globallock;

/* cache eviction pointer */
static int cep = 0;

/* initializes the cashing system */
void
cache_init ()
{
	/* loop variables */
	int i,j;

	/* allocate kernel pages for cache */
	for (i = 0; i < (CACHE_SIZE / blocks_per_page); i++)
	{
		/* get a page from kernel memory */
		void *kpage = palloc_get_page (PAL_ZERO);
		for (j = 0; j < blocks_per_page; j++)
		{
			/* init the block */                        
			struct cache_block *c = (struct cache_block*) malloc(sizeof(struct cache_block));

			c->reader = 0;
			c->writer = 0;
			c->bid = -1;
			c->kpage = kpage + j * BLOCK_SECTOR_SIZE ;
			c->dirty = false;
			c->accessed = false;

			/* save to cache */
			cache[i * blocks_per_page + j] = c;
		}
	}

	/*create a bitmap that represents the free entries in the cache table */
	cache_table = bitmap_create (CACHE_SIZE);

	/* init list, lock and counting semaphore */
	lock_init(&cache_globallock);
	list_init(&readahead_list);
	sema_init(&readahead_cnt, 0);
}


/* adds a block to cache */
static size_t
cache_add (block_sector_t bid)
{
	/* lock the cache */
	lock_acquire(&cache_globallock);
	
	//bool hellYeah = bid == (unsigned) 163;

	/* lock for a free_cache_block cache block */
	size_t free_cache_block = bitmap_scan (cache_table, 0, 1, false);
	
	//if(DEBUG || hellYeah) printf("bitscan complete bla\n");

	/* if no free cache block is found, evict one and
	 * search again */
	if (free_cache_block == BITMAP_ERROR) {
		
		//if(DEBUG || hellYeah) printf("evict some\n");
		cache_evict();
		free_cache_block = bitmap_scan (cache_table, 0, 1, false);
	}

	ASSERT(free_cache_block != BITMAP_ERROR);
	//if(DEBUG || hellYeah) printf("add cache block %d\n",bid);

	/* copy block to cache */
	block_read (fs_device, bid, cache[free_cache_block]->kpage);

	/* setup cache entry */
	cache[free_cache_block]->dirty = false;
	cache[free_cache_block]->accessed = false;
	cache[free_cache_block]->bid = bid;

	/* set used bit of the cache table for this entry */
	bitmap_set (cache_table, free_cache_block, true);

	/* release the lock for the cache table */
	lock_release(&cache_globallock);

	if(CACHE_DEBUG) printf("added cache block %u for sector %u\n", (unsigned int) free_cache_block, (unsigned int) bid);
	
	return free_cache_block;
}


/* write the cache entry back to disk */
static void
cache_writeback (int idx)
{
	if(CACHE_DEBUG) printf("writeback cache block %i to disk block %i\n", idx, (int) cache[idx]->bid);

	ASSERT(bitmap_test (cache_table,idx));
	ASSERT(lock_held_by_current_thread(&cache_globallock));
        
	/* register as writer */
	cache[idx]->writer++;

	/* if cache block is dirty right it back */
	if (cache[idx]->dirty)
		block_write(fs_device, cache[idx]->bid, cache[idx]->kpage);

	/* unregister as writer */
	cache[idx]->writer--;
}


/* finds the block in the cache table, returns -1 if it isn't in cache
the rw flag is to increase the read ( 0 ) or write ( 1 ) variable in order to avoid race conditions 
between reading the cache block and reading or writing to it */
static int
cache_find_block (block_sector_t bid, int read_write)
{
	lock_acquire(&cache_globallock);

	int i;
	for (i = 0; i < CACHE_SIZE ; i++) {
		if (cache[i]->bid == bid)
		{
			if ( read_write == CACHE_READ ) cache[i]->reader++;
			if ( read_write == CACHE_WRITE ) cache[i]->writer++;

			lock_release(&cache_globallock);                        
            		return i;
		}       
	}

	lock_release(&cache_globallock);

	return -1;
}


/* read size bytes from block bid beginning at offset into buffer */
void
cache_read (block_sector_t bid, void * buffer, int offset, int size)
{
	ASSERT(offset < BLOCK_SECTOR_SIZE);

	int cache_id = cache_find_block(bid, CACHE_READ);
        
	/* if not found load into cache */
	if(cache_id == -1)
	{
		/* copy block from disk */
		cache_id = cache_add(bid);
		ASSERT(cache_id != -1);

		/* increment number of reader manually */
		cache[cache_id]->reader++;

		/* add read-ahead block */
		//TODO cache_readahead(bid + 1);
	}

	/* copy the corresponding section into buffer */
	memcpy (buffer, cache[cache_id]->kpage + offset, size);

	/* update cache flags */
	cache[cache_id]->accessed = true;
	cache[cache_id]->reader--;

	if(CACHE_DEBUG)  printf("read cache %u\n", (unsigned int) cache_id);

}


/* write size bytes from buffer into cache block */
void
cache_write (block_sector_t bid, const void *buffer, int offset, int size)
{
	ASSERT(offset < BLOCK_SECTOR_SIZE);
	ASSERT(offset + size <= BLOCK_SECTOR_SIZE);

	/* find cache block */
	int cache_id = cache_find_block(bid, CACHE_WRITE);
        
	//if(((unsigned) buffer) == 134556864) printf("CACHE a, bid:%u\n", bid);

	/* if cache block not present, load */
	if(cache_id == -1)
	{
		cache_id = cache_add(bid);
		
		/* increment number of reader manually */
		cache[cache_id]->writer++;
	}
	
	//if(((unsigned) buffer) == 134556864) printf("CACHE b\n");
	
	ASSERT(cache_id != -1);

	/* copy buffer content into cache */
	memcpy (cache[cache_id]->kpage + offset, buffer, size);
	cache[cache_id]->accessed = true;
	cache[cache_id]->dirty = true;
	cache[cache_id]->writer--;

	if(CACHE_DEBUG) printf("wrote cache %u: @offset %i from buffer %x with size %i\n", (unsigned int) cache_id, offset, (unsigned int) buffer, size);
}


/* evicts a cache block */
void
cache_evict ()
{
	ASSERT(lock_held_by_current_thread(&cache_globallock));

	//unsigned loops = 0;

	/* as long as no cache block has been evicted */
	while (true)
	{
		/*
		if(loops > 3 * CACHE_SIZE) {
			printf("Cache block %u | writer: %u | reader: %u\n", cep, cache[cep]->writer, cache[cep]->reader);
		}
		*/

		/* search cache block to evict */
		/* if no one is writing and reading the block */
		if (cache[cep]->writer == 0 && cache[cep]->reader == 0)
		{
	            	/* if cache block was accessed before
	            	 * give it a second chance */
	            	if (cache[cep]->accessed)
	            	{
	            		cache[cep]->accessed = false;
        	        }
            		/* if cache block was not accessed nor
	            	 * written in the last clock turn
	            	 * evict it */
        	    	else
	                {
				if(CACHE_DEBUG) printf("evicted cache block %u\n", (unsigned int) cep);

				cache_writeback(cep);
				bitmap_set (cache_table, cep, false);
				/* zero block first? */
				return;
	                }
		}
		cep = (cep + 1) % CACHE_SIZE;
		//loops++;
	}
}



/* flush the cash - write back all dirty blocks */
void
cache_flush()
{
	if(CACHE_DEBUG) printf("flushing cache\n");

	lock_acquire(&cache_globallock);
        
	int i;
	for (i = 0; i < CACHE_SIZE; i++)
		cache_writeback(i);

	lock_release(&cache_globallock);
}


/* adds block next of the file to the read-ahead list  */
void
cache_add_readahead_block(block_sector_t block_sector)
{
	if(CACHE_DEBUG) printf("insert read-ahead block\n");

	lock_acquire(&readahead_lock);

	/* create and initialize read-ahead element */
	struct readahead_elem *re = (struct readahead_elem *) malloc ( sizeof(struct readahead_elem));
	re->block_sector = block_sector;

	/* add to read-ahead list */
	list_push_back (&readahead_list, &re->elem);

	/* increase list counter and wake read-ahead thread */
	sema_up(&readahead_cnt);

	lock_release(&readahead_lock);
}


/* load read-ahead block */
void
cache_readahead (block_sector_t bid)
{
	/* if block is not in cache, load it */
	if (cache_find_block(bid,-1) == -1) {
		cache_add (bid);
	}
}
