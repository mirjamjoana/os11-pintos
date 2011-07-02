#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "devices/block.h"
#include "threads/synch.h"
#include <stdio.h>

#define CACHE_DEBUG 0

#define CACHE_READ 0
#define CACHE_WRITE 1
#define CACHE_SIZE 64

void cache_init (void);
void cache_flush (void);

void cache_read (block_sector_t bid, void * buffer, int offset, int readsize);
void cache_write (block_sector_t bid, const void * buffer, int offset, int writesize);
void cache_readahead (block_sector_t next);


/* read-ahead data structures */
struct readahead
{
	block_sector_t bid;
	struct list_elem elem;
};

struct lock lock_readahead;
struct list list_readahead;
struct condition cond_readahead;

#endif /* filesys/cache.h */

