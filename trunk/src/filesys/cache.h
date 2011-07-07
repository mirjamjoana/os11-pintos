#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "devices/block.h"
#include "threads/synch.h"
#include <stdio.h>

#define CACHE_DEBUG 0

/* constants */
#define CACHE_READ 0
#define CACHE_WRITE 1
#define CACHE_SIZE 64

/* read-ahead data structures */
struct readahead_elem
{
	struct list_elem elem; /* list element */
	block_sector_t block_sector;	/* block sector */

};

/* global list of read-ahead blocks */
struct list readahead_list;
struct lock readahead_lock;

/* counting semaphore for read-ahead list */
struct semaphore readahead_cnt;
struct condition readahead_cond;

/* methods */
void cache_init (void);
void cache_flush (void);
void cache_read (block_sector_t bid, void * buffer, int offset, int readsize);
void cache_write (block_sector_t bid, const void * buffer, int offset, int writesize);
void cache_readahead (block_sector_t next);

#endif /* filesys/cache.h */

