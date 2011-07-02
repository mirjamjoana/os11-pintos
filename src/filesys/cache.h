#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "devices/block.h"
#include "threads/synch.h"

#define debug 0
#include <stdio.h>

void cache_read (block_sector_t bid, void * buffer, int offset, int readsize);
void cache_init (void);

void cache_write (block_sector_t bid, void * buffer, int offset, int writesize);
void cache_save_cachetable(void);
void cache_do_readahead (block_sector_t next);

//for the read ahead thread
struct lock lock_readahead;
struct list list_readahead;
struct condition cond_readahead;

//structure for the readahead list
struct readahead {

        block_sector_t bid;
        struct list_elem elem;

};

#endif /* filesys/cache.h */

