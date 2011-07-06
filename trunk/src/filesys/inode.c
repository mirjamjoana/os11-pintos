#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/cache.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#define INODE_DEBUG 0
#define FILE_DEBUG 0
#define INODE_PRINT 0

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Offsets inside an disk inode */
#define INODE_OFFSET_TYPE 0
#define INODE_OFFSET_LENGTH 4
#define INODE_OFFSET_SECTOR_COUNT 8
#define INODE_OFFSET_SECTOR_MAGIC 12
#define INODE_OFFSET_DBS 16
#define INODE_OFFSET_IDBS 512 - 8
#define INODE_OFFSET_DIDBS 512 - 4

#define INODE_DIRECT_BLOCKS 122
#define INODE_INDIRECT_BLOCKS 128
#define INODE_DOUBLY_DIRECT_BLOCKS 128 * 128 /* => max: ~8Mb */

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long.

   128 * 4 byte = 512 byte */
struct inode_disk
{
    enum file_t type;											/* File or Directory. */
    off_t length;                       						/* Size in bytes. */
    unsigned sector_count;										/* Count of disk block sectors in use. */
    unsigned magic;                     						/* Magic number. */
    block_sector_t direct_block_sectors[INODE_DIRECT_BLOCKS];	/* Direct block sectors. */
    block_sector_t indirect_block_sector;						/* Indirect block sector. */
    block_sector_t doubly_indirect_block_sector; 				/* Doubly indirect block sector. */
};

struct indirect_block_sector
{
    block_sector_t direct_block_sectors[INODE_INDIRECT_BLOCKS];	/* Indirect block sectors. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

static void
inode_print(struct inode *inode)
{
	struct inode_disk *id = malloc(sizeof(struct inode_disk));
	cache_read(inode->sector, id, 0, sizeof(struct inode_disk));

	printf("INODE STATS FOR INODE %u --------------------------------------------\n", inode->sector);	
	printf("INODE TYPE: %u\n", (unsigned) id->type);
	printf("INODE LEGNTH: %i\n", id->length);
	printf("INODE SECTOR COUNT: %u\n", id->sector_count);
	printf("INODE DIRECT BLOCK SECTORS: ");

	unsigned i;
	for(i = 0; i < INODE_DIRECT_BLOCKS; i++)
	{
		printf(" | %u : %u", i, id->direct_block_sectors[i]);
	}

	printf("\nINODE INDIRECT BLOCK SECTOR: %u\n", id->indirect_block_sector);
	printf("INODE DOUBLY INDIRECT BLOCK SECTOR: %u\n", id->doubly_indirect_block_sector);

}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
	ASSERT (inode != NULL);

	block_sector_t block_sector = -1;

	if (pos < inode_length(inode))
	{
		/* block sector offset */
		off_t offset = pos / BLOCK_SECTOR_SIZE;

		/* local copy of disks inode */
		struct inode_disk* id = malloc(sizeof(struct inode_disk));
		cache_read(inode->sector, id, 0, sizeof(struct inode_disk));

		/* read from direct block sector */
		if(offset < INODE_DIRECT_BLOCKS)
		{
			block_sector = id->direct_block_sectors[offset];
			//if(INODE_DEBUG) printf("INODE: offset %i in inode %u leads to direct block sector %u\n", pos, inode->sector, block_sector);
		}

		/* read from indirect block sector */
		else if (offset < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS)
		{
			off_t indirect_offset = offset - INODE_DIRECT_BLOCKS;
			cache_read(id->indirect_block_sector, (void *) &block_sector,
					indirect_offset * sizeof(block_sector_t), sizeof(block_sector_t));
			
			//if(INODE_DEBUG) printf("INODE: offset %i in inode %u leads to indirect block sector %u\n", pos, inode->sector, block_sector);
		}

		/* read from doubly indirect block sector */
		else if (offset < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS + INODE_DOUBLY_DIRECT_BLOCKS)
		{
			/* entry count of all doubly indirect sector blocks */
			unsigned entry_cnt = offset - (INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS);

			/* internal offsets */
			off_t doubly_indirect_offset = entry_cnt / INODE_INDIRECT_BLOCKS;
			off_t indirect_offset = entry_cnt % INODE_DIRECT_BLOCKS;

			/* fetch indirect block sector */
			cache_read(id->doubly_indirect_block_sector, (void *) &block_sector,
					doubly_indirect_offset * sizeof(block_sector_t), sizeof(block_sector_t));

			/* fetch block sector */
			cache_read(block_sector, (void *) &block_sector,
					indirect_offset * sizeof(block_sector_t), sizeof(block_sector_t));
			
			//if(INODE_DEBUG) printf("INODE: offset %i in inode %u leads to doubly indirect block sector %u\n", pos, inode->sector, block_sector);

		}
		else
			ASSERT(false);

		free(id);
	}

	return block_sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}


/* add sector block_sector to inode inode */
static void
inode_add_block(struct inode* inode, block_sector_t block_sector)
{
	ASSERT(lock_held_by_current_thread(&inode->lock));

	//if(INODE_DEBUG && INODE_PRINT) inode_print(inode);
	
	/* local copy of disks inode */
	struct inode_disk* id = malloc(sizeof(struct inode_disk));
	cache_read(inode->sector, id, 0, sizeof(struct inode_disk));

	/* direct block sectors */
	if(id->sector_count < INODE_DIRECT_BLOCKS)
	{
		if(INODE_DEBUG) printf("INODE: adding block %u to direct block sectors of %u @ position %u\n", block_sector, inode->sector, id->sector_count);

		/* add to direct blocks */
		id->direct_block_sectors[id->sector_count] = block_sector;
	}

	/* indirect block sector */
	else if (id->sector_count < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS)
	{
		if(INODE_DEBUG) printf("INODE: adding block %u to indirect block sector of %u\n", block_sector, inode->sector);

		/* offset in indirect list */
		off_t offset = id->sector_count - INODE_DIRECT_BLOCKS;

		/* create indirect block if this is
		 * the first element in the indirect list */
		if(offset == 0)
		{
			/* empty block */
			void *zero = malloc(BLOCK_SECTOR_SIZE);

			/* create indirect block */
			block_sector_t indirect_bs;
			free_map_allocate (1, &indirect_bs);

			/* save to disks inode */
			id->indirect_block_sector = indirect_bs;

			/* write back empty indirect sector */
			cache_write(indirect_bs, zero, 0, BLOCK_SECTOR_SIZE);
		}

		ASSERT(id->indirect_block_sector != 0);

		/* add sector to indirect sector list */
		cache_write(id->indirect_block_sector, (void *) &block_sector,
				offset * sizeof(block_sector_t), sizeof(block_sector_t));
	}

	/* doubly indirect sector */
	else if (id->sector_count < INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS + INODE_DOUBLY_DIRECT_BLOCKS)
	{
		if(INODE_DEBUG) printf("INODE: adding block %u to doubly indirect block sector of %u\n", block_sector, inode->sector);

		/* count of all doubly indirect block sectors */
		off_t entry_cnt = id->sector_count - (INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS);

		/* offset in the doubly indirect list */
		off_t offset_doubly_indirect = entry_cnt / INODE_INDIRECT_BLOCKS;

		/* offset in the indirect list */
		off_t offset_indirect = entry_cnt % INODE_INDIRECT_BLOCKS;

		/* create doubly indirect block if this is
		 * the first element in the doubly indirect list */
		if(entry_cnt == 0)
		{
			/* empty block */
			void *zero = malloc(BLOCK_SECTOR_SIZE);

			/* create doubly indirect block sector */
			block_sector_t di_block_sector;
			free_map_allocate (1, &di_block_sector);

			/* save to disks inode */
			id->doubly_indirect_block_sector = di_block_sector;

			/* write back empty indirect sector */
			cache_write(di_block_sector, zero, 0, BLOCK_SECTOR_SIZE);
		}

		/* create indirect block sector if this is the first entry */
		if(offset_indirect == 0)
		{
			/* empty block */
			void *zero = malloc(BLOCK_SECTOR_SIZE);

			/* create indirect block sector */
			block_sector_t indirect_block_sector;
			free_map_allocate (1, &indirect_block_sector);

			/* initialize empty indirect block sector */
			cache_write(indirect_block_sector, zero, 0, BLOCK_SECTOR_SIZE);

			/* save indirect block sector to doubly indirect block sector */
			cache_write(id->doubly_indirect_block_sector, (void *) indirect_block_sector,
					offset_doubly_indirect * sizeof(block_sector_t), sizeof(block_sector_t));
		}

		ASSERT(id->doubly_indirect_block_sector != 0);

		/* fetch indirect block sector number */
		block_sector_t indirect_block_sector;
		cache_read(id->doubly_indirect_block_sector, (void *) &indirect_block_sector,
				offset_doubly_indirect * sizeof(block_sector_t), sizeof(block_sector_t));

		ASSERT(indirect_block_sector != 0);

		/* add block sector number to indirect block sector */
		cache_write(indirect_block_sector, (void *) &block_sector, offset_indirect, sizeof(block_sector_t));
	}
	else
	{
		/* something went horribly wrong. */
		ASSERT(false);
	}

	/* increment sector count and write back */
	id->sector_count++;
	cache_write(inode->sector, (void *) id, 0, BLOCK_SECTOR_SIZE);

	free(id);

	//if(INODE_DEBUG && INODE_PRINT) inode_print(inode);
}

/* extend inode at sector sector with length bytes */
static bool
inode_extend (struct inode* inode, off_t ext_length)
{
	if(INODE_DEBUG || FILE_DEBUG) printf("INODE: extending inode %u by %i bytes\n", inode->sector, ext_length);

	lock_acquire(&inode->lock);

	bool success = true;

	/* local copy of disk inode */
	struct inode_disk* id = malloc(sizeof(struct inode_disk));
	cache_read(inode->sector, id, 0, sizeof(struct inode_disk));

	/* free space left in bytes */
	off_t free_space = id->sector_count * BLOCK_SECTOR_SIZE - id->length;

	/* needed sectors */
	size_t sectors = bytes_to_sectors (ext_length - free_space);

	/* add sector to inode */
	unsigned i;
	block_sector_t block_sector;
	for(i = 0; i < sectors; i++)
	{
		/* allocate one vector at a time */
		if(free_map_allocate (1, &block_sector))
		{
			/* add new block to inode */
			inode_add_block(inode, block_sector);
		}
		/* not enough space on disk - abort */
		else
		{
			printf("INODE: that should not happen.\n");
			success = false;
			break;
		}
	}

	if(!success)
	{
		/* TODO cleanup allocated space? */
		ASSERT(false);
	}

	/* increment length and write back */
	id->length += ext_length;
	cache_write(inode->sector, (void *) &id->length, INODE_OFFSET_LENGTH, 4);

	lock_release(&inode->lock);
	
	if(INODE_DEBUG || FILE_DEBUG) printf("INODE: completetd extending inode %u by %i bytes : %u\n", inode->sector, ext_length, (unsigned)success);

	return success;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, enum file_t file_type)
{
	if(INODE_DEBUG || FILE_DEBUG) printf("INODE: creating inode for sector %u with inital size %i\n", sector, length);

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL)
	{

		disk_inode->length = 0;
		disk_inode->sector_count = 0;
		disk_inode->magic = INODE_MAGIC;
		disk_inode->type = file_type;

		/* create empty file */
		cache_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);

		/* open the file */
		struct inode* inode = inode_open(sector);

		/* extend file by length bytes */
		inode_extend(inode, length);
	
		/* close file */
		inode_close(inode);

		/* free space */
		free (disk_inode);

		success = true;
    }

	return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
	if(INODE_DEBUG || FILE_DEBUG) printf("INODE: opening inode %u\n", sector);

  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}


/* Returns INODE's type. */
enum file_t
inode_get_filetype(const struct inode *inode)
{
	/* fetch file type from disk */
	enum file_t filetype = FILE;
	cache_read(inode->sector, &filetype, INODE_OFFSET_TYPE, sizeof(enum file_t));

	return filetype;
}

/* truncates the inode to length 0 */
static void
inode_truncate (struct inode *inode)
{
	if(INODE_DEBUG) printf("INODE: inode %u is beeing truncated\n", inode->sector);

	ASSERT(lock_held_by_current_thread(&inode->lock));

	/* local copy of disks inode */
	struct inode_disk* id = malloc(BLOCK_SECTOR_SIZE);
	cache_read(inode->sector, id, 0, BLOCK_SECTOR_SIZE);

	/* if there is a block left */
	if(id->sector_count > 0)
	{
		/* delete all doubly indirect block sectors */
		if(id->sector_count > INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS)
		{
			ASSERT(id->sector_count <= INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS + INODE_DOUBLY_DIRECT_BLOCKS);

			/* fetch doubly indirect block sector */
			struct indirect_block_sector *doubly_indirect_bs = malloc(BLOCK_SECTOR_SIZE);
			cache_read(id->doubly_indirect_block_sector, doubly_indirect_bs, 0, BLOCK_SECTOR_SIZE);

			/* doubly indirect blocks */
			unsigned di_length = id->sector_count - (INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS);
			off_t di_offset;

			/* delete every indirect block listed */
			while(di_length > 0)
			{
				/* doubly indirect block offset */
				di_offset = di_length / INODE_INDIRECT_BLOCKS;

				/* fetch indirect block sector */
				struct indirect_block_sector *indirect_bs = malloc(BLOCK_SECTOR_SIZE);
				cache_read(doubly_indirect_bs->direct_block_sectors[di_offset], indirect_bs,
						0, BLOCK_SECTOR_SIZE);

				/* number of entries in indirect block sector */
				unsigned entry_cnt = di_length;
				if(entry_cnt > INODE_INDIRECT_BLOCKS) { entry_cnt = entry_cnt % INODE_INDIRECT_BLOCKS; }

				/* release every block sector registered */
				unsigned i;
				block_sector_t entry;
				for(i = 0; i < entry_cnt; i++)
				{
					/* fetch block sector number */
					entry = indirect_bs->direct_block_sectors[i];

					/* release block sector */
					free_map_release (entry, 1);
				}

				/* decrement length */
				di_length -= entry_cnt;
			}

			ASSERT(di_length == 0);

			/* only indirect and direct block sectors are left */
			id->sector_count = INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS;
		}

		/* delete all indirect block sectors */
		if(id->sector_count > INODE_DIRECT_BLOCKS)
		{
			ASSERT(id->sector_count <= INODE_DIRECT_BLOCKS + INODE_INDIRECT_BLOCKS);

			/* internal count */
			unsigned cnt = id->sector_count - INODE_DIRECT_BLOCKS;

			/* fetch indirect block sector */
			struct indirect_block_sector *indirect_bs = malloc(BLOCK_SECTOR_SIZE);
			cache_read(id->indirect_block_sector, indirect_bs, 0, BLOCK_SECTOR_SIZE);

			/* release every block sector registered */
			unsigned i;
			block_sector_t entry;
			for(i = 0; i < cnt; i++)
			{
				/* fetch block sector number */
				entry = indirect_bs->direct_block_sectors[i];

				/* release block sector */
				free_map_release (entry, 1);
			}
		}

		ASSERT(id->sector_count <= INODE_DIRECT_BLOCKS);

		/* delete direct block sectors */
		unsigned i;
		block_sector_t entry;
		for(i = 0; i < id->sector_count; i++)
		{
			/* fetch block sector number */
			entry = id->direct_block_sectors[i];

			/* release block sector */
			free_map_release (entry, 1);
		}

		/* save counter to inode */
		id->sector_count = 0;
		id->length = 0;

		/* writeback inode */
		cache_write(inode->sector, (void *) id, 0, BLOCK_SECTOR_SIZE);
	}
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
	if(INODE_DEBUG || FILE_DEBUG) printf("INODE: closing inode %u \n", inode->sector);
	if(INODE_PRINT) inode_print(inode);

	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0)
	{
		lock_acquire(&inode->lock);

		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed)
		{
			if(INODE_DEBUG) printf("INODE: removing inode %u\n", inode->sector);

			/* truncate inode to size 0 */
			inode_truncate(inode);

			/* release inode */
			free_map_release (inode->sector, 1);
		}

		lock_release(&inode->lock);

		free (inode);
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
	if(INODE_DEBUG) printf("INODE: reading inode %u @ offset %i into buffer %x. Size: %i bytes\n", inode->sector, offset, (unsigned) buffer_, size);

	void *buffer = buffer_;
	off_t bytes_read = 0;

	while (size > 0)
	{
		/* Disk sector to read, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector (inode, offset);
	
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* legal sector found */
		if(sector_idx != (block_sector_t) -1)
		{
			/* Bytes left in inode, bytes left in sector, lesser of the two. */
			off_t inode_left = inode_length (inode) - offset;
			int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
			int min_left = inode_left < sector_left ? inode_left : sector_left;

			/* Number of bytes to actually copy out of this sector. */
			int chunk_size = size < min_left ? size : min_left;
			if (chunk_size <= 0)
				break;

			/* read chunk from cache */
			cache_read(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);

			/* Advance. */
			size -= chunk_size;
			offset += chunk_size;
			bytes_read += chunk_size;
		}
		else
		{
			/* EOF reached. */
			if(INODE_DEBUG) printf("INODE: end of file\n");
			break;
		}
	}

	if(INODE_DEBUG) printf("INODE: %i bytes read\n", bytes_read);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
	if(INODE_DEBUG) printf("INODE: writing inode %u @ offset %i from buffer %x. Size: %i bytes\n", inode->sector, offset, (unsigned) buffer_, size);

	const void *buffer = buffer_;
	off_t bytes_written = 0;

	if (inode->deny_write_cnt)
		return 0;

	/* current inode size */
	off_t length = inode_length (inode);

	/* space left in last sector */
	off_t space_left = BLOCK_SECTOR_SIZE - length % BLOCK_SECTOR_SIZE;
	if(space_left == BLOCK_SECTOR_SIZE)
		space_left = 0;

	/* add block sectors if needed */
	if(offset + size > length)
	{
		/* extend file */
		ASSERT(inode_extend (inode, offset + size - length));
	
		/* update length */
		length += offset + size;
	}

/*	
	bool findSomething = false;
	if(offset == 29241) {
		findSomething = true;
		printf("START findSomething DEBUG MODE\n");
	}
*/
	/* write to file */
	while (size > 0)
	{
		//if(findSomething) printf("LOOP\n");
	
		/* Sector to write, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		//if(findSomething) printf("a\n");
		
		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = length - offset;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		//if(findSomething) printf("chunk size: %i\n", chunk_size);
		//if(findSomething) printf("cache_write(sector %u, buffer %u, sector offset %i, chunk size %i\n", sector_idx, (unsigned) buffer + bytes_written, sector_ofs, chunk_size);
		
		/* write chunk to cache */
		cache_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);
	
		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
    }

	//if(findSomething) printf("Bytes written: %u\n", bytes_written);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
	off_t file_length;

	/* read cache and save file length to file_length */
	cache_read (inode->sector, (void *)(&file_length), INODE_OFFSET_LENGTH, sizeof(off_t));

	return file_length;
}
