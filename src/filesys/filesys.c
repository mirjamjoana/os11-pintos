#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h" 

#define DEBUG_FILESYS 0

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
	fs_device = block_get_role(BLOCK_FILESYS);

	if (fs_device == NULL)
		PANIC ("No file system device found, can't initialize file system.");

	inode_init();
	free_map_init();
	cache_init();

	if (format)
		do_format();

	free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
	cache_flush();
	free_map_close ();
}

/* Search for file name in directory tree.
 * Returns file if successful, NULL otherwise. */
static struct file*
filesys_get_file (const char *name)
{
	/* check and fetch path and file name */
	char *path = NULL;
	char *file = NULL;
	dir_get_path_and_file(name, path, file);

	/* fetch target dir */
	struct dir *target_dir = dir_getdir(path);

	/* if target dir exists look for file */
	if(target_dir != NULL)
	{
		/* fetch file */
		struct inode *file_inode = NULL;
		dir_lookup(target_dir, file, &file_inode);

		/* close directory and return file */
		dir_close (target_dir);
		return file_open (file_inode);
	}
	return NULL;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum file_t type) 
{
	if(DEBUG_FILESYS) printf("FILESYS: creating %s %s with initial size %i\n", type == FILE ? "file" : "directory", name, initial_size);

	bool success = false;
	char *path = NULL;
	char *file_name = NULL;

	/* split up path in file name and path */
	if(name != NULL && dir_get_path_and_file(name, path, file_name))
	{
		/* fetch parent directory */
		struct dir *parent = dir_getdir(path);
		struct inode *parent_inode = dir_get_inode(parent);

		/* if parent exists and name is ok */
		if(parent != NULL)
		{
			/* allocate disk sector */
			block_sector_t sector;
			ASSERT(free_map_allocate(1, &sector));

			if(type == DIRECTORY)
			{
				/* create dir */
				ASSERT(dir_create(sector, parent_inode->sector));
			}
			else
			{
				/* create file */
				ASSERT(inode_create(sector, parent_inode->sector, FILE));
			}

			/* save file/dir to parent dir */
			dir_add(parent, file_name, sector);

			/* close parent */
			dir_close(parent);
			success = true;
		}

		/* free resources */
		free(path);
		free(file_name);
	}

	return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
	if(DEBUG_FILESYS) printf("FILESYS: opening %s\n", name);

	return filesys_get_file(name);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
	if(DEBUG_FILESYS) printf("FILESYS: removing %s\n", name);

	/* TODO check if directory */
	struct file *file = filesys_open(name);
	struct inode * my_inode = file_get_inode (file);
	enum file_t type = inode_get_filetype (my_inode);

	if (type == DIRECTORY) {
		/* check and fetch path and file name */
		char *path = NULL;
		char *file = NULL;
		bool success = dir_get_path_and_file(name, path, file);
		if (!success) return false;
		
		//get the correct dir
		struct dir *dir = dir_getdir(path);

		/* get sectors of given directory, root and current working director */
		block_sector_t sector = my_inode->sector;
		block_sector_t temp1 = file_get_inode((void *)(thread_current()->working_dir))->sector;
		block_sector_t temp2 = file_get_inode((void *)dir_open_root())->sector;

		/* check whether this is an attempt to delete the current or root directory */
		if (sector == temp1 || sector == temp2) {
			return false;
		}
		else {
			/* check if directory is empty */
			bool success = dir != NULL && dir_isempty (dir);
			if (!success) {
				dir_close(dir);
				return false;
			}
			/* is it still opened? */
			if (my_inode->open_cnt > 1) return false;
			else /* TODO loeschen */ return true;
		}
	}
	else {
		/* TODO alter Code */
		struct dir *dir = dir_open_root ();
		bool success = dir != NULL && dir_remove (dir, name);
		dir_close (dir);

		return success;
	}
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();

  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
