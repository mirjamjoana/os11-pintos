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
	if(DEBUG_FILESYS) printf("FILESYS: init\n");

	fs_device = block_get_role(BLOCK_FILESYS);

	if (fs_device == NULL)
		PANIC ("No file system device found, can't initialize file system.");

	inode_init();
	free_map_init();
	cache_init();
	
	/* setting main threads working directory to root */
	thread_current()->working_dir = dir_open_root();

	if (format)
		do_format();

	free_map_open();

	if(DEBUG_FILESYS) printf("FILESYS: set thread {%s} working dir to %u\n", thread_current()->name, thread_current()->working_dir->inode->sector);

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
	if(name == NULL || strlen(name) == 0)
		return NULL;

	/* check and fetch path and file name */
	char *path = NULL;
	char *file = NULL;
	dir_get_path_and_file(name, &path, &file);

	if(DEBUG_FILESYS) printf("FILESYS: dir path: {%s} dir name: {%s}\n", path, file);
	if(DEBUG_FILESYS) printf("FILESYS: thread {%s} working dir: {%u}\n",thread_current()->name, thread_current()->working_dir->inode->sector);

	/* fetch target dir */
	struct dir *target_dir = path == NULL ? dir_reopen(thread_current()->working_dir) : dir_getdir(path);

	if(DEBUG_FILESYS) printf("FILESYS: dir = %u\n", target_dir->inode->sector);

	/* if target dir exists look for file */
	if(target_dir != NULL)
	{
		/* file is directory itself */
		if(strcmp(file, "") == 0)
		{
			return file_open(target_dir->inode);
		}
		
		/* fetch file */
		struct inode *file_inode = NULL;
		dir_lookup(target_dir, file, &file_inode);

		/* close directory and return file */
		dir_close (target_dir);
		return file_open(file_inode);
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

	/* name can only be NAME_MAX long */
	if(strlen(name) > NAME_MAX)
		return false;
	
	/* if name is not null nor emptry and well formated */
	if(name != NULL && strcmp(name, "") != 0 && dir_get_path_and_file(name, &path, &file_name))
	{
		/* fetch parent directory */
		struct dir *parent;
		
		/* fetch parent */
		if(path == NULL)
			parent = dir_reopen(thread_current()->working_dir);
		else
			parent = dir_getdir(path);

		struct inode *parent_inode = dir_get_inode(parent);

		/* check if element is existing */
		struct inode* existence_check;

		/* if parent exists and name is ok */
		if(parent != NULL && !dir_lookup(parent, name, &existence_check))
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
				ASSERT(inode_create(sector, initial_size, FILE));
			}

			/* save file/dir to parent dir */
			dir_add(parent, file_name, sector);
			success = true;
		}
		else
		{
			/* close inode again */
			inode_close(existence_check);
		}
		
		/* close parent */
		dir_close(parent);
		
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

	/* fetch file */
	struct file *file = filesys_open(name);

	/* if no file / directory with the given name can be found, abort. */
	if(file == NULL)
		return false;

	bool success = false;

	/* get parent directory */
	char *parent_path;
	char *file_path;
	dir_get_path_and_file(name, &parent_path, &file_path);	
	
	/* if parent path is empty, use the working dir as parent */
	struct file *parent_file;
	if(strcmp(parent_path, "") == 0)
		parent_file = file_open(thread_current()->working_dir->inode);
	else
	 	parent_file = filesys_open(parent_path);

	ASSERT(inode_get_filetype(parent_file->inode) == DIRECTORY);

	/* init temp parent dir */
	struct dir parent;
	parent.inode = parent_file->inode;
	parent.pos = parent_file->pos;

	struct inode * my_inode = file_get_inode(file);
	enum file_t type = inode_get_filetype(my_inode);

	if (type == DIRECTORY) 
	{
		if(DEBUG_FILESYS) printf("FILESYS: removing directory %s @ sector %u\n", name, file->inode->sector);
		/* create temp dir */
		struct dir temp_dir;
		temp_dir.inode = my_inode;
		temp_dir.pos = 0;

		/* get sectors of given directory, root and current working director */
		block_sector_t sector = my_inode->sector;
		block_sector_t work_dir_sec = thread_current()->working_dir->inode->sector;
		block_sector_t root_sec = dir_open_root()->inode->sector;

		/* check whether this is an attempt to delete the current or root directory */
		if (sector == work_dir_sec || sector == root_sec)
		{	
			if(DEBUG_FILESYS) printf("FILESYS: cannot remove {%s} - root / working dir\n", name);
			return false;
		}
		else 
		{
			/* check if directory is empty */
			if(dir_isempty(&temp_dir) && temp_dir.inode->open_cnt <= 1)
			{
				/* delete link from parent */
				ASSERT(dir_remove(&parent, file_path));

				/* free resources */
				inode_remove(file->inode);
				success = true;
			}
			else
			{
				if(DEBUG_FILESYS) printf("FILESYS: DIR NOT EMPTY %s open count: %u\n", name, temp_dir.inode->open_cnt);
			}
		}
	}
	else
	{	
		if(DEBUG_FILESYS) printf("FILESYS: removing file %s\n", name);
		ASSERT(dir_remove(&parent, file_path));
		inode_remove(file->inode);
		success = true;
	}
	
	/* close files */
	file_close(file);
	file_close(parent_file);

	if(DEBUG_FILESYS) printf("FILESYS: remove {%s} %s successful\n", name, success ? "" : "not");

	return success;
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
