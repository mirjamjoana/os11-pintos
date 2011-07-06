#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#define DIR_DEBUG 0

static char* string_self = ".";
static char* string_parent = "..";

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, block_sector_t parent)
{
	if(DIR_DEBUG) printf("DIR: creating dir @ sector %u with NO entries\n", sector /*, entry_cnt*/);
	bool success = true;
	struct dir new_dir;

	/* create empty directory */
	success &= inode_create (sector, 0, DIRECTORY);

	/* open dirs inode */
	new_dir.inode = inode_open(sector);
	new_dir.pos = 0;

	/* add "." and ".." to dir */
	success &= dir_add(&new_dir, string_self, sector);
	success &= dir_add(&new_dir, string_parent, parent);

	return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
	if(DIR_DEBUG) printf("DIR: opening dir @ sector NA\n");

  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
	if(DIR_DEBUG) printf("DIR: opening root dir @ sector %u\n", ROOT_DIR_SECTOR);
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
	if(DIR_DEBUG) printf("DIR: closing dir\n");
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
	if(DIR_DEBUG) printf("DIR: looking up file %s in dir ... \n", name);

	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
	   ofs += sizeof e)
	{
		if (e.in_use && !strcmp (name, e.name))
		{
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			if(DIR_DEBUG) printf("DIR: file %s found.\n", name);
				return true;
		}
	}
  
	if(DIR_DEBUG) printf("DIR: file %s NOT found.\n", name);
	return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
	if(DIR_DEBUG) printf("DIR: adding file/dir %s @ sector %u to dir \n", name, inode_sector);
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;


  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

 if(DIR_DEBUG) printf("DIR: searching a free slot\n");
 
  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  if(DIR_DEBUG) printf("DIR: write to free slot\n");

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  if(DIR_DEBUG) printf("DIR: creating %s successfull.\n", success ? " " : "not");
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
	if(DIR_DEBUG) printf("DIR: removing file %s from dir %u\n", name, dir->inode->sector);
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
	if(DIR_DEBUG) printf("DIR: reading dir\n");
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

/* Splits up dir_path and saves the corresponding parts into
 * path and dir name. Returns true if legal, false if not. */
bool
dir_get_path_and_file (const char * dir_path, char* path, char* name)
{
	if(DIR_DEBUG) printf("DIR: splitting up path in name and path: %s\n", dir_path);

	/* path can only look like this:
	 *
	 * a) absolute:
	 * 		1) /c
	 * 		2) /c/
	 * 		1) /b/c
	 * 		2) /b/c/
	 *
	 * b) relative:
	 * 		1) c
	 * 		2) c/
	 * 		3) b/c
	 * 		4) b/c/
	 * */

	size_t dir_path_len = strlen(dir_path);

	/* create local copy of dir_path */
	char* local_copy = malloc(dir_path_len + 1);
	strlcpy(local_copy, dir_path, dir_path_len);

	/* delete last character if its '/' */
	if((size_t) strrchr(local_copy, '/') == dir_path_len){
		local_copy[dir_path_len] = 0x0;
	}

	/* path can now only look like this:
	 *
	 * a) absolute:
	 * 		1) /c
	 * 		1) /b/c
	 *
	 * b) relative:
	 * 		1) c
	 * 		3) b/c
	 * */

	/* get path/dir separator */
	char *seperator = strrchr(local_copy, '/');

	/* relative, no path */
	if(seperator == NULL)
	{
		path = NULL;
		name = local_copy;

		if(DIR_DEBUG) printf("DIR: split up path in name and path - path : {}, name : {%s}\n", name);

		return true;
	}

	/* absolute, no path (=root) */
	else if(seperator == local_copy)
	{
		path = malloc(2);
		*path = '/';
		*(path + sizeof(char)) = 0x0;

		name = malloc(dir_path_len);
		strlcpy(name, dir_path + sizeof(char), dir_path_len - 1);

		if(DIR_DEBUG) printf("DIR: split up path in name and path - path : {%s}, name : {%s}\n", path, name);
	}

	/* everything else */
	else
	{
		/* save path */
		unsigned path_len = seperator - local_copy;
		path = malloc(path_len + 1);
		strlcpy(path, local_copy, path_len);

		/* save dir name */
		unsigned name_len = dir_path_len - (seperator - local_copy);
		name = malloc(name_len + 1);
		strlcpy(name, seperator + 1, name_len);

		if(DIR_DEBUG) printf("DIR: split up path in name and path - path : {%s}, name : {%s}\n", path, name);
	}

	free(local_copy);
	return true;
}

/* Opens directory at path. Returns directory on success, NULL on failure.
 * User has to close dir. */
struct dir*
dir_getdir(const char *path)
{
	struct dir* current_dir;
	unsigned path_len = strlen(path);

	/* check if path is relative or absolute */
	if(path[0] == '/')
		current_dir = dir_open_root();
	else
		current_dir = dir_reopen(thread_current()->working_dir);

	/* create local copy of dir_path */
	char* path_copy = malloc(path_len + 1);
	strlcpy(path_copy, path, path_len);

	/* traverse directory tree */

	/* char s[] = "  String to  tokenize. "; */
	char *next, *save_ptr;
	struct inode* next_inode = NULL;

	if(DIR_DEBUG) printf("DIR: traversing directory\n");

	for (next = strtok_r (path_copy, "/", &save_ptr); next != NULL;
			next = strtok_r (NULL, "/", &save_ptr))
	{
		/* found next directory */
		if(dir_lookup(current_dir, next, &next_inode))
		{
			/* switch to next directory */
			current_dir = dir_open(next_inode);
			dir_close(current_dir);
		}
		/* directory not found -> abort */
		else
		{
			if(DIR_DEBUG) printf("DIR: traversed directory: FAIL.\n");

			dir_close(current_dir);
			return NULL;
		}
	}

	if(DIR_DEBUG) printf("DIR: traversed directory: success.\n");

	/* return last directory */
	return current_dir;
}

/* Returns true iff "." and ".." are the only inhabitants of dir */
bool
dir_isempty (struct dir* dir) {
	struct dir_entry e;
	struct inode *inode = NULL;

	/* Open inode. */
  	inode = inode_open (e.inode_sector);

	char * temp = (char *)malloc(sizeof(char) * (NAME_MAX + 1) );
    struct dir * dirtemp = dir_open(inode);

	//is dir empty?
    if (dir_readdir(dirtemp,temp)) {
    	free(temp);
        dir_close(dirtemp);
        return false;
	}
	else return true;

}