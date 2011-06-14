#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/palloc.h"
#include <hash.h>
#include "filesys/file.h"

#define STACK_GROW_LIMIT 8 /* stack grow max 32 bytes at once (8 x 32 bit)*/

/*
 * The supplemental page table is used for at least two purposes.
 * Most importantly, on a page fault, the kernel looks up the virtual
 * page that faulted in the supplemental page table to find out what
 * data should be there. Second, the kernel consults the supplemental
 * page table when a process terminates, to decide what resources to
 * free.
 *
 * - save hash value in virtual address part of the pte
 */

/* info about the file on disk OR page on swap disk */
struct sup_pte
{
	struct hash_elem elem; /* the hash element */

	bool swap;			/* 1 => swap, 0 => disk */
	struct file * f;			/* file / page link */
	uint32_t offset; 	/* internal file offset */
	uint32_t length; 	/* size of the file contents */
};

/* standard page allocation and release */
void *get_user_page (enum palloc_flags);
void *get_multiple_user_pages (enum palloc_flags, size_t page_cnt);
void free_user_page (void * page);
void free_multiple_user_pages (void * pages, size_t page_cnt);

/* page destructor */
void destroy_user_pages(void);

/* lazy allocation */
void *create_lazy_user_pages (struct file* file, uint32_t offset, uint32_t length);

/* stack grow methods */
bool is_legal_stack_growth (void **esp);
void grow_stack (void **esp);

bool install_user_page (void *upage, void *kpage, bool writable);

#endif
