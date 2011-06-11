#include "vm/page.h"
#include "vm/frame.h"
#include "threads/palloc.h"
#include <debug.h>
#include "threads/vaddr.h"
#include "threads/thread.h"

/* supplemental page table */

void *get_user_page(enum palloc_flags flags) {
	return get_user_frame(flags);
}

void *get_multiple_user_pages(enum palloc_flags flags, size_t page_cnt){
	return get_user_frames(flags, page_cnt);
}

void free_user_page(void * page){
	return palloc_free_page(page);
}

void free_multiple_user_pages(void * pages, size_t page_cnt){
	return palloc_free_multiple(pages, page_cnt);
}

void *create_lazy_user_page (struct file* file UNUSED, uint32_t offset UNUSED, uint32_t length UNUSED) {
	return NULL;
}

static bool
is_legal_stack_growth (void **esp)
{	
	bool success = false;
	struct thread *current_thread = thread_current();
	/* checks whether there is enough space left (less than 8MB occupied) */
	if ((PHYS_BASE - *esp) > 800000) {
		current_thread->exit_status = -1;
		thread_exit();
	}

	/* check whether it is an illegal push operation (more than 32 bytes beyond (PHYS_BASE - 8MB)) */
	if ( (*esp - 20) < (PHYS_BASE - 800000 )) {
		current_thread->exit_status = -1;
		thread_exit();
	}

	uint8_t *kpage;
	kpage = get_user_page (PAL_ZERO);
	if (kpage != NULL) 
	  {
	    success = install_page (((uint8_t *) *esp) - PGSIZE, kpage, true);
	    if (success)
		*esp = *esp + PGSIZE;
	    else
	    	free_user_page (kpage);
	  }
	return success;
 	
}
