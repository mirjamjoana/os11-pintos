#include "vm/page.h"
#include "vm/frame.h"
#include "threads/palloc.h"
#include <debug.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"


void *
get_multiple_user_pages(enum palloc_flags flags, size_t page_cnt)
{
	/* allocate user frame */
	return alloc_user_frames(flags, page_cnt);
}


void *
get_user_page(enum palloc_flags flags)
{
	return get_multiple_user_pages(flags, 1);
}


void
free_multiple_user_pages(void * pages, size_t page_cnt)
{
	lock_acquire(&user_frames_lock);

	/* TODO check if pages are present */
	/* TODO present ? delete MM frame : delete SWAP frame */

	/* delete hash entry */
	unregister_frames(pages, page_cnt);

	palloc_free_multiple(pages, page_cnt);

	lock_release(&user_frames_lock);
}

void
free_user_page(void * page)
{
	free_multiple_user_pages(page, 1);
}


void
destroy_user_pages(void)
{
	/* TODO check swap memory for user frames */
	destroy_user_frames();
}

void *
create_lazy_user_pages (struct file* file UNUSED, uint32_t offset UNUSED, uint32_t length UNUSED)
{
	return NULL;
}


bool
is_legal_stack_growth (void **esp)
{	
	void *current_esp =  (void*) thread_current()->stack;

	if(current_esp - *esp < STACK_GROW_LIMIT)
		return true;

	return false;
}


void
grow_stack (void **esp)
{
	/* TODO check if new page is necessary */
	if(false /* new_page_necessary() */)
	{
		/* checks whether there is enough space left (less than 8MB occupied) */
		if ((PHYS_BASE - *esp) < 0x800000)
		{
			uint8_t *kpage;
			kpage = get_user_page (PAL_ZERO);

			if (kpage != NULL)
			{
				bool success = install_page (((uint8_t *) *esp) - PGSIZE, kpage, true);
				if (success)
					*esp = *esp + PGSIZE;
				else
					free_user_page (kpage);
			}
		}
	}
}

bool
install_user_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  register_frame(upage, kpage);

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


