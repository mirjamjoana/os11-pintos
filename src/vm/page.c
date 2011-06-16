#include <debug.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static bool install_lazy_user_page (void *upage, void *kpage, bool writable);
static struct sup_page *page_lookup (const void *address);

struct page *page_lookup_swap (const void *address, struct thread *);


//returns the name where the page is located
const char *
page_type_name (enum page_type type)
{
  static const char *page_type_names[3] =
    {
      "frame",
      "swap",
      "MMAP"
    };

  ASSERT (type < 3);
  return page_type_names[type];
}


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

	unsigned i;
	uint32_t * pte;
	

	/*
	for(i = 0; i < page_cnt; i++)
	{
		pte = get_pte(thread_current()->pagedir, (const void *) pages + i * PGSIZE);

		if(*pte & PTE_P)
		{

		}

	}
	 */

	/* delete hash entry */
	unregister_frames(pages, page_cnt);

	/* free pages */
	palloc_free_multiple(pages, page_cnt);

	/* cleanup page dir */
	for(i = 0; i < page_cnt; i++)
	{
		pagedir_clear_page(thread_current()->pagedir, pages);
	}

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

void
create_lazy_user_page (struct file* file, struct Elf32_Ehdr *ehdr)
{
	/* create sup pte */
	struct sup_page*  p = (struct sup_page *) malloc(sizeof(struct sup_page));

	p->f = file;
	p->isExec = true;
	p->swap = false;
	p->ehdr = ehdr;
	p->vaddr = (void *) (ehdr->e_entry & PTE_ADDR);

	/* insert into sup page table */
	ASSERT(hash_replace (&thread_current()->sup_page_table, &p->elem) == NULL);

	/* create page dir dummy pointing to first kernel page.
	 * ASSUMPTION: first kernel page is always zeroed */
	ASSERT(install_lazy_user_page(p->vaddr, PHYS_BASE, true));

	/* get page table entry */
	uint32_t *pte = get_pte(thread_current()->pagedir, p->vaddr);

	/* set present to false */
	*pte = *pte & ~PTE_P;

	/* set vaddress to eip */
	*pte = (*pte & PTE_FLAGS) | (ehdr->e_entry & PTE_ADDR);

}
 

bool
is_legal_stack_growth (void *fault_addr, void* esp)
{	
	if(DEBUG) printf("Check for legal stack growth. esp: %x - access at: %x\n", (uint32_t) esp, (uint32_t) fault_addr);
	
	uint32_t fault_ptr = (uint32_t) fault_addr;
	uint32_t stack_ptr = (uint32_t) esp;

	/* fault address under esp */
	if(fault_ptr <= stack_ptr)
	{
		if(DEBUG) printf("fault address under esp\n");
		/* max 32 byte */		
		return ((stack_ptr - fault_ptr) <= STACK_GROW_LIMIT);
	}
	/* fault address above esp */
	else
	{
		/* somewhere between first page and esp */
		return fault_ptr < (uint32_t)(PHYS_BASE - PGSIZE);
	}
}


bool
install_user_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  register_frame(upage, kpage);

  if(DEBUG) printf("Installing User Page: %x -> %x\n", (unsigned int) upage, (unsigned int) kpage);

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static bool
install_lazy_user_page (void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current ();

	if(DEBUG) printf("Installing Lazy User Page: %x -> %x\n", (unsigned int) upage, (unsigned int) kpage);

	/* Verify that there's not already a page at that virtual
	   address, then map our page there. */
	return (pagedir_get_page (t->pagedir, upage) == NULL
			&& pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Returns a hash value for frame f. */
unsigned
sup_page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct sup_page *p = hash_entry (p_, struct sup_page, elem);
  return hash_int ((int) (((unsigned int) p->vaddr) & PTE_ADDR));
}

/* Returns true if frame a precedes frame b. */
bool
sup_page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct sup_page *a = hash_entry (a_, struct sup_page, elem);
  const struct sup_page *b = hash_entry (b_, struct sup_page, elem);

  return ((unsigned int) a->vaddr & PTE_ADDR) < ((unsigned int) b->vaddr & PTE_ADDR);
}


/* finds hash entry and handles swap / load */
bool
find_and_load_page(void* vaddr)
{
	bool success = false;
	struct sup_page* p = page_lookup(vaddr);
	if(p != NULL)
	{
		/* complete initialization */
		if((unsigned int) p->vaddr == USER_CODE_START)
		{
			success = load_user_code_and_data(p->f, p->ehdr);
		}
		else if(p->swap)
		{
			/* swap in page */
		}
		else
		{
			/* load memory mapped page from file */
			success = load_mmap_data(p);
		}
	}

	if(DEBUG && !success) printf("did not find page");
	return success;
}


void
grow_stack (void *fault_addr)
{
	if(DEBUG) printf("growing stack for address %x\n", (unsigned int) fault_addr);

	/* checks whether there is enough space left (less than 8MB occupied) */
	if ((PHYS_BASE - fault_addr) < MAX_USER_STACK_SIZE)
	{
		lock_acquire(&user_frames_lock);

		uint8_t *kpage;
		kpage = get_user_page (PAL_ZERO);

		ASSERT (kpage != NULL);

		ASSERT (install_user_page (pg_round_down(fault_addr), kpage, true));

		lock_release(&user_frames_lock);
	}

}

/* hash search */
static struct sup_page *
page_lookup (const void *address)
{
  struct sup_page p;
  struct hash_elem *e;

  p.vaddr = (void *) ((unsigned int)address & PTE_ADDR);
  e = hash_find (&thread_current()->sup_page_table, &p.elem);
  return e != NULL ? hash_entry (e, struct sup_page, elem) : NULL;
}

<<<<<<< .mine
/* Returns the frame containing the given address,
   or a null pointer if no such page exists. */
struct page *
page_lookup_swap (const void *address, struct thread * t)
{
  struct page p;
  struct hash_elem *e;
  //make sure the address is aligned
  p.vaddr = (void *) ((unsigned int)address - (unsigned int)address % PGSIZE);
  e = hash_find (&t->sup_page_table, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}


//this function will swap a page from memory to frame
//this function just gets called from the running thread
void page_swap_out (void * vaddr) {

        struct page *cur;
        //get the page
        cur = page_lookup_swap(vaddr, thread_current());
        //look what kind of page it is
        switch (cur->type) {

        case (PAGE_FRAME):      //trigger a kernel panic this should not happen
                PANIC ("Userpage should be in frame table\n");
        case (PAGE_SWAP):       /* page is in swap so we have to pull it out and save it in a frame */
                {
                //get a free frame from the frame table         
                void * frame = (void *)get_frame();
                lock_acquire(&user_frames_lock);
                //swap the frame table and swap slot
                get_swap ((size_t)cur->paddr, frame);
                //set the variables in the page table
                cur->paddr = frame;
                cur->type=PAGE_FRAME;
                //reset the page table to the new physical address
                bool check = pagedir_set_page (thread_current()->pagedir, cur->vaddr, cur->paddr, cur->writable);
                ASSERT(check);
                lock_release(&user_frames_lock);
                }
                break;
                case (PAGE_MMAP): //load a page from a mmap file to the frame
                        {
                        void * kpage = (void *)get_frame();
                        lock_acquire(&user_frames_lock);
                
                        off_t offset = cur->offset;
                        off_t readbytes = cur->readbytes;

                        struct file * file = find_file(cur->mapid)->file;

                        if (file == NULL) printf("problem\n");

                        //set the correct offset that is hidden in paddr
                        file_seek (file, offset);

                        int val = 0;
                        if (readbytes > 0) val = file_read (file, kpage,readbytes);
               
                        //put in the newly allocated
                        if (pagedir_set_page (thread_current()->pagedir, cur->vaddr, kpage, cur->writable) == false) printf("couldnt put in page\n");
                        //set type to frame since it is loaded now      
                        cur->paddr = (void *)kpage;                     
                        cur->type = PAGE_FRAME;
                        //reset the dirty bit of the kpage since it wasn't really changed anything in the page
                        pagedir_set_dirty (thread_current()->pagedir, kpage, false);

                        lock_release(&user_frames_lock);
                        }
                        break;
                default:
                break;

        }
        //lock_release(&thread_current()->page_lock);
}

<<<<<<< .mine
//this function will swap a page from the frame table to the swap 
void page_swap_in (void * vaddr, struct thread * t) {
=======
void delete_lazy_mmap_page(void* upage)
{
	struct sup_page * page = page_lookup ((const void*) upage);

	hash_delete(&thread_current()->sup_page_table, &page->elem);
}

bool
load_mmap_data(struct sup_page* p)
{
	/* fetch information */
	struct file* file = p->f;
	uint32_t offset = p->offset;
	uint32_t length = p->length;
>>>>>>> .r139

        struct page *cur;

        cur = page_lookup_swap(vaddr, t);

        switch (cur->type) {

                case (PAGE_FRAME):
                        {
                        if(cur->mapid < 0) {
                                cur->paddr = (size_t *)add_swap(cur->paddr);
                                cur->type=PAGE_SWAP;
                        } else {
                                //we have a memory mapped file
                                off_t offset = cur->offset;
                                off_t writebytes = cur->readbytes;

                                if (pagedir_is_dirty (t->pagedir, cur->vaddr) || pagedir_is_dirty (t->pagedir, cur->paddr)) {
                                        //the file is a zero page from exec 
                                        if(cur->mapid == 2) {
                                                cur->paddr = (size_t *)add_swap(cur->paddr);
                                                cur->type=PAGE_SWAP;
                                                break;
                                        }

                                        struct file * file = find_file(cur->mapid)->file;
                
                                        if (file == NULL) printf("problem\n");

                                        //set the correct offset that is hidden in paddr
                                        file_seek (file, offset);

                                        if (file_write (file, cur->paddr, writebytes) != writebytes) {
                                                PANIC("Error writing to file");
                                        }
                                }       
                                cur->type = PAGE_MMAP;
                        }
                        }       
                        break;
                case (PAGE_SWAP):       /* shouldn't happen */
                        PANIC ("Page is already in swap\n");
                default:
                        break;
                }
                pagedir_clear_page (t->pagedir, cur->vaddr);
}

<<<<<<< .mine
//finds the virtual memory address for a physical one
//needed for page eviction in frame.c
void * get_vaddr_page (void * kpage, struct thread * t) {
=======
	if(DEBUG && len != size){
		printf("read: %u, size: %u\n", (uint32_t) len, (uint32_t) size);
	}
	ASSERT(install_user_page(upage, kpage, true));
>>>>>>> .r139

        //look through the frames in the table beginning at the end
        struct hash_iterator i;

        void * result = NULL;

        lock_acquire(&t->page_lock);

        hash_first (&i, t->page_table);
        while (hash_next (&i)) {
                struct page *p = hash_entry (hash_cur (&i), struct page, hash_elem);
                if (p->type == PAGE_FRAME && p->paddr == kpage) {
                        result = p->vaddr;
                        break;
                }
        }
        //make sure result is not NULL
        ASSERT(result);

        lock_release(&t->page_lock);

        return result;
}


