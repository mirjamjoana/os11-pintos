#include "vm/frame.h"
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <string.h>
#include <hash.h>

/* static member functions */
static struct frame * frame_lookup (const void *address);

void * swap_frame (void);

void
user_frames_init()
{
	hash_init (&user_frames, frame_hash, frame_less, NULL);
	lock_init (&user_frames_lock);
}

/*
 * allocates frame_cnt continuous frames from user space
 * an returns kernel virtual address of the first one
 */
void *
alloc_user_frames(enum palloc_flags flags, size_t frame_cnt)
{
	ASSERT(lock_held_by_current_thread(&user_frames_lock));

	/* try to allocate without swap */
	void* frames = palloc_get_multiple(flags | PAL_USER, frame_cnt);

	if(frames == NULL) {
		/* TODO try to swap out pages for allocation */
		if (SWAP) frames = swap_frame();

	}

	return frames;
}

void
register_frame (void *upage, void *kpage)
{
	ASSERT(lock_held_by_current_thread(&user_frames_lock));

	struct frame*  f = (struct frame *) malloc(sizeof(struct frame));
	f->id = pg_no(kpage);
	f->pagedir = thread_current()->pagedir;
	f->upage = upage;

	ASSERT(hash_replace (&user_frames, &f->hash_elem) == NULL);
}

void
unregister_frames (void *kpage, size_t page_cnt)
{
	ASSERT(lock_held_by_current_thread(&user_frames_lock));

	unsigned int i;
	for(i = 0; i < page_cnt; i++)
	{
		/* fetch frame */
		struct frame* f = frame_lookup(kpage + PGSIZE * i);

		if(f->pagedir == thread_current()->pagedir)
		{
			/* delete hash entry */
			hash_delete(&user_frames, &f->hash_elem);

			/* free data structure */
			free(f);
		}
		else {
			printf("Privilege violation: delete frame entry of another process");
			thread_exit();
		}
	}

}

/* destroy every user frame of the current thread */
void
destroy_user_frames()
{
	if(DEBUG) printf("Destroying user frames for process %i\n", thread_current()->tid);

	struct hash_iterator i;
	uint32_t *pagedir = thread_current()->pagedir;

start:
	hash_first (&i, &user_frames);

	while (hash_next (&i))
	  {
	    struct frame *f = hash_entry (hash_cur (&i), struct frame, hash_elem);    
	  
	    if(f->pagedir == pagedir)
	    {
		    if(DEBUG) printf("Deleting hash entry id: %i, uaddr: %x, pagedir: %x\n", f->id, (unsigned int) f->upage, (unsigned int) f->pagedir);
	    	/* delete frame from hash */
	    	hash_delete(&user_frames, &f->hash_elem);

			/* release allocated space */
			free(f);

			/* iterator invalidates after hash modification,
			 * have to build iterator again */
			goto start;
		}
	  }
}

/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
static struct frame *
frame_lookup (const void *address)
{
  struct frame f;
  struct hash_elem *e;

  f.id = pg_no(address);
  e = hash_find (&user_frames, &f.hash_elem);
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

/* Returns a hash value for frame f. */
unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame *f = hash_entry (f_, struct frame, hash_elem);
  return hash_int (f->id);
}

/* Returns true if frame a precedes frame b. */
bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct frame *a = hash_entry (a_, struct frame, hash_elem);
  const struct frame *b = hash_entry (b_, struct frame, hash_elem);

  return a->id < b->id;
}


//this functions gets a new frame and returns the corresponding memory page
uint8_t * get_frame (void ) {
        //frame for the table
        struct swap_frame * f = NULL;
        //try to get a page
        //lock the frame table
        lock_acquire(&user_frames_lock);
        uint8_t * kpage = palloc_get_page (PAL_USER | PAL_ZERO);

        //check if hash table is full
        if (kpage == NULL) {
                //now we have to evict a page
                kpage = swap_frame();
        }

        //create a new frame otherwise
        f = (struct swap_frame *) malloc (sizeof(struct swap_frame));

        //in case there was a problem with getting a page
        ASSERT(kpage);

        //save the threads id and the physical address in the new frame struct
        f->thread = thread_current();
        f->addr = kpage;
        f->lock = false;

        hash_insert (&user_frames, &f->hash_elem);

        //release the lock for the frame table
        lock_release(&user_frames_lock);

        return kpage;
}


//for the eviction policy
void * swap_frame (void) {
        //look through the frames in the table to find one to swap with the clock algorithm
        struct hash_iterator i;

        void * frame_swap = NULL;

        while (frame_swap == NULL) {
        hash_first (&i, &user_frames);
        while (hash_next (&i)) {
                struct swap_frame *f = hash_entry (hash_cur (&i), struct swap_frame, hash_elem);
                void * vaddr = (void *)get_vaddr_page(f->addr,f->thread);
                //page is dirty then swap it otherwise set it to 0 and go for the next one
                //true case
                if (f->lock == false) {
                        if (pagedir_is_accessed (f->thread->pagedir, vaddr) ) {
                                //set dirty bit to false
                                pagedir_set_accessed (f->thread->pagedir, vaddr, false);
                        } else {
                                //page is dirty so we can swap it
                                page_swap_in(vaddr,f->thread);
                                unregister_frames(f->addr, 1);
                                frame_swap = palloc_get_page (PAL_USER | PAL_ZERO); 
                                break;
                        }
                }
        }
        }

        ASSERT(frame_swap);
        return frame_swap;
}



