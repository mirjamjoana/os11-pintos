#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>
#include <hash.h>


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
	}

	return frames;
}

void
//register_frames(void *frames, size_t frame_cnt, size_t frame_idx)
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
