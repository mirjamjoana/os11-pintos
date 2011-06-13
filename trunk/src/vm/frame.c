#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
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

//	struct pool *user_pool = get_user_pool();
//
//	void *frames = NULL;
//	size_t frame_idx;
//
//	if (frame_cnt == 0)
//		return NULL;
//
//	/* acquire user pool lock */
//	lock_acquire (&user_pool->lock);
//
//	/* check for frame_cnt free frames */
//	frame_idx = bitmap_scan_and_flip (user_pool->used_map, 0, frame_cnt, false);
//
//	/* if no free slot has been found */
//	if (frame_idx == BITMAP_ERROR)
//	{
//		/* TODO swap frame_cnt frames to disk and repeat */
//	}
//
//	/* if a free slot has been found */
//	if (frame_idx != BITMAP_ERROR)
//	{
//		/* save frame pointer */
//		frames = user_pool->base + PGSIZE * frame_idx;
//	}
//
//	ASSERT(frames != NULL);
//
//	/* initialize page with zeroes */
//	if(flags & PAL_ZERO)
//		memset (frames, 0, PGSIZE * frame_cnt);
//
//	/* release user pool lock */
//	lock_release (&user_pool->lock);
//
//	return frames;

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

/* Returns a hash value for frame f. */
unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame *f = hash_entry (f_, struct frame, hash_elem);
  return hash_bytes (&f->id, sizeof f->id);
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
