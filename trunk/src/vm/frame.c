#include "vm/frame.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include <string.h>

/*
 * allocates frame_cnt frames from user space
 */
void *
get_user_frames(enum palloc_flags flags, size_t frame_cnt)
{
	struct pool *user_pool = get_user_pool();
	void *frames;
	size_t frame_idx;

	if (frame_cnt == 0)
	return NULL;

	/* acquire user pool lock */
	lock_acquire (&user_pool->lock);

	/* check for frame_cnt free frames */
	frame_idx = bitmap_scan_and_flip (user_pool->used_map, 0, frame_cnt, false);

	/* if a free slot has been found */
	if (frame_idx != BITMAP_ERROR)
	{
	  /* save frame pointer */
	  frames = user_pool->base + PGSIZE * frame_idx;
	}
	else
	{
	  /* TODO swap some frame to disk */
		frames = NULL;
	}

	if (frames != NULL && flags & PAL_ZERO)
		memset (frames, 0, PGSIZE * frame_cnt);

	/* release user pool lock */
	lock_release (&user_pool->lock);

	return frames;
}

/*
 * allocates a frame from user space
 */
void *
get_user_frame (enum palloc_flags flags) {
	return get_user_frames(flags, 1);
}
