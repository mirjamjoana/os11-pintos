#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/bitmap.h"
#include "threads/palloc.h"

/* Main memory allocation */

void *get_user_frame (enum palloc_flags);
void *get_user_frames (enum palloc_flags, size_t page_cnt);

//static void replace_frame(void *frame);

#endif
