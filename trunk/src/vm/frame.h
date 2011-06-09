#ifndef VM_FRAME_H
#define VM_FRAME_H


/* Main memory allocation */

void check_for_free_frames(int count);

void replace_frame(void *frame);

#endif
