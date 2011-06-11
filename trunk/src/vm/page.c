#include "vm/page.h"
#include "vm/frame.h"
#include "threads/palloc.h"
#include <debug.h>

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
