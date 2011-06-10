#include "vm/page.h"
#include "threads/palloc.h"

/* supplemental page table */

void *get_user_page(enum palloc_flags flags) {
	return palloc_get_page (PAL_USER | flags);
}

void *get_multiple_user_pages(enum palloc_flags flags, size_t page_cnt){
	return palloc_get_multiple (PAL_USER | flags, page_cnt);
}

void free_user_page(void * page){
	return palloc_free_page(page);
}

void free_multiple_user_pages(void * pages, size_t page_cnt){
	return palloc_free_multiple(pages, page_cnt);
}
