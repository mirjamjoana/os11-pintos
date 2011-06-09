#include "vm/page.h"
#include "vm/frame.h"
#include "threads/palloc.h"

/* supplemental page table */

void *get_user_page(enum palloc_flags) {
	return palloc_get_page (PAL_USER | palloc_flags);
}

void *get_multiple_user_pages(enum palloc_flags, size_t page_cnt){
	return palloc_get_pages (PAL_USER | palloc_flags, page_cnt);

}
void free_user_page(void * page){
	return palloc_free_page(page);
}

void free_multiple_user_pages(void * pages, size_t page_cnt){
	return palloc_free_pages(pages, page_cnt);
}
