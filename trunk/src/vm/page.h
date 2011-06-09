#ifndef VM_PAGE_H
#define VM_PAGE_H

/* supplemental page table */

void *get_user_page (enum palloc_flags);
void *get_multiple_user_pages (enum palloc_flags, size_t page_cnt);
void free_user_page (void * page);
void free_multiple_user_pages (void * pages, size_t page_cnt);

#endif
