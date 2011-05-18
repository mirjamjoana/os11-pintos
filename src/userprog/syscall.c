#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* checks the validity of a user pointer 
Returns the byte value if successful, -1 if UADDR points to
not accessible memory.*/
static int
syscall_check_pointer (const uint8_t *uaddr)
{
  // TODO
  struct thread *cur = thread_current ();
  uint32_t *pd;
  pd = cur->pagedir;

  // Checks whether UADDR is a nullpointer
  if (pd == NULL)
    {
	return -1;
    }

  // Checks whether UADDR points to unmapped memory and whether it is a user address
  else if (pagedir_get_page(pd, uaddr) == NULL)
    {
	return -1;
    }
  else
	return pagedir_get_page(*pd, *uaddr);
}