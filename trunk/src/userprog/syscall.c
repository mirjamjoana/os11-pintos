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

	/* retrieve system call number */
	int current_syscall = get_system_call();

	/* handle syscall with its prodecure */
	handle(current_syscall, args);
}

/* get current syscall */
static int
get_system_call()
{
	// get system call number from user space
	
	// match system call number to syscall enum

	// FIXME
	return SYSCALL_ERROR;
}

/* invoke corresponding syscall prodecure */
static void 
handle(syscall sc, char* args)
{
	switch(sc)
	{
		case SYS_HALT:
			handle_halt(args);
			break;

		case SYS_EXIT:
			handle_exit(args);
			break;

		case SYS_EXEC:
			handle_exec(args);
			break;

		case SYS_WAIT:
			handle_wait(args);
			break;

		/* file system calls */
		case SYS_CREATE:
			handle_create(args);
			break;
 
		case SYS_REMOVE:
			handle_remove(args);
			break;

		case SYS_OPEN:
			handle_open(args);
			break;

		case SYS_FILESIZE:
			handle_filesize(args);
			break;

		case SYS_READ:
			handle_read(args);
			break;

		case SYS_WRITE:
			handle_write(args);
			break;

		case SYS_SEEK:
			handle_seek(args);
			break;

		case SYS_TELL:
			handle_tell(args);
			break;

		case SYS_CLOSE:
			handle_close(args);
			break;

		default: /* SYSCALL_ERROR: */
			handle_no_such_syscall(args);
			break;
	}
}

void handle_halt(char* args)  {}

void handle_exit(char* args)  {}

void handle_exec(char* args)  {
	char* cmd_line = NULL;
	pid_t pid = exec (cmd_line);
}
	
void handle_wait(char* args)  {
	pid_t pid = NULL;
	int exit_value = wait (pid);
}
	
void handle_create(char* args) {}
	
void handle_remove(char* args)  {}
	
void handle_open(char* args) {}

void handle_filesize(char* args)  {}
	
void handle_read(char* args) {}
	
void handle_write(char* args) {}
	
void handle_seek(char* args) {}
	
void handle_tell(char* args) {}
	
void handle_close(char* args) {}
	
void handle_no_such_syscall(char* args) {
	printf("No such system call.\n");
	thread_exit();
}
	

void halt (void) {
//FIXME
}

void exit (int status) {
//FIXME
}

pid_t exec (const char *cmd_line) {
//FIXME
	return (pid_t) 0;
}

int wait (pid_t pid) {
//FIXME
	return 0;
}

bool create (const char *file, unsigned initial_size) {
//FIXME
	return false;
}

bool remove (const char *file) {
	//FIXME
	return false;
}

int 
open (const char *file) 
{ WAIT:
	//FIXME
	return 0;
}

int 
filesize (int fd)
{
	//FIXME
	return 0;
}

int read (int fd, void *buffer, unsigned size) {
	//FIXME
	return 0;
}

int write (int fd, const void *buffer, unsigned size) {
	//FIXME
	return 0;
}

void seek (int fd, unsigned position)
{
	//FIXME
	return 0;
}

unsigned tell (int fd) {
	//FIXME
	return (unsigned) 0;
}

void close (int fd) {
	//FIXME
}

/* get the one argument from user space */
static void 
get_argument(const uint8_t *uaddr, int* arg)
{
	uint32_t address = syscall_check_pointer (uaddr);
	
	if(address != -1){
		// TODO getValue
		//*arg = getValue(uaddr);
	} else {
		printf("Segmentation fault.");
		thread_exit();
	}
	// FIXME
}

/* checks the validity of a user pointer 
Returns the byte value if successful, -1 if UADDR points to
not accessible memory.*/
static int
syscall_check_pointer (const uint8_t *uaddr)
{
  // TODO
  struct thread *cur = thread_current (); /* userspace? */
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

