#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"


static void syscall_handler (struct intr_frame *);

void handle(int syscall);
void handle_halt(void);
void handle_exit(void);
void handle_exec(void);
void handle_wait(void);
void handle_create(void);
void handle_remove(void);
void handle_open(void);
void handle_filesize(void);
void handle_read(void);
void handle_write(void);
void handle_seek(void);
void handle_tell(void);
void handle_close(void);
void handle_no_such_syscall(void);

void halt (void);
void exit (int status);
int exec (const char *cmd_line);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


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
	// get system call number from user space
	// match system call number to syscall enum
	int syscall = SYS_HALT;

	/* handle syscall with its prodecure */
	handle(syscall);
}


/* invoke corresponding syscall prodecure */
void 
handle(int syscall)
{
	switch(syscall)
	{
		case SYS_HALT:
			handle_halt();
			break;

		case SYS_EXIT:
			handle_exit();
			break;

		case SYS_EXEC:
			handle_exec();
			break;

		case SYS_WAIT:
			handle_wait();
			break;

		/* file system calls */
		case SYS_CREATE:
			handle_create();
			break;
 
		case SYS_REMOVE:
			handle_remove();
			break;

		case SYS_OPEN:
			handle_open();
			break;

		case SYS_FILESIZE:
			handle_filesize();
			break;

		case SYS_READ:
			handle_read();
			break;

		case SYS_WRITE:
			handle_write();
			break;

		case SYS_SEEK:
			handle_seek();
			break;

		case SYS_TELL:
			handle_tell();
			break;

		case SYS_CLOSE:
			handle_close();
			break;

		default: /* SYSCALL_ERROR: */
			handle_no_such_syscall();
			break;
	}
}

void handle_halt()  {}

void handle_exit()  {}

void handle_exec()  {
	//char* cmd_line = NULL;
	//struct pid_t pid = exec(cmd_line);
}
	
void handle_wait()  {
	//struct pid_t pid;
	//int exit_value = wait (pid);
}
	
void handle_create() {}
	
void handle_remove()  {}
	
void handle_open() {}

void handle_filesize()  {}
	
void handle_read() {}
	
void handle_write() {}
	
void handle_seek() {}
	
void handle_tell() {}
	
void handle_close() {}
	
void handle_no_such_syscall() {
	printf("No such system call.\n");
	thread_exit();
}
	

void halt (void) {
//FIXME
}

// returns 0 if successful, -1 otherwise
void exit (int status) {
	//FIXME
	struct thread *cur = thread_current (); /* userspace? */

	/* if there is a parent process waiting (methods are not defined at the moment)
	if (cur_is_someone_waiting()) 
	{
		struct thread *par = cur_getParent();
		par_syscall_return_status(status);
		cur_exit();
	}
	else 
	{
		cur_exit();
	}*/
}

int exec (const char *cmd_line) {
//FIXME
	return 0;
}

int wait (int pid) {
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
void 
get_argument(const struct uint8_t *uaddr, int* arg)
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
int
syscall_check_pointer (const struct uint8_t *uaddr)
{
  // TODO
  struct thread *cur = thread_current (); /* userspace? */
  struct uint32_t *pd;
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
	return (int) pagedir_get_page(pd, uaddr);
}

