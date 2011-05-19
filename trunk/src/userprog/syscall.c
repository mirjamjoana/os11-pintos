#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

#define MAX_CONSOLE_BUFFER 200

static void syscall_handler (struct intr_frame *);

void handle_halt(struct intr_frame *f);
void handle_exit(struct intr_frame *f);
void handle_exec(struct intr_frame *f);
void handle_wait(struct intr_frame *f);
void handle_create(struct intr_frame *f);
void handle_remove(struct intr_frame *f);
void handle_open(struct intr_frame *f);
void handle_filesize(struct intr_frame *f);
void handle_read(struct intr_frame *f);
void handle_write(struct intr_frame *f);
void handle_seek(struct intr_frame *f);
void handle_tell(struct intr_frame *f);
void handle_close(struct intr_frame *f);
void handle_no_such_syscall(struct intr_frame *f);

void syscall_get_arguments(const struct intr_frame *f, int arg_number, int *arg_array);
void syscall_set_return_value (struct intr_frame *f, int ret_value);
int syscall_check_pointer (const void *uaddr);

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
syscall_handler (struct intr_frame *f) 
{
	printf ("system call!\n");

	/* retrieve system call number 
	and switch to corresponding method */
	unsigned int syscall_number = *( (unsigned int*) f->esp);

	switch(syscall_number)
	{
		case SYS_HALT:
			handle_halt(f);
			break;

		case SYS_EXIT:
			handle_exit(f);
			break;

		case SYS_EXEC:
			handle_exec(f);
			break;

		case SYS_WAIT:
			handle_wait(f);
			break;

		/* file system calls */
		case SYS_CREATE:
			handle_create(f);
			break;
 
		case SYS_REMOVE:
			handle_remove(f);
			break;

		case SYS_OPEN:
			handle_open(f);
			break;

		case SYS_FILESIZE:
			handle_filesize(f);
			break;

		case SYS_READ:
			handle_read(f);
			break;

		case SYS_WRITE:
			handle_write(f);
			break;

		case SYS_SEEK:
			handle_seek(f);
			break;

		case SYS_TELL:
			handle_tell(f);
			break;

		case SYS_CLOSE:
			handle_close(f);
			break;

		default: /* SYSCALL_ERROR: */
			handle_no_such_syscall(f);
			break;
	}
}

void handle_halt(struct intr_frame *f UNUSED)  {}

void handle_exit(struct intr_frame *f UNUSED)  {
	/* fetch current status of the user process */
	int status;
	syscall_get_arguments(f, 1, &status);
	
	/* call exit */
	exit(status);
}

void handle_exec(struct intr_frame *f UNUSED)  {
	//char* cmd_line = NULL;
	//struct pid_t pid = exec(cmd_line);
}
	
void handle_wait(struct intr_frame *f UNUSED)  {
	//struct pid_t pid;
	//int exit_value = wait (pid);
}
	
void handle_create(struct intr_frame *f UNUSED) {}
	
void handle_remove(struct intr_frame *f UNUSED)  {}
	
void handle_open(struct intr_frame *f UNUSED) {}

void handle_filesize(struct intr_frame *f UNUSED)  {}
	
void handle_read(struct intr_frame *f UNUSED) {}
	
void handle_write(struct intr_frame *f UNUSED) {
	
}
	
void handle_seek(struct intr_frame *f UNUSED) {}
	
void handle_tell(struct intr_frame *f UNUSED) {}
	
void handle_close(struct intr_frame *f UNUSED) {}
	
void handle_no_such_syscall(struct intr_frame *f UNUSED) {
	unsigned int syscall_number = *( (unsigned int*) f->esp);
	printf("No such system call: %i.\n", syscall_number);
	thread_exit();
}
	
void halt (void) {
//FIXME
}


void exit (int status UNUSED) {
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

int exec (const char *cmd_line UNUSED) {
//FIXME
	return 0;
}

int wait (int pid UNUSED) {
//FIXME
	return 0;
}

bool create (const char *file UNUSED, unsigned initial_size UNUSED) {
//FIXME
	return false;
}

bool remove (const char *file UNUSED) {
	//FIXME
	return false;
}

int 
open (const char *file UNUSED) 
{
	//FIXME
	return 0;
}

int 
filesize (int fd UNUSED)
{
	//FIXME
	return 0;
}

int read (int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED) {
	//FIXME
	return 0;
}

int write (int fd, const void *buffer, unsigned size) {
	/* local variables */
	int writing_count = 0;

	switch(fd) 
	{
		case 1: /* console */
			if(size > MAX_CONSOLE_BUFFER)
			{
				//split up buffer
			}
			/* */
			//putbuf();
			break;

		default:
			printf("no such file format: %i", fd);
			thread_exit();
	}

	return writing_count;
}

void seek (int fd UNUSED, unsigned position UNUSED)
{
	//FIXME
}

unsigned tell (int fd UNUSED) {
	//FIXME
	return (unsigned UNUSED) 0;
}

void close (int fd UNUSED) {
	//FIXME
}


/*

Thus, when the system call handler syscall_handler() gets control, the system call number is in the 32-bit word at the caller's stack pointer, the first argument is in the 32-bit word at the next higher address, and so on. The caller's stack pointer is accessible to syscall_handler() as the esp member of the struct intr_frame passed to it. (struct intr_frame is on the kernel stack.)

The 80x86 convention for function return values is to place them in the EAX register. System calls that return a value can do so by modifying the eax member of struct intr_frame. 

*/

void 
syscall_get_arguments(const struct intr_frame *f, int arg_number, int* arg_array)
{
	/* loop argument count */
	int i;

	/* virtual argument address */
	uint32_t *v_address_arg = ((uint32_t*) f->esp ) + 4;

	/* physical argument address */
	int *p_address_arg;

	/* get arg_number arguments from the stack*/
	for(i = 0; i < arg_number; i++)
	{
		/* fetch stack pointer of argument 0 and check validity*/
		//p_address_arg = (int) syscall_check_pointer(v_address_arg);
		
		/* get argument 0 */
		arg_array[i] = *p_address_arg;

		/* increase stack pointer */
		v_address_arg += 4;
	}
}

/* saves the return value in the eax register of the user process */
void
syscall_set_return_value (struct intr_frame *f, int ret_value)
{
	*((int*)f->eax) = ret_value;
}

/* checks the validity of a user pointer 
Returns the byte value if successful, -1 if UADDR points to
not accessible memory.*/
int
syscall_check_pointer (const void *uaddr)
{
	// TODO check if this really works ..
	struct thread *cur = thread_current (); /* userspace? */
	struct uint32_t *pd;
	pd = cur->pagedir;

	// Checks whether UADDR is a nullpointer
	if (pd == NULL)
	{
		printf("Null pointer.\n");
		thread_exit();
	}

	// Checks whether UADDR points to unmapped memory and whether it is a user address
	else if (pagedir_get_page(pd, uaddr) == NULL)
	{
		printf("Segmentation fault.\n");
		thread_exit();
	}
	else
		return pagedir_get_page(pd, uaddr);
}

