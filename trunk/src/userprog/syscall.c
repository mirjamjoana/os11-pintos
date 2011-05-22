#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"

#define CONSOLE_BUFFER_SIZE 100
#define DEBUG 1

/* prototypes */
static void syscall_handler (struct intr_frame *f);

static void handle_halt(struct intr_frame *f);
static void handle_exit(struct intr_frame *f);
static void handle_exec(struct intr_frame *f);
static void handle_wait(struct intr_frame *f);
static void handle_create(struct intr_frame *f);
static void handle_remove(struct intr_frame *f);
static void handle_open(struct intr_frame *f);
static void handle_filesize(struct intr_frame *f);
static void handle_read(struct intr_frame *f);
static void handle_write(struct intr_frame *f);
static void handle_seek(struct intr_frame *f);
static void handle_tell(struct intr_frame *f);
static void handle_close(struct intr_frame *f);
static void handle_no_such_syscall(struct intr_frame *f);

static void* syscall_get_argument(const struct intr_frame *f, unsigned int arg_number);
static void syscall_set_return_value (struct intr_frame *f, int ret_value);
static void* syscall_get_kernel_address (const void *uaddr);

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

/* shared variables */
static struct lock filesystem_lock; /* mutex semaphore for filesystem */
//static int open_files[MAX_OPEN_FILES]; /* array of the currently opened files */

void
syscall_init (void) 
{
	lock_init(&filesystem_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
 * System call handler
 *
 * retrieves system call number from user space
 * and invokes the requested method
 */
static void
syscall_handler (struct intr_frame *f) 
{
	printf ("system call!\n");

	/* retrieve system call number 
	and switch to corresponding method */
	unsigned int syscall_number = *( (unsigned int*) f->esp);

	switch(syscall_number)
	{
		/* process system calls */
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

static void
handle_halt(struct intr_frame *f UNUSED)
{
	halt();
}

static void
handle_exit(struct intr_frame *f)
{
	int *status = (int *) syscall_get_argument(f, 0); /* exit status */
	
	/* call exit */
	exit(*status);
}

static void
handle_exec(struct intr_frame *f)
{
	char* cmd_line = (char *) syscall_get_argument(f, 0); /* command line input */

	/* switch to exec method and save process id pid */
	int pid = exec(cmd_line);

	/* return process id */
	syscall_set_return_value(f, pid);
}
	
static void
handle_wait(struct intr_frame *f)
{
	int *pid = (int *) syscall_get_argument(f, 0); /* process id */

	/* wait for child process, if possible */
	int exit_value = wait(*pid);

	/* return the exit value */
	syscall_set_return_value(f, exit_value);
}
	
static void
handle_create(struct intr_frame *f UNUSED)
{
	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */
	unsigned int* initial_size = (unsigned int*) syscall_get_argument(f, 1); /* initial file size */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* create file and save success */
	bool success = create(file, *initial_size);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return success */
	syscall_set_return_value(f, (int) success);

}
	
static void
handle_remove(struct intr_frame *f)
{
	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* remove file and save success */
	bool success = remove(file);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return success */
	syscall_set_return_value(f, (int) success);
}
	
static void
handle_open(struct intr_frame *f)
{
	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* remove file and save success */
	bool success = open(file);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return success */
	syscall_set_return_value(f, (int) success);
}

static void
handle_filesize(struct intr_frame *f)
{
	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* fetch size */
	int size = filesize(fd);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return size */
	syscall_set_return_value(f, size);
}
	
static void
handle_read(struct intr_frame *f)
{
	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */
	void * buffer = (void *) syscall_get_argument(f, 1); /* target buffer pointer */
	unsigned int size = (unsigned int) syscall_get_argument(f, 2); /* target buffer size */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* read file and save read count */
	int read_count = read(fd, buffer, size);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return size */
	syscall_set_return_value(f, read_count);
}
	
static void
handle_write(struct intr_frame *f)
{
	int fd = *((int*)syscall_get_argument(f, 0)); /* file descriptor */
	const void *buffer = (const void*) syscall_get_argument(f, 1); /* target buffer pointer */
	unsigned size = *((unsigned int*)syscall_get_argument(f, 2)); /* target buffer size */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* write buffer of size size into file fd */
	int write_count = write(fd, buffer, size);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return write count */
	syscall_set_return_value(f, write_count);
}
	
static void handle_seek(struct intr_frame *f) {
	int fd = *((int*)syscall_get_argument(f, 0)); /* file descriptor */
	unsigned position = *((unsigned int*)syscall_get_argument(f, 1)); /* file position */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* write buffer of size size into file fd */
	seek(fd, position);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void handle_tell(struct intr_frame *f) {
	int fd = *((int*)syscall_get_argument(f, 0)); /* file descriptor */

	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	/* fetch position of file fd */
	unsigned position = tell(fd);

	/* release file system lock */
	lock_release(&filesystem_lock);

	/* return position */
	syscall_set_return_value(f, position);
}
	
static void handle_close(struct intr_frame *f UNUSED) {
	lock_acquire(&filesystem_lock);

	lock_release(&filesystem_lock);
}
	
static void handle_no_such_syscall(struct intr_frame *f UNUSED) {
	unsigned int syscall_number = *( (unsigned int*) f->esp);
	printf("No such system call: %i.\n", syscall_number);
	thread_exit();
}


/*
 * Terminates Pintos by calling power_off() (declared in "threads/init.h").
 * This should be seldom used, because you lose some information about possible
 * deadlock situations, etc.
 */
void halt (void) {
	/* shutdown pintos */
	shutdown_power_off();
}

/*
 * Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it (see below), this is the status
 * that will be returned. Conventionally, a status of 0 indicates success
 * and nonzero values indicate errors.
 */
void exit (int status) {

	/* get current thread */
	struct thread *cur_thread = thread_current();
	/* get list element of current thread */
	struct child *list_element = list_entry (&(cur_thread->childelem), struct child, elem);
	/* get parent thread */
	struct thread *parent_thread = list_element->parent;

	/* if thread has a parent thread, save exit status */
	if (parent_thread != NULL)
	{
		 /* set exit status */
		list_element->exit_status = status;

		/* set termination semaphore */
		sema_up(list_element->terminated);
	}

	/* TODO free resources */

	/* print exit message */
	printf ("%s: exit(%d)\n", cur_thread->name, status);

	/* exit and delete thread */
	thread_exit();
}

/*
 * Runs the executable whose name is given in cmd_line, passing any given
 * arguments, and returns the new process's program id (pid). Must return
 * pid -1, which otherwise should not be a valid pid, if the program cannot
 * load or run for any reason. Thus, the parent process cannot return from
 * the exec until it knows whether the child process successfully loaded its
 * executable. You must use appropriate synchronization to ensure this.
 */
int exec (const char *cmd_line) {
	return (int) process_execute(cmd_line);
}

/*
 * Waits for a child process pid and retrieves the child's exit status.
 *
 * If pid is still alive, waits until it terminates. Then, returns the status
 * that pid passed to exit. If pid did not call exit(), but was terminated by
 * the kernel (e.g. killed due to an exception), wait(pid) must return -1. It
 * is perfectly legal for a parent process to wait for child processes that
 * have already terminated by the time the parent calls wait, but the kernel
 * must still allow the parent to retrieve its child's exit status, or learn
 * that the child was terminated by the kernel.
 *
 * wait must fail and return -1 immediately if any of the following conditions is
 * true:
 *   *  pid does not refer to a direct child of the calling process.
 *   *  pid is a direct child of the calling process if and only if the calling process
 *     		received pid as a return value from a successful call to exec.
 *
 * Note that children are not inherited: if A spawns child B and B spawns child
 * process C, then A cannot wait for C, even if B is dead. A call to wait(C) by
 * process A must fail. Similarly, orphaned processes are not assigned to a new
 * parent if their parent process exits before they do.
 *
 * The process that calls wait has already called wait on pid. That is, a process
 * may wait for any given child at most once. Processes may spawn any number of children,
 * wait for them in any order, and may even exit without having waited for some or all
 * of their children. Your design should consider all the ways in which waits can occur.
 *
 * All of a process's resources, including its struct thread, must be freed whether its
 * parent ever waits for it or not, and regardless of whether the child exits before
 * or after its parent.
 *
 * You must ensure that Pintos does not terminate until the initial process exits.
 * The supplied Pintos code tries to do this by calling process_wait() (in "userprog/process.c")
 * from main() (in "threads/init.c"). We suggest that you implement process_wait() according
 * to the comment at the top of the function and then implement the wait system call in
 * terms of process_wait().
 */
int wait (int pid) {
	/* wait for child process with process id pid */
	return process_wait(pid);
}

/*
 * Creates a new file called file initially initial_size bytes in size. Returns true
 * if successful, false otherwise. Creating a new file does not open it: opening the
 * new file is a separate operation which would require a open system call.
 */
bool create (const char *file UNUSED, unsigned initial_size UNUSED) {
//FIXME
	return false;
}

/*
 * Deletes the file called file. Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed, and removing
 * an open file does not close it. See Removing an Open File, for details.
 */
bool remove (const char *file UNUSED) {
	//FIXME
	return false;
}

/*
 * Opens the file called file. Returns a nonnegative integer handle
 * called a "file descriptor" (fd), or -1 if the file could not be
 * opened.
 *
 * File descriptors numbered 0 and 1 are reserved for the console:
 * fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is
 * standard output. The open system call will never return either of
 * these file descriptors, which are valid as system call arguments
 * only as explicitly described below.
 *
 * Each process has an independent set of file descriptors. File
 * descriptors are not inherited by child processes.
 *
 * When a single file is opened more than once, whether by a single
 * process or different processes, each open returns a new file
 * descriptor. Different file descriptors for a single file are
 * closed independently in separate calls to close and they do not
 * share a file position.
 */
int 
open (const char *file UNUSED) 
{
	//FIXME
	return 0;
}

/*
 * Returns the size, in bytes, of the file open as fd.
 */
int 
filesize (int fd UNUSED)
{
	//FIXME
	return 0;
}

/*
 * Reads size bytes from the file open as fd into buffer. Returns
 * the number of bytes actually read (0 at end of file), or -1 if
 * the file could not be read (due to a condition other than end
 * of file). Fd 0 reads from the keyboard using input_getc().
 */
int read(int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED) {
	//FIXME
	return 0;
}

/*
 * Writes size bytes from buffer to the open file fd. Returns the
 * number of bytes actually written, which may be less than size if
 * some bytes could not be written.
 *
 * Writing past end-of-file would normally extend the file, but file
 * growth is not implemented by the basic file system. The expected
 * behavior is to write as many bytes as possible up to end-of-file
 * and return the actual number written, or 0 if no bytes could be
 * written at all.
 *
 * Fd 1 writes to the console. Your code to write to the console should
 * write all of buffer in one call to putbuf(), at least as long as
 * size is not bigger than a few hundred bytes. (It is reasonable to
 * break up larger buffers.) Otherwise, lines of text output by different
 * processes may end up interleaved on the console, confusing both
 * human readers and our grading scripts.
 */
int write (int fd, const void *buffer, unsigned size) {
	/* local variables */
	int writing_count = 0;

	switch(fd) 
	{
		case STDOUT_FILENO: /* System console, stdio.h */

			/* split too large buffer */
			if(size > CONSOLE_BUFFER_SIZE)
			{
				/* TODO split buffer in chunks of
				 * CONSOLE_BUFFER_SIZE large buffers */
				putbuf((const char *)buffer, size);
				writing_count += size;
			} else {
				/* write buffer as it is to console */
				putbuf((const char *)buffer, size);
				writing_count += size;
			}
			break;

		case STDIN_FILENO: /* not assigned yet */
			break;

		default: { /* check user thread file descriptors */

			/* get file descriptor list */
			struct list *file_descriptors = &(thread_current()->file_descriptors);

			/* loop variables */
			struct list_elem *e;
			struct file_descriptor_elem *fde;

			for (e = list_begin (file_descriptors); e != list_end (file_descriptors); e = list_next(e))
			{
				fde = list_entry (e, struct file_descriptor_elem, elem);

				/* if the right file descriptor has been found
				 * write buffer to file */
				if (fde->file_descriptor == fd)
				{
					writing_count += file_write (fde->file, buffer, size);
					break; /* jump out of for-loop */
				}
			}
			break; /* jump out of switch-case */

			/* no fitting file desciptor found, panic! */
			printf("No such file descriptor: %i\n", fd);

			//TODO return to handler and terminate process
		}
	}

	return writing_count;
}

/*
 * Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file. (Thus, a position of
 * 0 is the file's start.)
 *
 * A seek past the current end of a file is not an error. A later read
 * obtains 0 bytes, indicating end of file. A later write extends the file,
 * filling any unwritten gap with zeros. (However, in Pintos files have a
 * fixed length until project 4 is complete, so writes past end of file will
 * return an error.) These semantics are implemented in the file system and
 * do not require any special effort in system call implementation.
 */
void seek (int fd UNUSED, unsigned position UNUSED)
{
	//FIXME
}

/*
 * Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
 */
unsigned tell (int fd UNUSED) {
	//FIXME
	return (unsigned) 0;
}

/*
 * Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
 */
void close (int fd UNUSED) {
	//FIXME
}


/*
 * Get argument arg_number from user space.
*/
static void * syscall_get_argument(const struct intr_frame *f, unsigned int arg_number)
{
	/* virtual address of argument arg_number */
	uint32_t *user_address_arg = ((uint32_t*) f->esp ) + (arg_number + 1) * sizeof(void *);

	/* fetch and return kernel address of argument arg_number */
	return syscall_get_kernel_address(user_address_arg);
}

/* saves the return value in the eax register of the user process */
static void syscall_set_return_value (struct intr_frame *f, int ret_value)
{
	*((int*)f->eax) = ret_value;
}

/*
 * Gets the kernel virtual space address of user space
 * address uaddr. Returns NULL if uaddr points to not
 * accessible memory.
 */
static void * syscall_get_kernel_address (const void *uaddr)
{
	struct thread *current_thread = thread_current();
	uint32_t *pd = current_thread->pagedir;

	// Checks whether UADDR is a nullpointer
	if (pd == NULL || uaddr == NULL)
	{
		if(DEBUG) printf("Null pointer.\n");
		printf ("%s: exit(%d)\n", thread_name(),-1);
		thread_exit();
	}

	// Checks whether UADDR points to unmapped memory and whether it is a user address
	else if ( uaddr <= (void *) 0x08084000 /* - 64 * 1024 * 1024 */ || uaddr >= PHYS_BASE)
	{
		if(DEBUG) printf("Segmentation fault.\n");
		printf ("%s: exit(%d)\n", thread_name(),-1);
		thread_exit();
	}
	else
		return pagedir_get_page(pd, uaddr);
}

