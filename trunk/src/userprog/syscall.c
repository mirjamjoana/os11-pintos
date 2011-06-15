#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "vm/page.h"

#define CONSOLE_BUFFER_SIZE 100
#define MAX_OPEN_FILES 128
#define DEBUG_PUTBUF 0

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
static void handle_mmap(struct intr_frame *f);
static void handle_munmap(struct intr_frame *f);

static void* syscall_get_argument(const struct intr_frame *f, unsigned int arg_number);
static void syscall_set_return_value (struct intr_frame *f, int ret_value);
static void* syscall_get_kernel_address (const void *uaddr);
static struct file* syscall_get_file(int file_descriptor);
static void syscall_check_pointer(const void * ptr);

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
mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapping);

/* global variables */
extern struct lock filesystem_lock; /* mutex semaphore for filesystem */

void
syscall_init (void) 
{
	if(DEBUG) printf("Register syscall handler.\n");
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

	/* retrieve system call number 
	and switch to corresponding method */
	unsigned int syscall_number = *((unsigned int*) syscall_get_kernel_address(f->esp));

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

		case SYS_MMAP:
			handle_mmap(f);
			break;	
			
		case SYS_MUNMAP:
			handle_munmap(f);
			break;	

		default: /* SYSCALL_ERROR: */
			handle_no_such_syscall(f);
			break;
	}
}

static void
handle_halt(struct intr_frame *f UNUSED)
{
	if(DEBUG) printf("halt\n");
	halt();
}

static void
handle_exit(struct intr_frame *f)
{
	if(DEBUG) printf("exit\n");

	int status = (int) syscall_get_argument(f, 0); /* exit status */

	/* call exit */
	exit(status);
}

static void
handle_exec(struct intr_frame *f)
{
	if(DEBUG) printf("exec\n");

	char* cmd_line = (char *) syscall_get_argument(f, 0); /* command line input */

	/* check pointer */
	syscall_check_pointer((const void *)cmd_line);

	/* switch to exec method and save process id pid */
	int pid = exec(cmd_line);

	/* return process id */
	syscall_set_return_value(f, pid);
}
	
static void
handle_wait(struct intr_frame *f)
{
	if(DEBUG) printf("wait\n");

	int pid = (int) syscall_get_argument(f, 0); /* process id */

	/* wait for child process, if possible */
	int exit_value = wait(pid);

	/* return the exit value */
	syscall_set_return_value(f, exit_value);
}
	
static void
handle_create(struct intr_frame *f UNUSED)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("create\n");

	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */
	syscall_check_pointer((const void *) file);	/* check the file */
	
	unsigned int initial_size = (unsigned int) syscall_get_argument(f, 1); /* initial file size */

	/* create file and save success */
	bool success = create(file, initial_size);

	/* return success */
	syscall_set_return_value(f, (int) success);

	/* release file system lock */
	lock_release(&filesystem_lock);

}
	
static void
handle_remove(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("remove\n");

	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */
	syscall_check_pointer((const void *)file);	/* check the file */

	/* remove file and save success */
	bool success = remove(file);

	/* return success */
	syscall_set_return_value(f, (int) success);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void
handle_open(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("open\n");

	const char* file = (const char*) syscall_get_argument(f, 0); /* filename */
	syscall_check_pointer((const void *) file);	/* check the file */

	/* remove file and save success */
	int handle = open(file);

	/* return success */
	syscall_set_return_value(f, handle);

	/* release file system lock */
	lock_release(&filesystem_lock);
}

static void
handle_filesize(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("filesize\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */

	/* fetch size */
	int size = filesize(fd);

	/* return size */
	syscall_set_return_value(f, size);

	/* release file system lock */
	lock_release(&filesystem_lock);

}
	
static void
handle_read(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("read\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */
	
	void * buffer = (void *) syscall_get_argument(f, 1); /* target buffer pointer */
	syscall_check_pointer(buffer);	/* check the buffer */

	unsigned int size = (unsigned int) syscall_get_argument(f, 2); /* target buffer size */

	/* read file and save read count */
	int read_count = read(fd, buffer, size);

	/* return size */
	syscall_set_return_value(f, read_count);

	/* release file system lock */
	lock_release(&filesystem_lock);

}
	
static void
handle_write(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */
	const void *buffer = (const void*) syscall_get_argument(f, 1); /* target buffer pointer */
	syscall_check_pointer(buffer);	/* check the buffer */

	unsigned size = (unsigned int) syscall_get_argument(f, 2); /* target buffer size */

	if(DEBUG) printf("Write: fd: %i  buffer: %x  size: %i\n", fd, (uint32_t) buffer, size);

	/* write buffer of size size into file fd */
	int write_count = write(fd, buffer, size);

	/* return write count */
	syscall_set_return_value(f, write_count);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void
handle_seek(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("seek\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */
	unsigned position = (unsigned int) syscall_get_argument(f, 1); /* file position */

	/* write buffer of size size into file fd */
	seek(fd, position);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void
handle_tell(struct intr_frame *f)
{
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("tell\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */

	/* fetch position of file fd */
	unsigned position = tell(fd);

	/* return position */
	syscall_set_return_value(f, (int) position);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void 
handle_close(struct intr_frame *f UNUSED) 
{	
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("close\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */

	/* fetch position of file fd */
	close(fd);

	/* release file system lock */
	lock_release(&filesystem_lock);
}

static void 
handle_mmap(struct intr_frame *f UNUSED) 
{	
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("mmap\n");

	int fd = (int) syscall_get_argument(f, 0); /* file descriptor */
	void *addr = (void*) syscall_get_argument(f, 1); /* target mapping pointer */

    syscall_check_pointer(addr);	/* check the address */

	/* map file fd to addr */
	mapid_t mapid = mmap(fd, addr);
	
	/* return position */
	syscall_set_return_value(f, (int) mapid);

	/* release file system lock */
	lock_release(&filesystem_lock);
}

static void 
handle_munmap(struct intr_frame *f UNUSED) 
{	
	/* acquire file system lock */
	lock_acquire(&filesystem_lock);

	if(DEBUG) printf("mmap\n");

	mapid_t mapping = (int) syscall_get_argument(f, 0); /* map id */

	/* unmap file specified by mapping */
	munmap(mapping);

	/* release file system lock */
	lock_release(&filesystem_lock);
}
	
static void
handle_no_such_syscall(struct intr_frame *f UNUSED)
{
	unsigned int syscall_number = *( (unsigned int*) f->esp);
	if(DEBUG) printf("No such system call: %i.\n", syscall_number);
	thread_current()->exit_status = -1;
	thread_exit();
}


/*
 * Terminates Pintos by calling power_off() (declared in "threads/init.h").
 * This should be seldom used, because you lose some information about possible
 * deadlock situations, etc.
 */
void
halt (void)
{
	/* shutdown pintos */
	shutdown_power_off();
}

/*
 * Terminates the current user program, returning status to the kernel.
 * If the process's parent waits for it (see below), this is the status
 * that will be returned. Conventionally, a status of 0 indicates success
 * and nonzero values indicate errors.
 */
void
exit (int status)
{
	/* save exit status */
	thread_current()->exit_status = status;

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
int
exec (const char *cmd_line)
{
	/* execute process */
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
int
wait (int pid)
{
	/* wait for child process with process id pid */
	return process_wait(pid);
}

/*
 * Creates a new file called file initially initial_size bytes in size. Returns true
 * if successful, false otherwise. Creating a new file does not open it: opening the
 * new file is a separate operation which would require a open system call.
 */
bool
create (const char *file, unsigned initial_size)
{
	/* create file called file with initial size initial_size*/
	return filesys_create(file, initial_size);
}

/*
 * Deletes the file called file. Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed, and removing
 * an open file does not close it. See Removing an Open File, for details.
 */
bool
remove (const char *file)
{
	/* removes file from file system */
	return filesys_remove(file);
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
open (const char *file_name)
{
	/* open file */
    struct file *file = filesys_open(file_name);

    /* check if file is opened properly */
    if (file == NULL){
    	return -1;
    }

    /* fetch file descriptor list */
    struct list* file_descriptors = &thread_current()->file_descriptors;

    /* if there is space left */
    if(list_size(file_descriptors) < MAX_OPEN_FILES)
    {
    	/* create new file descriptor for file file */
    	struct file_descriptor_elem *file_descriptor = (struct file_descriptor_elem *) malloc(sizeof(struct file_descriptor_elem));

    	/* set & increase file descriptor number */
    	file_descriptor->file_descriptor = thread_current()->fd_next_id++;

    	/* set file in file descriptor */
    	file_descriptor->file = file;

    	/* insert new file descriptor into descriptor list */
		list_push_front(file_descriptors, &file_descriptor->elem);

		return file_descriptor->file_descriptor;
    }
    else
    {
    	return -1;
    }
}

/*
 * Returns the size, in bytes, of the file open as fd.
 */
int 
filesize (int fd)
{
	/* get file */
	struct file *f = syscall_get_file(fd);

	/* return size */
	return (int) file_length(f);
}

/*
 * Reads size bytes from the file open as fd into buffer. Returns
 * the number of bytes actually read (0 at end of file), or -1 if
 * the file could not be read (due to a condition other than end
 * of file). Fd 0 reads from the keyboard using input_getc().
 */
int
read(int fd, void *buffer, unsigned size)
{
	/* get file */
	struct file *f = syscall_get_file(fd);

	/* read size bytes into buffer and
	 * return actually read bytes */
	if(f != NULL)
		return (int) file_read(f, buffer, (off_t) size);

	return -1;
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
int
write (int fd, const void *buffer, unsigned size)
{
	/* local variables */
	int writing_count = 0;

	switch(fd) 
	{
		case STDOUT_FILENO: { /* System console, stdio.h */

			/* split too large buffer */
			if(false && size > CONSOLE_BUFFER_SIZE)
			{
				/* split buffer in chunks of
				 * CONSOLE_BUFFER_SIZE large buffers */

				void * buffer_pointer =  (void *) buffer;

				unsigned i;
				for(i = 0; i < size; i += CONSOLE_BUFFER_SIZE)
				{
					putbuf((const char *)buffer_pointer + i, CONSOLE_BUFFER_SIZE);
					writing_count += CONSOLE_BUFFER_SIZE;
				}

			} else {

				if(DEBUG_PUTBUF) hex_dump(0, buffer, size, true);

				/* write buffer as it is to console */
				if(DEBUG_PUTBUF) printf("putting stuff on user console: %s\n", (const char*) buffer);
				putbuf((const char *)buffer, size);
				writing_count += size;
			}
			break;
		}

		case STDIN_FILENO: /* not assigned yet */
			break;

		default: { /* check user thread file descriptors */

			/* try to catch file with file descriptor fd */
			struct file * f = syscall_get_file(fd);

			/* if matching file descriptor has been found */
			if(f != NULL)
			{
				if(DEBUG) printf("writing to user fd %i\n", fd);
				/* write buffer to file */
				writing_count += file_write(f, buffer, size);

				if(DEBUG) printf("%i bytes have been written\n", writing_count);
			}
			else {
				/* no fitting file desciptor found, panic! */
				if(DEBUG) printf("No such file descriptor: %i\n", fd);
				return -1;
			}
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
void
seek (int fd, unsigned position)
{
	/* get file */
	struct file *f = syscall_get_file(fd);

	/* set file position to position */
	file_seek(f, (off_t) position);
}

/*
 * Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
 */
unsigned
tell (int fd)
{
	/* get file */
	struct file *f = syscall_get_file(fd);

	/* return next file position */
	return (unsigned) file_tell(f);
}

/*
 * Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
 */
void
close (int fd)
{
	if(DEBUG) printf("try to close file %i\n", fd);

	/* get threads file descriptors */
	struct list* file_descriptors = &(thread_current()->file_descriptors);

	/* loop variables */
	struct list_elem *e;
	struct file_descriptor_elem *fde;

	/* search matching file */
	for (e = list_begin (file_descriptors); e != list_end (file_descriptors); e = list_next(e))
	{
		/* fetch list element */
		fde = list_entry (e, struct file_descriptor_elem, elem);

		/* if matching element has been found  */
		if (fde->file_descriptor == fd)
		{
			if(DEBUG) printf("file %i found. closing.\n", fd);
			/* close and delete file object */
			file_close(fde->file);

			/* remove child from list */
			list_remove(&(fde->elem));
			
			/* free resources */
		       	free(fde);

			return;
		}
	}
	if(DEBUG) printf("file %i not found!\n", fd);
}


/*
 * Get argument arg_number from user space.
*/
static void *
syscall_get_argument(const struct intr_frame *f, unsigned int arg_number)
{
	/* virtual address of argument arg_number */
	uint32_t *user_address_arg = ((uint32_t*) f->esp + arg_number + 1);

	/* fetch and return kernel address of argument arg_number */
	return (void *) *((uint32_t*)syscall_get_kernel_address(user_address_arg));
}

/*
 * Save the return value in the eax register
 * of the user process
 */
static void
syscall_set_return_value (struct intr_frame *f, int ret_value)
{
	f->eax = ret_value;
}

/* Checks whether any given pointer is valid */
static void
syscall_check_pointer (const void *ptr) 
{
	syscall_get_kernel_address(ptr);
}


/*
 * Gets the kernel virtual space address of user space
 * address uaddr. Returns NULL if uaddr points to not
 * accessible memory.
 */
static void *
syscall_get_kernel_address (const void *uaddr)
{
	struct thread *current_thread = thread_current();
	uint32_t *pd = current_thread->pagedir;

	/* Checks whether UADDR is a nullpointer */
	if (pd == NULL || uaddr == NULL)
	{
		if(DEBUG) printf("Null pointer.\n");
		current_thread->exit_status = -1;
		thread_exit();
	}

	/* Checks whether UADDR points to unmapped memory and whether it is a user address */
	else if ( uaddr < (void *) 0x08048000 /* - 64 * 1024 * 1024 */ || uaddr >= PHYS_BASE)
	{
		if(DEBUG) printf("Segmentation fault @ %x\n", (uint32_t) uaddr);
		current_thread->exit_status = -1;
		thread_exit();
	}
	else
	{
		/* fetch pointer */
		void * address = pagedir_get_page(pd, uaddr);
		if(address != NULL)
			return address;

		current_thread->exit_status = -1;
		thread_exit();
	}
}

/*
 * Get file descriptor element from file descriptor list
 * with id fd.
 */
static struct file *
syscall_get_file(int file_descriptor)
{
	/* get threads file descriptors */
	struct list* file_descriptors = &(thread_current()->file_descriptors);

	/* loop variables */
	struct list_elem *e;
	struct file_descriptor_elem *fde;

	/* search matching file */
	for (e = list_begin (file_descriptors); e != list_end (file_descriptors); e = list_next(e))
	{
		/* fetch list element */
		fde = list_entry (e, struct file_descriptor_elem, elem);

		/* if the right file descriptor has been found return file */
		if (fde->file_descriptor == file_descriptor)
		{
			return fde->file;
		}
	}

	/* if no file descriptor is found, return null */
	return NULL;
}

/* maps file fd into virtual pages beginning at addr */
mapid_t 
mmap (int fd, void *addr) 
{
	/* fails if file has a length of zero bytes */
	if (filesize(fd) == 0) {
		return MAP_FAILED;
	}
	/* fails if addr is zero */
	else if (addr == NULL) {
		return MAP_FAILED;
	}
	/* checks whether address is page-aligned*/
	else if (pg_ofs(addr) != 0) {
	    return MAP_FAILED;
	}
	switch(fd) 
	{
		/* console input and output are not mappable */
		case STDOUT_FILENO: return -1; break;
		case STDIN_FILENO: return -1; break;
		default: 
		{
		    size_t size = filesize(fd);

            void *page_start; 
		    /* checks whether the file fits into a multiple of pages */
		     if (size % PGSIZE != 0) {
			
		        /* allocate all fully occupied pages */
		        page_start = (void*) get_multiple_user_pages(PAL_ZERO, ((size / PGSIZE) + 1));
			}
			else {
			    /* allocate pages */
		        page_start = (void*) get_multiple_user_pages(PAL_ZERO, (size / PGSIZE));
			} 
				   
            mapid_t mapid = -1;
            
	        /* get threads file descriptors */
	        struct list* file_descriptors = &(thread_current()->file_descriptors);

	        /* loop variables */
	        struct list_elem *e;
	        struct file_descriptor_elem *fde;

	        /* search matching file */
	        for (e = list_begin (file_descriptors); e != list_end (file_descriptors); e = list_next(e))
	        {
		        /* fetch list element */
		        fde = list_entry (e, struct file_descriptor_elem, elem);

		        /* if the right file descriptor has been found map file */
		        if (fde->file_descriptor == fd)
		        {
			        fde->mapid = fde->file_descriptor;
			        mapid = fde->mapid;
			        
			        struct list* mappings = &(thread_current()->mappings);
			        
			        /* map file to pages */
	                // TODO
			        
			        /* insert new mapped file desciptor into list of mappings */
		            list_push_front(mappings, &fde->elem);
		        }
	        }
	        
	        
			
			/* TODO */
			return mapid;	
		}
	}
}


/* Unmaps the mapping designated by mapping, which must be a mapping ID 
returned by a previous call to mmap by the same process that has not yet been 
unmapped.  */
void 
munmap (mapid_t mapping) 
{   
    /* get threads file descriptors */
    struct list* file_descriptors = &(thread_current()->file_descriptors);
    mapid_t mapid = -1;
           
    /* loop variables */
    struct list_elem *e;
    struct file_descriptor_elem *fde;

    /* search matching file */
    for (e = list_begin (file_descriptors); e != list_end (file_descriptors); e = list_next(e))
    {
	     /* fetch list element */
	     fde = list_entry (e, struct file_descriptor_elem, elem);

	     /* if the right file descriptor has been found fetch mapid */
	     if (fde->mapid == mapping)
	     {
		     mapid = fde->mapid;
	     }
	     if (mapid != -1) {
	     
	        /* check whether this is a mapping id that was returned by a 
	        previous call of mmap */
	        struct list* mappings = &(thread_current()->mappings);
	        struct file_descriptor_elem *mapped;
	        
	        /* search matching file */
	        for (e = list_begin (mappings); e != list_end (mappings); e = list_next(e))
	        {
		        /* fetch list element */
		        mapped = list_entry (e, struct file_descriptor_elem, elem);

		        /* if the right file descriptor has been found return file */
		        if (mapped->mapid == mapping)
		        {
			        // TODO write pages back to file
			        
			        /* remove mapping */
			        list_remove(&(mapped->elem));
		        }
	        }
	        
	        /* TODO: write all pages back to the file: free_multiple_user_pages() */
	     }
	     else {
	        return;
	     }
     }
}
