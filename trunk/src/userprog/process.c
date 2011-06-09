#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

#define DEBUG_EXIT 0 

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
struct child* process_get_child(struct thread* parent, tid_t child_tid);

/* global variable */
extern struct lock filesystem_lock;


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command_line_input)
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;

	strlcpy (fn_copy, command_line_input, PGSIZE);

	/* make another copy of the file name */
    char *file_name = (char *) malloc(strlen(command_line_input) + sizeof(char));
    strlcpy(file_name, command_line_input, strlen(command_line_input) + sizeof(char));

	/* extract file name */
	char * save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);

	return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *command_line_input)
{
    /* loop variables */
    char *token, *save_ptr;

    /* copy of the command line input */
    void *command_line_input_copy = malloc(strlen(command_line_input) + sizeof(char));
    memcpy(command_line_input_copy, (const void*) command_line_input, strlen((const char*)command_line_input) + sizeof(char));

	/* count number of arguments */
	int argument_count = 0;
	for (token = strtok_r ((char *)command_line_input, " ", &save_ptr); token != NULL;
		token = strtok_r (NULL, " ", &save_ptr)){
		   argument_count++;		
	}
	
	/* create array of argument pointers */
	char** arguments = malloc(argument_count * sizeof(char*));

	/*
	* save token pointers into arguments array
	*
	* arguments[0] => filename
	* arguments[1..n] => argument 0 .. n-1
	*/
	int i = 0;
	for (token = strtok_r ((char *)command_line_input_copy, " ", &save_ptr); token != NULL;
		token = strtok_r (NULL, " ", &save_ptr))
	{
		   //printf("token %i: %s @ %x [%i bytes]\n", i, token, (unsigned)token, strlen(token));
		   arguments[i] = token;
		   //printf("token %i: %s @ %x [%i bytes] -- CHECK\n", i, arguments[i], (unsigned)arguments[i], strlen(arguments[i]));
		   i++;
	}

	/* assert that the command line input
	  has not changed over time */
	ASSERT(argument_count == i);

	char *file_name = (char *)command_line_input;
	struct intr_frame if_;
	bool success;

	/* Initialize interrupt frame and load executable. */
	memset (&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	
	/* aquire file lock, load and release */
	lock_acquire(&filesystem_lock);
	success = load (file_name, &if_.eip, &if_.esp);
	lock_release(&filesystem_lock);

	/* If load failed, quit. */
	if (!success) {
		thread_exit ();
	}

	/* free resources */
	palloc_free_page (command_line_input);

    /* copy arguments on stack. example stack:
     *
	Address         Name			Data			Type
	0xbffffffc      argv[3][...]    "bar\0"			char[4]
	0xbffffff8      argv[2][...]    "foo\0"			char[4]
	0xbffffff5      argv[1][...]    "-l\0"			char[3]
	0xbfffffed      argv[0][...]    "/bin/ls\0"		char[8]
	0xbfffffec      word-align      0				uint8_t
	0xbfffffe8      argv[4]         0				char *
	0xbfffffe4      argv[3]         0xbffffffc		char *
	0xbfffffe0      argv[2]         0xbffffff8		char *
	0xbfffffdc      argv[1]         0xbffffff5		char *
	0xbfffffd8      argv[0]         0xbfffffed		char *
	0xbfffffd4      argv            0xbfffffd8		char **
	0xbfffffd0      argc            4				int
	0xbfffffcc      return address  0				void (*) ()

no argument:
	Address         Name			Data			Type
	0xbffffff0      argv[0][...]    "args-none\0"	char[8]
	0xbfffffec      word-align      0				uint8_t
	0xbfffffdc      argv[1]         0				char *
	0xbfffffd8      argv[0]         0xbfffffed		char *
	0xbfffffd4      argv            0xbfffffd8		char **
	0xbfffffd0      argc            1				int
	0xbfffffcc      return address  0				void (*) ()
	*/

    /* get stack pointer */
    void* esp = if_.esp;
    void* initial_esp = esp; /* debug */


  //  printf("Start copying %i arguments to stack. ESP: %x\n", argument_count, (unsigned) esp);

    /* loop variables */
    int j;
    const void * src;
    unsigned size;

//    printf("push argument values\n");

    /* push argument values on stack */
    for (j = argument_count - 1; j >= 0; j--)
    {
            /* fetch argument pointer */
            src = (const void *) arguments[j];

            /* get argument size */
            size = strlen(arguments[j]) + 1;

            /* decrement stack pointer */
            esp -= size;

            /* store argument stack pointer */
            arguments[j] = esp;
		
	   // printf("copying %i bytes from  %x to %x\n", size, (unsigned) src, (unsigned) esp);
            
	    /* copy argument */
            memcpy(esp, src, size);
    }

    /* check if stack pointer is word aligned */
    unsigned fragmentation = ((unsigned) esp) % 4;
    if(fragmentation != 0)
    {
            /* if not, make it! */
            esp -= fragmentation;
    }

    /* stack pointer has to be word aligned */
    ASSERT(((unsigned)esp) % 0x4 == 0);

//    printf("copy sparator\n");
    /* copy separator to stack */
    esp -= 4;
    uint32_t seperator = 0x0;
    memcpy(esp, (void *)&seperator, sizeof(uint32_t));

    /* psuh argument addresses on stack */
    for (j = argument_count - 1; j >= 0; j--)
    {
            /* decrement esp */
            esp -= sizeof(uint32_t);

            /* save argv pointer */
            *((uint32_t *) esp) = (uint32_t) arguments[j];
    }

    /* push argv (address of arguments[0]) on the stack */
    esp -= sizeof(uint32_t);
    *((uint32_t *) esp) = (uint32_t) esp + sizeof(uint32_t);

    /* push argc on the stack */
    esp -= sizeof(uint32_t);
    *((uint32_t *) esp) = (uint32_t) argument_count;

    /* push return address on the stack */
    esp -= sizeof(uint32_t);
    *((uint32_t *) esp) = (uint32_t) 0;

//    printf("Finished copying arguments on stack.\n");

    /* debugging */
    //hex_dump((uintptr_t) 0, esp, (unsigned) initial_esp - (unsigned) esp, true);

    /* update frame esp */
    if_.esp = esp;

    /* free resources */
    free(command_line_input_copy);

    /* initialization complete */
   	struct child * c = process_get_child(thread_current()->parent, thread_current()->tid);
    c->init_success = true;
    sema_up(&c->initialized);

	/* Start the user process by simulating a return from an
	 interrupt, implemented by intr_exit (in
	 threads/intr-stubs.S).  Because intr_exit takes all of its
	 arguments on the stack in the form of a `struct intr_frame',
	 we just point the stack pointer (%esp) to our stack frame
	 and jump to it. */
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	/* get child element */
	struct child *child = process_get_child(thread_current(), child_tid);

	if(DEBUG_EXIT) printf("thread %i waiting for %i to complete ...\n", thread_current()->tid, child_tid);

	/* if child is still active, wait for process completion */
	if(child != NULL && child->parent == thread_current())
	{
		/* wait to decrement waiting semaphore */
		sema_down(&child->terminated);

		if(DEBUG_EXIT) printf("thread %i progresses. child %i has completed.\n", thread_current()->tid, child_tid);
		/* fetch exit status */
		int exit_status = child->exit_status;

		/* remove terminated child from list */
		list_remove(&child->elem);
		
		/* free resources */
		free(child);

		/* return exit status */
		return exit_status;

	} else {

		if(DEBUG_EXIT) printf("thread %i progesses. no such child exists.\n", thread_current()->tid);
		/* no child */
		return -1;
	}
}

/* Free the current process's resources. */
void
process_exit (void)
{
	struct thread *cur = thread_current ();
	uint32_t *pd;

	/* get file system mutex */
	if(!lock_held_by_current_thread(&filesystem_lock))
		lock_acquire(&filesystem_lock);
	
	/* close all open files and empty file list */
	while(!list_empty(&thread_current()->file_descriptors))
	{
		/* get current list element */
		struct list_elem *e = list_pop_front(&thread_current()->file_descriptors);

		/* get file descriptor element */
		struct file_descriptor_elem *fde = list_entry(e, struct file_descriptor_elem, elem);

		/* close file */
		file_close(fde->file);

		/* remove element from list */
		list_remove(&fde->elem);

		/* free file descriptor element */
		free(fde);
	}

	/* release file system mutex */
	lock_release(&filesystem_lock);

	/* empty children list */
	while(!list_empty(&thread_current()->children))
	{
		/* get current list element */
		struct list_elem *e = list_pop_front(&thread_current()->children);

		/* get child */
		struct child *c = list_entry(e, struct child, elem);

		/* remove child from list */
		list_remove(&c->elem);

		/* free child element */
		free(c);
	}

	/* Destroy the current process's page directory and switch back
	 to the kernel-only page directory. */
	pd = cur->pagedir;
	if (pd != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		cur->pagedir to NULL before switching page directories,
		so that a timer interrupt can't switch back to the
		process page directory.  We must activate the base page
		directory before destroying the process's page
		directory, or our active page directory will be one
		that's been freed (and cleared). */
		cur->pagedir = NULL;
		pagedir_activate (NULL);
		pagedir_destroy (pd);
	}

	/* try to get child element of current thread */
	struct child *list_element = process_get_child(cur->parent, cur->tid);
	if(DEBUG_EXIT) printf("process exit - parent: %i - child: %i", cur->parent->tid, cur->tid);

	/* save changes to parent children list */
	if(list_element != NULL)
	{
		/* set exit status */
		list_element->exit_status = cur->exit_status;

		/* increment semaphore initialized */
		sema_up(&list_element->initialized);

		/* increment termination semaphore */
		sema_up(&list_element->terminated);

		if(DEBUG_EXIT) printf("increased semaphore for process %i", cur->tid);
	} else {
		if(DEBUG_EXIT) printf("coult not find child element for process %s", cur->name);
	}


	if(DEBUG_EXIT) printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>> TRY TO CLOSE FILE\n");
	/* end executable file protection */
	if(cur->executable != NULL){
		if(DEBUG_EXIT) printf("closing executable file\n");
		file_allow_write(cur->executable);
		file_close(cur->executable);
	} else {
		if(DEBUG_EXIT) printf("FILE NOT FOUND\n");
	}
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

 /* Close file if something went wrong,
  * deny writes on the file if everthing's fine. */
  if(!success)
	  file_close (file);
  else {
	  t->executable = file;
	  file_deny_write(file);
  }

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = get_user_page(0x0);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          free_user_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          free_user_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = get_user_page (PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        free_user_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/*
 * Find child with id child_id.
 */
struct child*
process_get_child(struct thread* parent, tid_t child_tid)
{
	if(DEBUG_EXIT) printf("searchin child %i in parent %i - ", (unsigned) child_tid, parent->tid);

	/* list of child threads */
	struct list* children = &(parent->children);

	/* loop variables */
	struct list_elem *e;
	struct child *c = NULL;

	/* search child with tid child_tid and return its termination semaphore */
	for (e = list_begin (children); e != list_end (children); e = list_next (e))
	{
			c = list_entry (e, struct child, elem);

			if(DEBUG_EXIT)printf("|%i-%i| ", c->tid, child_tid);

			if(c->tid == child_tid)
			{
					if(DEBUG_EXIT) printf("found.\n");
					return c;
			}
	}

	if(DEBUG_EXIT) printf("not found.\n");

	return NULL;
}

