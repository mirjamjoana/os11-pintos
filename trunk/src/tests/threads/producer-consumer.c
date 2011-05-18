/*
 * Tests producer/consumer communication with different numbers of threads.
 * Automatic checks only catch severe problems like crashes.
 */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "devices/timer.h"

#define TEXT "Hello world"
#define SIZE 11 /* word count without NULL */

void init_producer_consumer(void);
void producer_consumer(unsigned int num_producer, unsigned int num_consumer);
void producer(void *aux UNUSED);
void consumer(void *aux UNUSED);

/* buffer variables */
static char text[] = TEXT;

/* the bounded buffer */
static char buffer[SIZE];

/* buffer positions */
static int head = 0;
static int tail = 0;
static int wrap = 0;

/* locks */
static struct lock mutex;

/* condition */
static struct condition not_full;
static struct condition not_empty;

/*
 * The test method
 */
void
test_producer_consumer(void)
{
	/* initialize the scenario */
	init_producer_consumer();

	/* generate producers & consumers */
    producer_consumer(0, 0);
    producer_consumer(1, 0);
    producer_consumer(0, 1);
    producer_consumer(1, 1);
    producer_consumer(3, 1);
    producer_consumer(1, 3);
    producer_consumer(4, 4);
    producer_consumer(7, 2);
    producer_consumer(2, 7);
    producer_consumer(6, 6);

    /* 'think we've passed */
    pass();
}

/*
 *  Initializes the producer and consumer
 *  monitor variables
 */
void
init_producer_consumer(void) {

	/* monitor lock */
	lock_init(&mutex);

	/* buffer conditions */
	cond_init(&not_empty);
	cond_init(&not_full);
}

/*
 * Creates num_producer producer and num_consumer consumer threads
 */
void
producer_consumer(unsigned int num_producer, unsigned int num_consumer)
{
	/* loop variables */
	unsigned int i;
	
		/* create consumer */
    for(i = 0; i < num_consumer; i++)
	{
		thread_create ("consumer", 1, consumer, &mutex);
	}

	/* create producer */
    for(i = 0; i < num_producer; i++)
	{
		thread_create ("producer", 1, producer, &mutex);
	}
}


/*
 * Consumes all characters placed in the buffer
 * buffer, and waits if there is nothing more to consumer.
 */
void
consumer(void *aux UNUSED){
	char c;

	/* as long as there are characters in the buffer */
	while(true)
	{
		/* enter critical section */
		lock_acquire(&mutex);
		
		/* check if there is a character left in the buffer */
		while (head == tail && wrap == 0)
		{
			/* if no character is left, inform the producer threads
			 to get work done and wait until a character has been placed */
			cond_broadcast(&not_full, &mutex);
			cond_wait(&not_empty, &mutex);
		}

		/* take a character from the buffer */
		c = buffer[tail];

		/* update read pointer */
		tail = (tail+1) % SIZE;

		/* check if we have had a wrap-around */
		if(tail == 0) {
			wrap--;
		}

		/* check that there isn't more than a single wrap-around
		 of the head pointer */
		ASSERT(wrap == 0 || wrap == 1)
		
		/* inform the producer threads that the buffer is not full (anymore) */
		cond_broadcast(&not_full, &mutex);

		/* leave the critical section */
		lock_release(&mutex);
	}
};

/*
 * Produces characters based on the string text
 * and puts them into the buffer buffer.
 *
 * Terminates when all characters have been placed in the buffer.
 */
void
producer(void *aux UNUSED){
	/* local variables */
	int position = 0;
	char c;

	/* as long as we have characters to produce */
	while(text[position] != '\0'){
		
		/* enter critical section */
		lock_acquire(&mutex);

		/* check if buffer is full */
		while (head == tail && wrap == 1)
		{
			/* state that the buffer is not empty and wait
			  for consumer to free a slot of the buffer */
			cond_broadcast(&not_empty, &mutex);
			cond_wait(&not_full, &mutex);
		}

		/* fetch the next character from the text
		 and save it to the buffer */
		c = text[position];
		buffer[head] = c;
		
		/* update the writer & reader positions */
		head = (head + 1) % SIZE;
		position++;
		
		/* check if we have a wrap-around */
		if(head == 0) {
			wrap++;
		}
		
		/* assert that the head can only be one
		 wrap-around in front of tail */
		ASSERT(wrap == 0 || wrap == 1)

		/* wake up consumers, state that the buffer is not
		 empty any more */
		cond_broadcast(&not_empty, &mutex);

		/* leave critical section */
		lock_release(&mutex);
	}
};
