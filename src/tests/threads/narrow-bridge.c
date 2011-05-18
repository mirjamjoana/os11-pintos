#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/random.h"

/* constants */
#define BRIDGE_CAPACITY 3
#define LEFT_TO_RIGHT 0
#define RIGHT_TO_LEFT 1
#define NORMAL 0
#define EMERGENCY 1

#define MAX_SLEEPTIME 10


void narrow_bridge(unsigned int num_vehicles_left, unsigned int num_vehicles_right,
        unsigned int num_emergency_left, unsigned int num_emergency_right);

void init_bridge(void);

void left_vehicle(void *aux UNUSED);
void right_vehicle(void *aux UNUSED);
void left_emergency_vehicle(void *aux UNUSED);
void right_emergency_vehicle(void *aux UNUSED);
void one_vehicle(int direc, int prio);

void arrive_bridge(int direc, int prio);
void cross_bridge(int direc, int prio);
void exit_bridge(int direc, int prio);

void print_stats(void);

/*
 * semaphores & global variables
 * necessary to ensure mutual exclusion
 */
static struct semaphore bridge; /* has BRIDGE_CAPACITY slots */
static struct semaphore mutex; /* binary mutex semaphore */
static struct semaphore emergency_vehicles_left; /* number of emergency vehicles waiting on the left side */
static struct semaphore emergency_vehicles_right; /* number of emergency vehicles waiting on the right side */

static int current_direction = LEFT_TO_RIGHT; /* current driving direction of the bridge traffic */

/* counting variables */
static struct semaphore vehicles_left;
static struct semaphore vehicles_right;

void test_narrow_bridge(void)
{
	init_bridge();

    narrow_bridge(0, 0, 0, 0);
    narrow_bridge(1, 0, 0, 0);
    narrow_bridge(0, 0, 0, 1);
    narrow_bridge(0, 4, 0, 0);
    narrow_bridge(0, 0, 4, 0);
    narrow_bridge(3, 3, 3, 3);
    narrow_bridge(4, 3, 4 ,3);
    narrow_bridge(7, 23, 17, 1);
    narrow_bridge(40, 30, 0, 0);
    narrow_bridge(30, 40, 0, 0);
    narrow_bridge(23, 23, 1, 11);
    narrow_bridge(22, 22, 10, 10);
    narrow_bridge(0, 0, 11, 12);
    narrow_bridge(0, 10, 0, 10);
    narrow_bridge(0, 10, 10, 0);
    pass();
}

/* initializes semaphores */
void init_bridge(void){

	/* seed the random number generator */
	random_init((unsigned int)123456789);

	/* initialize bridge slots & mutex */
	sema_init(&bridge, BRIDGE_CAPACITY);
	sema_init(&mutex, 1);

	/* initialize counting semaphores */
	sema_init(&emergency_vehicles_left, 0);
	sema_init(&emergency_vehicles_right, 0);
	sema_init(&vehicles_left, 0);
	sema_init(&vehicles_right, 0);
}

/*
 * Creates a narrow bridge scenario with num_vehicles_left + num_emergency_left
 * on the left side and num_vehicles_right + num_emergency_right vehicles on the
 * right side.
 *
 * Every vehicle is represented by its own thread. Vehicles arrive at a bridge (1),
 * cross the bridge (2) and leave the bridge (3).
 */
void narrow_bridge(unsigned int num_vehicles_left, unsigned int num_vehicles_right,
        unsigned int num_emergency_left, unsigned int num_emergency_right)
{
	/* local variables */
	unsigned int i;

	/* create left vehicle threads */
	for(i = 0; i < num_vehicles_left; i++)
		thread_create("vehicle_left", 1, left_vehicle, NULL);

	/* create left emergency vehicle threads */
	for(i = 0; i < num_emergency_left; i++)
		thread_create("em_vehicle_left", 1, left_emergency_vehicle, NULL);

	/* create right vehicle threads */
	for(i = 0; i < num_vehicles_right; i++)
		thread_create("vehicle_right", 1, right_vehicle, NULL);

	/* create right emergency vehicle threads */
	for(i = 0; i < num_emergency_right; i++)
		thread_create("em_vehicle_right", 1, right_emergency_vehicle, NULL);
}

/* normal vehicle, driving direction left to right */
void left_vehicle(void *aux UNUSED){
	int direc = LEFT_TO_RIGHT;
	int prio = NORMAL;
	one_vehicle(direc, prio);
}

/* emergency vehicle, driving direction left to right */
void left_emergency_vehicle(void *aux UNUSED){
	int direc = LEFT_TO_RIGHT;
	int prio = EMERGENCY;
	one_vehicle(direc, prio);
}

/* normal vehicle, driving direction right to left */
void right_vehicle(void *aux UNUSED){
	int direc = RIGHT_TO_LEFT;
	int prio = NORMAL;
	one_vehicle(direc, prio);
}

/* emergency vehicle, driving direction right to left */
void right_emergency_vehicle(void *aux UNUSED){
	int direc = RIGHT_TO_LEFT;
	int prio = EMERGENCY;
	one_vehicle(direc, prio);
}

/* abstract vehicle with direction direc and priority prio*/
void one_vehicle(int direc, int prio) {
  arrive_bridge(direc,prio);
  cross_bridge(direc,prio);
  exit_bridge(direc,prio);
}

/* vehicle arrives at bridge and tries to enter it */
void arrive_bridge(int direc, int prio) {

	/* local variables */
	struct semaphore *vehicle_list = NULL;

	/* save a pointer to our own waiting list */
	if(prio == EMERGENCY) {
		if(direc == LEFT_TO_RIGHT){
			vehicle_list = &emergency_vehicles_left;
		} else {
			vehicle_list = &emergency_vehicles_right;
		}
	}
	/* for statistical purpose only */
	else {
		if(direc == LEFT_TO_RIGHT){
			vehicle_list = &vehicles_left;
		} else {
			vehicle_list = &vehicles_right;
		}
	}

	sema_up(vehicle_list);

	/* if the current driving direction is contrary to ours */
	while(true) {

		/* enter critical section */
		sema_down(&mutex);

		/*
		 * if no one is on the bridge or the direction is already ours
		 * and we are an emergency vehicle or no emergency vehicle is waiting
		 */
		if((bridge.value == BRIDGE_CAPACITY || current_direction == direc)
			&& (prio == EMERGENCY || (emergency_vehicles_left.value +emergency_vehicles_right.value) == 0))
		{

			/* change direction to ours */
			current_direction = direc;

			/* decrement free bridge slots */
			sema_down(&bridge);

			/* decrement our vehicle waiting list */
			sema_down(vehicle_list);

			/* leave critical section */
			sema_up(&mutex);

			break;
		}

		/* leave critical section */
		sema_up(&mutex);

		//give others a chance, maybe they have more luck
		thread_yield();
	}
}

/* vehicle enters the bridge drives through the end */
/* wait 0 - MAX_SLEEPTIME (default: 10) CPU ticks for passing the bridge */
void cross_bridge(int direc UNUSED, int prio UNUSED) {

	/* generate random between 0 and MAX_SLEEPTIME */
	unsigned int random = (unsigned int)random_ulong();
	random = random % MAX_SLEEPTIME;

	/* sleep 0-MAX_SLEEPTIME ticks */
	thread_sleep((int64_t)random);
}

/* vehicle leaves the bridge */
void exit_bridge(int direc UNUSED, int prio UNUSED) {

	/* finally, we have to increment the slots available for passing the bridge*/
	sema_up(&bridge);
}

/* prints the current vehicle and bridge status */
void print_stats() {
	char c;
	if(current_direction == LEFT_TO_RIGHT)
		c = '>';
	else
		c = '<';

		printf("|VL %i\t|EVL %i\t|B\t%c%i%c\t|EVR %i\t|VR %i\t|\n",
				vehicles_left.value, emergency_vehicles_left.value,
				c, BRIDGE_CAPACITY-bridge.value, c,
				emergency_vehicles_right.value, vehicles_right.value );

}
