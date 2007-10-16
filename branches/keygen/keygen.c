/*
    Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
    Copyright (C) 2007  Simon Wenner, Christian Wäckerlin, Pascal Sachs

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


// pthread.h has to be included first
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>


#define BUFFSIZE 20
#define CHARSIZE 96
#define OFFSET 32

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes.
unsigned int otp_generate_key_pair(const char* alice,const char* bob,const char* path,const char* source, unsigned int size);
*/

// Definition for the funcions and global variables. => Has to be moved into the header file later
unsigned char bit2char(short buf[7]);
void *devrand();
void *audio();
void *threads();
void *numofbytes();
static void *stub(void *arg);
pthread_mutex_t mutex;
int number;


/*
*	The main function starts the threads which collect entropie from different sources.
*/
int main() {
	pthread_t p1, p2, p3, p4; 		// define threads
	number = 0;
	pthread_mutex_init(&mutex, NULL);		// create mutex
	

// create threads
	if(pthread_create (&p2, NULL, devrand, NULL) >= 0) printf("collecting entropie from /dev/random\n");

	if(pthread_create (&p1, NULL, audio, NULL) >= 0) printf("collecting entropie from /dev/audio\n");
	
	if(pthread_create (&p3, NULL, threads, NULL) >= 0) printf("collecting entropie from thread timing\n");

	pthread_create (&p4, NULL, numofbytes, NULL);

// wait for threads to return
	pthread_join (p1, NULL);
	pthread_join (p2, NULL);
	pthread_join (p3, NULL);
	pthread_join (p4, NULL);

// destroy mutex
	pthread_mutex_destroy(&mutex);

	return 0;
} // end main();


/*
* function which takes an array of 7 bits, and output an ascii char. The buf array should only contain
* 0 or 1, else the return value is not usefule
*/
unsigned char bit2char(short buf[7]) {
	short i,l,in;
	unsigned char out;
	l = 1;
	in = 0;
	for(i = 0; i < 7; i++) {
		in += buf[i] * l;
		l *= 2;
	}
	out = (unsigned char)in;
	return out;
} // end bit2char()


void *numofbytes() {
	while(1) {	
		printf("%i Bytes im File\n", number);
		sleep(5);
	}
}

/*
* devrand() collects entropie from the /dev/random device and writes it into a keyfile
*/
void *devrand() {
	int fd1, file;
	unsigned char c1;
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fd1 = open("/dev/random", O_RDONLY)) < 0) {
		printf("could not open /dev/random \n");
		return 0;
	}
	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		printf("could not open keyfile \n");
		return 0;
	}
	
	size = 0;
	while(1) {
		if(read(fd1, &c1, 1) < 0) {
			printf("read error");
		}
		
		buffer[size] = (unsigned char)((c1 % CHARSIZE) + OFFSET);
		size++;
		
		if(size == BUFFSIZE) {
			pthread_mutex_lock(&mutex);
			if(write(file, &buffer, BUFFSIZE) < 0) {
				printf("write error");
				return 0;
			}
		//	printf("Random: %s\n", buffer);
			number += size;
			pthread_mutex_unlock(&mutex);
			size = 0;
			usleep(5);
		}
	}
	
	close(fd1);
	close(file);
} // end devrand()


/*
*	a helper function for the threads function
*/
static void *stub(void *arg) {
	return 0;
} // end stub ()


/*
*	threads() collects entropie from thread timing, by just mesuring the time it takes
*	to open and close the stub() thread. This function takes one sample every second
* 	and writes the entropie to the keyfile
*/
void *threads() {
	short i;
	unsigned char diff;
	struct timeval start, finish;
	int file;
	pthread_t tid;

	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		printf("could not open keyfile \n");
		return 0;
	}

	while(1) {
		gettimeofday(&start, NULL);
		for(i = 0; i < 100; i++) {
			if(pthread_create(&tid, 0, stub, 0) >= 0) pthread_join(tid, 0);
		}
		gettimeofday(&finish, NULL);
		diff = (unsigned char)(((finish.tv_usec - start.tv_usec) % CHARSIZE) + OFFSET);
		
		pthread_mutex_lock(&mutex);
		if(write(file, &diff, 1) < 0) {
			printf("write error");
			return 0;
		}
		//printf("Threads: %c\n", diff);
		number++;
		pthread_mutex_unlock(&mutex);

		sleep(1);
	}
	
	close(file);
} // end threads()


/*	
	audio() collect entropie from /dev/audio and xor it with a value from /dev/urandom to
	get a better distribution even if no sound is running. 
	This function generates one bit of entropie out of 7 samples, generates an ascii char
	and write this to the keyfile
*/
void *audio() {
	int fd, fd1, file;
	short i;
	unsigned char c, d, oldc;
	short buf[8];
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fd = open("/dev/audio", O_RDONLY)) < 0) {
		printf("could not open /dev/audio \n");
		return 0;
	}
	if((fd1 = open("/dev/urandom", O_RDONLY)) < 0) {
		printf("could not opne /dev/urandom \n");
		return 0;
	}
	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		printf("could not open keyfile \n");
		return 0;
	}

	i = 0;
	size = 0;

	while(1) {
		if(read(fd, &c, 1) < 0) return 0;
		buf[i] = (short)c % 2;
		i++;
		if(c == oldc) usleep(500);
		oldc = c;
		if(i == 7) {
			if(read(fd1, &d, 1) < 0) {
				printf("read error");
				return 0;
			}
			buffer[size] = (unsigned char)(((d  ^ bit2char(buf)) % CHARSIZE) + OFFSET);
			size++;
			if(size == BUFFSIZE) { 
					pthread_mutex_lock(&mutex);
					if(write(file, &buffer, BUFFSIZE) < 0) {
						printf("write error");
						return 0;
					}
				//	printf("Audio: %s \n", buffer);
					number += size;
					pthread_mutex_unlock(&mutex);
					size = 0;
			}
			i = 0;
			usleep(5);
		}
	}
	close(fd);
	close(fd1);
	close(file);
} // end audio()

