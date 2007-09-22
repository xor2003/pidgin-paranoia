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


// Definition for the funcions. Has to be moved into the header file later
char bit2char(short buf[7]);
void *devrand();
void *audio();
void *threads();
static void *stub(void *arg);


// The main function starts the threads which collect entropie from different sources.
int main() {
	pthread_t p1, p2, p3;

	pthread_create (&p2, NULL, devrand, NULL);
	printf("/dev/random sammelt daten\n");

    pthread_create (&p1, NULL, audio, NULL);
	printf("/dev/audio sammelt daten\n");
	
	pthread_create (&p3, NULL, threads, NULL);
	printf("collection entropie from thread timing:\n");

	pthread_join (p1, NULL);
	pthread_join (p2, NULL);
	pthread_join (p3, NULL);

	return 0;
}


// function which takes an array of 7 bits, and output an ascii char
char bit2char(short buf[7]) {
	short i,l,in;
	char out;
	l = 1;
	in = 0;
	for(i=0;i<7;i++) {
		in += buf[i] * l;
		l *= 2;
	}
	out = (char)in;
	return out;
}

// devrand() collects entropie from the /dev/random device and writes it into a keyfile
void *devrand() {
	int fd1, file, n;
	char c1;

	fd1 = open("/dev/random", O_RDONLY);
	file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644);

	while(1) {
		read(fd1, &n, 1);
		c1 = (char)(n % 127);
		write(file, &c1, 1);
		usleep(1);
	}
}

static void *stub(void *arg) {
	return 0;
}

// threads() Collects entropie from thread timing
void *threads() {
	short i;
	char diff;
	struct timeval start, finish;
	pthread_t tid;

	while(1) {
		gettimeofday(&start, NULL);
		for(i = 0; i < 100; i++) {
			if(pthread_create(&tid,0,stub,0) >= 0) pthread_join(tid,0);
		}
		gettimeofday(&finish, NULL);
		diff = (char)((finish.tv_usec - start.tv_usec) % 127);
		printf("%c\n", diff);
		sleep(1);
	}
}

/*	
	audio() collect entropie from /dev/audio and xor it with a value from /dev/urandom to
	get a better distribution even if no sound is running. 
	This function generates one bit of entropie out of 7 samples, generates an ascii char
	and write this to the console.
*/
void *audio() {
	int fd,fd1;
	short i;
	char c, oldc, d;
	short buf[7];

	if((fd = open("/dev/audio", O_RDONLY)) < 0) {
		printf("error! couldn't open device\n");
		abort();
	}
	fd1 = open("/dev/urandom", O_RDONLY);

	i = 0;
	while(1) {
		if(read(fd, &c, 1) < 0) abort();
		if(c != oldc && (short)c >= 0) {
			buf[i] = (short)c % 2;
			i++;
		}
		oldc = c;
		if(i == 7) {
			while((short)d < 0) read(fd1,&d,1);
			d = (d % 127) ^ bit2char(buf);			
			//printf("%c ",d);
			i = 0;
		usleep(1);
		}
	}
}


