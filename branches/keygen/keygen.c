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
#include <glib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>

/*
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
*/


#define BUFFSIZE 20
#define CHARSIZE 256
#define OFFSET 0

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes.
unsigned int otp_generate_key_pair(const char* alice,const char* bob,const char* path,const char* source, unsigned int size);
*/

// Definition for the funcions and global variables. => Has to be moved into the header file later
unsigned char bit2char(short buf[8]);
gpointer devrand(gpointer data);
gpointer audio(gpointer data);
gpointer stub(gpointer data);
gpointer threads(gpointer data);
gpointer sysstate(gpointer data);
gpointer mutex = NULL;


/*
*	The main function starts the threads which collect entropie from different sources.
*/
int main() {
	GThread *p1, *p2, *p3, *p4;	 	 		// define threads
	int number;

	number = 100000;
	g_thread_init(NULL);
	mutex = g_mutex_new();		// create mutex

// create threads
	if((p2 = g_thread_create(devrand, &number, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/random\n");
	if((p1 = g_thread_create(audio, &number, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/audio\n");
	if((p3 = g_thread_create(threads, &number, TRUE, NULL)) != NULL) g_print("collecting entropy from thread timing\n");
	if((p4 = g_thread_create(sysstate, &number, TRUE, NULL)) != NULL) g_print("collecting entropy from system state\n");

// wait for threads to return
	g_thread_join (p1);
	g_thread_join (p2);
	g_thread_join (p3);
	g_thread_join (p4);

// destroy mutex
	g_mutex_free(mutex);

	return 0;
} // end main();


/*
* function which takes an array of 8 bits, and output an ascii char. The buf array should only contain
* 0 or 1, else the return value is not usefule
*/
unsigned char bit2char(short buf[8]) {
	short i,l,in;
	unsigned char out;
	l = 1;
	in = 0;
	for(i = 0; i < 8; i++) {
		in += buf[i] * l;
		l *= 2;
	}
	out = (unsigned char)in;
	return out;
} // end bit2char()


/*
* devrand() collects entropie from the /dev/random device and writes it into a keyfile
*/
gpointer devrand(gpointer data) {
	int fd1, file;
	unsigned char c1;
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fd1 = open("/dev/random", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/random \n");
		return 0;
	}
	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		g_printerr("could not open keyfile \n");
		return 0;
	}

	size = 0;
	while(1) {
		if(read(fd1, &c1, 1) < 0) {
			g_print("read error");
		}

		buffer[size] = (unsigned char)((c1 % CHARSIZE) + OFFSET);
		size++;

		if(size == BUFFSIZE) {
			g_mutex_lock(mutex);
			if(*((int *)(data)) < size) {
				g_mutex_unlock(mutex);
				break;
			}
			if(write(file, &buffer, BUFFSIZE) < 0) {
				g_printerr("write error");
				return 0;
			}
			*((int *)(data)) -= size;
			g_mutex_unlock(mutex);
			size = 0;
			usleep(5);
		}
	}

	close(fd1);
	close(file);
	return 0;
} // end devrand()


/*
*	a helper function for the threads function
*/
gpointer stub(gpointer data) {
	return 0;
} // end stub ()


/*
*	threads() collects entropie from thread timing, by just mesuring the time it takes
*	to open and close the stub() thread. This function takes one sample every second
* 	and writes the entropie to the keyfile
*/
gpointer threads(gpointer data) {
	short i;
	unsigned char diff;
	struct timeval start, finish;
	int file;
	GThread *tid;

	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		g_printerr("could not open keyfile \n");
		return 0;
	}

	while(1) {
		gettimeofday(&start, NULL);
		for(i = 0; i < 100; i++) {
			if((tid = g_thread_create(stub, NULL, TRUE, NULL)) != NULL) g_thread_join(tid);
		}
		gettimeofday(&finish, NULL);
		diff = (unsigned char)(((finish.tv_usec - start.tv_usec) % CHARSIZE) + OFFSET);

		g_mutex_lock(mutex);
		if(*((int *)(data)) == 0) {
			g_mutex_unlock(mutex);
			break;
		}
		if(write(file, &diff, 1) < 0) {
			g_printerr("write error");
			return 0;
		}
		(*((int *)(data)))--;
		g_mutex_unlock(mutex);

		sleep(1);
	}

	close(file);
	return 0;
} // end threads()


/*
	audio() collect entropie from /dev/audio and xor it with a value from /dev/urandom to
	get a better distribution even if no sound is running.
	This function generates one bit of entropie out of 7 samples, generates an ascii char
	and write this to the keyfile
*/
gpointer audio(gpointer data) {
	int fd, fd1, file;
	short i;
	unsigned char c, d, oldc;
	short buf[8];
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fd = open("/dev/audio", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/audio \n");
		return 0;
	}
	if((fd1 = open("/dev/urandom", O_RDONLY)) < 0) {
		g_printerr("could not opne /dev/urandom \n");
		return 0;
	}
	if((file = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		g_printerr("could not open keyfile \n");
		return 0;
	}

	i = 0;
	size = 0;

	while(1) {
		if(read(fd, &c, 1) < 0) return 0;
		buf[i] = ((unsigned short)c) % 2;
		i++;
		if(i == 8) {
			if(read(fd1, &d, 1) < 0) {
				g_printerr("read error");
				return 0;
			}
			c = bit2char(buf);
			if(c == oldc) usleep(500);
			oldc = c;
			buffer[size] = (unsigned char)(((d  ^ c) % CHARSIZE) + OFFSET);
			size++;
			if(size == BUFFSIZE) {
					g_mutex_lock(mutex);
					if(*((int *)(data)) < size) {
						g_mutex_unlock(mutex);
						break;
					}
					if(write(file, &buffer, BUFFSIZE) < 0) {
						g_printerr("write error");
						return 0;
					}
					*((int *)(data)) -= size;
					g_mutex_unlock(mutex);
					size = 0;
			}
			i = 0;
			usleep(5);
		}
	}
	close(fd);
	close(fd1);
	close(file);
	return 0;
} // end audio()

gpointer sysstate(gpointer data) {
	int minflt, fp, who;
	double systime, usertime;
	unsigned int result = 0, old_result = 0;
	char c;
	struct rusage usage;
	who = RUSAGE_SELF;

	fp = open("keyfile",O_RDWR|O_CREAT|O_APPEND,00644);

	while (1) {
		getrusage(who, &usage);
		usleep(500);
		minflt = usage.ru_minflt;
		systime = usage.ru_stime.tv_sec*1000000+usage.ru_stime.tv_usec;
		usertime = usage.ru_utime.tv_sec*1000000+usage.ru_utime.tv_usec;
		result = minflt + (unsigned int)systime + (unsigned int)usertime;
		result %= 256;

		if(result  != old_result) {
			c = (char)result;
			g_mutex_lock(mutex);

			if(*((int *)(data)) == 0) {
				g_mutex_unlock(mutex);
				break;
			}

			write(fp, &c, 1);
			(*((int *)(data)))--;
			g_mutex_unlock(mutex);
		}
		old_result = result;
	}
	close(fp);
	return 0;
}
