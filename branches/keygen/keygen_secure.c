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


#include <glib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <string.h>

#define BUFFSIZE 20
#define CHARSIZE 256
#define OFFSET 0

/* Private data struct */
struct _entropy {
	int length;
	char pool[10];
} entropy;

// Definition for the funcions and global variables. => Has to be moved into the header file later
unsigned char bit2char(short buf[8]);
gpointer devrand(gpointer data);
gpointer audio(gpointer data);
gpointer stub(gpointer data);
gpointer threads(gpointer data);
gpointer sysstate(gpointer data);
gpointer prng(gpointer data);
gpointer mutex = NULL;


/*
*	The main function starts the threads which collect entropie from different sources.
*/
int main() {
	GThread *p1, *p2, *p3, *p4;	 	 		// define threads
#ifdef FAST
	GThread *p5;
#endif
	int length;

	entropy.length = 100000;
	length = entropy.length;
	// initalize pool
	memset(entropy.pool,'\0',10);

	g_thread_init(NULL);
	mutex = g_mutex_new();		// create mutex

// create threads
	if((p2 = g_thread_create(devrand, &length, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/random\n");
	if((p1 = g_thread_create(audio, &length, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/audio\n");
	if((p3 = g_thread_create(threads, &length, TRUE, NULL)) != NULL) g_print("collecting entropy from thread timing\n");
	if((p4 = g_thread_create(sysstate, &length, TRUE, NULL)) != NULL) g_print("collecting entropy from system state\n");
#ifdef FAST
	if((p5 = g_thread_create(prng, &length, TRUE, NULL)) != NULL) g_print("collecting entropy from PRNG\n");
#endif

// wait for threads to return
	g_thread_join (p1);
	g_thread_join (p2);
	g_thread_join (p3);
	g_thread_join (p4);
#ifdef FAST
	g_thread_join (p5);
#endif

// destroy mutex
	g_mutex_free(mutex);

	return 0;
} // end main();


unsigned char bit2char(short buf[8])
/*
* function which takes an array of 8 bits, and output an ascii char. The buf array should only contain
* 0 or 1, else the return value is not usefule
*/
{
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


gpointer devrand(gpointer data)
/*
* devrand() collects entropie from the /dev/random device and writes it into a keyfile
*/

{
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
			g_print("read error\n");
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
				g_printerr("write error\n");
				return 0;
			}
			*((int *)(data)) -= size;
			g_mutex_unlock(mutex);
			size = 0;
		}
		usleep(5);
	}

	close(fd1);
	close(file);
	return 0;
} // end devrand()


gpointer stub(gpointer data)
/*
*	a helper function for the threads function
*/
{
	return 0;
} // end stub ()


gpointer threads(gpointer data)
/*
*	threads() collects entropie from thread timing, by just mesuring the time it takes
*	to open and close the stub() thread. This function takes one sample every second
* 	and writes the entropie to the keyfile
*/
{
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
			g_printerr("write error\n");
			return 0;
		}
		(*((int *)(data)))--;
		g_mutex_unlock(mutex);

		sleep(1);
	}

	close(file);
	return 0;
} // end threads()


gpointer audio(gpointer data)
/*
	audio() collect entropie from /dev/audio and xor it with a value from /dev/urandom to
	get a better distribution even if no sound is running.
	This function generates one bit of entropie out of 7 samples, generates an ascii char
	and write this to the keyfile
*/
{
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
			g_mutex_lock(mutex);
			if(read(fd1, &d, 1) < 0) {
				g_printerr("read error\n");
				g_mutex_unlock(mutex);
				return 0;
			}
			g_mutex_unlock(mutex);
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
						g_printerr("write error\n");
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


gpointer sysstate(gpointer data)
/*
*	sysstate() collects entropy by adding up system time user time and minor pagefaults and generates one byte of entropy
*	if the current state is different from the last state. Because I use microseconds as measurement, the time depends on
*	the CPU strenght and only the time of the current program is measured the output is not predictable or manipulatable
*	from outside.
*/
{
	int minflt, fp, who;
	double systime, usertime;
	unsigned int result = 0, old_result = 0;
	char c;
	struct rusage usage;
	who = RUSAGE_SELF;

	fp = open("keyfile", O_RDWR|O_CREAT|O_APPEND, 00644);

	while (1) {
		getrusage(who, &usage);
		usleep(500);
		minflt = usage.ru_minflt;
		systime = usage.ru_stime.tv_sec*1000000+usage.ru_stime.tv_usec;
		usertime = usage.ru_utime.tv_sec*1000000+usage.ru_utime.tv_usec;
		result = minflt + (unsigned int)systime + (unsigned int)usertime;
		result = (result % CHARSIZE) + OFFSET;

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
} //end sysstat()


gpointer prng(gpointer data)
/*
*	prng gets entropy from the pseudorandom number generator /dev/urandom
*/
{
	int fp_file, fp_prng;
	unsigned short c;

	if((fp_file = open("keyfile", O_RDWR|O_CREAT|O_APPEND, 00644)) < 0) {
		g_printerr("could not open keyfile\n");
		return 0;
	}

	if((fp_prng = open("/dev/urandom", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/urandom\n");
		return 0;
	}

	while(1) {
		g_mutex_lock(mutex);
		if(read(fp_prng, &c, 1) != 1) {
			g_printerr("read error\n");
			g_mutex_unlock(mutex);
			return 0;
		}
		g_mutex_unlock(mutex);

		c = (c % CHARSIZE) + OFFSET;

		g_mutex_lock(mutex);
		if(*((int *)(data)) == 0) {
			g_mutex_unlock(mutex);
			break;
		}
		if(write(fp_file, &c, 1) != 1) {
			g_printerr("write error\n");
			g_mutex_unlock(mutex);
			return 0;
		}
		(*((int *)(data)))--;
		g_mutex_unlock(mutex);


		usleep(5);
	}

	close(fp_file);
	close(fp_prng);
	return 0;
} // end prng()
