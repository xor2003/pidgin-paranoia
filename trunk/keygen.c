/*
    Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
    Copyright (C) 2007-2008  Pascal Sachs

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
#include <stdio.h>
#include <string.h>

// buffer which is stores the bytes before they are written into the keyfile
#define BUFFSIZE 20
// do not change, for developement purpose
#define CHARSIZE 256
#define OFFSET 0


// Definition for the funcions and global variables.
GThread *generate_keys_from_keygen(char *alice, char *bob, unsigned int size, int loop);
GThread *generate_keys_from_file(char *alice, char *bob, char *file, unsigned int size, int loop);
int otp_invert(char *src, char *dest);
int otp_loop_invert(char *src);
unsigned int otp_get_id();
unsigned char bit2char(short buf[8]);
gpointer key_from_file(gpointer data);
gpointer start_generation(gpointer data);
gpointer devrand(gpointer data);
gpointer audio(gpointer data);
gpointer stub(gpointer data);
gpointer threads(gpointer data);
gpointer sysstate(gpointer data);
gpointer prng(gpointer data);
gpointer keygen_mutex = NULL;

// private key data for the threads
struct _key_data {
	int size;
	int loop;
	char *alice, *bob, *file;
} key_data;


int otp_invert(char *src, char *dest)
/*
*	Write the bytewise inverse of src to dest
*	src and dest must be a valide filename with correct path
* 	return 0 for success, -1 if a failure occures
*/
{
	FILE *fpin, *fpout;
	int c;
	long file_length;

	if(src == NULL || dest == NULL) {
		g_printerr("source or destination NULL\n");
		return -1;
	}

	if(strcmp(src,dest) == 0) {
		g_printerr("source and destination same file\n");
		return -1;
	}

	if((fpin = fopen(src, "r")) == NULL) {
		g_printerr("couldn't open source\n");
		return -1;
	}

	if((fpout = fopen(dest, "w")) == NULL) {
		g_printerr("couldn't open destination\n");
		fclose(fpin);
		return -1;
	}

	fseek(fpin, -1, SEEK_END);
	file_length = ftell(fpin);

	while(file_length >= 0) {
		c = fgetc(fpin);
		fputc(c, fpout);
		fseek(fpin, -2, SEEK_CUR);
		file_length--;
	}

	fclose(fpin);
	fclose(fpout);

	return 0;
} // end invert()


int otp_loop_invert(char *src)
/*
*	append inverse of src to src.
*	src must be a valide filename with correct path.
* 	return 0 for success, -1 if a failure occures
*/
{
	FILE *fpin, *fpout;
	int c;
	long file_length;

	if(src == NULL) {
		g_printerr("source NULL\n");
		return -1;
	}

	if((fpin = fopen(src, "r")) == NULL) {
		g_printerr("couldn't open source\n");
		return -1;
	}

	if((fpout = fopen(src, "a")) == NULL) {
		g_printerr("couldn't open source for writing\n");
		fclose(fpin);
		return -1;
	}

	fseek(fpin, -1, SEEK_END);
	file_length = ftell(fpin);

	while(file_length >= 0) {
		c = fgetc(fpin);
		fputc(c, fpout);
		fseek(fpin, -2, SEEK_CUR);
		file_length--;
	}

	fclose(fpin);
	fclose(fpout);

	return 0;
} // end loop_invert()


unsigned int otp_get_id()
/*
*	get a random id from /dev/urandom
*/
{
	int fp_urand;
	unsigned int id;


	if((fp_urand = open("/dev/urandom", O_RDONLY)) < 0 ) {
		g_printerr("device open error\n");
		return 0;
	}

	if(read(fp_urand, &id, sizeof(id)) != sizeof(id)) {
		g_printerr("read error\n");
		close(fp_urand);
		return 0;
	}

	close(fp_urand);

	return id;
} // end get_id()


GThread *generate_keys_from_file(char *alice, char *bob, char *file, unsigned int size, int loop)
/*
*	generate the key pair for alice and bob out of a entropy file
*	alice, bob and file must be correct filenames including the correct absolute path
*	size should be strictly positiv in bytes.
*	loop is zero if it should generate a loop key
*/
{
	GThread *key_file_thread;
	if(alice == NULL || bob == NULL || file == NULL) {
		g_printerr("input NULL\n");
		return NULL;
	}

	key_data.alice = g_strdup(alice);
	key_data.bob = g_strdup(bob);
	key_data.file = g_strdup(file);
	key_data.loop = loop;
	key_data.size = size;

	// initialize g_thread if not already done.
	// The program will abort if no thread system is available!
	if (!g_thread_supported()) g_thread_init (NULL);

	if((key_file_thread = g_thread_create(key_from_file ,NULL, TRUE, NULL)) == NULL) {
		g_printerr("couldn't create thread");
	}

	return key_file_thread;
}

gpointer key_from_file(gpointer data)
/*
*	thread function which creates a keyfile from a file.
*/
{
	FILE *fp_alice, *fp_file;
	unsigned int file_length;
	int c;

	if((fp_file = fopen(key_data.file, "r")) == NULL) {
		g_printerr("couldn't open file for reading\n");
		return NULL;
	}

// check if the entropy file has enough entropy to generate the key
	fseek(fp_file, -1, SEEK_END);
	if((file_length = ftell(fp_file)) < key_data.size) {
		g_printerr("file doesn't have enough entropy\n");
		fclose(fp_file);
		return NULL;
	}
	rewind(fp_file);

	if((fp_alice = fopen(key_data.alice, "w")) == NULL) {
		g_printerr("couldn't open keyfile alice for writing\n");
		fclose(fp_file);
		return NULL;
	}

	while(key_data.size > 0) {
		c = fgetc(fp_file);
		fputc(c, fp_alice);
		key_data.size--;
	}

	fclose(fp_file);
	fclose(fp_alice);

	if(key_data.loop == 0) {
		otp_loop_invert(key_data.alice);
	} else otp_invert(key_data.alice, key_data.bob);

	return 0;
}


GThread *generate_keys_from_keygen(char *alice, char *bob, unsigned int size, int loop)
/*h
*	generate the key pair for alice and bob
*	alice and bob must be the correct filenames including the correct absoute path.
*	Size should be strictly positiv in bytes.
*/
{
	GThread *key_thread;

// check if the function inputs are correct
	if(alice == NULL) {
		g_printerr("Alice file pointer NULL\n");
		return NULL;
	}

	if(bob == NULL) {
		g_printerr("Bob file pointer NULL\n");
		return NULL;
	}


// initialize g_thread if not already done.
// The program will abort if no thread system is available!
	if (!g_thread_supported()) g_thread_init (NULL);

// set key_data
	if(loop == 0) {
		key_data.size = size/2;
	} else key_data.size = size;
	key_data.loop = loop;
	key_data.alice = g_strdup(alice);
	key_data.bob = g_strdup(bob);

	if((key_thread = g_thread_create(start_generation, NULL, TRUE, NULL)) != NULL) g_print("keygen started\n");

	return key_thread;
}


gpointer start_generation(gpointer data)
/*
*	start threaded key generation
*/
{
// define threads
	GThread *p1, *p2, *p3, *p4;
#ifdef FAST
	GThread *p5;
#endif

// create mutex
	keygen_mutex = g_mutex_new();

// create threads
	if((p2 = g_thread_create(devrand, NULL, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/random\n");
	if((p1 = g_thread_create(audio, NULL, TRUE, NULL)) != NULL) g_print("collecting entropy from /dev/audio\n");
	if((p3 = g_thread_create(threads, NULL, TRUE, NULL)) != NULL) g_print("collecting entropy from thread timing\n");
	if((p4 = g_thread_create(sysstate, NULL, TRUE, NULL)) != NULL) g_print("collecting entropy from system state\n");
#ifdef FAST
	if((p5 = g_thread_create(prng, NULL, TRUE, NULL)) != NULL) g_print("collecting entropy from PRG\n");
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
	g_mutex_free(keygen_mutex);

// create the inverted key
	if(key_data.size != 0) {
		g_printerr("could not finish writing process\n");
		key_data.size = 0;
		return 0;
	}

	if(key_data.loop != 0) {
		otp_invert(key_data.alice, key_data.bob);
	} else {
		otp_loop_invert(key_data.alice);
	}

	g_free(key_data.alice);
	g_free(key_data.bob);

	return 0;
} // end start_generation();


unsigned char bit2char(short buf[8])
/*
* bit2char takes an array of 8 bits, and output an ascii char. The buf array should only contain
* 0 or 1, to get an useful result
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
* devrand() collects entropie from the /dev/random device and writes it into the alice keyfile
*/
{
	int fp_rand, fp_alice;
	unsigned char c1;
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fp_rand = open("/dev/random", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/random \n");
		return 0;
	}
	if((fp_alice = open(key_data.alice, O_RDWR|O_CREAT|O_APPEND, 00644)) < 0) {
		g_printerr("could not open %s \n", key_data.alice);
		close(fp_rand);
		return 0;
	}

	size = 0;
	while(1) {
		if(read(fp_rand, &c1, 1) < 0) {
			g_print("read error\n");
		}

		buffer[size] = (unsigned char)((c1 % CHARSIZE) + OFFSET);
		size++;

		if(size == BUFFSIZE) {
			g_mutex_lock(keygen_mutex);
			if(key_data.size < size) {
				g_mutex_unlock(keygen_mutex);
				break;
			}
			if(write(fp_alice, &buffer, BUFFSIZE) < 0) {
				g_printerr("write error\n");
				g_mutex_unlock(keygen_mutex);
				break;
			}
			key_data.size -= size;
			g_mutex_unlock(keygen_mutex);
			size = 0;
		}
		usleep(5);
	}

	close(fp_rand);
	close(fp_alice);
	return 0;
} // end devrand()


/*
*	a helper function for the threads function
*/
gpointer stub(gpointer data) {
	return 0;
} // end stub ()


gpointer threads(gpointer data)
/*
*	threads() collects entropie from thread timing, by just mesuring the time it takes
*	to open and close the stub() thread. This function takes one sample every second
* 	and writes the entropie into the alice keyfile
*/
{
	short i;
	unsigned char diff;
	struct timeval start, finish;
	int fp_alice;
	GThread *tid;

	if((fp_alice = open(key_data.alice,O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		g_printerr("could not open %s \n", key_data.alice);
		return 0;
	}

	while(1) {
		gettimeofday(&start, NULL);
		for(i = 0; i < 100; i++) {
			if((tid = g_thread_create(stub, NULL, TRUE, NULL)) != NULL) g_thread_join(tid);
		}
		gettimeofday(&finish, NULL);
		diff = (unsigned char)(((finish.tv_usec - start.tv_usec) % CHARSIZE) + OFFSET);

		g_mutex_lock(keygen_mutex);
		if(key_data.size == 0) {
			g_mutex_unlock(keygen_mutex);
			break;
		}
		if(write(fp_alice, &diff, 1) < 0) {
			g_printerr("write error\n");
			g_mutex_unlock(keygen_mutex);
			break;
		}
		key_data.size--;
		g_mutex_unlock(keygen_mutex);

		sleep(1);
	}

	close(fp_alice);
	return 0;
} // end threads()


gpointer audio(gpointer data)
/*
	audio() collect entropie from /dev/audio and xor it with a value from /dev/urandom to
	get a better distribution even if no sound is running.
	This function generates one bit of entropie out of 7 samples, generates an ascii char
	and write this into the alice keyfile
*/
{
	int fp_audio, fp_urand, fp_alice;
	short i;
	unsigned char c, d, oldc;
	short buf[8];
	unsigned char buffer[BUFFSIZE];
	int size;

	if((fp_audio = open("/dev/audio", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/audio \n");
		return 0;
	}
	if((fp_urand = open("/dev/urandom", O_RDONLY)) < 0) {
		g_printerr("could not opne /dev/urandom \n");
		close(fp_audio);
		return 0;
	}
	if((fp_alice = open(key_data.alice,O_RDWR|O_CREAT|O_APPEND,00644)) < 0) {
		g_printerr("could not open %s \n", key_data.alice);
		close(fp_audio);
		close(fp_urand);
		return 0;
	}

	i = 0;
	size = 0;
	oldc = '\0';

	while(1) {
		if(read(fp_audio, &c, 1) < 0) {
			g_printerr("error while reading /dev/audio, exiting thread\n");
			break;
		}
		buf[i] = ((unsigned short)c) % 2;
		i++;
		if(i == 8) {
			g_mutex_lock(keygen_mutex);
			if(read(fp_urand, &d, 1) < 0) {
				g_printerr("read error\n");
				g_mutex_unlock(keygen_mutex);
				break;
			}
			g_mutex_unlock(keygen_mutex);
			c = bit2char(buf);
			if(c == oldc) usleep(500);
			oldc = c;
			buffer[size] = (unsigned char)(((d  ^ c) % CHARSIZE) + OFFSET);
			size++;
			if(size == BUFFSIZE) {
					g_mutex_lock(keygen_mutex);
					if(key_data.size < size) {
						g_mutex_unlock(keygen_mutex);
						break;
					}
					if(write(fp_alice, &buffer, BUFFSIZE) < 0) {
						g_printerr("write error\n");
						g_mutex_unlock(keygen_mutex);
						break;
					}
					key_data.size -= size;
					g_mutex_unlock(keygen_mutex);
					size = 0;
			}
			i = 0;
			usleep(5);
		}
	}
	close(fp_audio);
	close(fp_urand);
	close(fp_alice);
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
	int minflt, fp_alice, who;
	double systime, usertime;
	unsigned int result = 0, old_result = 0;
	char c;
	struct rusage usage;
	who = RUSAGE_SELF;

	if((fp_alice = open(key_data.alice, O_RDWR|O_CREAT|O_APPEND, 00644)) < 0){
		g_printerr("could not open %s\n", key_data.alice);
		return 0;
	}

	while (1) {
		if(getrusage(who, &usage) < 0) {
			g_printerr("resurce usage not supported, exit thread\n");
			break;
		}
		usleep(500);
		minflt = usage.ru_minflt;
		systime = usage.ru_stime.tv_sec*1000000+usage.ru_stime.tv_usec;
		usertime = usage.ru_utime.tv_sec*1000000+usage.ru_utime.tv_usec;
		result = minflt + (unsigned int)systime + (unsigned int)usertime;
		result = (result % CHARSIZE) + OFFSET;

		if(result != old_result) {
			c = (char)result;
			g_mutex_lock(keygen_mutex);

			if(key_data.size == 0) {
				g_mutex_unlock(keygen_mutex);
				break;
			}

			write(fp_alice, &c, 1);
			key_data.size--;
			g_mutex_unlock(keygen_mutex);
		}
		old_result = result;
	}
	close(fp_alice);
	return 0;
} // end sysstate()


gpointer prng(gpointer data)
/*
*	prng collects entropy from the pseudo random generator /dev/urandom. This function is only used if the FAST flag is set.
*	This function weakens the key, and is only used to fasten the generation process.
*/
{
	int fp_alice, fp_prng;
	unsigned short c;

	if((fp_alice = open(key_data.alice, O_RDWR|O_CREAT|O_APPEND, 00644)) < 0) {
		g_printerr("could not open %s\n", key_data.alice);
		return 0;
	}

	if((fp_prng = open("/dev/urandom", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/urandom\n");
		close(fp_alice);
		return 0;
	}

	while(1) {
		g_mutex_lock(keygen_mutex);
		if(read(fp_prng, &c, 1) != 1) {
			g_printerr("read error\n");
			g_mutex_unlock(keygen_mutex);
			break;
		}
		g_mutex_unlock(keygen_mutex);

		c = (c % CHARSIZE) + OFFSET;

		g_mutex_lock(keygen_mutex);
		if(key_data.size == 0) {
			g_mutex_unlock(keygen_mutex);
			break;
		}
		if(write(fp_alice, &c, 1) != 1) {
			g_printerr("write error\n");
			g_mutex_unlock(keygen_mutex);
			break;
		}
		key_data.size--;
		g_mutex_unlock(keygen_mutex);


		usleep(5);
	}

	close(fp_alice);
	close(fp_prng);
	return 0;
} // end prng;
