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

/* glib includes */
#include <glib.h>
#include <glib-object.h>

/* libotp includes */
#include "libotp.h"
#include "libotp-internal.h"
#include "keygen.h"

/* libc includes */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* declarations */
typedef struct {
	gsize size;
	gboolean is_loopkey;
	gchar *alice, *bob, *src;
	struct otp_config* config;
	gpointer keygen_mutex;
} KeyData;

gpointer keygen_main_thread(gpointer data);
gpointer devrand(gpointer data);
gpointer audio(gpointer data);
gpointer stub(gpointer data);
gpointer threads(gpointer data);
gpointer sysstate(gpointer data);
gpointer prng(gpointer data);

/* defines */
#define BUFFSIZE 20
// do not change, for developement purpose
#define CHARSIZE 256
#define OFFSET 0

/* ------------------------- TOOLS --------------------------*/
OtpError keygen_invert(char *src, char *dest)
/*
*	Write the bytewise inverse of src to dest
*	src and dest must be a valide filename with correct path
* 	return 0 for success, -1 if a failure occures
*/
{
	FILE *fpin, *fpout;
	gint c;
	gsize file_length;
	
	if(src == NULL || dest == NULL) {
		g_printerr("source or destination NULL\n");
		return OTP_ERR_KEYGEN_ERROR3;
	}

	if((fpin = fopen(src, "r")) == NULL) {
		g_printerr("couldn't open source\n");
		return OTP_ERR_KEYGEN_ERROR3;
	}

	if((fpout = fopen(dest, "a")) == NULL) {
		g_printerr("couldn't open destination\n");
		fclose(fpin);
		return OTP_ERR_KEYGEN_ERROR3;
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

	return OTP_OK;
} // end invert()


struct otp *keygen_get_pad(gchar *filename, KeyData *key_data) 
/*
	Get the OTP pad for filename. 
	filename has to be a regluar entropy file with absolute path.
*/
{
	struct otp *pad;
	gchar *alice_relative;
	gchar **splited;
	gint i;
	
	if(filename == NULL) {
		g_printerr("Input NULL\n");
		return NULL;
	}
	
	splited = g_strsplit(filename, PATH_DELI, -1);
	
	/* get the relative filename*/
	i = 0;
	while(splited[i] != NULL) i++;

	alice_relative = splited[i-1];
	
	/* generate pad from file */	
	pad = otp_pad_create_from_file(key_data->config, alice_relative);
	
	g_strfreev(splited);
	
	return pad;
} // end keygen_get_pad()


unsigned char bit2char(short buf[8]);


/* ------------------------- ACCESS -------------------------*/

OtpError keygen_keys_generate(char *alice_file, char *bob_file,
		gsize size, const char *entropy_source, void *config)
/*
*	Generate the keyfiles alice and bob from the source entropy_source, which
*	can be either a regular entropy file, a character device or NULL for the
*	internal key generator
*/
{
	KeyData key_data;
	key_data.config = (struct otp_config *)config;
	
	if(alice_file == NULL || bob_file == NULL || config == NULL) {
		g_printerr("input NULL\n");
		otp_conf_decrement_number_of_keys_in_production(key_data.config);
		return OTP_ERR_KEYGEN_ERROR1;
	}
	
	key_data.alice = g_strdup(alice_file);
	key_data.bob = g_strdup(bob_file);
	if(strcmp(alice_file, bob_file)) {
		key_data.size = size;
	} else key_data.size = size / 2;
	key_data.src = g_strdup(entropy_source);
	
	// initialize g_thread if not already done.
	// The program will abort if no thread system is available!
	if (!g_thread_supported()) g_thread_init (NULL);
	
	key_data.keygen_mutex = g_mutex_new();

	if(g_thread_create(keygen_main_thread, NULL, TRUE, (gpointer)&key_data) == NULL) {
		otp_conf_decrement_number_of_keys_in_production(key_data.config);
		g_printerr("couldn't create thread");
		return OTP_ERR_KEYGEN_ERROR1;
	}

	return OTP_OK;
}

unsigned int keygen_id_get()
/* return a random id */
{
	return (unsigned int)g_random_int();
}	

/* ------------------------- THREADS ------------------------*/

gpointer keygen_main_thread(gpointer data)
{
	return NULL;
}

gpointer devrand(gpointer data) 
/*
*	Thread which collects entropy from the standart unix random device
*/
{	
	KeyData key_data;	
	int fp_rand, fp_alice;
	unsigned char c1;
	unsigned char buffer[BUFFSIZE];
	int size;
	
	key_data = *((KeyData *)data);

	if((fp_rand = open("/dev/random", O_RDONLY)) < 0) {
		g_printerr("could not open /dev/random \n");
		return 0;
	}
	if((fp_alice = open(key_data.alice, O_RDWR|O_CREAT|O_APPEND, 00644)) < 0) {
		g_printerr("could not open alice file \n");
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
			g_mutex_lock(key_data.keygen_mutex);
			if(key_data.size < size) {
				g_mutex_unlock(key_data.keygen_mutex);
				break;
			}
			if(write(fp_alice, &buffer, BUFFSIZE) < 0) {
				g_printerr("write error\n");
				g_mutex_unlock(key_data.keygen_mutex);
				break;
			}
			key_data.size -= size;
			g_mutex_unlock(key_data.keygen_mutex);
			size = 0;
		}
		usleep(5);
	}

	close(fp_rand);
	close(fp_alice);
	return 0;
} // end devrand()

gpointer audio(gpointer data);
gpointer stub(gpointer data);
gpointer threads(gpointer data);
gpointer sysstate(gpointer data);
gpointer prng(gpointer data);
