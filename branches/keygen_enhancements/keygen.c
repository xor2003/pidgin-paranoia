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
#include <gio/gio.h>

/* libotp includes */
#include "libotp.h"
#include "libotp-internal.h"
#include "keygen.h"


/* declarations */
typedef struct {
	gsize size;
	gboolean is_loopkey;
	gchar *alice, *bob, *src;
	struct otp_config* config;
	gpointer keygen_mutex;
	GOutputStream *fp_alice;
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
OtpError keygen_invert(gchar *src, gchar *dest)
/*
*	Write the bytewise inverse of src to dest
*	src and dest must be a valide filename with correct path
* 	return 0 for success, -1 if a failure occures
*/
{
	GOutputStream *fpout;
	GFile *dest_file;
	GMappedFile *src_file;
	gchar *buffer;
	gsize file_length;
	gint position;
	
	if(src == NULL || dest == NULL) {
		g_printerr("source or destination NULL\n");
		return OTP_ERR_KEYGEN_ERROR3;
	}
	
	src_file = g_mapped_file_new(src, 0, NULL);	
	file_length = g_mapped_file_get_length(src_file);
	buffer = g_mapped_file_get_contents(src_file);
	
	dest_file = g_file_new_for_commandline_arg(dest);
	fpout = (GOutputStream *)g_file_append_to(dest_file, G_FILE_CREATE_PRIVATE, NULL, NULL);

	if(file_length <= 0 || fpout == NULL) {
		g_printerr("couldn't get file stream\n");
		g_mapped_file_free(src_file);
		g_output_stream_close(fpout, NULL, NULL);
		return OTP_ERR_KEYGEN_ERROR3;
	}
	
	buffer = (gchar *)g_malloc(file_length);
	g_file_get_contents(src, &buffer, &file_length, NULL);	
	
	position = file_length - 1;
	while(position >= 0) {
		if(g_output_stream_write(fpout, &buffer[position], 1, NULL, NULL) != 1) {
			g_printerr("wasn't able to create bob key\n");
			g_mapped_file_free(src_file);
			g_output_stream_close(fpout, NULL, NULL);
			return OTP_ERR_KEYGEN_ERROR1;
		}
		position--;
	}
	
	g_mapped_file_free(src_file);
	g_output_stream_close(fpout, NULL, NULL);
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


guchar bit2char(gshort buf[8]);

void free_key_data(KeyData *key_data) {
	g_free(key_data->alice);
	g_free(key_data->bob);
	g_free(key_data->src);
	g_free(key_data);
} // end free_key_data()


/* ------------------------- ACCESS -------------------------*/

OtpError keygen_keys_generate(char *alice_file, char *bob_file,
		gsize size, const char *entropy_source, void *config)
/*
*	Generate the keyfiles alice and bob from the source entropy_source, which
*	can be either a regular entropy file, a character device or NULL for the
*	internal key generator
*/
{
	KeyData *key_data;
	
	if(alice_file == NULL || bob_file == NULL || config == NULL) {
		g_printerr("input NULL\n");
		otp_conf_decrement_number_of_keys_in_production(config);
		return OTP_ERR_KEYGEN_ERROR1;
	}

	/* fill key_data struct */
	key_data = (KeyData *)g_malloc0(sizeof(KeyData));	
	key_data->config = (struct otp_config *)config;
	key_data->alice = g_strdup(alice_file);
	key_data->bob = g_strdup(bob_file);
	if(g_strcmp0(alice_file, bob_file)) {
		key_data->size = size;
	} else key_data->size = size / 2;
	key_data->src = g_strdup(entropy_source);
	
	/* Try to create alice file */
	key_data->fp_alice = (GOutputStream *) g_file_create(g_file_new_for_commandline_arg(key_data->alice), 
															G_FILE_CREATE_PRIVATE, NULL, NULL);
	if(key_data->fp_alice == NULL) {
		free_key_data(key_data);
		return OTP_ERR_FILE_EXISTS;
	}
	
	/* initialize g_thread if not already done.
	   The program will abort if no thread system is available! */
	if (!g_thread_supported()) g_thread_init (NULL);
	
	key_data->keygen_mutex = g_mutex_new();

	/* Try to start thread for key generation */
	if(g_thread_create(keygen_main_thread, NULL, TRUE, (gpointer)key_data) == NULL) {
		otp_conf_decrement_number_of_keys_in_production(key_data->config);
		g_printerr("couldn't create thread");
		free_key_data(key_data);
		return OTP_ERR_KEYGEN_ERROR1;
	}

	return OTP_OK;
} // end keygen_keys_generate

guint keygen_id_get()
/* return a random id */
{
	return (guint)g_random_int();
}	 // end keygen_id_get()

/* ------------------------- THREADS ------------------------*/

gpointer keygen_main_thread(gpointer data)
{
	free_key_data((KeyData *)data);
	return NULL;
} // end keygen_main_thread()

gpointer devrand(gpointer data) 
/*
*	Thread which collects entropy from the standart unix random device
*/
{	
	KeyData *key_data;	
	GInputStream *fp_rand;
	gchar buffer[BUFFSIZE];
	gssize size;
	
	key_data = (KeyData *)data;

	fp_rand = (GInputStream *) g_file_read(g_file_new_for_commandline_arg("/dev/random"), NULL, NULL);
	if(fp_rand == NULL) {
		g_printerr("could not open /dev/random \n");
		return 0;
	}

	while(1) {
		if((size = g_input_stream_read(fp_rand, buffer, BUFFSIZE, NULL, NULL)) == -1) {
			g_printerr("read error\n");
		} else {
			g_mutex_lock(key_data->keygen_mutex);
			if(key_data->size < size) {
				g_mutex_unlock(key_data->keygen_mutex);
				break;
			}
			if((size = g_output_stream_write(key_data->fp_alice, buffer, size, NULL, NULL)) == -1) {
				g_printerr("write error\n");
				g_mutex_unlock(key_data->keygen_mutex);
				break;
			}
			key_data->size -= size;
			g_mutex_unlock(key_data->keygen_mutex);
		}
		g_usleep(100);
	}

	g_input_stream_close(fp_rand, NULL, NULL);
	return 0;
} // end devrand()

gpointer audio(gpointer data)
/*
*	audio() collect entropie from /dev/audio and unbias it with the improved Neumann Algorithm to
*	get a better distribution.
*	For the entropy collection only the last bit of the audio channle is taken.
*/
{
	return 0;
} // end audio()


gpointer stub(gpointer data) 
/*
*	Stub Thread for thread timing measurement
*/
{
	return 0;
} // end stub()

gpointer threads(gpointer data) 
/*
*	threads() collects entropie from thread timing, by just mesuring the time it takes
*	to open and close the stub() thread. This function takes one sample every second
* 	and writes the entropie into the alice keyfile
*/
{
	KeyData *key_data;
	GTimer *timer;
	GThread *tid;
	gint i;
	gchar c;
	gulong ms;
	
	key_data = (KeyData *)data;
	timer = g_timer_new();
	while(1) {
		g_timer_start(timer);
		for(i = 0; i < 100; i++) {
			if((tid = g_thread_create(stub, NULL, TRUE, NULL)) != NULL) g_thread_join(tid);
		}
		g_timer_stop(timer);
		g_timer_elapsed(timer, &ms);
		c = (char) ((ms % CHARSIZE) + OFFSET);
		g_mutex_lock(key_data->keygen_mutex);
		if(key_data->size == 0) {
			g_mutex_unlock(key_data->keygen_mutex);
			break;
		}
		if(g_output_stream_write(key_data->fp_alice, &c, 1, NULL, NULL) != 1) {
			g_printerr("write error\n");
			g_mutex_unlock(key_data->keygen_mutex);
			break;
		}
		key_data->size--;
		g_mutex_unlock(key_data->keygen_mutex);
		g_usleep(1000000);
	}
	g_timer_destroy(timer);
	return 0;
} // end threads()


gpointer sysstate(gpointer data);

gpointer prng(gpointer data)
/*
*	prng collects entropy from the pseudo random generator /dev/urandom. If this device is not available it will
*	use the glib random number generator.
*/
{
	KeyData *key_data;
	GInputStream *fp_prng;
	gchar buffer[BUFFSIZE];
	gsize size;
	gint i;
	
	key_data = (KeyData *)data;
	
	fp_prng = (GInputStream *)g_file_read(g_file_new_for_commandline_arg("/dev/urandom"), NULL, NULL);
	if(fp_prng == NULL) g_printerr("/dev/random not available, taking glib prng\n");

	while(1) {	
		if(fp_prng == NULL) {
			for(i = 0; i < BUFFSIZE; i++) buffer[i] = (char)g_random_int_range(OFFSET, CHARSIZE + OFFSET);
			size = BUFFSIZE;
		} else {
			size = g_input_stream_read(fp_prng, buffer, BUFFSIZE, NULL, NULL);
		}
		if(size >= 0) {
			g_mutex_lock(key_data->keygen_mutex);
			if(key_data->size < size) {
				g_mutex_unlock(key_data->keygen_mutex);
				break;
			}
			if((size = g_output_stream_write(key_data->fp_alice, buffer, size, NULL, NULL)) == -1) {
				g_printerr("write error\n");
				g_mutex_unlock(key_data->keygen_mutex);
				break;
			}
			key_data->size -= size;
			g_mutex_unlock(key_data->keygen_mutex);
		}
		g_usleep(100);
	}
	return 0;
} // end prng;
