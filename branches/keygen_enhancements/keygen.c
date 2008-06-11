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


struct otp *keygen_get_pad(KeyData *key_data) 
/*
	Get the OTP pad for filename. 
	filename has to be a regluar entropy file with absolute path.
*/
{
	struct otp *pad;
	gchar *alice_relative;
	

	/* get relative filename*/	
	alice_relative = g_path_get_basename(key_data->alice);
	
	/* generate pad from file */	
	pad = otp_pad_create_from_file(key_data->config, alice_relative);
	
	g_free(alice_relative);
	
	return pad;
} // end keygen_get_pad()


guchar bit2char(gshort buf[8]) 
/*
*	Input a buf which elements are 1 or 0 and the function will output
*	a char as output.
*/
{
	gshort i, byte;
	
	/* Convert the buffer into one byte */
	byte = 0;
	for(i = 0; i < 8; i++) byte += buf[i] * (1<<i);

	return (guchar)byte;
}

gint improved_neumann(guchar buffer[BUFFSIZE]) {
	gint size, i, j, count;
	guchar current;
	size = 0;
	count = 0;
	current = 0;
	
	for(i = 0; i < BUFFSIZE; i++) {
		for(j = 0; j < 2; j++) {
			switch((int)((buffer[i] >> i*4)&0xF)) {
				case 1:	case 5:	case 13:
					count += 2;
					break;
				case 3:
					count++;
					break;
				case 4: case 6:	case 7:
					count++;
					if(count > 7) break;
					current += (1 << count);
					count++;
					break;
				case 2:	case 9:	case 14:
					current += (1 << count);
					count += 2;
					break;
				case 8:	case 10: case 11:
					current += (1 << count);
					count++;
					if(count > 7) break;
					current += (1 << count);
					count++;
					break;
				case 12:
					current += (1 << count);
					count++;
					break;
				default:
					break;
			}
			if(count > 7) {
				buffer[size] = current;
				size++;
				count = 0;
			}
		}
	}
	return size;
}

gint keys_from_source(KeyData *key_data, GFile *source) {
	GInputStream *fp_source;
	gssize size;
	gchar buffer[BUFFSIZE];
	
	fp_source = (GInputStream *) g_file_read(source, NULL, NULL);
	
	if(fp_source == NULL) {
		g_printerr("couldn't open entropy source stream\n");
		return -1;
	}
	
	while(1) {
		if(key_data->size == 0) {
			break;	
		} else if(key_data->size >= BUFFSIZE) {
			size = BUFFSIZE;
		} else if(key_data->size < BUFFSIZE) {
			size = key_data->size;

		} else {
			g_printerr("unknown size error\n");
			g_input_stream_close(fp_source, NULL, NULL);
			return -1;
		}
		
		if((size = g_input_stream_read(fp_source, buffer, size, NULL, NULL)) == -1) {
			g_input_stream_close(fp_source, NULL, NULL);
			g_printerr("read error\n");
			return -1;
		}
		
		if((size = g_output_stream_write(key_data->fp_alice, buffer, size, NULL, NULL)) == -1) {
			g_input_stream_close(fp_source, NULL, NULL);
			g_printerr("write error\n");
			return -1;
		}	
		key_data->size -= size;
	}

	g_input_stream_close(fp_source, NULL, NULL);
	return 0;
}

void free_key_data(KeyData *key_data) 
/*
*	Free the KeyData struct
*/
{
	g_free(key_data->alice);
	g_free(key_data->bob);
	g_free(key_data->src);
	g_mutex_free(key_data->keygen_mutex);
	g_output_stream_close(key_data->fp_alice, NULL,  NULL);
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
	gchar *tmp_file;
	
	if(alice_file == NULL || bob_file == NULL || config == NULL) {
		g_printerr("input NULL\n");
		otp_conf_decrement_number_of_keys_in_production(config);
		return OTP_ERR_KEYGEN_ERROR1;
	}

	/* fill key_data struct */
	key_data = (KeyData *)g_malloc0(sizeof(KeyData));	
	key_data->config = (struct otp_config *)config;
	key_data->alice = g_strdup(alice_file);

	if(g_strcmp0(g_path_get_basename(alice_file), g_path_get_basename(bob_file))) {
		key_data->bob = g_strdup(bob_file);
		key_data->size = size;
		key_data->is_loopkey = FALSE;
	} else {
		key_data->bob = g_strdup(alice_file);
		key_data->size = size / 2;
		key_data-> is_loopkey = TRUE;
	}
	key_data->src = g_strdup(entropy_source);
	
	/* initialize g_thread if not already done.
	   The program will abort if no thread system is available! */
	if (!g_thread_supported()) g_thread_init (NULL);
	
	/* Create the mutex */
	key_data->keygen_mutex = g_mutex_new();
	
	/* Try to create alice file */
	tmp_file = g_strdup_printf("%s%s%s",g_get_tmp_dir(), G_DIR_SEPARATOR_S, g_path_get_basename(key_data->alice));
	key_data->fp_alice = (GOutputStream *)g_file_create(g_file_new_for_commandline_arg(tmp_file), 
															G_FILE_CREATE_PRIVATE, NULL, NULL);
	g_free(tmp_file);
	if(key_data->fp_alice == NULL) {
		free_key_data(key_data);
		return OTP_ERR_FILE_EXISTS;
	}	

	/* Try to start thread for key generation */
	if(g_thread_create(keygen_main_thread, (gpointer)key_data, TRUE, NULL) == NULL) {
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
	KeyData *key_data;
	struct otp *pad;
	gchar *tmp_file, *bob_file;
	GFile *source;
	GFileInfo *info;
	gsize size;
	gboolean error;
	GThread *t_audio, *t_random, *t_prng, *t_threads;
	
	key_data = (KeyData *)data;
	error = FALSE;

	if(key_data->src == NULL) {
		/* integrated keygen */
		if((t_random = g_thread_create(devrand, (gpointer)key_data, TRUE, NULL)) == NULL) g_printerr("fail: /dev/random\n");
		if((t_audio = g_thread_create(audio, (gpointer)key_data, TRUE, NULL)) == NULL) g_printerr("fail: /dev/audio\n");
		if((t_threads = g_thread_create(threads, (gpointer)key_data, TRUE, NULL)) == NULL) g_printerr("fail: thread timing\n");
		if((t_prng = g_thread_create(prng, (gpointer)key_data, TRUE, NULL)) == NULL) g_printerr("fail PRNG\n");
		
		g_thread_join(t_random);
		g_thread_join(t_audio);
		g_thread_join(t_threads);
		g_thread_join(t_prng);
	} else {	
		source = g_file_new_for_commandline_arg(key_data->src);
		info = g_file_query_info(source, "*",G_FILE_QUERY_INFO_NONE, NULL, NULL);
		switch(g_file_info_get_file_type(info)) {
			case G_FILE_TYPE_REGULAR:
				size = g_file_info_get_size(info);
				if(size < key_data->size) {
					g_printerr("Entropy File to small\n");
					error = TRUE;
					break;
				}
				if(keys_from_source(key_data, source) != 0) {
					g_printerr("error in entropy source\n");
					error = TRUE;
				}
				break;
			case G_FILE_TYPE_SPECIAL:
				if(keys_from_source(key_data, source) != 0) {
					g_printerr("error in entropy source\n");
					error = TRUE;
				}
				break;
			default:
				g_printerr("unsupported source\n");
				error = TRUE;
				break;
		}
	}
	
	if(!error) {
		tmp_file = g_strdup_printf("%s%s%s",g_get_tmp_dir(), G_DIR_SEPARATOR_S, g_path_get_basename(key_data->alice));
		if(key_data->is_loopkey) {
			bob_file = tmp_file;
		} else {
			bob_file = key_data->bob;
		}
		if(keygen_invert(tmp_file, bob_file) != OTP_OK) {
			g_printerr("error in creation of bob key\n");
		} else {
			g_file_move(g_file_new_for_commandline_arg(tmp_file), 
						g_file_new_for_commandline_arg(key_data->alice), 
						G_FILE_COPY_NONE, NULL, NULL, NULL, NULL);
			pad = keygen_get_pad(key_data);
			g_signal_emit_by_name(G_OBJECT(otp_conf_get_trigger(key_data->config)), "keygen_key_done_signal", 100.0, pad);
		}
		g_free(tmp_file);
	} else g_printerr("error!!!\n");

	otp_conf_decrement_number_of_keys_in_production(key_data->config);
	free_key_data(key_data);

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
	KeyData *key_data;
	GInputStream *fp_audio;
	gshort readbuf[8];
	guchar writebuf[BUFFSIZE];
	guint count;
	gssize size;

	key_data = (KeyData *)data;
	
	/* create audio file stream */
	fp_audio = (GInputStream *) g_file_read(g_file_new_for_commandline_arg("/dev/audio"), NULL, NULL);
	
	if(fp_audio == NULL) {
		g_printerr("couldn't open /dev/audio \n");
		return 0;
	}
	
	/* read from input and write to output */
	count = 0;
	while(1) {
		if(g_input_stream_read(fp_audio, readbuf, 8, NULL, NULL) != 8) {
			g_printerr("audio read error\n");	
		} else if(count < BUFFSIZE) {
			writebuf[count] = bit2char(readbuf);
			count++;
		} else {
			size = improved_neumann(writebuf);
			g_mutex_lock(key_data->keygen_mutex);
			if(key_data->size < size) {
				g_mutex_unlock(key_data->keygen_mutex);
				break;
			}
			if((size = g_output_stream_write(key_data->fp_alice, writebuf, size, NULL, NULL)) != -1) {
				key_data->size -= size;
				g_mutex_unlock(key_data->keygen_mutex);
				count = 0;
			} else {
				g_printerr("write error\n");
				g_mutex_unlock(key_data->keygen_mutex);
				return 0;
			}
		}
		
		g_usleep(100);
	}
	/* close file streams */
	g_input_stream_close(fp_audio, NULL, NULL);
	
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
		g_usleep(1000);
	}
	return 0;
} // end prng;
