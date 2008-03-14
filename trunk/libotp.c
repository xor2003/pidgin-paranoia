/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2007-2008  Christian Wäckerlin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

/* --------------------------- Note -----------------------------------
 * This is the libotp code. 
 * */

/*  ------------------- Constants (don't change) -------------------
 * Changing this makes your one-time-pad incompatible */

#define PAD_EMPTYCHAR '\0'        /* Char that is used to mark the pad as used. */

/*  ------------------- Constants (you can change them) ------------ */

#define PATH_DELI "/"					/* For some reason some strange
				 * operatingsystems use "\" */
#define BLOCKSIZE 1000					/* The blocksize used in the keyfile
				 * creation function */
#define ERASEBLOCKSIZE 1024				/* The blocksize used in the key
				 * eraseure function */
#define DEFAULT_RNDLENMAX 25			/* Default value: Maximal length of the added
				 * random-length tail onto the encrypted message */
#define MIN_PADDING 5			/* The mininal length of this tailing string 
								* This allows future checks if the message
								* was decrypted correctly. */
#define DEFAULT_IMPROBABILITY 1E-12		/* Default value: If a key with less
				 * probability then this occurs, throw the key away */

/*  ------------------- Defines (essential) ------------------------
 * All defines needed for full opt functionality! Regarded
 * as stable. The encryption is worthless without those! */

#define UCRYPT                  /* Encryption and decryption only enabled if defined */
#define KEYOVERWRITE    /* Overwrite the used key-sequence in the keyfile */

/*  ------------------- Defines (optional) ------------------------
 * These defines give new, additional features. */

#define RNDMSGLEN               /* Add a random-length string onto the message */

#define PRINT_ERRORS
/* Print errors to the terminal if enabled (Recommanded)*/

/*  ------------------- Defines (in development) ------------------------
 * In development. Regraded as unstable. Those functions are nice
 * but not critical. */

#define CHECKKEY                /* Histogram/repeat checking of the key (Needs testing) */

//#ifdef IMMED_CLOSE_FILES		
/* This enforces the old behaviour where the 
 * keyfiles were closed immediatly after usage */

/*  ------------------- Defines (for development) ------------------------
 * Useful for Developpers */

//#define DEBUG
/* Some general debug output */

//#define DEBUG_MSG
/* Produces lots of output
 * Enables the function otp_printint and dumps the way of the 
 * message and key byte by byte. */

/*  -------------------------- Includes ---------------------------- */

/* GNUlibc includes */
#include <stdlib.h>
#include <string.h>
#include <math.h>
/* to manipulate files */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
/* to create directories */
#include <dirent.h>

/* GNOMElib */
#include <glib.h>
#include <glib-object.h>

/* The public functions of this library */
#include "libotp.h"
#include "libotp-internal.h"

/* Key generation functions*/
#include "keygen.h"

#if defined DEBUG_MSG || defined DEBUG || defined PRINT_ERRORS
#include <stdio.h>
#endif



/* ------------------- Private data structures -------------------- */

struct otp {
 	char* src; 					/* for pidgin: 'account' like alice@jabber.org */
	char* dest; 				/* for pidgin: 'account' like bob@jabber.org */
	char* id; 					/* 8 digits unique random number of the key pair (hex) */
	char* filename; 			/* The full path and the filename defined in the libotp spec */
	gsize position; 			/* start positon for the next encryption */
	gsize encrypt_start_pos;	/* The position that is given to Bob */
	gboolean using_protected_pos;/* Only used for messages and signals 
 * from the protected entropy. Otherwise set to zero */
	gsize entropy; 				/* the size (in bytes) of the entropy left for the sender */
	gsize filesize; 			/* The size of the file in bytes */
	OtpError syndrome;			/* contains the status of this otp pad, if this
 * is relvant for the future, i.e. OTP_WARN_KEY_NOT_RANDOM */
	struct otp_config* config;	/* The settings associated with this pad. */
	gboolean file_is_open;		/* Whether the file is already open */
	int fd;						/* The file descriptor of the keyfile. Note: libc: 'int open(..)' */
	struct flock* fl;			/* The file lock */
	char* data;					/* The contents of the keyfile if open */
// TODO:
//	gboolean keygen_blocked;	/* Checked by otp_keygen -> OtpError if blocked */
//	gpointer keygen_process;	/* ??? */
};

struct otp_config {
	char* client_id;			/* Choose the ID of your client, i.e. for debug messages */
	char* path;					/* The absolute path were the keyfiles are stored */
	char* export_path;			/* The absolute path were to export bob's newly created keys */
	unsigned int pad_count; 	/* A counter for the number of associated otp structs */
	gsize random_msg_tail_max_len;		/* max. padding added onto every message */
	double msg_key_improbability_limit;	/* entropy for message encryption with 
 * less probable content will be rejected */
 	unsigned int number_of_keys_in_production;		/* The Number of keys currently in production */
 	GObject* keygen_signal_trigger;		/* Trigger to emit signal on */
};

/*  ----------------- Private Functions of the Library------------ */

static void otp_xor(char** message, char** key, gsize len)
/* XOR message and key. This function is the core of the library. */
{
	gsize i;
	for (i = 0; i < (len-1); i++) {
		(*message)[i] = (*message)[i]^(*key)[i];
	}
	g_free(*key);
}

#ifdef DEBUG_MSG
static void otp_printint(char* m, gsize len, const char* hint, const struct otp_config* config)
/* Helper function for debugging */
{
	gsize i;
	printf("%s:\t%s:\t", config->client_id, hint);
	for (i = 0; i < len; i++) {
		printf("%i ", m[i]);
	}
	printf("\n");
}
#endif

static void otp_calc_entropy(struct otp* pad)
/* Calculate the free entropy */
{
	gsize entropy = pad->filesize/2-pad->position-OTP_PROTECTED_ENTROPY;
	if (entropy < 0) {
		pad->entropy = 0;
	} else {
		pad->entropy = entropy;
	}
}

static OtpError otp_open_keyfile(struct otp* pad)
/* Opens a keyfile with memory mapping */
{
	struct stat fstat;
	if (pad->file_is_open == TRUE) {
#ifdef DEBUG
		printf("%s: %s: file is already open.\n",pad->config->client_id, pad->id);
#endif
		return OTP_OK;
}

	/* Open file desriptor */
	if ((pad->fd = open(pad->filename, O_RDWR)) == -1) {
#ifdef PRINT_ERRORS
		perror("open");
#endif
		return OTP_ERR_FILE;
	}

	/* Get Filesize */
	if (stat(pad->filename, &fstat) == -1) {
#ifdef PRINT_ERRORS
		perror("stat");
#endif
		close(pad->fd);
		return OTP_ERR_FILE;
	}
	pad->filesize = fstat.st_size;

	/* mmap 
	 * Note: Because the memory map maps the whole file, the exclusive lock
	 * set onto the first half of the file will always prevent an other 
	 * application from opening the same key. */
	
	if ((pad->data = mmap((caddr_t)0, pad->filesize, PROT_READ | PROT_WRITE,
			MAP_SHARED, pad->fd, 0)) == (caddr_t)(-1)) {
#ifdef PRINT_ERRORS
		perror("mmap");
#endif
		close(pad->fd);
		return OTP_ERR_FILE;
	}
#ifdef DEBUG
	printf("%s: pad  %s opened in fd %u\n",pad->config->client_id, pad->id, pad->fd);
#endif
	/* File lock */
	pad->fl = (struct flock*)g_malloc(sizeof(struct flock));
	pad->fl->l_type = F_WRLCK;		/* Get an exclusive lock */
	pad->fl->l_whence = SEEK_SET;	/* Lock from the beginning of the file */
	pad->fl->l_start  = 0;
	/* Lock until the end of the part that is used to encrypt */
	pad->fl->l_len    = pad->filesize/2;
	pad->fl->l_pid    = getpid();
	
	if ((fcntl(pad->fd, F_SETLK, pad->fl)) == -1) {
		munmap(pad->data, pad->filesize);
		g_free(pad->fl);
		pad->fl = NULL;
		close(pad->fd);
#ifdef PRINT_ERRORS
		perror("fcntl");
#endif
		return OTP_ERR_FILE;
	}
#ifdef DEBUG
	printf("%s: filelock: -1 if not locked: %d\n",pad->config->client_id,fcntl(pad->fd, F_GETLK, pad->fl));
#endif

	/* Everything is fine */
	pad->file_is_open = TRUE;
	return OTP_OK;
}

static void otp_close_keyfile(struct otp* pad)
/* Closes a keyfile with memory mapping */
{
	if (pad->file_is_open == FALSE) {
#ifdef PRINT_ERRORS
		printf("%s: %s: file is already closed!\n",pad->config->client_id, pad->id);
#endif
		return;
}
#ifdef DEBUG
	printf("%s: pad  %s closed in fd %u\n",pad->config->client_id, pad->id, pad->fd);
#endif
	pad->fl->l_type   = F_UNLCK;
	if ((fcntl(pad->fd, F_SETLK, pad->fl)) == -1) {
#ifdef PRINT_ERRORS
		perror("fcntl");
#endif
	}
	munmap(pad->data, pad->filesize);
	g_free(pad->fl);
	pad->fl = NULL;
	close(pad->fd);
	pad->file_is_open = FALSE;
	return;
}

static gsize otp_seek_pos(const struct otp* pad)
/* Seeks the position where the pad can be used for encryption */
{
	gsize pos = 0;
	char* data = pad->data;
	while ( ((data+pos)[0] == PAD_EMPTYCHAR) && (pos < pad->filesize) ) {
		pos++;
	}
#ifdef DEBUG
	printf("%s: pad  %s seeked: found pos %u\n",pad->config->client_id, pad->id, pos);
#endif
	return pos;
}

static gboolean otp_id_is_valid(const char* id_str)
/* Check if the ID is valid */
{
	if ( strlen(id_str) == OTP_ID_LENGTH * sizeof(char)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean otp_key_is_random(char** key, gsize len, 
		const struct otp_config* config)
/* Checks the key by statistical means
 *
 * */
{
	unsigned int i, rep = 1;
	double repeatprob;
//	char *c="test1111";
//	len=strlen(c);
	char* c = *key;
	unsigned int lastc = 257; /* Startvalue: This is not a char */
	for (i = 0; i < len; i++) {
		if (c[i] == lastc) {
			rep++;
		} else {
			lastc = c[i];
		}
	}
	/* Probability for a repeat of len*/
	repeatprob = 1.0; // TODO v.0.2: Formula needed
	if (repeatprob < config->msg_key_improbability_limit) {
		/* Fail if the probability for a random key to have a repeat is smaller than the tolerance. */
#ifdef PRINT_ERRORS
//		if (pad->syndrome != OTP_WARN_KEY_NOT_RANDOM) {
//				pad->syndrome = pad->syndrome | OTP_WARN_KEY_NOT_RANDOM;
//		}
		printf("%s: Probability for a repeat of len %i: %e\n", config->client_id, rep, repeatprob);
#endif
		return FALSE;
	}
	return TRUE;
}

static OtpError otp_get_encryptkey_from_file(char** key, struct otp* pad, 
			gsize len, struct otp_config* config)
/* Gets the key to encrypt from the keyfile */
{
	gsize i = 0;
	gsize protected_entropy = OTP_PROTECTED_ENTROPY;
	gsize position = pad->position;
	OtpError syndrome = OTP_OK;
	
	if (pad->using_protected_pos == TRUE) {
		/* allow usage of protected entropy*/
		protected_entropy = 0;
	}
	if ( (position+len-1 > (pad->filesize/2-protected_entropy) )
			|| position < 0 ) {
		return OTP_ERR_KEY_EMPTY;
	}
	if (pad->file_is_open == FALSE) {
		syndrome = otp_open_keyfile(pad);
		if (syndrome > OTP_WARN) return syndrome;
	}
	*key = (char*)g_malloc((len)*sizeof(char));
	memcpy(*key, pad->data+position, len-1);
	/* the pad could be anything... using memcpy */
	char *datpos = pad->data+position;

#ifdef CHECKKEY
	/* TODO v0.2: What should i do if the key is rejected?
	 * ATM it just fails and destroys the keyblock.*/
#ifdef KEYOVERWRITE
	if ((otp_key_is_random(key, len-1, config) == FALSE) && (pad->using_protected_pos == FALSE)) {
		syndrome = syndrome | OTP_WARN_KEY_NOT_RANDOM;
		/* not using protected entropy, make the used key unusable
		 * in the keyfile */
		for (i = 0; i < (len - 1); i++) datpos[i] = PAD_EMPTYCHAR;
		pad->position = pad->position + len -1;
		otp_calc_entropy(pad);
		return syndrome;
	}
#endif
#endif
	if (pad->using_protected_pos == FALSE) {
#ifdef KEYOVERWRITE
		/* Make the used key unusable in the keyfile unless the entropy
		 * is protected */
		for (i = 0; i < (len - 1); i++) {
			datpos[i] = PAD_EMPTYCHAR;
		}
#endif
	/* In all cases where the protected entropy is not used */
		pad->position = pad->position + len -1;
	}
	otp_calc_entropy(pad);
#ifdef IMMED_CLOSE_FILES
	otp_close_keyfile(pad);
#endif
	return syndrome;
}

static OtpError otp_get_decryptkey_from_file(char** key, struct otp* pad, 
			gsize len, gsize decryptpos)
/* Gets the key to decrypt from the keyfile */
{
	gsize i = 0;
	OtpError syndrome = OTP_OK;
	if ((decryptpos + (len+1) + pad->filesize/2) > pad->filesize
			|| decryptpos < 0) { /* < 0 is not needed but is more understandable */
		syndrome = OTP_ERR_KEY_SIZE_MISMATCH;
		return syndrome;
	}
	if (pad->file_is_open == FALSE) {
		syndrome = otp_open_keyfile(pad);
		if (syndrome > OTP_WARN) return syndrome;
	}
	if (syndrome > OTP_WARN) return syndrome;

	char* vkey = (char*)g_malloc( len*sizeof(char) );
	char* datpos = pad->data + pad->filesize - decryptpos - (len+1);
	/* read reverse*/
	for (i = 0; i <= (len -1); i++) vkey[i] = datpos[len - i];
	*key = vkey;
#ifdef IMMED_CLOSE_FILES
	otp_close_keyfile(pad);
#endif
	return syndrome;
}

static void otp_base64_encode(char** message, gsize len)
/* Encodes message into the base64 form */
{
	char* msg = g_base64_encode( (guchar*)*message, len);
	/* The size has changed */
	len = (strlen(msg)+1) * sizeof(char);

	g_free(*message);
	*message = msg;
	return;
}

static void otp_base64_decode(char **message, gsize* plen)
/* Decodes message from the base64 form
 * The function needs the length as pointer because the length will change*/
{
	guchar* msg = g_base64_decode( *message, plen);
	g_free(*message);
	*message = (char*)msg;
	return;
}

static OtpError otp_udecrypt(char** message, struct otp* pad, gsize decryptpos)
/* Decrypt the message  */
{
	gsize len = (strlen(*message)+1)* sizeof(char);
	char* space1 = "";
	char** key = &space1;
	otp_base64_decode(message, &len);
	OtpError syndrome = OTP_OK;
	syndrome = otp_get_decryptkey_from_file(key, pad, len, decryptpos);
	if (syndrome > OTP_WARN) return syndrome;
#ifdef DEBUG_MSG
	otp_printint(*key, len, "decryptkey", pad->config);
#endif
	otp_xor(message, key, len);
#ifdef DEBUG_MSG 
	otp_printint(*key,len, "decrypt-xor", pad->config);
#endif
	return syndrome;
}

static OtpError otp_uencrypt(char** message, struct otp* pad)
/* Encrypt the message  */
{
	gsize len = (strlen(*message)+1) * sizeof(char);
	char* space1 = "";
	char** rand = &space1;
	char* space2 = "";
	char** key = &space2;
	char* msg;
	unsigned char rnd;
	OtpError syndrome = OTP_OK;

#ifdef RNDMSGLEN
	if (pad->using_protected_pos == FALSE) { /* No random tail for signals */
		/* get one byte from keyfile for random length */
		syndrome = otp_get_encryptkey_from_file(rand, pad, 1+1, pad->config);
		pad->encrypt_start_pos += 1;
		if ( syndrome > OTP_WARN ) return syndrome;
		rnd = (unsigned char)*rand[0]*pad->config->random_msg_tail_max_len/255 
				+ MIN_PADDING;
		g_free(*rand);
		msg = g_malloc0(rnd+len);       /* Create a new,longer message */
		memcpy(msg, *message, len-1);
		g_free(*message);
		*message = msg;
		len += rnd;
	}
#endif
	syndrome = otp_get_encryptkey_from_file(key, pad, len, pad->config);
	if ( syndrome > OTP_WARN ) return syndrome;
#ifdef DEBUG_MSG
	otp_printint(*key,len, "encryptkey", pad->config);
#endif
	otp_xor(message, key, len);
#ifdef DEBUG_MSG 
	otp_printint(*key,len, "encrypt-xor", pad->config);
#endif
	otp_base64_encode(message, len);
	return syndrome;
}


/*  ----------------- Public Functions of the Library------------
 * Exported in libtop.h */


OtpError otp_pad_erase_entropy(struct otp* pad)
/* destroys a keyfile by using up all encryption-entropy */
{
	if (pad == NULL) return OTP_ERR_INPUT;
	pad->using_protected_pos = FALSE;
	gsize len = (ERASEBLOCKSIZE+1) * sizeof(char);
	char* space1 = "";
	char** key = &space1;
	/* Using up all entropy */
	OtpError syndrome = OTP_OK;
	while (syndrome <= OTP_WARN ) {
		syndrome = otp_get_encryptkey_from_file(key, pad, len, pad->config);
	}
	syndrome = OTP_OK;
	len = 1+1;
	while (syndrome <= OTP_WARN) {
		syndrome = otp_get_encryptkey_from_file(key, pad, len, pad->config);
	}
	if (syndrome == OTP_ERR_KEY_EMPTY) syndrome = OTP_OK;
	return syndrome;
}

OtpError otp_generate_key_pair(struct otp_config *config, 
		const char* alice, const char* bob, 
		const char* source, gsize size)
//TODO: v0.2: give the filenames back
/* 	Depending on the source keys of size for alice and bob are generated by the integrated
*	key generator (default), out of an entropy file or out of a character device. 
*	Currently there can only be one key at the moment generated. */
{
	if (alice == NULL || bob == NULL || config == NULL || size <= 0) {
		return OTP_ERR_INPUT;
	}
	/* Check for things like '/'. Alice and Bob will become filenames */
	if ((g_strrstr(alice, PATH_DELI) != NULL)
			|| (g_strrstr(bob, PATH_DELI) != NULL)) {
		return OTP_ERR_INPUT;
	}
	
	/* Check if the keygen is already in use and if not set: one key in generation. */
	if(otp_conf_get_number_of_keys_in_production(config) > 0) return OTP_ERR_GENKEY_KEYGEN_IN_USE;
	otp_conf_increment_number_of_keys_in_production(config);
	
	gchar *alice_file, *bob_file;
	unsigned int id;
	struct stat rfstat;
	
	/* create filenames with the correct path*/
	id = keygen_id_get();
	
	alice_file = (char *)g_strdup_printf("%s%s%s%s%s%s%.8X", 
			otp_conf_get_path(config), 
			PATH_DELI, alice, FILE_DELI, bob, FILE_DELI, id);
	bob_file = (char *)g_strdup_printf("%s%s%s%s%s%s%.8X", 
			otp_conf_get_export_path(config), 
			PATH_DELI, bob, FILE_DELI, alice, FILE_DELI, id);
	
	if(stat(alice_file, &rfstat) == 0) {
		g_free(alice_file);
		g_free(bob_file);
		return OTP_ERR_FILE_EXISTS;
	}

	/* choose the correct source and generate the key if possible */	
	if(source == NULL) { /* use the integrated keygen */
		if(keygen_keys_generate(alice_file, bob_file, size, 
									(strcmp(alice, bob) == 0), (void *)config) == NULL) {
			g_free(alice_file);
			g_free(bob_file);
			return OTP_ERR_KEYGEN_ERROR1;
		}
		g_free(alice_file);
		g_free(bob_file);
		return OTP_OK;
	} else { /* use a file as source */
		if(stat(source, &rfstat) < 0) { /* using a real file as source */
#ifdef PRINT_ERRORS
			printf("%s: sourcefile doesn't exist\n",config->client_id);
#endif
			otp_conf_decrement_number_of_keys_in_production(config);
			g_free(alice_file);
			g_free(bob_file);
			return OTP_ERR_FILE;
		}
		if(S_ISREG(rfstat.st_mode)) {
			if(keygen_keys_generate_from_file(alice_file, bob_file, source, size, 
									(strcmp(alice, bob) == 0), (void *)config) == NULL) {
				g_free(alice_file);
				g_free(bob_file);
				return OTP_ERR_KEYGEN_ERROR1;
			}
			g_free(alice_file);
			g_free(bob_file);
			return OTP_OK;
		} else if(S_ISCHR(rfstat.st_mode)) { /* using a stream as source */
			if(keygen_keys_generate_from_device(alice_file, bob_file, source, size, 
									(strcmp(alice, bob) == 0), (void *)config) == NULL) {
				g_free(alice_file);
				g_free(bob_file);
				return OTP_ERR_KEYGEN_ERROR1;
			}
			g_free(alice_file);
			g_free(bob_file);
			return OTP_OK;
		} else {
#ifdef PRINT_ERRORS
			printf("%s: sourcefile type is not supported\n",config->client_id);
#endif
			otp_conf_decrement_number_of_keys_in_production(config);
			g_free(alice_file);
			g_free(bob_file);
			return OTP_ERR_FILE;
		}
		otp_conf_decrement_number_of_keys_in_production(config);
		g_free(alice_file);
		g_free(bob_file);
		return OTP_ERR_FILE;
	}
}


OtpError otp_encrypt_warning(struct otp* pad, char** message, gsize protected_pos)
/* encrypts a message with the protected entropy.
 * protected_pos is the position in bytes to use. */
{
	OtpError syndrome = OTP_OK;
	if (pad == NULL || message == NULL || *message == NULL || protected_pos < 0) {
		if (protected_pos <= OTP_PROTECTED_ENTROPY - strlen(*message)) {
			return OTP_ERR_INPUT;
		}
	}
	pad->using_protected_pos = TRUE;
	pad->position = pad->filesize/2-OTP_PROTECTED_ENTROPY-protected_pos;
	pad->encrypt_start_pos = pad->position;
	char* old_msg = g_strdup(*message);
#ifdef UCRYPT
	syndrome = otp_uencrypt(message, pad);
	if (syndrome > OTP_WARN) {
		pad->using_protected_pos = FALSE;
#ifdef PRINT_ERRORS
		printf("%s: encrypt warning failed: %.8X\n",pad->config->client_id, syndrome);
#endif
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif
	/* Our position in the pad */
	char* pos_str = g_strdup_printf("%u", pad->encrypt_start_pos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char* new_msg = g_strconcat(pos_str, MSG_DELI,
	                            pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
	pad->using_protected_pos = FALSE;
	g_free(old_msg);
	return syndrome;
}

char* otp_id_get_from_message(const struct otp_config* config, const char *msg)
/* extracts and returns the ID from a given encrypted message.
 * Leaves the message constant. Returns NULL if it fails.*/
{
	if (msg == NULL || config == NULL) return NULL;
	gchar** m_array = g_strsplit(msg, MSG_DELI, 3);
	if ( (m_array[0] == NULL) || (m_array[1] == NULL) ) {
		g_strfreev(m_array);
		return NULL;
	}
	char* id_str = g_strdup(m_array[1]);
	g_strfreev(m_array);
	if (otp_id_is_valid(id_str) == TRUE) {
		return id_str;
	} else {
		g_free(id_str);
		return NULL;
	}
}

struct otp* otp_pad_create_from_file(
				struct otp_config* config, const char* filename)
/* Creates an otp struct, returns NULL if the filename is incorrect,
 * or if the file is missing */
{
	if (filename == NULL || config == NULL ) return NULL;

	gchar** f_array = g_strsplit(filename, FILE_DELI, 3);

	if ( (f_array[0] == NULL) || (f_array[1] == NULL)
				|| (f_array[2] == NULL) ) {
		g_strfreev(f_array);
		return NULL;
	}

	gchar** p_array = g_strsplit(f_array[2], FILE_SUFFIX_DELI, 3);
	if ((p_array[0] == NULL ) || (p_array[1] == NULL || p_array[2] != NULL )) {
		g_strfreev(f_array);
		g_strfreev(p_array);
		return NULL;
	}
	if (strcmp(p_array[1], FILE_SUFFIX) != 0) {
		g_strfreev(f_array);
		g_strfreev(p_array);
		return NULL;
	}
	struct otp* pad;
	pad = (struct otp *)g_malloc(sizeof(struct otp));
	pad->using_protected_pos = FALSE;
	pad->filename = g_strconcat(config->path, filename, NULL);
	pad->fd = 0;
	pad->file_is_open = FALSE;
	pad->fl = NULL;
	
	pad->config = config;
	config->pad_count++;

	/* Our source i.e alice@yabber.org */
	pad->src = g_strdup(f_array[0]);
	/* Our dest i.e bob@yabber.org */
	pad->dest = g_strdup(f_array[1]);
	/* Our ID */
	pad->id = g_strdup(p_array[0]);
	pad->syndrome = OTP_OK;
	g_strfreev(p_array);
	g_strfreev(f_array);

	if (otp_id_is_valid(pad->id) == FALSE) {
		otp_pad_destroy(pad);
		return NULL;
	}

	if (otp_open_keyfile(pad) > OTP_WARN) return NULL;

	pad->position = otp_seek_pos(pad);
	otp_calc_entropy(pad);
	otp_close_keyfile(pad);
	
#ifdef DEBUG 
	printf("%s: pad created: %u pads open.\n", config->client_id, config->pad_count);
#endif
	return pad;
}

void otp_pad_destroy(struct otp* pad)
/* destroys an otp object */
{
	if (pad != NULL) {
		pad->config->pad_count--;
#ifdef DEBUG 
		printf("%s: pad destroyed: %u pads open.\n", pad->config->client_id, pad->config->pad_count);
#endif
		if (pad->src != NULL) g_free(pad->src);
		if (pad->dest != NULL) g_free(pad->dest);
		if (pad->id != NULL) g_free(pad->id);
		if (pad->filename != NULL) g_free(pad->filename);
		g_free(pad);
	}
}

OtpError otp_encrypt(struct otp* pad, char** message)
/* Creates the actual string of the encrypted message that is given to the application.
   returns TRUE if it could encrypt the message */
{
	OtpError syndrome = OTP_OK;
#ifdef DEBUG_MSG 
	otp_printint(*message,strlen(*message), "before encrypt", pad->config);
#endif
	if (pad == NULL || message == NULL || *message == NULL) return OTP_ERR_INPUT;
	pad->using_protected_pos = FALSE;
	pad->encrypt_start_pos = pad->position;
	char* old_msg = g_strdup(*message);
#ifdef UCRYPT
	syndrome = otp_uencrypt(message, pad);
	if (syndrome > OTP_WARN) {
#ifdef PRINT_ERRORS
		printf("%s: encrypt failed: %.8X\n",pad->config->client_id, syndrome);
#endif
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif

	/* Our position in the pad*/
	char* pos_str = g_strdup_printf("%u", pad->encrypt_start_pos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char* new_msg = g_strconcat(pos_str, MSG_DELI, pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
#ifdef DEBUG_MSG 
	otp_printint(*message,strlen(*message), "after encrypt", pad->config);
#endif
	g_free(old_msg);
	return syndrome;
}

OtpError otp_decrypt(struct otp* pad, char** message)
/* Strips the encrypted message and decrypts it.
   returns TRUE if it could decrypt the message  */
{
#ifdef DEBUG_MSG 
	otp_printint(*message, strlen(*message), "before decrypt", pad->config);
#endif
	OtpError syndrome = OTP_OK;
	if (pad == NULL) return OTP_ERR_INPUT;
	pad->using_protected_pos = FALSE;
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);
	if ( (m_array[0] == NULL)
			|| (m_array[1] == NULL)
			|| (m_array[2] == NULL) ) {
		g_strfreev(m_array);
		return OTP_ERR_MSG_FORMAT;
		}
	/* Our position to decrypt in the pad */
	int testpos = g_ascii_strtoll( strdup(m_array[0]), NULL, 10);
	if (testpos < 0 || testpos > pad->filesize/2) {
		g_strfreev(m_array);
		return OTP_ERR_KEY_SIZE_MISMATCH;
	}
	gsize decryptpos = (unsigned int) testpos;
	if (strcmp(m_array[1], pad->id) != 0) {
		g_strfreev(m_array);
		return OTP_ERR_ID_MISMATCH;
	}
	char* old_msg = g_strdup(*message);
	char* new_msg = g_strdup(m_array[2]);
	g_free(*message);
	*message = new_msg;
	g_strfreev(m_array);

#ifdef UCRYPT
	syndrome = otp_udecrypt(message, pad, decryptpos);
	if (syndrome > OTP_WARN) {
#ifdef PRINT_ERRORS
		printf("%s: decrypt failed: %.8X\n",pad->config->client_id, syndrome);
#endif
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif

#ifdef DEBUG_MSG 
	otp_printint(*message,strlen(*message), "after decrypt", pad->config);
#endif
	g_free(old_msg);
	return syndrome;
}

/* ------------------ otp_config ------------------------------ */

struct otp_config* otp_conf_create(
				const char* client_id,
				const char* path,
				const char* export_path)
/* Creation of the config stucture of the library, sets some parameters
 * Default values:
 * Sets msg_key_improbability_limit = DEFAULT_IMPROBABILITY
 * Sets random_msg_tail_max_len = DEFAULT_RNDLENMAX */
{
	DIR *dp;
	if (client_id == NULL || path == NULL || export_path == NULL) return NULL;

	struct otp_config* config;
	config = (struct otp_config *)g_malloc(sizeof(struct otp_config));
	config->client_id = g_strdup(client_id);
	config->path = g_strdup(path);
	config->export_path = g_strdup(export_path);
	config->msg_key_improbability_limit = DEFAULT_IMPROBABILITY;
	config->random_msg_tail_max_len = DEFAULT_RNDLENMAX;
	config->pad_count = 0; /* Initialize with no associated pads */
	config->number_of_keys_in_production = 0; /* Initialize with no keys in generation */

#ifdef DEBUG
	printf("%s: config created with: %s, %s, %s, %e, %i\n", config->client_id, config->client_id,
			config->path, config->export_path, config->msg_key_improbability_limit,
			config->random_msg_tail_max_len);
#endif
	/* check for paranoia dir and exportdir*/
	dp = opendir(config->path);
	if (dp == NULL) {
		/* Create the directory because it does not exist */
		mkdir(config->path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP );
#ifdef DEBUG 
		printf("%s: created directory %s\n", config->client_id,config->path);
#endif
	} else {
		closedir(dp);
	}
	dp = opendir(config->export_path);
	if (dp == NULL) {
		/* Create the directory because it does not exist */
		mkdir(config->export_path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP );
#ifdef DEBUG 
		printf("%s: created directory %s\n", config->client_id,config->export_path);
#endif
	} else {
		closedir(dp);
	}

return config;
}

OtpError otp_conf_destroy(struct otp_config* config)
{
/* Freeing of the otp_config struct
 * This fails with OTP_ERR_CONFIG_PAD_COUNT if there are any pads open in this config */
	if (config == NULL) return OTP_ERR_INPUT;
	if (config->pad_count != 0) {
#ifdef DEBUG 
		printf("%s: config can not be destroyed: %i pads open!\n", 
				config->client_id, config->pad_count);
#endif
		return OTP_ERR_CONFIG_PAD_COUNT;
	}
#ifdef DEBUG 
	printf("%s: config destroyed\n", config->client_id);
#endif
	if (config->client_id != NULL) g_free(config->client_id);
	if (config->path != NULL) g_free(config->path);
	if (config->export_path != NULL) g_free(config->export_path);
	g_free(config);
	return OTP_OK;
}

/* ------------------ otp_config get functions ------------------- */

const char* otp_conf_get_path(const struct otp_config* config)
/* Gets a reference to the path in the config
 * Does not need to be freed.  */
{
	if (config == NULL) return NULL;
#ifdef DEBUG
	printf("%s: read config->path: %s\n",config->client_id, config->path);
#endif
	return config->path;
}

const char* otp_conf_get_export_path(const struct otp_config* config)
/* Gets a reference to the export path in the config
 * Does not need to be freed.  */
{
	if (config == NULL) return NULL;
#ifdef DEBUG
	printf("%s: read config->export_path: %s\n",config->client_id, config->export_path);
#endif
	return config->export_path;
}

gsize otp_conf_get_random_msg_tail_max_len(const struct otp_config* config)
/* Gets random_msg_tail_max_len */
{
	if (config == NULL) return 0;
#ifdef DEBUG
	printf("%s: read config->random_msg_tail_max_len: %u\n",config->client_id, config->random_msg_tail_max_len);
#endif
	return config->random_msg_tail_max_len;
}

double otp_conf_get_msg_key_improbability_limit(const struct otp_config* config)
/* Gets msg_key_improbability_limit */
{
	if (config == NULL) return 0;
#ifdef DEBUG
	printf("%s: read config->msg_key_improbability_limit: %e\n",config->client_id, config->msg_key_improbability_limit);
#endif
	return config->msg_key_improbability_limit;
}

unsigned int otp_conf_get_number_of_keys_in_production(const struct otp_config* config)
/* Gets the number of keys in production in the keygen */
{
	if (config == NULL) return 0;
#ifdef DEBUG
		printf("%s: Number of keys in generation: %i\n",config->client_id, config->number_of_keys_in_production);
#endif
	return config->number_of_keys_in_production;
}

void* otp_conf_get_trigger(const struct otp_config* config)
/* gets the trigger to emit a signal for the plugin */
{
	if(config == NULL) return NULL;
	return (void *)config->keygen_signal_trigger;
}

/* ------------------ otp_config set functions ------------------- */

OtpError otp_conf_set_path(struct otp_config* config, const char* path)
/* Sets the path where the .entropy-files are stored */
{
	if (config == NULL || path == NULL) return OTP_ERR_INPUT;
	if (config->path == NULL) return OTP_ERR_INPUT;
	g_free(config->path);
	config->path = g_strdup(path);
#ifdef DEBUG
	printf("%s: set config->path: %s\n",config->client_id, config->path);
#endif
	return OTP_OK;
}

OtpError otp_conf_set_export_path(struct otp_config* config, const char* export_path)
/* Sets the export path where the .entropy-files are stored */
{
	if (config == NULL || export_path == NULL) return OTP_ERR_INPUT;
	if (config->export_path == NULL) return OTP_ERR_INPUT;
	g_free(config->export_path);
	config->export_path = g_strdup(export_path);
#ifdef DEBUG
	printf("%s: set config->export_path: %s\n",config->client_id, config->export_path);
#endif
	return OTP_OK;
}

OtpError otp_conf_set_random_msg_tail_max_len(struct otp_config* config,
				 gsize random_msg_tail_max_len)
/* Sets random_msg_tail_max_len:
 * 					The max length of the randomly added tailing charakters
 * 					to prevent 'eve' from knowng the length of the message.
 * 					Disabled if 0. Default is already set to DEFAULT_RNDLENMAX */
{
	if (config == NULL) return OTP_ERR_INPUT;
	config->random_msg_tail_max_len = random_msg_tail_max_len;
#ifdef DEBUG
	printf("%s: set config->random_msg_tail_max_len: %u\n",config->client_id, config->random_msg_tail_max_len);
#endif
	return OTP_OK;
}

OtpError otp_conf_set_msg_key_improbability_limit(struct otp_config* config,
				 double msg_key_improbability_limit)
/* Sets msg_key_improbability_limit:
 * 					If the used random entropy shows pattern that are less likely
 * 					then this limit, the entropy is discarded and an other block of
 * 					entropy is used. A warning OTP_WARN_KEY_NOT_RANDOM is given.
 * 					Disabled if 0.0. Default is already set to DEFAULT_IMPROBABILITY. */
{
	if (config == NULL) return OTP_ERR_INPUT;
	if (msg_key_improbability_limit < 0.0 || msg_key_improbability_limit > 1.0) return OTP_ERR_INPUT;
	config->msg_key_improbability_limit = msg_key_improbability_limit;
#ifdef DEBUG
	printf("%s: set config->msg_key_improbability_limit: %e\n",config->client_id, config->msg_key_improbability_limit);
#endif
	return OTP_OK;
}

OtpError otp_conf_increment_number_of_keys_in_production(struct otp_config* config)
/* Increments the number of keys in production in the keygen
 * This function makes only sense if used in the keygen itself */
{
	if(config == NULL) return OTP_ERR_INPUT;
	config->number_of_keys_in_production++;
#ifdef DEBUG
		printf("%s: Number of keys in generation: %i\n",config->client_id, config->number_of_keys_in_production);
#endif
	return OTP_OK;
}

OtpError otp_conf_decrement_number_of_keys_in_production(struct otp_config* config)
/* Increments the number of keys in production in the keygen
 * This function makes only sense if used in the keygen itself */
{
	if(config == NULL) return OTP_ERR_INPUT;
	if((config->number_of_keys_in_production - 1) < 0) {
#ifdef PRINT_ERRORS
		printf("%s: 0 keys in production! Can not decrement the amount of keys in production!\n",config->client_id);
#endif
		return OTP_ERR_INPUT;
	}
	config->number_of_keys_in_production--;
#ifdef DEBUG
		printf("%s: Number of keys in generation: %i\n",config->client_id, config->number_of_keys_in_production);
#endif
	return OTP_OK;
}

OtpError otp_conf_set_trigger(struct otp_config* config, void* trigger)
/*	Set the trigger in the config file, which is needed to
*	to emit a signal for key generation information */
{
	if(trigger == NULL || config == NULL) return OTP_ERR_INPUT;
	
	config->keygen_signal_trigger = (GObject *)trigger;
	return OTP_OK;
}



/* ------------------ otp_pad get functions ------------------- */

const char* otp_pad_get_src(struct otp* mypad)
/* gets a reference to the source, i.e alice@jabber.org */
{
	if (mypad == NULL) return NULL;
	return mypad->src;
}

const char* otp_pad_get_dest(struct otp* mypad)
/* gets a reference to the destination, i.e bob@jabber.org */
{
	if (mypad == NULL) return NULL;
	return mypad->dest;
}


const char* otp_pad_get_id(struct otp* mypad)
/* gets a reference to the ID, 8 digits unique random number of the key pair (hex) */
{
	if (mypad == NULL) return NULL;
	return mypad->id;
}

const char* otp_pad_get_filename(struct otp* mypad)
/* gets a reference to the full path and the filename defined in the libotp spec */
{
	if (mypad == NULL) return NULL;
	return mypad->filename;
}

gsize otp_pad_get_entropy(struct otp* mypad)
/* gets the size (in bytes) of the entropy left for the sender */
{
	if (mypad == NULL) return 0;
	return mypad->entropy;
}

gsize otp_pad_get_filesize(struct otp* mypad)
/* gets the size of the file in bytes */
{
	if (mypad == NULL) return 0;
	return mypad->filesize;
}

gsize otp_pad_get_position(struct otp* mypad)
/* gets the current encrypt-position (in bytes) in the keyfile */
{
	if (mypad == NULL) return 0;
	return mypad->position;
}

OtpError otp_pad_get_syndrome(struct otp* mypad)
/* gets an OtpError that contains information about the status of the pad */
{
	if (mypad == NULL) return 0;
	return mypad->syndrome;
}

struct otp_config* otp_pad_get_conf(struct otp* mypad)
/* gets the config of this pad as reference */
{
	if (mypad == NULL) return NULL;
	return mypad->config;
}

void otp_pad_use_less_memory(struct otp* pad)
/* closes the filehandle and the memory map. 
 * You can do this any time you want, it will just save memory */
{
	if (pad->file_is_open == TRUE) {
#ifdef PRINT_ERRORS
		printf("%s: file and memory map closed.\n", pad->config->client_id);
#endif
		otp_close_keyfile(pad);
	} else {
#ifdef PRINT_ERRORS
		printf("%s: this pad has no open file.\n", pad->config->client_id);
#endif
	}
}
