/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2007  Christian Wäckerlin
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

/*  -------------------------- Includes ---------------------------- */

/* GNUlibc includes */
#include <stdlib.h>
#include <stdio.h>
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

/* The public functions of this library */
#include "libotp.h"

/*  ------------------- Constants (don't change) -------------------
 * Changing this makes your one-time-pad incompatible */

#define FILE_DELI " "            /* Delimiter in the filename */
#define MSG_DELI "|"             /* Delimiter in the encrypted message */
#define PAD_EMPTYCHAR '\0'        /* Char that is used to mark the pad as used. */
#define FILE_SUFFIX ".entropy"   /* The keyfiles have to end with
				 * this string to be valid. This string has to be separated by ".". */
#define NOENTROPY_SIGNAL "*** I'm out of entropy!"       /* The message that
							 * is send in case the sender is out of entropy */
#define ID_SIZE		4	/* The size in bytes of the ID. */

/*  ------------------- Constants (you can change them) ------------ */

#define PATH_DELI "/"					/* For some reason some strange
				 * operatingsystems use "\" */
#define BLOCKSIZE 1000					/* The blocksize used in the keyfile
				 * creation function */
#define ERASEBLOCKSIZE 1024				/* The blocksize used in the key
				 * eraseure function */
#define DEFAULT_RNDLENMAX 30			/* Default value: Maximal length of the added
				 * random-length tail onto the encrypted message */
#define DEFAULT_IMPROBABILITY 1E-12		/* Default value: If a key with less
				 * probability then this occurs, throw the key away */

#define REPEATTOL 1E-12				// TODO: Remove, replace by otp_config
#define RNDLENMAX 30 				// TODO: Remove, replace by otp_config

/*  ------------------- Defines (essential) ------------------------
 * All defines needed for full opt functionality! Regarded
 * as stable. The encryption is worthless without those! */

#define UCRYPT                  /* Encryption and decryption only enabled if defined */
#define KEYOVERWRITE    /* Overwrite the used key-sequence in the keyfile */

/*  ------------------- Defines (optional) ------------------------
 * These defines give new, additional features. */

#define RNDMSGLEN               /* Add a random-length string onto the message */

/*  ------------------- Defines (in development) ------------------------
 * In development. Regraded as unstable. Those functions are nice
 * but not critical. */

//#define USEDESKTOP
/* Requires GNOMElib 2.14! Bob's
 * keyfile is placed onto the desktop. If not set, the
 * file is placed in the home directory.*/
#define CHECKKEY                /* Histogram/repeat checking of the key (Needs testing) */

/*  ------------------- Defines (for development) ------------------------
 * Useful for Developpers */

//#define DEBUG
                 /* Enables the function otp_printint
*                and dumps the way of the message and key byte by byte. */

/* ------------------- Private data structures -------------------- */
struct otp_config {
	char* client_id;
	char* path;
	char* export_path;
	unsigned int pad_count; /* A counter for the number of associated otp structs (has no effect) */
	gsize random_msg_tail_max_len;
	double msg_key_improbability_limit;
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

#ifdef DEBUG
static void otp_printint(char* m, gsize len, const char* hint)
/* Helper function for debugging */
{
	gsize i;
	printf("\t\t%s:\t", hint);
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

static OtpError otp_open_keyfile(int* fd, char** data, struct otp* pad)
/* Opens a keyfile with memory mapping */
{
	struct stat fstat;
	if ((*fd = open(pad->filename, O_RDWR)) == -1) {
		perror("open");
		return OTP_ERR_FILE;
	}

	if (stat(pad->filename, &fstat) == -1) {
		perror("stat");
		close(*fd);
		return OTP_ERR_FILE;
	}
	pad->filesize = fstat.st_size;

	if ((*data = mmap((caddr_t)0, pad->filesize, PROT_READ | PROT_WRITE,
			MAP_SHARED, *fd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		close(*fd);
		return OTP_ERR_FILE;
	}
	return OTP_OK;
}

static void otp_close_keyfile(int* fd, char** data, struct otp* pad)
/* Closes a keyfile with memory mapping */
{
	munmap(*data, pad->filesize);
	close(*fd);
}

static gsize otp_seek_pos(const char* data, gsize filesize)
/* Seeks the position where the pad can be used for encryption */
{
	gsize pos = 0;
	while ( ((data+pos)[0] == PAD_EMPTYCHAR) && (pos < filesize) ) {
		pos++;
	}
	return pos;
}

static OtpError otp_seek_start(struct otp* pad)
/* Seeks the the starting position, filesize and entropy from the keyfile */
{
	int space1 = 0;
	int* fd = &space1;
	char* space2 = "";
	char** data = &space2;
	OtpError syndrome = otp_open_keyfile(fd, data, pad);
	if (syndrome == OTP_OK) {
		pad->position = otp_seek_pos(*data, pad->filesize);
		otp_calc_entropy(pad);
		otp_close_keyfile(fd, data, pad);
	} else {
		return syndrome;
	}
	return syndrome;
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

static gboolean otp_key_is_random(char** key, gsize len)
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
	if (repeatprob < REPEATTOL) {
		/* Fail if the probability for a random key to have a repeat is smaller than the tolerance. */
		printf("core-paranoia: Probability for a repeat of len %i: %e\n", rep, repeatprob);
		return FALSE;
	}
	return TRUE;
}

static OtpError otp_get_encryptkey_from_file(char** key, struct otp* pad, gsize len)
/* Gets the key to encrypt from the keyfile */
{
	int space1 = 0;
	int* fd = &space1;
	char* space2 = "";
	char** data = &space2;
	gsize i = 0;
	gsize protected_entropy = OTP_PROTECTED_ENTROPY;
	gsize position = pad->position;
	OtpError syndrome = OTP_OK;

	if (pad->protected_position != 0) {
		/* allow usage of protected entropy*/
		protected_entropy = 0;
		position = pad->protected_position;
	}
	if ( (position+len-1 > (pad->filesize/2-protected_entropy) )
			|| position < 0 ) {
		return OTP_ERR_KEY_EMPTY;
	}
	syndrome = otp_open_keyfile(fd, data, pad);
	if (syndrome > OTP_WARN) return syndrome;

	*key = (char*)g_malloc((len)*sizeof(char));
	memcpy(*key, *data+position, len-1);
	/* the pad could be anything... using memcpy */
	char *datpos = *data+position;

#ifdef CHECKKEY
	/* TODO v0.2: What should i do if the key is rejected?
	 * ATM it just fails and destroys the keyblock.*/
	if (otp_key_is_random(key, len-1) == FALSE) {
#ifdef KEYOVERWRITE
		if (pad->protected_position == 0) {
			syndrome = syndrome | OTP_WARN_KEY_NOT_RANDOM;
			/* not using protected entropy, make the used key unusable
			 * in the keyfile */
			for (i = 0; i < (len - 1); i++) datpos[i] = PAD_EMPTYCHAR;
		}
		if (pad->protected_position == 0) {
			pad->position = pad->position + len -1;
		}
		otp_calc_entropy(pad);
		return syndrome;
#endif
	}
#endif
#ifdef KEYOVERWRITE
	if (pad->protected_position == 0) {
		/* Make the used key unusable in the keyfile unless the entropy
		 * is protected */
		for (i = 0; i < (len - 1); i++) {
			datpos[i] = PAD_EMPTYCHAR;
		}
	}
#endif
	otp_close_keyfile(fd, data, pad);
	if (pad->protected_position == 0) {
		pad->position = pad->position + len -1;
	}
	/* In all cases where the protected entropy is not used */
	otp_calc_entropy(pad);
	return syndrome;
}

static OtpError otp_get_decryptkey_from_file(char** key, struct otp* pad, gsize len, gsize decryptpos)
/* Gets the key to decrypt from the keyfile */
{
	int space1 = 0;
	int* fd = &space1;
	char* space2 = "";
	char** data = &space2;
	gsize i = 0;
	OtpError syndrome = OTP_OK;
	if ((decryptpos + (len+1) + pad->filesize/2) > pad->filesize
			|| decryptpos < 0) {
		syndrome = OTP_ERR_KEY_SIZE_MISMATCH;
		return syndrome;
	}
	syndrome = otp_open_keyfile(fd, data, pad);
	if (syndrome > OTP_WARN) return syndrome;

	char* vkey = (char*)g_malloc( len*sizeof(char) );
	char* datpos = *data + pad->filesize - decryptpos - (len+1);
	/* read reverse*/
	for (i = 0; i <= (len -1); i++) vkey[i] = datpos[len - i];
	*key = vkey;
	otp_close_keyfile(fd, data, pad);
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
#ifdef DEBUG
	otp_printint(*key, len, "paranoia: decryptkey");
#endif
	otp_xor(message, key, len);
#ifdef DEBUG
	otp_printint(*key,len, "paranoia: decrypt-xor");
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
	/* get one byte from keyfile for random length */
	syndrome = otp_get_encryptkey_from_file(rand, pad, 1+1);
	if ( syndrome > OTP_WARN ) return syndrome;

	rnd = (unsigned char)*rand[0]*RNDLENMAX/255;
	g_free(*rand);
	msg = g_malloc0(rnd+len);       /* Create a new,longer message */
	memcpy(msg, *message, len-1);
	g_free(*message);
	*message = msg;
	len += rnd;
#endif
	syndrome = otp_get_encryptkey_from_file(key, pad, len);
	if ( syndrome > OTP_WARN ) return syndrome;
#ifdef DEBUG
	otp_printint(*key,len, "paranoia: encryptkey");
#endif
	otp_xor(message, key, len);
#ifdef DEBUG
	otp_printint(*key,len, "paranoia: encrypt-xor");
#endif
	otp_base64_encode(message, len);
	return syndrome;
}


/*  ----------------- Public Functions of the Library------------
 * Exported in libtop.h */


OtpError otp_erase_key(struct otp* pad)
/* destroys a keyfile by using up all encryption-entropy */
{
	if (pad == NULL) return OTP_ERR_INPUT;
	pad->protected_position = 0;
	gsize len = (ERASEBLOCKSIZE+1) * sizeof(char);
	char* space1 = "";
	char** key = &space1;
	/* Using up all entropy */
	OtpError syndrome = OTP_OK;
	while (syndrome <= OTP_WARN ) {
		syndrome = otp_get_encryptkey_from_file(key, pad, len);
	}
	syndrome = OTP_OK;
	len = 1+1;
	while (syndrome <= OTP_WARN) {
		syndrome = otp_get_encryptkey_from_file(key, pad, len);
	}
	if (syndrome == OTP_ERR_KEY_EMPTY) syndrome = OTP_OK;
	return syndrome;
}

OtpError otp_generate_key_pair(const char* alice,
                                   const char* bob, const char* path,
                                   const char* source, gsize size)
//TODO: v0.2: give the filenames back
//TODO: v0.2: support loop-keys (alice=bob)
//unsigned int otp_generate_key_pair(const char* alice,
//                                   const char* bob, const char* path,
//                                   const char* source, unsigned int size
//                                   char** filenames[])
 /* The function can only generate Keyfiles with a filesize of n*BLOCKSIZE*/

{
	char *alice_file, *bob_file, id[8];
	char *home_path;
	unsigned int key_size;
	GThread *my_thread;

	if (alice == NULL || bob == NULL || path == NULL
			|| source == NULL || size <= 0) {
		return OTP_ERR_INPUT;
	}
	/* Check for things like '/'. Alice and Bob will become filenames */
	if ((g_strrstr(alice, PATH_DELI) != NULL)
			|| (g_strrstr(bob, PATH_DELI) != NULL)) {
		return OTP_ERR_INPUT;
	}
	/* Loop-Keys not supported */
//	if (strcmp(alice, bob) == 0) return OTP_ERR_LOOP_KEY;


	if ( size/BLOCKSIZE == (float)size/BLOCKSIZE ) {
		size = size/BLOCKSIZE;
	} else {
		size = size/BLOCKSIZE + 1;
	}
#ifdef DEBUG
	g_print("paranoia: otp_genkey initial checks\n");
#endif

	sprintf(id, "%.8X", otp_get_id());
	key_size = size * BLOCKSIZE;
	home_path = (char *)g_getenv ("HOME");
	if(!home_path) home_path = (char *)g_get_home_dir();

	alice_file = (char *)g_strdup_printf("%s%s %s %s.entropy", path, alice, bob, id);
	bob_file = (char *)g_strdup_printf("%s%s%s %s %s.entropy",home_path, PATH_DELI,bob, alice, id);

	my_thread = generate_keys_from_keygen(alice_file, bob_file, key_size, strcmp(alice, bob));

	g_free(alice_file);
	g_free(bob_file);

	return OTP_OK;
}


OtpError otp_encrypt_warning(struct otp* pad, char** message, gsize protected_pos)
/* encrypts a message with the protected entropy.
 * protected_pos is the position in bytes to use. */
{
	OtpError syndrome = OTP_OK;
	if (pad == NULL || message == NULL || *message == NULL || protected_pos <= 0) {
		if (protected_pos <= OTP_PROTECTED_ENTROPY - strlen(*message)) {
			return OTP_ERR_INPUT;
		}
	}
	char* old_msg = g_strdup(*message);
	gsize oldpos = pad->position;
	// TODO v0.2 oldpos is unflexible
	pad->protected_position = pad->filesize/2-OTP_PROTECTED_ENTROPY-protected_pos;
#ifdef RNDMSGLEN
	oldpos += 1;
#endif

#ifdef UCRYPT
	syndrome = otp_uencrypt(message, pad);
	if (syndrome > OTP_WARN) {
		pad->protected_position = 0;
		printf("syndrome: %.8X\n",syndrome);
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif
	/* Our position in the pad */
	char* pos_str = g_strdup_printf("%u", oldpos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char* new_msg = g_strconcat(pos_str, MSG_DELI,
	                            pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
	pad->protected_position = 0;
	g_free(old_msg);
	return syndrome;
}

char* otp_get_id_from_message(char** message)
/* extracts and returns the ID from a given encrypted message.
 * Leaves the message constant. Returns NULL if it fails.*/
{
	if (message == NULL || *message == NULL) return NULL;
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);
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

struct otp* otp_get_from_file(const char* path, const char* input_filename)
/* Creates an otp struct, returns NULL if the filename is incorrect,
 * or if the file is missing */
{
	if (input_filename == NULL || path == NULL ) return NULL;

	gchar** f_array = g_strsplit(input_filename, FILE_DELI, 3);

	if ( (f_array[0] == NULL) || (f_array[1] == NULL)
				|| (f_array[2] == NULL) ) {
		g_strfreev(f_array);
		return NULL;
	}

	gchar** p_array = g_strsplit(f_array[2], ".", 2);
	if ((p_array[0] == NULL ) || (p_array[1] == NULL )) {
		if (g_str_has_suffix(f_array[2], FILE_SUFFIX) == FALSE )
			g_strfreev(f_array);
			g_strfreev(p_array);
			return NULL;
	}

	struct otp* pad;
	pad = (struct otp *)g_malloc(sizeof(struct otp));
	pad->protected_position = 0;
	pad->filename = g_strconcat(path, input_filename, NULL);

	/* Our source i.e alice@yabber.org */
	pad->src = g_strdup(f_array[0]);
	/* Our dest i.e bob@yabber.org */
	pad->dest = g_strdup(f_array[1]);
	/* Our ID */
	pad->id = g_strdup(p_array[0]);
	pad->syndrome = OTP_OK;
	g_strfreev(p_array);
	g_strfreev(f_array);

	if (otp_id_is_valid(pad->id) == FALSE) return NULL;

	OtpError syndrome = otp_seek_start(pad);
	if (syndrome > OTP_WARN) {
		otp_destroy(pad);
		return NULL;
	}
	return pad;
}

void otp_destroy(struct otp* pad)
/* destroys an otp object */
{
	if (pad != NULL) {
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
#ifdef DEBUG
	otp_printint(*message,strlen(*message), "paranoia: before encrypt");
#endif
	if (pad == NULL || message == NULL || *message == NULL) return OTP_ERR_INPUT;
	pad->protected_position = 0;
	gsize oldpos = pad->position;
	char* old_msg = g_strdup(*message);
#ifdef RNDMSGLEN
	oldpos += 1;
#endif
#ifdef UCRYPT
	syndrome = otp_uencrypt(message, pad);
	if (syndrome > OTP_WARN) {
		printf("syndrome: %.8X\n",syndrome);
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif

	/* Our position in the pad*/
	char* pos_str = g_strdup_printf("%u", oldpos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char* new_msg = g_strconcat(pos_str, MSG_DELI, pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
#ifdef DEBUG
	otp_printint(*message,strlen(*message), "paranoia: after encrypt");
#endif
	g_free(old_msg);
	return syndrome;
}

OtpError otp_decrypt(struct otp* pad, char** message)
/* Strips the encrypted message and decrypts it.
   returns TRUE if it could decrypt the message  */
{
#ifdef DEBUG
	otp_printint(*message, strlen(*message), "paranoia: before decrypt");
#endif
	OtpError syndrome = OTP_OK;
	if (pad == NULL) return OTP_ERR_INPUT;
	pad->protected_position = 0;
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL)
			|| (m_array[1] == NULL)
			|| (m_array[2] == NULL) ) {
		g_strfreev(m_array);
		return OTP_ERR_MSG_FORMAT;
		}
	char* old_msg = g_strdup(*message);

	/* Our position to decrypt in the pad */
	gsize decryptpos = (unsigned int)g_ascii_strtoll( strdup(m_array[0]), NULL, 10);
	if (strcmp(m_array[1], pad->id) != 0) return OTP_ERR_ID_MISMATCH;
	char* new_msg = g_strdup(m_array[2]);
	g_free(*message);
	*message = new_msg;
	g_strfreev(m_array);

#ifdef UCRYPT
	syndrome = otp_udecrypt(message, pad, decryptpos);
	if (syndrome > OTP_WARN) {
		printf("syndrome: %.8X\n",syndrome);
		g_free(*message);
		*message = old_msg;
		return syndrome;
	}
#endif

#ifdef DEBUG
	otp_printint(*message,strlen(*message), "paranoia: after decrypt");
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
	if (client_id == NULL || path == NULL || export_path == NULL) return NULL;

	struct otp_config* config;
	config = (struct otp_config *)g_malloc(sizeof(struct otp_config));
	config->client_id = g_strdup(client_id);
	config->path = g_strdup(path);
	config->export_path = g_strdup(export_path);
	config->msg_key_improbability_limit = DEFAULT_IMPROBABILITY;
	config->random_msg_tail_max_len = DEFAULT_RNDLENMAX;
	config->pad_count = 0; /* Initialize with no associated pads */

#ifdef DEBUG
	printf("paranoia: config created with: %s, %s, %s, %e, %i\n", config->client_id,
			config->path, config->export_path, config->msg_key_improbability_limit,
			config->random_msg_tail_max_len);
#endif

return config;
}

OtpError otp_conf_destroy(struct otp_config* config)
{
/* Freeing of the otp_config struct
 * This fails with OTP_ERR_CONFIG_PAD_COUNT if there are any pads open in this config */
	if (config == NULL) return OTP_ERR_INPUT;
	if (config->pad_count != 0) return OTP_ERR_CONFIG_PAD_COUNT;

	if (config->client_id != NULL) g_free(config->client_id);
	if (config->path != NULL) g_free(config->path);
	if (config->export_path != NULL) g_free(config->export_path);
	g_free(config);

#ifdef DEBUG
	printf("paranoia: config destroyed\n");
#endif
	return OTP_OK;
}

/* ------------------ otp_config get functions ------------------- */

const char* otp_conf_get_path(const struct otp_config* config)
/* Gets a reference to the path in the config
 * Does not need to be freed.  */
{
	if (config == NULL) return NULL;
#ifdef DEBUG
	printf("paranoia: read config->path: %s\n",config->path);
#endif
	return config->path;
}

const char* otp_conf_get_export_path(const struct otp_config* config)
/* Gets a reference to the export path in the config
 * Does not need to be freed.  */
{
	if (config == NULL) return NULL;
#ifdef DEBUG
	printf("paranoia: read config->export_path: %s\n",config->export_path);
#endif
	return config->export_path;
}

gsize otp_conf_get_random_msg_tail_max_len(const struct otp_config* config)
/* Gets random_msg_tail_max_len */
{
	if (config == NULL) return 0;
#ifdef DEBUG
	printf("paranoia: read config->random_msg_tail_max_len: %u\n",config->random_msg_tail_max_len);
#endif
	return config->random_msg_tail_max_len;
}

double otp_conf_get_msg_key_improbability_limit(const struct otp_config* config)
/* Gets msg_key_improbability_limit */
{
	if (config == NULL) return 0;
#ifdef DEBUG
	printf("paranoia: read config->msg_key_improbability_limit: %e\n",config->msg_key_improbability_limit);
#endif
	return config->msg_key_improbability_limit;
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
	printf("paranoia: set config->path: %s\n",config->path);
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
	printf("paranoia: set config->export_path: %s\n",config->export_path);
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
	printf("paranoia: set config->random_msg_tail_max_len: %u\n",config->random_msg_tail_max_len);
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
	printf("paranoia: set config->msg_key_improbability_limit: %e\n",config->msg_key_improbability_limit);
#endif
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
/* gets an the config associated with this pad */
// TODO
//struct otp_config* otp_get_conf(struct otp* mypad);
