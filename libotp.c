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

/*  ------------------- Constants (you can change them) ------------ */

#define PATH_DELI "/"            /* For some reason some strange
				 * operatingsystems use "\" */
#define BLOCKSIZE 1024          /* The blocksize used in the keyfile
				 * creation function */
#define ERASEBLOCKSIZE 1024     /* The blocksize used in the key
				 * eraseure function */
#define REPEATTOL 1E-12         /* If a repeated sequence with less
				 * probability then this occurs, throw the key away */
#define NUMBERSIGMA 6           /* (not implemented) If the sum over
				 * the key is more than this number of sigmas away from the average,
				 * then reject key (probability:1.9*10^-9) */
#define RNDLENMAX 30            /* Maximal length of the added
				 * random-length tail onto the encrypted message */

/*  ------------------- Defines (essential) ------------------------
 * All defines needed for full opt functionality! Regarded
 * as stable. The encryption is worthless without those! */

#define UCRYPT                  /* Encryption and decryption only enabled if defined */
#define KEYOVERWRITE    /* Overwrite the used key-sequence in the keyfile */

/*  ------------------- Defines (optional) ------------------------
 * These defines give new, additional features. */

//#define USEDESKTOP
/* Requires GNOMElib 2.14! Bob's
 * keyfile is placed onto the desktop. If not set, the
 * file is placed in the home directory.*/

/*  ------------------- Defines (in development) ------------------------
 * In development. Regraded as unstable. Those functions are nice
 * but not critical. */

#define CHECKKEY                /* Histogram/repeat checking of the key */
#define RNDMSGLEN               /* Add a random-length string onto the message */

/*  ------------------- Defines (for development) ------------------------
 * For development. */

//#define DEBUG
                 /* Enables the function otp_printint
*                and dumps the way of the message and key byte by byte. */

/*  ----------------- Private Functions of the Library------------ */

static int otp_xor(char **message, char **key, int len)
/* XOR message and key. This function is the core of the library. */
{
	int i;
	for (i = 0; i < (len-1); i++) {
		(*message)[i] = (*message)[i]^(*key)[i];
	}
	g_free(*key);
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

#ifdef DEBUG
static void otp_printint(char *m, int len, const char *hint)
/* Helper function for debugging */
{
	int i;
	printf("\t\t%s:\t",hint);
	for (i = 0; i < len; i++) {
		printf("%i ", m[i]);
	}
	printf("\n");
}
#endif

static void otp_calc_entropy(struct otp* pad)
/* Calculate the free entropy */
{
	int entropy = pad->filesize/2-pad->position-OTP_PROTECTED_ENTROPY;
	if (entropy < 0) {
		pad->entropy = 0;
	} else {
		pad->entropy = entropy;
	}
}

static int otp_open_keyfile(int *fd, char **data, struct otp* pad)
/* Opens a keyfile with memory mapping */
{
	struct stat fstat;
	if ((*fd = open(pad->filename, O_RDWR)) == -1) {
		perror("open");
		pad = NULL;
		return FALSE;
	}

	if (stat(pad->filename, &fstat) == -1) {
		perror("stat");
		pad = NULL;
		return FALSE;
	}
	pad->filesize = fstat.st_size;

	if ((*data = mmap((caddr_t)0, pad->filesize, PROT_READ | PROT_WRITE,
	                  MAP_SHARED, *fd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		pad = NULL;
		return FALSE;
	}
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

static int otp_close_keyfile(int *fd, char **data, struct otp* pad)
/* Closes a keyfile with memory mapping */
{
	munmap(*data, pad->filesize);
	close(*fd);
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

static int otp_seek_pos(char *data, int filesize)
/* Seeks the position where the pad can be used for encryption */
{
	int pos = 0;
	while ( ((data+pos)[0] == PAD_EMPTYCHAR) && (pos < filesize) ) {
		pos++;
	}
	return pos;
}

static struct otp* otp_seek_start(struct otp* pad)
/* Seeks the the starting position,filesize and entropy from the keyfile */
{
	int space1 = 0;
	int *fd = &space1;
	char *space2 = "";
	char **data = &space2;
	if (otp_open_keyfile(fd, data, pad)) {
		pad->position = otp_seek_pos(*data, pad->filesize);
		otp_calc_entropy(pad);
		otp_close_keyfile(fd, data, pad);
	} else {
		return NULL;
	}
	return pad;
}

static int otp_id_is_valid(char* id_str)
/* Check if the ID is valid */
{
	if ( strlen(id_str) == OTP_ID_LENGTH * sizeof(char)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static int otp_key_is_random(char **key, int len)
/* Checks the key by statistical means
 *
 * repeatprob=(1/256)^(repeatlength-1)*(keylength-repeatlength+1) */
{
	int i, rep = 1;
	double repeatprob;
//	char *c="test1111";
//	len=strlen(c);
	char *c = *key;
	int lastc = 257; /* Startvalue: This is not a char */
	for (i = 0; i < len; i++) {
		if (c[i] == lastc) {
			rep++;
		} else {
			lastc = c[i];
		}
	}
	repeatprob = pow(1/256.0, rep-1.0)*(len-rep+1);
//	printf("Probability for a repeat of len %i: %e\n",rep,repeatprob);
	if (repeatprob < REPEATTOL) {
		/* Fail if the probability for a random key to have a repeat is smaller than the tolerance. */
		printf("Probability for a repeat of len %i: %e\n", rep, repeatprob);
		return FALSE;
	}
	return TRUE;
}

static int otp_get_encryptkey_from_file(char **key, struct otp* pad, int len)
/* Gets the key to encrypt from the keyfile */
{
	int space1 = 0;
	int *fd = &space1;
	char *space2 = "";
	char **data = &space2;
	int i = 0;
	int protected_entropy = OTP_PROTECTED_ENTROPY;
	int position = pad->position;

	if (pad->protected_position != 0) {
		/* allow usage of protected entropy*/
		protected_entropy = 0;
		position = pad->protected_position;
	}
	if ( (position+len-1 > (pad->filesize/2-protected_entropy) )
	     || position < 0 ) return FALSE;

	if (otp_open_keyfile(fd, data, pad) == FALSE) return FALSE;

	char *vkey = (char *)g_malloc((len)*sizeof(char));
	memcpy(vkey, *data+position, len-1);
	/* the pad could be anything... using memcpy */
	*key = vkey;
	char *datpos = *data+position;

#ifdef CHECKKEY
	/* TODO v0.2: What should i do if the key is rejected?
	 * ATM it just fails and destroys the keyblock.*/
	if (otp_key_is_random(key, len-1) == FALSE) {
#ifdef KEYOVERWRITE
		if (pad->protected_position == 0) {
			/* not using protected entropy, make the used key unusable
			 * in the keyfile */
			for (i = 0 ; i < ( len - 1) ; i++) datpos[i] = PAD_EMPTYCHAR;
		}
		return FALSE;
#endif
	}
#endif
#ifdef KEYOVERWRITE
	if (pad->protected_position == 0) {
		/* Make the used key unusable in the keyfile unless the entropy
		 * is protected */
		for (i = 0 ; i < ( len - 1) ; i++) {
			datpos[i] = PAD_EMPTYCHAR;
		}
	}
#endif
	otp_close_keyfile(fd, data, pad);
	if (pad->protected_position == 0)
		pad->position = pad->position + len -1;
	/* In all cases where the protected entropy is not used */
	otp_calc_entropy(pad);
	return TRUE;  // TODO v0.2: Imperativ: Should be 0
}

static int otp_get_decryptkey_from_file(char **key, struct otp* pad, int len, int decryptpos)
/* Gets the key to decrypt from the keyfile */
{
	int space1 = 0;
	int *fd = &space1;
	char *space2 = "";
	char **data = &space2;
	int i = 0;
	if (pad->filesize < (pad->filesize-decryptpos - (len -1))
	    || (pad->filesize-decryptpos) < 0) return FALSE;
	if (otp_open_keyfile(fd, data, pad) == FALSE) return FALSE;

	char *vkey = (char *)g_malloc( len*sizeof(char) );
	char *datpos = *data + pad->filesize - decryptpos - (len - 1);
	/* read reverse*/
	for (i = 0; i <= (len -1); i++) vkey[i] = datpos[len - 2 - i];
	*key = vkey;
	otp_close_keyfile(fd, data, pad);
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

static int otp_base64_encode(char **message, gsize len)
/* Encodes message into the base64 form */
{
	char* msg = g_base64_encode( (guchar*)*message, len);
	/* The size has changed */
	len = (strlen(msg)+1) * sizeof(char);

	g_free(*message);
	*message = msg;
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

static int otp_base64_decode(char **message, gsize *plen)
/* Decodes message from the base64 form
 * The function needs the length as pointer because the length will change*/
{
	guchar* msg = g_base64_decode( *message, plen);
	g_free(*message);
	*message = (char*)msg;
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

static int otp_udecrypt(char **message, struct otp* pad, int decryptpos)
/* Decrypt the message  */
{
	gsize len = (strlen(*message)+1)* sizeof(char);
	char *space1 = "";
	char **key = &space1;
	otp_base64_decode(message, &len);

	if (otp_get_decryptkey_from_file(key, pad, len, decryptpos) == FALSE)
		return FALSE;
#ifdef DEBUG 
	otp_printint(*key,len, "paranoia: decryptkey");
#endif
	otp_xor(message, key, len);
	return TRUE;                    // TODO v0.2: Imperativ: Should be 0
}

static int otp_uencrypt(char **message, struct otp* pad)
/* Encrypt the message  */
{
	gsize len = (strlen(*message)+1) * sizeof(char);
	char *space1 = "";
	char **rand = &space1;
	char *space2 = "";
	char **key = &space2;
	char *msg;
	int rnd;

#ifdef RNDMSGLEN
	/* get one byte from keyfile for random length */
	if ( otp_get_encryptkey_from_file(rand, pad, 1+1)
	     == FALSE ) return FALSE;
	rnd = (unsigned char)*rand[0]*RNDLENMAX/255;
	g_free(*rand);
	msg = g_malloc0(rnd+len);       /* Create a new,longer message */
	memcpy(msg, *message, len-1);
	g_free(*message);
	*message = msg;
	len += rnd;
#endif
	if ( otp_get_encryptkey_from_file(key, pad, len)
			== FALSE ) return FALSE;
#ifdef DEBUG 
	otp_printint(*key,len, "paranoia: encryptkey");
#endif
	otp_xor(message, key, len);
	otp_base64_encode(message, len);
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}


/*  ----------------- Public Functions of the Library------------
 * Exported in libtop.h */


unsigned int otp_erase_key(struct otp* pad)
/* destroys a keyfile by using up all encryption-entropy */
{
	if (pad == NULL) return FALSE;
	pad->protected_position = 0;
	gsize len = (ERASEBLOCKSIZE+1) * sizeof(char);
	char *space1 = "";
	char **key = &space1;
	/* Using up all entropy */
	int result = TRUE;
	while (result == TRUE) {
		result = otp_get_encryptkey_from_file(key, pad, len);
	}
	result = TRUE;
	len = 1+1;
	while ( result == TRUE ) {
		result = otp_get_encryptkey_from_file(key, pad, len);
	}
	return TRUE; // TODO v0.2: Imperativ: Should be 0
}

unsigned int otp_generate_key_pair(const char* alice,
                                   const char* bob, const char* path,
                                   const char* source, unsigned int size)
//TODO: v0.2: give the filenames back
//TODO: v0.2: support loop-keys (alice=bob)
//unsigned int otp_generate_key_pair(const char* alice,
//                                   const char* bob, const char* path,
//                                   const char* source, unsigned int size
//                                   char** filenames[])
 /* The function can only generate Keyfiles with a filesize of n*BLOCKSIZE*/

{
	if (alice == NULL || bob == NULL || path == NULL
	    || source == NULL || size == 0) return FALSE;

	/* Check for things like '/'. Alice and Bob will become filenames */
	if ((g_strrstr(alice, PATH_DELI) != NULL)
	    || (g_strrstr(bob, PATH_DELI) != NULL)) return FALSE;
	
	/* Loop-Keys not supported */
	if (strcmp(alice,bob)==NULL) return FALSE;

	if ( size/BLOCKSIZE == (float)size/BLOCKSIZE ) {
		size = size/BLOCKSIZE;
	} else {
		size = size/BLOCKSIZE+1;
	}

	int rfd = 0;
	if ((rfd = open(source, O_RDONLY)) == -1) {
		perror("open");
		return FALSE;
	}
	struct stat rfstat;
	if (stat(source, &rfstat) == -1) {
		perror("stat");
		return FALSE;
	}

	unsigned int rfilesize = rfstat.st_size;
	/* If the source is to small and not a character dev */
	if ( !( ((rfstat.st_mode|S_IFCHR) == rfstat.st_mode)
	        || (rfilesize >= size*BLOCKSIZE) ) ) return FALSE;

	unsigned int id;
	/* Our ID */
	read(rfd, &id, sizeof(id));
	/* Our ID string */;
	char *idstr = g_strdup_printf("%.8X", id);

	DIR *dp;
	dp = opendir(path);
	if (dp == NULL) {
		/* Create the directory for the entropy files if it does not exist */
		mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP );
	} else {
		closedir(dp);
	}
	/* Opening the first file */
	char *afilename = g_strconcat(path, alice, FILE_DELI, bob, FILE_DELI, idstr, ".entropy", NULL);

	int afd = 0;
	char *space1 = "";
	char **adata = &space1;
	if ((afd = open(afilename, O_RDWR)) == -1) {
	} else {
		/* File already exists. I will not overwrite any existing file!*/
		close(afd);
		close(rfd);
		return FALSE;
	}
	if ((afd = open(afilename,
	                O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP ))
	    == -1) {
		perror("open");
		close(rfd);
		return FALSE;
	}
	char rand[BLOCKSIZE];
	int i = 0;

	/* Filling the first file */
	for (i = 0; i < size; i++) {
		read(rfd, rand, BLOCKSIZE);
		write(afd, rand, BLOCKSIZE);
	}
	/* Close the entropy source */
	close(rfd);
	/* Opening the secound file */
#ifdef USEDESKTOP
	/* Owned by Glib. No need for g_free */
	const char *desktoppath = g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP);
#else
	const char *desktoppath = g_get_home_dir ();
#endif

	char *bfilename = g_strconcat(desktoppath, PATH_DELI, bob, FILE_DELI,
	                              alice, FILE_DELI, idstr, ".entropy", NULL);

	int bfd = 0;
	if ((bfd = open(bfilename, O_RDWR)) == -1) {
	} else {
		/* File already exists. I will not overwrite any existing file!*/
		close(bfd);
		return FALSE;
	}
	if ((bfd = open(bfilename,
	                O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP )) == -1) {
		perror("open");
		close(afd);
		return FALSE;
	}
	/* Opening a memory map for the first file */
	struct stat afstat;
	if (stat(afilename, &afstat) == -1) {
		perror("stat");
		return FALSE;
	}
	int afilesize = afstat.st_size;
	if ((*adata = mmap((caddr_t)0, afilesize, PROT_READ, MAP_SHARED, afd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		return FALSE;
	}
	/* Create the reversed second file from the first one */
	int j = 0;
	char temp[BLOCKSIZE];
	for (i = afilesize-BLOCKSIZE; i >= 0; i = i-BLOCKSIZE) {
		for (j = 0; j < BLOCKSIZE; j++) {
			temp[BLOCKSIZE-1-j] = *(*adata+i+j);
		}
		write(bfd, temp, BLOCKSIZE);
	}
	/* Close the second file */
	close(bfd);
	/* Close the first file */
	munmap(adata, afilesize);
	close(afd);
	/* Cleanup */
	g_free(idstr);
	return TRUE;            // TODO v0.2: Imperativ: Should be 0
}


unsigned int otp_encrypt_warning(struct otp* pad, char **message, int protected_pos)
/* encrypts a message with the protected entropy.
 * protected_pos is the position in bytes to use. */
{
	if (pad == NULL) return FALSE;
	int oldpos = pad->position;
	pad->protected_position = pad->filesize/2-OTP_PROTECTED_ENTROPY-protected_pos;
#ifdef RNDMSGLEN
	oldpos += 1;
#endif

#ifdef UCRYPT
	if (otp_uencrypt(message, pad) == FALSE) {
		pad->protected_position = 0;
		return FALSE;
	}
#endif
	/* Our position in the pad */
	char *pos_str = g_strdup_printf("%u", oldpos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char *new_msg = g_strconcat(pos_str, MSG_DELI,
	                            pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
	pad->protected_position = 0;
	return TRUE;            // TODO v0.2: Imperativ: Should be 0
}

char* otp_get_id_from_message(char **message)
/* extracts and returns the ID from a given encrypted message.
 * Leaves the message constant. Returns NULL if it fails.*/
{
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);
	if ( (m_array[0] == NULL) || (m_array[1] == NULL) ) {
		return FALSE;
	}
	char *id_str = g_strdup(m_array[1]);
	if (otp_id_is_valid(id_str) == TRUE) {
		return id_str;
	} else {
		return NULL;
	}
}

struct otp* otp_get_from_file(const char* path, const char* input_filename)
/* Creates an otp struct, returns NULL if the filename is incorrect,
 * or if the file is missing */
{
	static struct otp* pad;
	pad = (struct otp *)g_malloc(sizeof(struct otp));
	pad->protected_position = 0;
	if (input_filename == NULL ) return NULL;
	if (path == NULL ) return NULL;
	char *filename = g_strconcat(path, input_filename, NULL);
	pad->filename = filename;
	gchar** f_array = g_strsplit(input_filename, FILE_DELI, 3);

	if ( (f_array[0] == NULL)
	     || (f_array[1] == NULL)
	     || (f_array[2] == NULL) ) return NULL;

	/* Our source i.e alice@yabber.org */
	char *src = g_strdup(f_array[0]);
	pad->src = src;
	/* Our dest i.e bob@yabber.org */
	char *dest = g_strdup(f_array[1]);
	pad->dest = dest;

	gchar** p_array = g_strsplit(f_array[2], ".", 2);
	if ( (p_array[0] == NULL ) || (p_array[1] == NULL ) ) return NULL;
	if ( g_str_has_suffix(f_array[2], FILE_SUFFIX) == FALSE ) return NULL;
	/* Our ID */
	char *id = g_strdup(p_array[0]);
	pad->id = id;

	g_strfreev(p_array);
	g_strfreev(f_array);

	if ( otp_id_is_valid(pad->id) == FALSE ) return NULL;

	pad = otp_seek_start(pad);
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

unsigned int otp_encrypt(struct otp* pad, char **message)
/* Creates the actual string of the encrypted message that is given to the application.
   returns TRUE if it could encrypt the message */
{
#ifdef DEBUG 
	otp_printint(*message,strlen(*message), "paranoia: before encrypt");
#endif
	if (pad == NULL) return FALSE;
	pad->protected_position = 0;
	int oldpos = pad->position;
#ifdef RNDMSGLEN
	oldpos += 1;
#endif
#ifdef UCRYPT
	if (otp_uencrypt(message, pad) == FALSE) return FALSE;
#endif

	/* Our position in the pad*/
	char *pos_str = g_strdup_printf("%u", oldpos);
	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	char *new_msg = g_strconcat(pos_str, MSG_DELI, pad->id, MSG_DELI, *message, NULL);
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
#ifdef DEBUG 
	otp_printint(*message,strlen(*message), "paranoia: after encrypt");
#endif
	return TRUE;            // TODO v0.2: Imperativ: Should be 0
}

unsigned int otp_decrypt(struct otp* pad, char **message)
/* Strips the encrypted message and decrypts it.
   returns TRUE if it could decrypt the message  */
{
#ifdef DEBUG 
	otp_printint(*message,strlen(*message), "paranoia: before decrypt");
#endif
	if (pad == NULL) return FALSE;
	pad->protected_position = 0;
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL)
	     || (m_array[1] == NULL)
	     || (m_array[2] == NULL) ) return FALSE;

	/* Our position to decrypt in the pad */
	int decryptpos = (unsigned int)g_ascii_strtoll( strdup(m_array[0]), NULL, 10);
	pad->id = g_strdup(m_array[1]);
	char *new_msg = g_strdup(m_array[2]);
	g_free(*message);
	*message = new_msg;
	g_strfreev(m_array);

#ifdef UCRYPT
	if (otp_udecrypt(message, pad, decryptpos) == FALSE) return FALSE;
#endif

#ifdef DEBUG 
	otp_printint(*message,strlen(*message), "paranoia: after decrypt");
#endif
	return TRUE;            // TODO v0.2: Imperativ: Should be 0
}
