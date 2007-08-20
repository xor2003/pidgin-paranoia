/*
    Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
    Copyright (C) 2007  Simon Wenner, Christian Wäckerlin

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

/* GNUlibc includes */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

/* strange fixes for strange warnings */
extern char *stpcpy (char *, const char *);
extern int asprintf(char **, const char *, unsigned int); 


/* GNOMElib */
#include <glib.h>


/* great stuff */
#include "libotp.h"

/* Some defintions */
#define FILE_DELI " "		/* Delimiter in the filename */
#define MSG_DELI "|"		/* Delimiter in the encrypted message */
#define PAD_EMPTYCHAR '\0'	/* Char that is used to mark the pad as used. */
#define PROTECTED_ENTROPY 100	/* The amount of entropy that is only used for "out of entropy" messages */ 
#define	FILE_SUFFIX ".entropy"	/* The keyfiles have to end with this string to be valid. This string has to be separated by ".". */
#define ID_LENGTH 8		/* Size of the ID-string */
#define NOENTROPY_SIGNAL "*** I'm out of entropy!"	/* The message that is send in case the sender is out of entropy */


/* All defines needed for full opt functionality! */

#define UCRYPT			/* Encryption and decryption only enabled if defined */
#define HAVEFILE		/* Do you have a file named pad->filename in your working dir? Used for struct *pad generation. (Works) */
#define HAVEKEYFILE		/* Do you have a file names pad->filename in your working dir? Used for en/decryption. */
#define KEYOVERWRITE		/* Overwrite the used key-sequence in the keyfile */


#define STATICKEY "dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4"


/*  ----------------- Lib One-Time Pad Functions (Internal)------------------ */

/* XOR message and key. This function is the core of the libary. */
static int otp_xor(char **message,char **key,int len) {
	int i;
	char *m,*k;

/* Do no XOR  */
/* 	printf("Warning: XOR disabled!!!!!!!!!!!!!!\n"); */
/* 	return 1; */			
	
	m = *message;
	k = *key;
/* 	otp_printint(m,len); */
/* 	otp_printint(p,len); */
	for (i = 0;i < (len-1);i++) {
/* 		printf("%c\t%d\t%c\t%d\t%d\n",m[i],m[i],p[i],p[i],m[i]^p[i]); */
		m[i]=m[i]^k[i];
	}
/* 	otp_printint(m,len);	 */
	*message=m;
	free(*key);
	return TRUE;
}

/* Helper function for debugging */
static int otp_printint(char *m,int len) {
	int i;
	printf("\t\tIntegers:\t");
	for (i = 0;i < len;i++) {
		printf("%d ",m[i]);
	}
	printf("\n");
	return TRUE;
}

/* Calculate the free entropy */
static void otp_calc_entropy(struct otp* pad){
	int entropy = pad->filesize / 2 - pad->position - PROTECTED_ENTROPY;		/* Calculate the free entropy */

	if (entropy < 0){
		pad->entropy = 0;
	} else {
		pad->entropy = entropy;
	}
}

/* Opens a keyfile with memory mapping */
static int otp_open_keyfile(int fd, char **data,struct otp* pad){
	struct stat fstat;
	if ((fd = open(pad->filename, O_RDWR)) == -1) {
		perror("open");
		pad=NULL;
		return FALSE;
	}

	if (stat(pad->filename, &fstat) == -1) {
		perror("stat");
		pad=NULL;
		return FALSE;
	}
	pad->filesize=fstat.st_size;

	if ((*data = mmap((caddr_t)0, pad->filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		pad=NULL;
		return FALSE;
	}
	return TRUE;
}

/* Closes a keyfile with memory mapping */
static int otp_close_keyfile(int fd, char **data,struct otp* pad){
	munmap(data, pad->filesize);
	close(fd);
	return TRUE;
}

/* Seek the position where the pad can be used for encryption */
static int otp_seek_pos(char *data,int filesize){
	int pos=0;
/* 	otp_printint(data+pos,10); */

	while ( ( (data+pos)[0] == PAD_EMPTYCHAR) && (pos < filesize) ) {
		pos++;
	}
	return pos;
}

/* Seeks the the starting position,filesize and entropy from the keyfile */
static struct otp* otp_seek_start(struct otp* pad){
/* 	char* path = get_current_dir_name(); */
	int fd=0; char *b=""; char **data; data=&b;
/* 	printf(" ");			Voodoo?  */
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
/* 	otp_printint(*data+99990,100); */

		pad->position = otp_seek_pos(*data,pad->filesize);
		otp_calc_entropy(pad);
		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
	}else{
		return NULL;
	}

/* 	printf("\t\tTest%u\n",h); */
	return pad;
}

/* Check if the ID is valid */
static char* otp_check_id(char* id_str){
	if ( strlen(id_str) == ID_LENGTH * sizeof(char)) {
		return id_str;				/* The ID only if the message was extracted as well.*/	
	}else{
		return NULL;
	}
}

/* Gets the key to encrypt from the keyfile */
static int otp_get_encryptkey_from_file(char **key , struct otp* pad, int len) {
	int fd=0; char *b=""; char **data; data=&b;
	int i=0;

/* 	printf("\ntest\t\t\t:%d\n\n",(pad->filesize / 2 - PROTECTED_ENTROPY)); */
	if ( (pad->position + len >= (pad->filesize / 2 - PROTECTED_ENTROPY) ) || pad->position < 0) {
		return FALSE;
	}
	
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
		char *vkey = (char *) malloc( (len) * sizeof(char) );
		memcpy( vkey, *data+pad->position ,len-1);  		/* the pad could be anything... use memcpy */
		*key=vkey;
/* 		otp_printint(*key,len-1); */

		char *datpos=*data+pad->position;
#ifdef KEYOVERWRITE
		for(i = 0 ; i < ( len - 1) ; i++){		/* Make the used key unusable in the keyfile */
/* 			printf(" %d \n",datpos[i]); */
			datpos[i] = PAD_EMPTYCHAR;
/* 			printf(" %d \n",datpos[i]); */
		}
#endif

/* 		msync(data, pad->filesize, MS_ASYNC); */
/* 		usleep(100000); */
		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
		pad->position = pad->position + len -1;
/* 		printf("\ntest\t\t\t:%d",pad->position); */
		otp_calc_entropy(pad);
		
	}else{
		return FALSE;
	}
	return TRUE;

}

/* Gets the key to decrypt from the keyfile */
static int otp_get_decryptkey_from_file(char **key , struct otp* pad, int len, int decryptpos) {
	int fd=0; char *b=""; char **data; data=&b;
	int i=0;
/* 	printf("\ndecryptpos\t\t\t:%d\n\n",decryptpos); */
	if (pad->filesize < (pad->filesize-decryptpos - (len -1)) || (pad->filesize-decryptpos) < 0) {
		return FALSE;
	}
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
		char *vkey = (char *) malloc( (len) * sizeof(char) );
/* 		printf("\ntest\t\t\t:%d\n\n",pad->filesize-decryptpos - (len -1)); */

		char *datpos = *data + pad->filesize - decryptpos - (len - 1);
		
		for (i=0; i <= (len -1); i++) {			/* read reverse*/
			vkey[i]=datpos[len - 2 - i];	
		}

		*key=vkey;
/* 		otp_printint(*key,len-1); */

/* 		msync(data, pad->filesize, MS_ASYNC); */
/* 		usleep(100000); */
		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
	}else{
		return FALSE;
	}
	return TRUE;
}

/* Encodes message into the base64 form */
static int otp_b64enc(char **message,int *len) {

	char* msg = g_base64_encode( (guchar*) *message,*len);	/* Gnomelib Base64 encode */
	*len = (strlen(msg)+1) * sizeof(char);			/* The size has changed */

	g_free(*message);
	*message = msg;
	return TRUE;
}

/* Decodes message from the base64 form */
static int otp_b64dec(char **message, int *len) {

	guchar* msg = g_base64_decode( *message, (guint*) len);	/* Gnomelib Base64 decode */

	g_free(*message);
	*message = (char*) msg;
	return TRUE;
}

/* Decrypt the message  */
static int otp_udecrypt(char **message, struct otp* pad, int decryptpos) {
	int a = (strlen(*message)+1)* sizeof(char); 				/* get length of the used memory*/
	int *len=&a;
	char *b="x"; char **key; key=&b;
	otp_b64dec( message, len );				/* decode base64 */

#ifdef HAVEKEYFILE
	if ( otp_get_decryptkey_from_file(key,pad,*len,decryptpos) == FALSE ) {
		return FALSE;
	}
#else
	char k[]=STATICKEY;
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); 					/* the pad could be anything... use memcpy */
	*key=vkey; 
#endif


	otp_xor( message, key, *len);				/* xor */
	return TRUE;
}

/* Encrypt the message  */
static int otp_uencrypt(char **message, struct otp* pad) {
	int a = (strlen(*message)+1) * sizeof(char);				/* get length of the used memory*/
	int *len=&a;
	char *b=""; char **key; key=&b;

#ifdef HAVEKEYFILE
	if ( otp_get_encryptkey_from_file(key,pad,*len) == FALSE ) {
		return FALSE;
	}
#else

	char k[]=STATICKEY; 
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); 					/* the pad could be anything... use memcpy */
	*key=vkey;
#endif

	otp_xor( message , key, *len);				/* xor */
	otp_b64enc( message , len );				/* encode base64 */
	
	return TRUE;
}


/*  ----------------- Public One-Time Pad Functions ------------ */

/* extracts and returns the ID from a given encrypted message. Leaves the message constant. Returns NULL if it fails.*/
char* otp_get_id_from_message(char **message){

	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL) || (m_array[1] == NULL) ) {
		return FALSE;
	}

	char *id_str = g_strdup(m_array[1]);

	return otp_check_id(id_str);
}

/* Creates an otp struct, returns NULL if the filename is incorrect,
   or if the file is missing */
struct otp* otp_get_from_file(const char* path, const char* input_filename){
	static struct otp* pad;
   	pad = (struct otp *) malloc(sizeof(struct otp));

	if (input_filename == NULL ) {	/* empty filename */
		return NULL;
	}

	if (path == NULL ) {	/* empty path */
		return NULL;
	}

	char *filename = g_strconcat(path,input_filename,NULL);
	pad->filename = filename;

	gchar** f_array = g_strsplit(input_filename, FILE_DELI, 3);

	if ( (f_array[0] == NULL) || (f_array[1] == NULL) || (f_array[2] == NULL) ) {
		return NULL;
	}
	char *src = g_strdup(f_array[0]);	/* Our source i.e alice@yabber.org */
	pad->src = src;

	char *dest = g_strdup(f_array[1]);	/* Our dest i.e bob@yabber.org */
	pad->dest = dest;

	gchar** p_array = g_strsplit(f_array[2], ".", 2);

	if ( (p_array[0] == NULL ) || (p_array[1] == NULL ) ) {
		return NULL;
	}
	if ( g_str_has_suffix(f_array[2], FILE_SUFFIX) == FALSE ) {
		return NULL;
	}
	char *id = g_strdup(p_array[0]);	/* Our ID */
	pad->id = id;

	g_strfreev(p_array);

	g_strfreev(f_array);

	if ( otp_check_id(pad->id) == NULL ) {
		return NULL;
	}

#ifdef HAVEFILE

	pad = otp_seek_start(pad);		/* Try to open the keyfile and get position ans size */
#else
/* 	 Dummy-values for development */
	if (pad != NULL) {
		pad->position = 10000;
		pad->filesize = 100000;
		otp_calc_entropy(pad);
	}
#endif
	return pad;
}
/* destroys an otp object */
void otp_destroy(struct otp* pad) {
/* 	if (pad != NULL) { */
/* 		if (pad->src != NULL) */
/* 			free(pad->src); */
/* 		if (pad->dest != NULL) */
/* 			free(pad->dest); */
/* 		if (pad->id != NULL) */
/* 			free(pad->id); */
/* 		if (pad->filename != NULL) */
/* 			free(pad->filename); */
/* 		free(pad); */
/* 	} */
}

/* Creates the actual string of the encrypted message that is given to the application.
returns TRUE if it could encrypt the message 
*/
unsigned int otp_encrypt(struct otp* pad, char **message){

	if(pad == NULL) {
		return 0;
	}
			
	char *pos_str;
	asprintf (&pos_str, "%ld",pad->position);			/* Our position in the pad*/

#ifdef UCRYPT
	if (otp_uencrypt(message,pad) == FALSE) {			/* Encrypt and base64 */
		return FALSE;
	}
#endif				

	char *new_msg = g_strconcat(pos_str,MSG_DELI,pad->id,MSG_DELI,*message,NULL);	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	g_free(*message);
	*message = new_msg;
	return TRUE;
}

/* Strips the encrypted message and decrypts it.
returns TRUE if it could decrypt the message  */
unsigned int otp_decrypt(struct otp* pad, char **message){

	if (pad == NULL) {
		return FALSE;
	}

	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL) || (m_array[1] == NULL) || (m_array[2] == NULL) ) {
		return FALSE;
	}

	int decryptpos = (unsigned int) g_ascii_strtoll ( strdup (m_array[0]) ,NULL,10); 	/* Our position to decrypt in the pad */
	pad->id = g_strdup(m_array[1]);

	char *new_msg = g_strdup(m_array[2]);
	g_free(*message);
	*message = new_msg;

	g_strfreev(m_array);

#ifdef UCRYPT

	if ( otp_udecrypt(message,pad,decryptpos) ) {		/* Decrypt and debase64 */
		return FALSE;
	}

#endif

/* 	printf("decrypt:\tMessage:\t%s\n",*message); */
	return TRUE;
}








/*  ----------------- TODO: REMOVE ME ------------------ */
void aaaa_encrypt(char **message) {

/* 	HELP: http://irc.essex.ac.uk/www.iota-six.co.uk/c/g6_strcat_strncat.asp */
	char *a_str = " << this message is encryptet"; 
	char *new_msg = g_strconcat(*message, a_str, NULL);

	g_free(*message);
	*message = new_msg;
	
/* 	HELP: change single elements of the char array */
/* 	(*message)[0] = 'A'; */

	return;
}

void aaaa_decrypt(char **message) {

/* 	HELP: http://irc.essex.ac.uk/www.iota-six.co.uk/c/g6_strcat_strncat.asp */
	char *a_str = " << this message is decryptet"; 
	char *new_msg = g_strconcat(*message, a_str, NULL);

	g_free(*message);
	*message = new_msg;

	return;
}



