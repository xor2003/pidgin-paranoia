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


// GNUlibc includes
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

// starnge fix for a warning
extern char *stpcpy (char *, const char *);

//GNOMElib
#include <glib.h>


// great stuff
#include "libotp.h"

// Some defintions
//#define TRUE 1
//#define FALSE 0
#define FILE_DELI " "		// Delimiter in the filename
#define MSG_DELI "|"		// Delimiter in the encrypted message
#define PAD_EMPTYCHAR '\0'	// Char that is used to mark the pad as used.
#define PROTECTED_ENTROPY 100


//#define HAVEFILE		// Do you have a file named pad->filename in your working dir? Used for struct *pad generation. (Works)
//#define HAVEKEYFILE		// Do you have a file names pad->filename in your working dir? Used for en/decryption. (BROKEN)



// ----------------- Lib One-Time Pad Functions (Internal)------------------
struct otp* otp_calc_entropy(struct otp* pad);


/* Encodes message into the base64 form */
int otp_b64enc(char **message, int *len) {
	//printf("b64enc:\t\tMessage:\t%s\n",*message);

	char* msg = (char*) g_base64_encode((char*) *message,*len);	/* Gnomelib Base64 encode */
	*len = (strlen(msg)+1) * sizeof(char);			/* The size has changed */

	free(*message);
	*message = msg;
	//printf("b64enc:\t\tMessage:\t%s\n",*message);
	return TRUE;
}

/* Decodes message from the base64 form */
int otp_b64dec(char **message, int *len) {

	char* msg = (char*) g_base64_decode((char*) *message,len);	/* Gnomelib Base64 decode */


	free(*message);
	*message = msg;
	//printf("b64dec:\t\tMessage:\t%s\n",*message);
	return TRUE;
}

/* Decrypt the message  */
int otp_udecrypt(char **message, struct otp* pad) {
	int a = (strlen(*message)+1)* sizeof(char); 				/* get length of the used memory*/
	int *len=&a;
	char *b="x"; char **key; key=&b;
	otp_b64dec( message, len );				/* decode base64 */

#ifdef HAVEKEYFILE
	otp_get_decryptkey_from_file(key,pad,*len);
#else
	char k[]="ziuzoiuoziuzoiuzoiuzoiuzoiuzoiewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl";
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); //the pad could be anything... use memcyp
	*key=vkey; 
#endif


	otp_xor( message, key, *len);				/* xor */
	return TRUE;
}


/* Encrypt the message  */
int otp_uencrypt(char **message, struct otp* pad) {
	int a = (strlen(*message)+1) * sizeof(char);				/* get length of the used memory*/
	int *len=&a;
	char *b=""; char **key; key=&b;		

#ifdef HAVEKEYFILE
	otp_get_encryptkey_from_file(key,pad,*len);

#else

	char k[]="ziuzoiuoziuzoiuzoiuzoiuzoiuzoiewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl"; 
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); //the pad could be anything... use memcyp
	*key=vkey;


#endif

	otp_xor( message , key, *len);				/* xor */
	otp_b64enc( message , len );				/* encode base64 */
	
	return TRUE;
}

/* Gets the key to encrypt from the keyfile */
int otp_get_encryptkey_from_file(char **key , struct otp* pad, int len) {
	char k[]="ziuzoiuoziuzoiuzoiuzoiuzoiuzoiewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl"; 
	char *vkey = (char *) malloc( (len) * sizeof(char) );
	memcpy(vkey,k,len-1); //the pad could be anything... use memcyp
	*key=vkey;
	return TRUE;

}

/* Gets the key to decrypt from the keyfile */
int otp_get_decryptkey_from_file(char **key , struct otp* pad, int len) {
	char k[]="ziuzoiuoziuzoiuzoiuzoiuzoiuzoiewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl"; 
	char *vkey = (char *) malloc( (len) * sizeof(char) );
	memcpy(vkey,k,len-1); //the pad could be anything... use memcyp
	*key=vkey;
	return TRUE;
}


/* XOR message and key. This function is the core of the libary. */
int otp_xor(char **message,char **pad,int len) {
	int i;
	char *m,*p;

	//printf("Warning: XOR disabled!!!!!!!!!!!!!!\n");
	//return 1;			//Do no XOR
	
	m = *message;
	p = *pad;
	//otp_printint(m,len);
	//otp_printint(p,len);
	for (i = 0;i < (len-1);i++) {
		//printf("%c\t%d\t%c\t%d\t%d\n",m[i],m[i],p[i],p[i],m[i]^p[i]); //debug
		m[i]=m[i]^p[i];
	}
	//otp_printint(m,len);	
	*message=m;

	return TRUE;
}

/* Helper function for debugging */
int otp_printint(char *m,int len) {
	//int len=strlen(m);
	int i;
	printf("\t\tIntegers:\t");
	for (i = 0;i < len;i++) {
		printf("%d ",m[i]);
	}
	printf("\n");
	return TRUE;
}

/* Seeks the the starting position,filesize and entropy from the keyfile */
struct otp* otp_seek_start(struct otp* pad){
	//char* path = get_current_dir_name();
	int fd; char *b=""; char **data; data=&b;

	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
	//otp_printint(*data+99990,100);

		pad->position = otp_seek_pos(*data,pad->filesize);
		pad=otp_calc_entropy(pad);

		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
	}

	//printf("\t\tTest%u\n",h);
	return pad;
}

/* Opens a keyfile with memory mapping */
int otp_open_keyfile(int fd, char **data,struct otp* pad){

	struct stat fstat;
	if ((fd = open(pad->filename, O_RDONLY)) == -1) {
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

	if ((*data = mmap((caddr_t)0, pad->filesize, PROT_READ, MAP_SHARED, fd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		pad=NULL;
		return FALSE;
	}
}

/* Closes a keyfile with memory mapping */
int otp_close_keyfile(int fd, char **data,struct otp* pad){
	munmap(data, pad->filesize);
	close(fd);
}

/* Seek the position where the pad can be used for encryption */
int otp_seek_pos(char *data,int filesize){
	int pos=0;
	//otp_printint(data+pos,10);

	while (  ( (data+pos)[0] == PAD_EMPTYCHAR) && (pos < filesize) ) {
		pos++;
	}
	return pos;
}

/* Calculate the free entropy */
struct otp* otp_calc_entropy(struct otp* pad){
	int entropy = pad->filesize / 2 - pad->position - PROTECTED_ENTROPY;		/* Calculate the free entropy */

	if (entropy < 0){
		pad->entropy = 0;
	} else {
		pad->entropy = entropy;
	}

	return pad;
}

// ----------------- Public One-Time Pad Functions ------------

/* extracts and returns the ID from a given encrypted message. Leaves the message constant. Returns NULL if it fails.*/
char* otp_get_id_from_message(char **message){
	const char d[] = MSG_DELI;
     	char *m,*mrun;
     	mrun = strdup (*message);
	if (*message == NULL ) {
		return NULL;
	}
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return NULL;
	}
	//printf("id:\tpos:\t%s\n",m);	/* Our position in the pad */
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return NULL;
	}
     	char *id_str = strdup (m);	/* Our ID */

	//printf("id:\tID:\t%s\n",m);
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return NULL;
	}					/* Our Message */
	//printf("id:\tmessage:\t%s\n",m);

	return id_str;				/* The ID only if the message was extracted as well.*/	
}

/* Creates an otp struct, returns NULL if the filename is incorrect,
   or if the file is missing */
struct otp* otp_get_from_file(const char* input_filename){
	static struct otp* pad;
   	pad = (struct otp *) malloc(sizeof(struct otp));

	char *filename;
	filename = (char *) malloc((strlen(input_filename) + 1) * sizeof(char) );
	strcpy(filename, input_filename);
	pad->filename = filename;


	const char d[] = FILE_DELI;		/* The delimiter */
     	char *c, *run;
     	run = strdup (filename);
	if (filename == NULL ) {	/* empty filename */
		return NULL;
	}


     	c = strsep (&run, d);		/* Our source i.e alice@yabber.org */
	if (c == NULL ) {
		return NULL;
	}
	char *src;
	src = (char *) malloc((strlen(c) + 1) * sizeof(char) );
	src = c; 
	pad->src = src;


     	c = strsep (&run, d);		/* Our dest i.e bob@yabber.org */
	if (c == NULL ) {
		return NULL;
	}
	char *dest;
	dest = (char *) malloc((strlen(c) + 1) * sizeof(char) );
	dest = c; 
	pad->dest = dest;


     	c = strsep (&run, d);		/* Our ID */
     	char *x,*xrun;
     	xrun = strdup (c);
	x = strsep (&xrun,".");
	if (c == NULL ) {
		return NULL;
	}
	char *id;
	id = (char *) malloc((strlen(c) + 1) * sizeof(char) );
	id = x;
	pad->id = id;

	// TODO: maybe check for ".otp" ?

	// Development: Constant atm

#ifdef HAVEFILE

	pad = otp_seek_start(pad);		//Try to open the keyfile and get position ans size

#else
	// Dummy-values for development
	pad->position = 3000;
	pad->filesize = 100000;
	pad = otp_calc_entropy(pad);
#endif

	return pad;
}

/* Creates the actual string of the encrypted message that is given to the application.
returns 1 if it could encrypt the message 
*/
unsigned int otp_encrypt(struct otp* pad, char **message){

	if(pad == NULL) {
		return 0;
	}
				
	char *pos_str;
	asprintf (&pos_str, "%ld",pad->position);			/* Our position in the pad*/
	char *id_str = pad->id;						/* Our ID */


	int ret = otp_uencrypt(message,pad);		/* Encrypt and base64 */

	int size=(strlen(*message) + strlen(pos_str) + strlen(id_str) + 1 + 2) * sizeof(char);
	//char *new_msg=(char* )g_strnfill((int) size,(gchar) "\0");   //Maybe a better way?
	char *new_msg = (char *) malloc( size ); 	/* Create a new, bigger **message */

	char *p = new_msg;	

	p = stpcpy (p, pos_str);			/*Concatinate everything*/
	p = stpcpy (p, "|");
	p = stpcpy (p, id_str);
	p = stpcpy (p, "|");
	p = stpcpy (p, *message);
	//printf("encrypt:\t\tMessage:\t%s\n",new_msg);

	//(new_msg)[(strlen(*message) + strlen(pos_str) + strlen(id_str) + 2) * sizeof(char)] = '\0';
	free(*message);
	*message = new_msg;			/*Something like "3EF9|34EF4588|M+Rla2w=" */
	return ret;
}

/* Strips the encrypted message and decrypts it.
returns 1 if it could decrypt the message  */
unsigned int otp_decrypt(struct otp* pad, char **message){

	if(pad == NULL) {
		return 0;
	}


	const char d[] = "|";
     	char *m,*mrun;
     	mrun = strdup (*message);
	//printf("xor:\t\tMessage:\t%s\n",*message);
	if (*message == NULL ) {
		return 0;
	}
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}
	pad->position = (unsigned int) g_ascii_strtoll ( strdup (m) ,NULL,10); 	/* Our position in the pad */
	//printf("decrypt:\tpos:\t%s\n",pos_str);
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}
     	pad->id = strdup (m);		/* Our ID */

	//printf("decrypt:\tID:\t%s\n",id_str);
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}					/* Our Message */

     	char *new_msg;				/* Create a new, smaller **message */
	new_msg = (char *) malloc((strlen(m) + 1) * sizeof(char)); 
	strcpy(new_msg, m);
	free(*message);
	*message = new_msg;
	//printf("xor:\t\tMessage:\t%s\n",*message);
	//printf("decrypt:\tMessage:\t%s\n",*message);
	int ret = otp_udecrypt(message,pad);		/* Decrypt and debase64 */;
	//printf("decrypt:\tMessage:\t%s\n",*message);
	return ret;
}








// ----------------- TODO: REMOVE ME ------------------
void aaaa_encrypt(char **message) {

	//HELP: http://irc.essex.ac.uk/www.iota-six.co.uk/c/g6_strcat_strncat.asp
	char *new_msg;
	char *a_str = " << this message is encryptet"; // can't be free()-d
	new_msg = (char *) malloc((strlen(*message) + strlen(a_str) + 1) * sizeof(char));
	strcpy(new_msg, *message);
	strcat(new_msg, a_str);

	free(*message);
	*message = new_msg;
	
	//HELP: change single elements of the char array
	//(*message)[0] = 'A';

	return;
}

void aaaa_decrypt(char **message) {

	//HELP: http://irc.essex.ac.uk/www.iota-six.co.uk/c/g6_strcat_strncat.asp
	char *new_msg;
	char *a_str = " << this message is decryptet"; // kann nicht ge-free-t werden
	new_msg = (char *) malloc((strlen(*message) + strlen(a_str) + 1) * sizeof(char));
	strcpy(new_msg, *message);
	strcat(new_msg, a_str);

	free(*message);
	*message = new_msg;

	return;
}



