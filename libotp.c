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

// starnge fix for a warning
extern char *stpcpy (char *, const char *);

//GNOMElib
#include <glib.h>


// great stuff
#include "libotp.h"

// Some defintions
#define TRUE 1
#define FALSE 0
#define FILE_DELI " "		// Delimiter in the filename
#define MSG_DELI "|"		// Delimiter in the encrypted message



// ----------------- Lib One-Time Pad Functions (Internal)------------------
int otp_getpad(int *len,char **pad);

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
int otp_udecrypt(char **message) {
	int a = (strlen(*message)+1)* sizeof(char); 				/* get length of the used memory*/
	int *len=&a;
	char *b="x"; char **pad; pad=&b;
	otp_b64dec( message, len );				/* decode base64 */
	int padok = otp_getpad( len ,pad);			/* get pad */
	otp_xor( message, pad, *len);				/* xor */
	//printf("udecrypt:\tMessage:\t%s\n",*message);
	return TRUE;
}


/* Encrypt the message  */
int otp_uencrypt(char **message) {
	int a = (strlen(*message)+1) * sizeof(char);				/* get length of the used memory*/
	int *len=&a;
	char *b="x"; char **pad; pad=&b;		

	int padok = otp_getpad( len ,pad);			/* get pad */
	otp_xor( message , pad, *len);				/* xor */
	otp_b64enc( message , len );				/* encode base64 */
	
	return TRUE;
}
/* Creates a pointer to a char-array with the pad */
int otp_getpad(int *len,char **pad) {


	char p[]="ziuzoiuoziuzoiuzoiuzoiuzoiuzoiewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl"; 
 
	char *vpad = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vpad,p,*len-1); //the pad could be anything... use memcyp
	*pad=vpad;

	//printf("pad:\t\tPad:\t\t%s\n",*pad);
	//printf("pointerin2:\t\t\t%u\n",pad);
	return TRUE;
}


/* xor message and pad  */
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

	pad->position = 99999;

	pad->size = 1000000;


	return pad;
}

/* Creates the actual string of the encrypted message that is given to the application.
returns 1 if it could encrypt the message 
*/
unsigned int otp_encrypt(struct otp* mypad, char **message){
	char *id_str = "42247524";			/* Our ID */
	char *pos_str = "379879879";			/* Our position in the pad*/


	int ret = otp_uencrypt(message);		/* Encrypt and base64 */

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
unsigned int otp_decrypt(struct otp* mypad, char **message){
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
     	char *pos_str = strdup (m);	/* Our position in the pad */
	//printf("decrypt:\tpos:\t%s\n",pos_str);
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}
     	char *id_str = strdup (m);	/* Our ID */

	//printf("decrypt:\tID:\t%s\n",id_str);
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}					/* Our Message */
	//printf("decrypt:\tMessage:\t%s\n",m);

     	char *new_msg;				/* Create a new, smaller **message */
	new_msg = (char *) malloc((strlen(m) + 1) * sizeof(char)); 
	strcpy(new_msg, m);
	free(*message);
	*message = new_msg;
	//printf("xor:\t\tMessage:\t%s\n",*message);

	return 	otp_udecrypt(message);		/* Decrypt and debase64 */;
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



