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

// ----------------- Lib One-Time Pad Functions (Internal)------------------
int otp_getpad(int *size,char **pad);

/* Encodes message into the base64 form */
int otp_b64enc(char **message, int *size) {
	//printf("b64enc:\t\tMessage:\t%s\n",*message);
	//printf("pointer:\t\t\t%u\n",size);

	guchar *gumsg = (guchar *) malloc( *size * sizeof(guchar) );
	memcpy(gumsg,*message,*size);

	gchar *gmsg = g_base64_encode(gumsg,*size);

	//g_print("b64enc:\t\tb64:\t\t%s\n",gmsg);
	//printf("b64enc:\t\tMessage:\t%d\n",strlen(gmsg));

	*size = strlen(gmsg) + 1;
	char *msg = (char *) malloc( *size * sizeof(char) );
	memcpy(msg,gmsg,*size);
	free(*message);
	*message = msg;
	//printf("b64enc:\t\tMessage:\t%s\n",*message);
	return 1;
}

/* Decodes message from the base64 form */
int otp_b64dec(char **message, int *size) {
	//printf("b64dec:\t\tMessage:\t%s\n",*message);
	//printf("pointer:\t\t\t%u\n",size);

	gchar *gmsg = (gchar *) malloc( *size * sizeof(gchar) );
	memcpy(gmsg,*message,*size);

	guchar *gumsg = g_base64_decode(gmsg,size);

	//g_print("b64dec:\t\tb64:\t\t%s\n",gumsg);

	char *msg = (char *) malloc( *size * sizeof(char) );
	memcpy(msg,gumsg,*size);
	free(*message);
	*message = msg;
	//printf("b64dec:\t\tMessage:\t%s\n",*message);
	return 1;
}

/* Decrypt the message  */
int otp_udecrypt(char **message) {
	int a = strlen(*message); 				/* get length */
	int *size=&a;
	char *b="x"; char **pad; pad=&b;

	//printf("udecrypt:\tSize:\t\t%d\n",*size);
	//printf("udecrypt:\tMessage:\t%s\n",*message);

	otp_b64dec( message, size );				/* decode base64 */
	//printf("udecrypt:\tSize:\t\t%d\n",*size);
	int padok = otp_getpad( size ,pad);			/* get pad */
	otp_xor( message, pad, *size );				/* xor */
	//printf("udecrypt:\tMessage:\t%s\n",*message);

	//--------------------------------------------------------------------
	// FIXME: from here on the '\0' sign of the message is missing or 
	//        moved (it's always too long). Do you xor '\0'? and b64 '\0' ?
	// WORKAROUND: this line is a work around to fix this bug.
	(*message)[*size] = '\0';
	// -------------------------------------------------------------------
	return 1;
}


/* Encrypt the message  */
int otp_uencrypt(char **message) {
	int a = strlen(*message);				/* get length */
	int *size=&a;
	char *b="x"; char **pad; pad=&b;			

	//printf("uencrypt:\tSize:\t\t%d\n",*size);
	int padok = otp_getpad( size ,pad);			/* get pad */
	//printf("Pad\t:%s\n",*pad);

	otp_xor( message , pad, *size );			/* xor */
	//printf("uencrypt:\tMessage:\t%s\n",*message);
	otp_b64enc( message , size );				/* encode base64 */
	return 1;
}
/* Creates a pointer to a char-array with the pad */
int otp_getpad(int *size,char **pad) {

	//printf("pointerin1:\t\t\t%u\n",pad);
	//printf("xor:\t\tSize:\t\t%d\n",*size);
	//printf("pointer:\t\t\t%u\n",pad);

	//       "123456789012345"
	char p[]="x    wdjlkdjhdjewrhlkewjfhewlkjrhewlrkjewhrlkwqj4rjkfoidshfkjljvclkxvhfalkj dshfkjvcxnidsrur59380732847324098327409832740329847320948732 498324dsmfndsmfndsfkmdsfjdsfhldsjfhsadlkf  f kcvölcxkvjkc vdsvlädöclkäl"; 
 
	char *vpad = (char *) malloc( (*size+1) * sizeof(char) );
	memcpy(vpad,p,*size); //the pad could be anything... use memcyp
	*pad=vpad;

	//printf("pad:\t\tPad:\t\t%s\n",*pad);
	//printf("pointerin2:\t\t\t%u\n",pad);
	return 1;
}


/* xor message and pad  */
int otp_xor(char **message,char **pad,int size) {
	int i;
	char *m,*p;

	//otp_printint(*message,size);
	//otp_printint(*pad,size);

	//printf("xor:\t\tMessage:\t%s\n",*message);
	//printf("xorp:\t\tMessage:\t%s\n",*pad);
	m = *message;
	p = *pad;
	
	for (i = 0;i < (size);i++) {
		//printf("%c\t%d\t%c\t%d\t%d\n",m[i],m[i],p[i],p[i],m[i]^p[i]); //debug
		m[i]=m[i]^p[i];
	}
	
	//otp_printint(*message,size);

	return 1;
}

/* Helper function for debugging */
int otp_printint(char *m,int size) {
	//int len=strlen(m);
	int i;
	printf("\t\tIntegers:\t");
	for (i = 0;i < size+1;i++) {
		printf("%d ",m[i]);
	}
	printf("\n");
	return 1;
}


// ----------------- Public One-Time Pad Functions ------------

/* Creates the struct otp  
HELP: How to signal a failure?!? Atm the strings are NULL in this case. */
struct otp* otp_get_from_file(char* input_filename){
	static struct otp* pad;
   	pad = (struct otp *)malloc(sizeof(struct otp));
	char *filename;
	//char empty[]='';

	filename = (char *) malloc( (sizeof(input_filename) + 1) * sizeof(char) );
	filename = input_filename; 
	pad->filename = filename;


	const char d[] = " ";		/* The delimiter */
     	char *c,*run;
     	run = strdup (filename);
	if (filename == NULL ) {
		// return 0;
	}


     	c = strsep (&run, d);		/* Our source i.e alice@yabber.org */
	if (c == NULL ) {
		//return 0;
	}
	char *src;
	src = (char *) malloc( (5 + 1) * sizeof(char) );
	src = c; 
	pad->src = src;


     	c = strsep (&run, d);		/* Our dest i.e bob@yabber.org */
	if (c == NULL ) {
		//return 0;
	}
	char *dest;
	dest = (char *) malloc( (5 + 1) * sizeof(char) );
	dest = c; 
	pad->dest = dest;


     	c = strsep (&run, d);		/* Our ID */
     	char *x,*xrun;
     	xrun = strdup (c);
	x = strsep (&xrun,".");
	if (c == NULL ) {
		//return 0;
	}
	char *id;
	id = (char *) malloc( (5 + 1) * sizeof(char) );
	id = x; 
	pad->id = id;


	// Development: Constant atm

	pad->position = 100000;

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

	char *new_msg;				/* Create a new, bigger **message */
	new_msg = (char *) malloc( (strlen(*message) + strlen(pos_str) + strlen(id_str) + 1 + 2) * sizeof(char) ); 
	char *p = new_msg;	

	p = stpcpy (p, pos_str);			/*Concatinate everything*/
	p = stpcpy (p, "|");
	p = stpcpy (p, id_str);
	p = stpcpy (p, "|");
	p = stpcpy (p, *message);
	//printf("encrypt:\t\tMessage:\t%s\n",new_msg);

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
	if (*message == NULL ) {
		return 0;
	}
     	m = strsep (&mrun, d);
	if (m == NULL ) {
		return 0;
	}
     	char *pos_str = strdup (m);	/* Our position in the pad*/
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



