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
#include <string.h>

// great stuff
#include "libotp.h"

// ----------------- Lib One-Time Pad Functions ------------------

/* decrypt the message  */
static int OTP_decrypt(char **message) {
	// TODO: many many checks!

	printf(message);
	printf("received a message!!! we should decrypt it :)\n");

	return 0; 
}

/* encrypt the message  */
static int OTP_encrypt(char **message) {
	// TODO: many many checks!

	aaaa_encrypt(message);

	// debug
	printf("we want to send a message!!! we should encrypt it :)\n");

	return 0;
}


/* xor message and pad and return the result in message 
The function needs the message and the pad to have the same size.*/
int otp_xor(char **message,char **pad) {
	char *m,*p;
	int i;
	int mlen,plen;
	mlen = strlen(*message);
	plen = strlen(*pad);

	printf("Length: %d\t%d\n",mlen,plen);  //
	//Stop if not the same size.
	if ( mlen != plen) {
		return 0;
	}


//	presult = malloc((34+1) * sizeof(char));
//	p = presult;

	m = *message;
	p = *pad;
	for (i = 0;i < mlen;i++) {
		//printf("%c\t%d\t%c\t%d\t%d\n",m[i],m[i],p[i],p[i],m[i]^p[i]); //debug
		m[i]=m[i]^p[i];
	}
	
	//printf("doing xor :)\n"); //debugm
	return 1;
}

// ----------------- Public One-Time Pad Functions ------------

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
}



