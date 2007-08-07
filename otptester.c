/*
    Pidgin-Paranoia Libotp Tester - Useful for the development of libotp.
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

// GNOMElib

// GNUlibc stuff
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


// great stuff
#include "libotp.h"

static int OTP_decrypt(char *message);
static int OTP_encrypt(char **message);

int main(void) {
	char **pmessage=NULL;
	char *message="Hello World!\n";
	printf(message);
	pmessage=&message;
	printf(*pmessage);
	aaaa_decrypt(pmessage);
	
	//char *msg;
	//char *tmp_str = "hallo";
	//msg = (char *) malloc((strlen(tmp_str) + 1) * sizeof(char));
	//strcpy(tmp_str, msg);
	//char **message = msg;
	//aaaa_encrypt(message);	

	//char *msg = "hallo";
	//char **message = msg;
	//aaaa_encrypt(message);
//	OTP_decrypt(message);
}

// ----------------- Siganl Handler ------------------

/* decrypt the message with libotp */
static int OTP_decrypt(char *message) {
	// TODO: many many checks!

	printf(message);
	printf("received a message!!! we should decrypt it :)\n");

	return 0; 
}

/* encrypt the message with libotp */
static int OTP_encrypt(char **message) {
	// TODO: many many checks!

	aaaa_encrypt(message);

	// debug
	printf("we want to send a message!!! we should encrypt it :)\n");

	return 0;
}



