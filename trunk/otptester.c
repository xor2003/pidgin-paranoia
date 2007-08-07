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


int main(void) {
	char **pmessage;
	//char *msg="Hello World!"; <<<<< Das scheint sich nicht mit free() zu vertragen.
	char *msg = (char *) malloc((strlen("Hello World!") + 1) * sizeof(char));
	strcpy(msg, "Hello World!");
	printf(msg);
	pmessage=&msg;
	printf(*pmessage);
	aaaa_decrypt(pmessage);
	printf(*pmessage);
	
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
	return 0;
}

