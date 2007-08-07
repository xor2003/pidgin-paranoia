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
	//char m[]="123455678"; 
	char m[]="TWVQPPSR]";  // wurde aus "12345678" erzeugt. zum testen.
	char p[]="eeeeeeeee";
	char **message;
	//char *msg="Hello World!"; <<<<< Das scheint sich nicht mit free() zu vertragen.
	char *vmessage = (char *) malloc((strlen(m) + 1) * sizeof(char));
	strcpy(vmessage, m);
	message=&vmessage;

	char **pad;
	char *vpad = (char *) malloc((strlen(p) + 1) * sizeof(char));
	strcpy(vpad, p);
	pad=&vpad;


	printf("Message before      :%s\n",*message);

	//aaaa_decrypt(pmessage);
	otp_xor(message,pad);

	printf("Message after       :%s\n",*message);
	
	return 0;
}

