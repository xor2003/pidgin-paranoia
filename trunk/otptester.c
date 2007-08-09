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
	//int a=0; int *size=&a;
	//*size=10;
	//       "123456789012345"
	char m[]="Hallo World!..."; // IMPORTANT: (pad has to have the same length)

	char **message;
	char *vmessage = (char *) malloc((strlen(m) + 1) * sizeof(char));
	strcpy(vmessage, m);
	message=&vmessage;




	printf("tester:\t\tMessage:\t%s\n",*message);
	//printf("tester:\t\tSize:\t\t%d\n",*size);

	otp_uencrypt(message);
	//otp_b64enc(message,size);

	//printf("tester:\t\tSize:\t\t%d\n",*size);
	printf("tester:\t\tMessage:\t%s\n",*message);

	otp_udecrypt(message);
	//otp_b64dec(message,size);

	//printf("tester:\t\tSize:\t\t%d\n",*size);
	printf("tester:\t\tMessage:\t%s\n",*message);
	
	return 0;
}

