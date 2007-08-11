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

int printint(char *m);


int main(void) {
	//int a=0; int *size=&a;
	//*size=10;
	//       "123456789012345"
	char m[]="ziuziuiuz"; // IMPORTANT: (pad has to be longer)

	char **message;
	char *vmessage = (char *) malloc((strlen(m) + 1) * sizeof(char));
	strcpy(vmessage, m);
	message=&vmessage;
	
	//long int i=384242343;
	//printf("tester:\t\tint:\t\t%ld\n",i);
	//char *c=l64a(i);
	//printf("tester:\t\tint:\t\t%s\n",c);
	//long int x=a64l (c);
	//printf("tester:\t\tint:\t\t%ld\n",x);

	char filename[]="alice@jabber.org bob@jabber.org 34EF4588.pad";
	struct otp* pad = otp_get_from_file(filename);
	printf("Pad:filename:\t\t\t%s\n",pad->filename);
	printf("Pad:Pos:\t\t\t%ld\n",pad->position);
	printf("Pad:Size:\t\t\t%ld\n",pad->size);

	printf("Pad:src:\t\t\t%s\n",pad->src);
	printf("Pad:dest:\t\t\t%s\n",pad->dest);
	printf("Pad:id::\t\t\t%s\n",pad->id);


	printf("\n--------------------------------------\n\n");

	printf("tester message:\t\t\tMessage:\t%s\n",*message);
	//otp_printint(*message);
	//printf("tester:\t\tSize:\t\t%d\n",*size);
	//otp_printint(*message,strlen(*message));


	//otp_uencrypt(message);
	//otp_b64enc(message,size);
	otp_encrypt(NULL,message);

	//printf("tester:\t\tSize:\t\t%d\n",*size);
	printf("tester encrypted:\t\tMessage:\t%s\n",*message);

	//otp_udecrypt(message);
	//otp_b64dec(message,size);
	otp_decrypt(NULL,message);

	//printf("tester:\t\tSize:\t\t%d\n",*size);
	printf("tester decrypted:\t\tMessage:\t%s\n",*message);
	//printint(*message);

	printf("\n--------------------------------------\n\n");
	
	return 0;
}


