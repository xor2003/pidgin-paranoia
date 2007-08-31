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

/* ### gcc `pkg-config --cflags --libs glib-2.0` o.c && ./a.out  */

/* GNOMElib */
#include <glib.h>

/* GNUlibc stuff */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>




/* great stuff */
#include "libotp.h"

#define PARANOIA_PATH "/.paranoia/"		/* TODO: REMOVE */

#define STATICMSG "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"

int main(void) {
/* 	int a=0; int *size=&a; */
/* 	*size=10; */
/* 	       "123456789012" */



/* 	char m[]="123456789012"; // IMPORTANT: (pad has to be longer) */
	char m[]= STATICMSG;
	char m2[]= "1";
/* 	char m[]="sdanfnmadsbfmnbdsafnmbadsfmnbsadmfnbasdmfndasnbfm,sfnb,mnsadfm,nadbfmndsbaf,mnbasdfn"; */

	/* Message creation */
	char **message;
	char *vmessage = (char *) g_malloc((strlen(m) + 1) * sizeof(char));
	strcpy(vmessage, m);
	message=&vmessage;
	
	char **message2;
	char *vmessage2 = (char *) g_malloc((strlen(m2) + 1) * sizeof(char));
	strcpy(vmessage2, m2);
	message2=&vmessage2;

	const gchar* home = g_get_home_dir();		/* set the global key folder  TODO: REMOVE! */
	char* path = (char *) g_malloc((strlen(home) + strlen(PARANOIA_PATH) + 1) * sizeof(char));
	strcpy(path, (char*) home);
	strcat(path, PARANOIA_PATH);

	

/* 	long int i=384242343; */
/* 	printf("tester:\t\%s\n",global_otp_path); */
/* 	char *c=l64a(i); */
/* 	printf("tester:\t\tint:\t\t%s\n",c); */
/* 	long int x=a64l (c); */
/* 	printf("tester:\t\tint:\t\t%ld\n",x); */


	/* Pad Testing .... */

/* 	char filename[]=" hello world.txt"; */
/* 	char filename[]="aa aa aa"; */
/* 	char filename[]="alexapfel@gmail.com alexapfel@gmail.com 11111111.entropy"; */
	char filename[]="alexapfel@gmail.com alexapfel@gmail.com 11111111.entropy";
	struct otp* pad = otp_get_from_file(path,filename);
	if (pad == NULL) {
		printf("Tester:File can not be opened!\n");
	}else{

//		printf("Pad:filename:\t\t\t%s\n",pad->filename);
//		printf("Pad:Pos:\t\t\t%u\n",pad->position);
//		printf("Pad:entropy:\t\t\t%u\n",pad->entropy);

//		printf("Pad:src:\t\t\t%s\n",pad->src);
//		printf("Pad:dest:\t\t\t%s\n",pad->dest);
//		printf("Pad:id:\t\t\t\t%s\n",pad->id);
//		printf("Pad:filesize:\t\t\t%u\n",pad->filesize);


/* 		printf("\n--------------------------------------\n\n"); */
/* 		printf("tester encrypted:\t\tMessage:\t%s\n",*message); */
		printf("tester encrypted:\t\tMessage:\t%s\n",*message);
		printf("tester encrypted:\t\tMessage:\t%s\n",*message2);
		printf("Pad:Pos:\t\t\t%u\n",pad->position);
		otp_encrypt_warning(pad,message,0);
		otp_encrypt(pad,message2);
		printf("tester encrypted:\t\tMessage:\t%s\n",*message);
		printf("tester encrypted:\t\tMessage:\t%s\n",*message2);
		printf("Pad:Pos:\t\t\t%u\n",pad->position);
//		printf("Pad:entropy:\t\t\t%u\n",pad->entropy);
		otp_destroy(pad);
	}
	printf("\n--------------------------------------\n\n"); 
	char *id=otp_get_id_from_message(message);
	//printf("tester encrypted:\t\tMessage:\t%s\n",id);


	char filename2[]="alexapfel@gmail.com alexapfel@gmail.com 11111111.entropy";
	struct otp* pad2 = otp_get_from_file(path,filename2);
	if (pad2 == NULL) {
		printf("Tester:File can not be opened!\n");
	}else{
/*
		printf("Pad:filename:\t\t\t%s\n",pad2->filename);
		printf("Pad:Pos:\t\t\t%ld\n",pad2->position);
		printf("Pad:entropy:\t\t\t%ld\n",pad2->entropy);

		printf("Pad:src:\t\t\t%s\n",pad2->src);
		printf("Pad:dest:\t\t\t%s\n",pad2->dest);
		printf("Pad:id:\t\t\t\t%s\n",pad2->id);
		printf("Pad:filesize:\t\t\t%ld\n",pad2->filesize);
*/

/* 		printf("\n--------------------------------------\n\n"); */
/* 		printf("tester encrypted:\t\tMessage:\t%s\n",*message); */
/* 		otp_encrypt(pad2,message); */
/* 		printf("tester encrypted:\t\tMessage:\t%s\n",*message); */
		otp_decrypt(pad,message);
		otp_decrypt(pad,message2);
		printf("tester decrypted:\t\tMessage:\t%s\n",*message);
		printf("tester decrypted:\t\tMessage:\t%s\n",*message2);
		//printf("Pad:Pos:\t\t\t%u\n",pad->position);
		//printf("Pad:entropy:\t\t\t%u\n",pad->entropy);
		otp_destroy(pad2);
	}
	
	
	
	return 0;
}


