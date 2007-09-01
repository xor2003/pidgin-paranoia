/*
    Pidgin-Paranoia Libotp Tester Application - Useful for the development of libotp.
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

char *programname;
int *argnumber;
int *argpos;
char **argvalue;
char *path;
struct otp* pad;
int debuglevel=0;
char **permmessage;


/* Usage */
int usage() {
    printf("%s: Usage: \"%s [OPTIONS] \"\n",programname,programname);
    printf("\
--setmessage message\n\
--encrypt\n\
--decrypt\n\
--create alice bob\n\
--openpad filename\n\
--closepad\n\
--test\n\
--debug\n\
--nodebug\n\
");
	return TRUE;
}

int create() {
	int takes=2;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	printf("%s\n",argvalue[*argpos]);
	printf("%s\n",argvalue[*argpos+1]);
	*argpos=*argpos+takes;
	return TRUE;	
}

int test() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	printf("Test point reached!\n");
	*argpos=*argpos+takes;
	return TRUE;	
}

int debug() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	debuglevel=1;
	*argpos=*argpos+takes;
	return TRUE;	
}

int nodebug() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	debuglevel=0;
	*argpos=*argpos+takes;
	return TRUE;	
}


int openpad() {
	int takes=1;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	pad = otp_get_from_file(path,argvalue[*argpos]);
	if (pad == NULL) {
		printf("Keyfile '%s' can not be opened!\n",argvalue[*argpos]);
		return FALSE;
	}
	
	
	if (debuglevel) {
		printf("* Keyfile '%s' opened!\n",argvalue[*argpos]);
		printf("* Pad:\tfilename:\t%s\n",pad->filename);
		printf("* Pad:\tPos:\t\t%u\n",pad->position);
		printf("* Pad:\tentropy:\t%u\n",pad->entropy);
		printf("* Pad:\tsrc:\t\t%s\n",pad->src);
		printf("* Pad:\tdest:\t\t%s\n",pad->dest);
		printf("* Pad:\tid:\t\t%s\n",pad->id);
		printf("* Pad:\tfilesize:\t%u\n",pad->filesize);
	}
	
	*argpos=*argpos+takes;
	return TRUE;	
}

int closepad() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	if (pad == NULL) {
		printf("Can not destroy a pad that does not exist!\n");
		return FALSE;
	}
	otp_destroy(pad);
	
	*argpos=*argpos+takes;
	return TRUE;	
}
	
int setmessage() {
	int takes=1;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	if (permmessage!=NULL) {
		g_free(*permmessage);
	}
	char *vmessage = g_strdup(argvalue[*argpos]);
	permmessage = &vmessage;
	if (debuglevel) {
		printf("* Message:\t\t%s\n",*permmessage);
	}

	*argpos=*argpos+takes;
	return TRUE;	
}

int encrypt() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	if (permmessage == NULL) {
		printf("No message set!\n");
		return FALSE;	
	}
	if (otp_encrypt(pad,permmessage) == FALSE) {
		printf("Encrypt failed!\n");		
		return FALSE;	
	}
	printf("Encrypted message:\t%s\n",*permmessage);
	if (debuglevel) {
		printf("* Pad:\tPos:\t\t%u\n",pad->position);
		printf("* Pad:\tentropy:\t%u\n",pad->entropy);
	}
	
	*argpos=*argpos+takes;
	return TRUE;	
}


		
int signalencrypt() {
	int takes=1;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	char *vmessage = g_strdup(argvalue[*argpos]);
	char **message = &vmessage;
	if (debuglevel) {
		printf("* Message:\t\t%s\n",*message);
	}
	if (otp_encrypt_warning(pad,message,0) == FALSE) {
		printf("Signalencrypt failed!\n");	
		return FALSE;	
	}
	printf("Enc. signal message:\t%s\n",*message);	
	
	if (debuglevel) {
		printf("* Pad:\tPos:\t\t%u\n",pad->position);
		printf("* Pad:\tentropy:\t%u\n",pad->entropy);
	}

	if (permmessage != NULL) {
		//g_free(**permmessage);
	}
	permmessage=message;
	
	
	*argpos=*argpos+takes;
	return TRUE;	
}

int decrypt() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	if (permmessage == NULL) {
		printf("No message set!\n");
		return FALSE;	
	}
	if (otp_decrypt(pad,permmessage) == FALSE) {
		printf("Decrypt failed!\n");	
		return FALSE;	
	}
	printf("Decrypted message:\t%s\n",*permmessage);
	
	*argpos=*argpos+takes;
	return TRUE;	
}


int main ( int argc , char *argv[] ) {
	printf("--------------------------------------------------------------------------------\n");
	programname=argv[0];
	argnumber=&argc;
	*argnumber=*argnumber-1;
	argvalue=&argv[1];
	int i=0;
	argpos=&i;
	
	const gchar* home = g_get_home_dir();		/* set the global key folder  TODO: REMOVE! */
	path = (char *) g_malloc((strlen(home) + strlen(PARANOIA_PATH) + 1) * sizeof(char));
	strcpy(path, (char*) home);
	strcat(path, PARANOIA_PATH);
	
	
	//printf("%d\n",*argnumber);
		
	if (*argnumber <= 0)
	{
		usage();		/* Show usage */
    	return(1);
	}
	for(i=0;i <= *argnumber;i++){
		//printf("argument:%s\n",argv[i+1]);
		
		if (!strcmp(argv[i],"--setmessage")) {
			if(setmessage()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--encrypt")) {
			if(encrypt()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--signalencrypt")) {
			if(signalencrypt()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--decrypt")) {
			if(decrypt()==FALSE){
				return 1;
			}
		}	

		if (!strcmp(argv[i],"--create")) {
			if(create()==FALSE){
				return 1;
			}
		}	
		
		if (!strcmp(argv[i],"--openpad")) {
			if(openpad()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--closepad")) {
			if(closepad()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--test")) {
			if(test()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--debug")) {
			if(debug()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--nodebug")) {
			if(nodebug()==FALSE){
				return 1;
			}
		}
	}
	printf("--------------------------------------------------------------------------------\n");
	printf("Reporting: All commands executed successfully!\n");
	
	return(0);
}
