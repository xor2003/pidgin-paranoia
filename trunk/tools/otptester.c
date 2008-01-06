/*
 * Pidgin-Paranoia Libotp Tester Application - Useful for the development of libotp.
 * Copyright (C) 2007  Christian Wäckerlin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

/* ### gcc `pkg-config --cflags --libs glib-2.0` o.c && ./a.out  */

/* GNOMElib */
#include <glib.h>

/* GNUlibc stuff */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>




/* great stuff */
#include "../libotp.h"

#define PARANOIA_PATH "/.paranoia/"		/* TODO: REMOVE */

char *programname;
int *argnumber;
int *argpos;
char **argvalue;
char *path;
struct otp* encryptpad;
struct otp* decryptpad;
int debuglevel=0;
char **permmessage;
int repeatnumber=1;
struct otp_config* config;


/* Usage */
int usage() {
    printf("%s: Usage: \"%s [OPTIONS] \"\n",programname,programname);
    printf("\
--setmessage message\n\
--repeat # TODO\n\
--encrypt\n\
--decrypt\n\
--genkey alice bob sourcefile size\n\
--openpad filename encrypt|decrypt\n\
--closepad encrypt|decrypt\n\
--create_config\n\
--destroy_config\n\
--erasekey\n\
--test\n\
--debug\n\
--nodebug\n\
\n\
%s --create_config --openpad \"bob@jabber.org alice@jabber.org 22222201.entropy\" encrypt --openpad \"alice@jabber.org bob@jabber.org 22222201.entropy\" decrypt --setmessage \"test\" --encrypt --decrypt --closepad encrypt --closepad decrypt --destroy_config\n\
",programname);
	return TRUE;
}

int something() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	//printf("%.8X\n",otp_conf_set_path(config, "testtest"));
	//printf("%.8X\n",otp_conf_set_export_path(config, "testtest"));
	//printf("%s\n",otp_conf_get_path(config));
	//printf("%s\n",otp_conf_get_export_path(config));
	//printf("%.8X\n",otp_conf_set_random_msg_tail_max_len(config,88));
	//printf("%i\n",otp_conf_get_random_msg_tail_max_len(config));
	//printf("%.8X\n",otp_conf_set_msg_key_improbability_limit(config,9));
	//printf("%e\n",otp_conf_get_msg_key_improbability_limit(config));
	//printf("%i\n",strlen("sdfsdfsdf http://pidgin-...."));
	return TRUE;	
}

int create_config() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	config = otp_conf_create("otptester", 
			"otp_path", "export_path");
	if (config == NULL) {
		printf("Error creating the otp_config!\n");
		return FALSE;
	}
	*argpos=*argpos+takes;
	return TRUE;	
}

int destroy_config() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	OtpError syndrome = otp_conf_destroy(config);
	if (syndrome > OTP_WARN) {
		printf("Error freeing the otp_config :\t%.8X\n",syndrome);
		return FALSE;
	}
	*argpos=*argpos+takes;
	return TRUE;	
}




int genkey() {
	int takes=4;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	unsigned int size = (unsigned int) g_ascii_strtoll (argvalue[*argpos+3] ,NULL,10); 
	if (debuglevel) {
		printf("* Username1:\t%s\n",argvalue[*argpos]);
		printf("* Username2:\t%s\n",argvalue[*argpos+1]);
		printf("* Sourcefile:\t%s\n",argvalue[*argpos+2]);
		printf("* Keypath:\t%s\n",path);
		printf("* Keysize:\t%u\n",size);
	}
	OtpError syndrome = otp_generate_key_pair(
			argvalue[*argpos],argvalue[*argpos+1],
			path, argvalue[*argpos+2],size);
	if (syndrome > OTP_WARN) {
		printf("Error creating keys %.8X\n",syndrome);
		return FALSE;
	}
	if (debuglevel) {
		printf("* Syndrome:\t%.8X\n",syndrome);
	}
	
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

int erasekey() {
	int takes=0;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	OtpError syndrome = otp_erase_key(encryptpad);
	if (syndrome > OTP_WARN) {
		printf("Error erasing keys %.8X\n",syndrome);
		return FALSE;
	}
	if (debuglevel) {
		printf("* Syndrome:\t%.8X\n",syndrome);
	}
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
	int takes=2;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	
	if (!strcmp(argvalue[*argpos+1],"encrypt")) {
		encryptpad = otp_get_from_file(path,argvalue[*argpos]);	
		if (encryptpad == NULL) {
			printf("Keyfile '%s' can not be opened!\n",argvalue[*argpos]);
			printf("* Message:\t\t%s\n",*permmessage);
		return FALSE;
		}	
		if (debuglevel) {
			printf("* Keyfile '%s' opened!\n",argvalue[*argpos]);
			printf("* Pad:\tfilename:\t%s\n",otp_pad_get_filename(encryptpad));
			printf("* Pad:\tPos:\t\t%u\n",otp_pad_get_position(encryptpad));
			printf("* Pad:\tentropy:\t%u\n",otp_pad_get_entropy(encryptpad));
			printf("* Pad:\tsrc:\t\t%s\n",otp_pad_get_src(encryptpad));
			printf("* Pad:\tdest:\t\t%s\n",otp_pad_get_dest(encryptpad));
			printf("* Pad:\tid:\t\t%s\n",otp_pad_get_id(encryptpad));
			printf("* Pad:\tfilesize:\t%u\n",otp_pad_get_filesize(encryptpad));
		}
	}
	if (!strcmp(argvalue[*argpos+1],"decrypt")) {
		decryptpad = otp_get_from_file(path,argvalue[*argpos]);	
		if (decryptpad == NULL) {
			printf("Keyfile '%s' can not be opened!\n",argvalue[*argpos]);
		return FALSE;
		}	
		if (debuglevel) {
			printf("* Keyfile '%s' opened!\n",argvalue[*argpos]);
			printf("* Pad:\tfilename:\t%s\n",otp_pad_get_filename(decryptpad));
			printf("* Pad:\tPos:\t\t%u\n",otp_pad_get_position(decryptpad));
			printf("* Pad:\tentropy:\t%u\n",otp_pad_get_entropy(decryptpad));
			printf("* Pad:\tsrc:\t\t%s\n",otp_pad_get_src(decryptpad));
			printf("* Pad:\tdest:\t\t%s\n",otp_pad_get_dest(decryptpad));
			printf("* Pad:\tid:\t\t%s\n",otp_pad_get_id(decryptpad));
			printf("* Pad:\tfilesize:\t%u\n",otp_pad_get_filesize(decryptpad));
		}	
	}
	
	*argpos=*argpos+takes;
	return TRUE;	
}

int closepad() {
	int takes=1;
	if(*argpos+takes-1 >= *argnumber) {
		return FALSE;
	}
	if (!strcmp(argvalue[*argpos],"decrypt")) {
		if (decryptpad == NULL) {
			printf("Can not destroy a pad that does not exist!\n");
			return FALSE;
		}
		otp_destroy(decryptpad);
	}
	
	if (!strcmp(argvalue[*argpos],"encrypt")) {
		if (encryptpad == NULL) {
			printf("Can not destroy a pad that does not exist!\n");
			return FALSE;
		}
		otp_destroy(encryptpad);
	}
	
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
	permmessage = g_malloc(sizeof(char*));
	*permmessage = g_strdup(argvalue[*argpos]);
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
	
	OtpError syndrome = otp_encrypt(encryptpad, permmessage);
	if (syndrome > OTP_WARN) {
		printf("Encrypt failed! %.8X\n",syndrome);
		printf("Message:\t\t%s\n",*permmessage);
		return FALSE;
	}
	printf("Encrypted message:\t%s\n",*permmessage);
	if (debuglevel) {
		printf("* Syndrome:\t\t%.8X\n",syndrome);
		printf("* Pad:\tPos:\t\t%u\n",otp_pad_get_position(encryptpad));
		printf("* Pad:\tentropy:\t%u\n",otp_pad_get_entropy(encryptpad));
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
		printf("* Message:\t%s\n",*message);
	}
	OtpError syndrome = otp_encrypt_warning(encryptpad,message,0);
	if (syndrome > OTP_WARN) {
		printf("Signalencrypt failed! %.8X\n",syndrome);
		printf("Message:\t\t%s\n",*permmessage);
		return FALSE;	
	}
	printf("Enc. signal message:\t%s\n",*message);	
	
	if (debuglevel) {
		printf("* Syndrome:\t\t%.8X\n",syndrome);
		printf("* Pad:\tPos:\t\t%u\n",otp_pad_get_position(encryptpad));
		printf("* Pad:\tentropy:\t%u\n",otp_pad_get_entropy(encryptpad));
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
//	char *stupid = g_strdup(*permmessage); // Timeing problem?
	if (permmessage == NULL) {
		printf("No message set!\n");
		return FALSE;	
	}
	if (debuglevel) {
		printf("* Encrypted message:\t%s\n",*permmessage);
	}
	OtpError syndrome = otp_decrypt(decryptpad,permmessage); 
	if (syndrome > OTP_WARN) {
		printf("Decrypt failed! %.8X\n",syndrome);
		printf("Message:\t\t%s\n",*permmessage);
		return FALSE;	
	}
	printf("Decrypted message:\t%s\n",*permmessage);
	
	if (debuglevel) {
		printf("* Syndrome:\t\t%.8X\n",syndrome);
	}
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
	
	const gchar* home = g_get_home_dir();
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

		if (!strcmp(argv[i],"--genkey")) {
			if(genkey()==FALSE){
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
		
		if (!strcmp(argv[i],"--erasekey")) {
			if(erasekey()==FALSE){
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
		
		if (!strcmp(argv[i],"--something")) {
			if(something()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--create_config")) {
			if(create_config()==FALSE){
				return 1;
			}
		}
		
		if (!strcmp(argv[i],"--destroy_config")) {
			if(destroy_config()==FALSE){
				return 1;
			}
		}
	}
	printf("--------------------------------------------------------------------------------\n");
	printf("Reporting: All commands executed successfully!\n");
	
	return(0);
}
