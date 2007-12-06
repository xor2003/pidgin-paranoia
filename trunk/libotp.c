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

/* GNUlibc includes */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* to manipulate files */
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
/* to create directories */
#include <dirent.h>

/* GNOMElib */
#include <glib.h>

/* great stuff */
#include "libotp.h"

/* Some defintions */
#define FILE_DELI " "		/* Delimiter in the filename */
#define MSG_DELI "|"		/* Delimiter in the encrypted message */
#define PATH_DELI "/"		/* For some reason some strange operatingsystems use "\" */
#define PAD_EMPTYCHAR '\0'	/* Char that is used to mark the pad as used. */
#define	FILE_SUFFIX ".entropy"	/* The keyfiles have to end with this string to be valid. This string has to be separated by ".". */
#define NOENTROPY_SIGNAL "*** I'm out of entropy!"	/* The message that is send in case the sender is out of entropy */
#define BLOCKSIZE 1024		/* The blocksize used in the keyfile creation function */
#define ERASEBLOCKSIZE 1024	/* The blocksize used in the key eraseure function */
#define REPEATTOL 1E-12		/* If a repeated secquence with less probability then this occurs, throw the key away */ 

/* All defines needed for full opt functionality! Redgarded as stable.*/

#define UCRYPT			/* Encryption and decryption only enabled if defined */
#define HAVEFILE		/* Do you have a file named pad->filename in your working dir? Used for struct *pad generation. */
#define HAVEKEYFILE		/* Do you have a file names pad->filename in your working dir? Used for en/decryption. */
#define KEYOVERWRITE	/* Overwrite the used key-sequence in the keyfile */
//#define USEDESKTOP			/* Requires GNOMElib 2.14! Bob's keyfile is placed onto the desktop. If not set, the file is placed in the .paranoia folder. */


/* Requried for development if HAVEFILE is not defined */
#define STATICKEY "dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4dkjfldsafxvdsa f dsf \0dsafds ew rewrd f dsf ds fe r ewr ew rew rewr ewq rew r ewrewrewrew r ewr e rew r wer ewr ewr werewfdsföldsaföldskjf \0\0\0  dsfrwef wre 4 32 4 324 32143244j43lk32j4k3214jf f ew rew rew r  3 4 324 324  324 324 32 4"

/* In development. Regraded as unstable */
#define CHECKKEY		/* Histogram checking of the key */

/*  ----------------- Lib One-Time Pad Functions (Internal)------------------ */

/* XOR message and key. This function is the core of the libary. */
static int otp_xor(char **message,char **key,int len) {
	int i;
	char *m,*k;		
	
	m = *message;
	k = *key;
/* 	otp_printint(m,len); */
/* 	otp_printint(p,len); */
	for (i = 0;i < (len-1);i++) {
/* 		printf("%c\t%d\t%c\t%d\t%d\n",m[i],m[i],p[i],p[i],m[i]^p[i]); */
		m[i]=m[i]^k[i];
	}
/* 	otp_printint(m,len);	 */
	*message=m;
	free(*key);
	return TRUE;
}

/* Helper function for debugging */
static int otp_printint(char *m,int len) {
	int i;
	printf("\t\tIntegers:\t");
	for (i = 0;i < len;i++) {
		printf("%d ",m[i]);
	}
	printf("\n");
	return TRUE;
}

/* Calculate the free entropy */
static void otp_calc_entropy(struct otp* pad){
	int entropy = pad->filesize / 2 - pad->position - OTP_PROTECTED_ENTROPY;		/* Calculate the free entropy */

	if (entropy < 0){
		pad->entropy = 0;
	} else {
		pad->entropy = entropy;
	}
}

/* Opens a keyfile with memory mapping */
static int otp_open_keyfile(int *fd, char **data,struct otp* pad){
	struct stat fstat;
	if ((*fd = open(pad->filename, O_RDWR)) == -1) {
		perror("open");
		pad=NULL;
		return FALSE;
	}

	if (stat(pad->filename, &fstat) == -1) {
		perror("stat");
		pad=NULL;
		return FALSE;
	}
	pad->filesize=fstat.st_size;

	if ((*data = mmap((caddr_t)0, pad->filesize, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		pad=NULL;
		return FALSE;
	}
	//printf("\nopen:\t%u %u\n\n",*fd,*data);
	return TRUE;
}

/* Closes a keyfile with memory mapping */
static int otp_close_keyfile(int *fd, char **data,struct otp* pad){
	//printf("\nclose:\t%u %u\n\n",*fd,*data);
	munmap(*data, pad->filesize);
	close(*fd);
	return TRUE;
}

/* Seek the position where the pad can be used for encryption */
static int otp_seek_pos(char *data,int filesize){
	int pos=0;
/* 	otp_printint(data+pos,10); */
	while ( ( (data+pos)[0] == PAD_EMPTYCHAR) && (pos < filesize) ) {
		pos++;
	}
	return pos;
}

/* Seeks the the starting position,filesize and entropy from the keyfile */
static struct otp* otp_seek_start(struct otp* pad){
/* 	char* path = get_current_dir_name(); */
	int *fd; char *b=""; char **data; data=&b; int wfd=0; fd=&wfd;
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
	
		//printf("\nworking:\t%u %u\n\n",*fd,*data);

		pad->position = otp_seek_pos(*data,pad->filesize);
		otp_calc_entropy(pad);
		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
	}else{
		return NULL;
	}
	printf("test\n");
	return pad;
}

/* Check if the ID is valid */
static char* otp_check_id(char* id_str){
	if ( strlen(id_str) == OTP_ID_LENGTH * sizeof(char)) {
		return id_str;				/* The ID only if the message was extracted as well.*/	
	}else{
		return NULL;
	}
}

/* Checks the key by statistical means 
 * 
 * repeatprob=(1/256)^(repeatlength-1)*(keylength-repeatlength) (please check this formula)
 * */
static int otp_check_key(char **key,int len) {
//	int histo[256]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int i,rep=1;
	double repeatprob=1.0;
//	int histomax;
//	char *c="1234567890000000";
//	len=strlen(c);
	char *c;
	c=*key;
	char lastc='\0';
	
	for(i=0;i<len;i++) {
//		histo[(unsigned int)c[i]]++;
		if (c[i]==lastc) {
			rep++;
			repeatprob*=(1/256.0); /* I don't like math.h */
		}else{
			lastc=c[i];
		}
	}
	repeatprob*=(len-rep);
//	histomax=0;
//	for (i=0;i<256;i++) {
//		if (histomax<histo[i]) {histomax=histo[i];}
//		printf("%d ",histo[i]);
//	}
//	printf("\n%d\t\t%d\t\t%d\n",len,histomax,rep);
	printf("\n%e\n\n",repeatprob);
	
	if (repeatprob<REPEATTOL) {
		return FALSE;
	}
	return TRUE;
}

/* Gets the key to encrypt from the keyfile */
static int otp_get_encryptkey_from_file(char **key , struct otp* pad, int len) {
	int *fd; char *b=""; char **data; data=&b; int wfd=0; fd=&wfd;
	int i=0;
	int protected_entropy=OTP_PROTECTED_ENTROPY;
	int position=pad->position;
	
	if (pad->protected_position != 0) {								
		protected_entropy=0;						/* allow usage of protected entropy*/
		position=pad->protected_position;
	}


	if ( (position + len -1 > (pad->filesize / 2 - protected_entropy) ) || position < 0) {
		return FALSE;
	}
	
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
		char *vkey = (char *) malloc( (len) * sizeof(char) );
		memcpy( vkey, *data+position ,len-1);  		/* the pad could be anything... use memcpy */
		*key=vkey;
/* 		otp_printint(*key,len-1); */
	
		char *datpos=*data+position;
	

#ifdef KEYOVERWRITE	
		if (pad->protected_position != 0) {	/* using protected entropy, do not destroy the protected entropy */
		}else{						
			for(i = 0 ; i < ( len - 1) ; i++){		/* Make the used key unusable in the keyfile */
/* 				printf(" %d \n",datpos[i]); */
				datpos[i] = PAD_EMPTYCHAR;
/* 				printf(" %d \n",datpos[i]); */
			}
		}
#endif

		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
		if (pad->protected_position == 0) {	/* In all cases where the protected entropy is not used */
			pad->position = pad->position + len -1;
		}
		otp_calc_entropy(pad);
		
	}else{
		return FALSE;
	}
	
#ifdef CHECKKEY
/* What should i do if the key is rejected? ATM it just fails.*/
	if (otp_check_key(key,len)==FALSE) {
		return FALSE;
	}
#endif
	return TRUE;

}

/* Gets the key to decrypt from the keyfile */
static int otp_get_decryptkey_from_file(char **key , struct otp* pad, int len, int decryptpos) {
	int *fd; char *b=""; char **data; data=&b; int wfd=0; fd=&wfd;
	int i=0;
/* 	printf("\ndecryptpos\t\t\t:%d\n\n",decryptpos); */
	if (pad->filesize < (pad->filesize-decryptpos - (len -1)) || (pad->filesize-decryptpos) < 0) {
		return FALSE;
	}
	if (otp_open_keyfile(fd,data,pad)) {		/* Open the keyfile */
		char *vkey = (char *) malloc( (len) * sizeof(char) );
/* 		printf("\ntest\t\t\t:%d\n\n",pad->filesize-decryptpos - (len -1)); */

		char *datpos = *data + pad->filesize - decryptpos - (len - 1);
		
		for (i=0; i <= (len -1); i++) {			/* read reverse*/
			vkey[i]=datpos[len - 2 - i];	
		}

		*key=vkey;
/* 		otp_printint(*key,len-1); */

/* 		msync(data, pad->filesize, MS_ASYNC); */
		otp_close_keyfile(fd,data,pad);		/* Close the keyfile */
	}else{
		return FALSE;
	}
	return TRUE;
}

/* Encodes message into the base64 form */
static int otp_b64enc(char **message,int *len) {

	char* msg = g_base64_encode( (guchar*) *message,*len);	/* Gnomelib Base64 encode */
	*len = (strlen(msg)+1) * sizeof(char);			/* The size has changed */

	g_free(*message);
	*message = msg;
	return TRUE;
}

/* Decodes message from the base64 form */
static int otp_b64dec(char **message, int *len) {

	guchar* msg = g_base64_decode( *message, (guint*) len);	/* Gnomelib Base64 decode */

	g_free(*message);
	*message = (char*) msg;
	return TRUE;
}

/* Decrypt the message  */
static int otp_udecrypt(char **message, struct otp* pad, int decryptpos) {
	int a = (strlen(*message)+1)* sizeof(char); 				/* get length of the used memory*/
	int *len=&a;
	char *b="x"; char **key; key=&b;
	otp_b64dec( message, len );				/* decode base64 */

#ifdef HAVEKEYFILE
	if ( otp_get_decryptkey_from_file(key,pad,*len,decryptpos) == FALSE ) {
		return FALSE;
	}
#else
	char k[]=STATICKEY;
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); 					/* the pad could be anything... use memcpy */
	*key=vkey; 
#endif


	otp_xor( message, key, *len);				/* xor */
	return TRUE;
}

/* Encrypt the message  */
static int otp_uencrypt(char **message, struct otp* pad) {
	int a = (strlen(*message)+1) * sizeof(char);				/* get length of the used memory*/
	int *len=&a;
	char *b=""; char **key; key=&b;


#ifdef HAVEKEYFILE
	if ( otp_get_encryptkey_from_file(key,pad,*len) == FALSE ) {
		return FALSE;
	}
#else

	char k[]=STATICKEY; 
	char *vkey = (char *) malloc( (*len) * sizeof(char) );
	memcpy(vkey,k,*len-1); 					/* the pad could be anything... use memcpy */
	*key=vkey;
#endif

	otp_xor( message , key, *len);				/* xor */
	otp_b64enc( message , len );				/* encode base64 */
	
	return TRUE;
}


/*  ----------------- Public One-Time Pad Functions ------------ */

/* destroys a keyfile by using up all encryption-entropy */
unsigned int otp_erase_key(struct otp* pad) {

	if(pad == NULL) {
		return FALSE;
	}
	pad->protected_position=0;		


	int a = (ERASEBLOCKSIZE+1) * sizeof(char);				/* get length of the used memory*/
	int *len=&a;
	char *b=""; char **key; key=&b;


#ifdef HAVEKEYFILE
	int result=TRUE;
	while( result == TRUE ) {
		result = otp_get_encryptkey_from_file(key,pad,*len);
	}
	result=TRUE;
	*len=1+1;
		while( result == TRUE ) {
		result = otp_get_encryptkey_from_file(key,pad,*len);
	}
#endif

	return TRUE;	
}

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes. If source is NULL, /dev/urandom is used. */
unsigned int otp_generate_key_pair(const char* alice,const  char* bob,const char* path,const char* source, unsigned int size) {
	if(alice == NULL || bob == NULL || path == NULL || source == NULL || size==0) {
		return FALSE;
	}
	if ( size/BLOCKSIZE == (float) size/BLOCKSIZE ) { /* The function can only generate Keyfiles with a filesize of n*BLOCKSIZE */
		size=size/BLOCKSIZE;
	}else{
		size=size/BLOCKSIZE+1;
	}	
	
	int rfd=0;
	if ((rfd = open(source, O_RDONLY)) == -1) {
		perror("open");
		return FALSE;
	}
	struct stat rfstat;
	if (stat(source, &rfstat) == -1) {
		perror("stat");
		return FALSE;
	}
	
	unsigned int rfilesize = rfstat.st_size;
	if ( !( ((rfstat.st_mode|S_IFCHR) == rfstat.st_mode) || (rfilesize >= size*BLOCKSIZE) ) ) {		/* If the source is to small and not a character dev */
		//printf("The source '%s' is too small!\n",source);
		return FALSE;
	}

	unsigned int id;
	read (rfd,&id,sizeof(id));		/* Our ID */
	//id=1000;

	char *idstr=g_strdup_printf ("%.8X",id);			/* Our ID string */;
	
	
	/* Create the directory for the entropy files if it does not exist */	
	DIR *dp;
	dp = opendir (path);
	if (dp == NULL) {
		mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP );	/* Create the directory */
	}else{
		closedir(dp);
	}


	/* Opening the first file */
	char *afilename=g_strconcat(path,alice,FILE_DELI,bob,FILE_DELI,idstr,".entropy",NULL);
	//printf("%s\n",afilename);
	
	int afd=0; char *ab=""; char **adata; adata=&ab;
	
	if ((afd = open(afilename, O_RDWR)) == -1) {
	}else{
		close(afd);
		close(rfd);
		return FALSE; 	/* File already exists. I will not overwrite any existing file!*/
	}

	if ((afd = open(afilename, O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP )) == -1) {
		perror("open");
		close(rfd);
		return FALSE;
	}
		
	char rand[BLOCKSIZE];
	int i=0;
	
	/* Filling the first file */
	for(i=0;i<size;i++) {
		read (rfd, rand, BLOCKSIZE);
		write (afd, rand, BLOCKSIZE);	
	}
	
	/* Close the entropy source */
	close(rfd);
	
	
	/* Opening the secound file */
#ifdef USEDESKTOP	
	const char *desktoppath=g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP);  /* Owned by Glib. No need for g_free */
	char *bfilename=g_strconcat(desktoppath,PATH_DELI,bob,FILE_DELI,alice,FILE_DELI,idstr,".entropy",NULL);
#else
	char *bfilename=g_strconcat(path,bob,FILE_DELI,alice,FILE_DELI,idstr,".entropy",NULL);
#endif	

	//printf("%s\n",bfilename);
	
	int bfd=0; 
	
	if ((bfd = open(bfilename, O_RDWR)) == -1) {
	}else{
		close(bfd);
		return FALSE; 	/* File already exists. I will not overwrite any existing file!*/
	}
	if ((bfd = open(bfilename, O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP )) == -1) {
		perror("open");
		close(afd);
		return FALSE;
	}
	
	
	/* Opening a memory map for the first file */
	struct stat afstat;
	if (stat(afilename, &afstat) == -1) {
		perror("stat");
		return FALSE;
	}
	int afilesize=afstat.st_size;
	if ((*adata = mmap((caddr_t)0, afilesize, PROT_READ , MAP_SHARED, afd, 0)) == (caddr_t)(-1)) {
		perror("mmap");
		return FALSE;
	}
	
	
	/* Create the reversed second file from the first one */
	int j=0;
	char temp[BLOCKSIZE];
	//otp_printint(*adata,afilesize);
	printf("Filesize:%u\n",afilesize);
	for(i=afilesize-BLOCKSIZE;i>=0;i=i-BLOCKSIZE) {
			for(j=0;j<BLOCKSIZE;j++) {
				temp[BLOCKSIZE-1-j]=*(*adata+i+j);
			}
		//otp_printint(temp,BLOCKSIZE);
		write(bfd,temp,BLOCKSIZE);
	}
	
	
	/* Close the secound file */
	close(bfd);
	
	/* Close the first file */
	munmap(adata, afilesize);
	close(afd);
	
	/* Cleanup */
	g_free(idstr);
	
	return TRUE;
}

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use. */
unsigned int otp_encrypt_warning(struct otp* pad, char **message, int protected_pos) {

	if(pad == NULL) {
		return FALSE;
	}
	pad->protected_position = pad->filesize / 2 - OTP_PROTECTED_ENTROPY-protected_pos;  /* Assign a position in the protected entropy */
	
	char *pos_str = g_strdup_printf ("%u",pad->protected_position);			/* Our position in the pad*/
#ifdef UCRYPT
	if (otp_uencrypt(message,pad) == FALSE) {			/* Encrypt and base64 */
		pad->protected_position=0;
		return FALSE;
	}
#endif				

	char *new_msg = g_strconcat(pos_str,MSG_DELI,pad->id,MSG_DELI,*message,NULL);	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
	
	
	pad->protected_position=0;
	return TRUE;
}

/* extracts and returns the ID from a given encrypted message. Leaves the message constant. Returns NULL if it fails.*/
char* otp_get_id_from_message(char **message){

	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL) || (m_array[1] == NULL) ) {
		return FALSE;
	}

	char *id_str = g_strdup(m_array[1]);

	return otp_check_id(id_str);
}

/* Creates an otp struct, returns NULL if the filename is incorrect,
   or if the file is missing */
struct otp* otp_get_from_file(const char* path, const char* input_filename){
	static struct otp* pad;
   	pad = (struct otp *) malloc(sizeof(struct otp));
   	pad->protected_position=0;

	if (input_filename == NULL ) {	/* empty filename */
		return NULL;
	}

	if (path == NULL ) {	/* empty path */
		return NULL;
	}

	char *filename = g_strconcat(path,input_filename,NULL);
	pad->filename = filename;

	gchar** f_array = g_strsplit(input_filename, FILE_DELI, 3);

	if ( (f_array[0] == NULL) || (f_array[1] == NULL) || (f_array[2] == NULL) ) {
		return NULL;
	}
	char *src = g_strdup(f_array[0]);	/* Our source i.e alice@yabber.org */
	pad->src = src;

	char *dest = g_strdup(f_array[1]);	/* Our dest i.e bob@yabber.org */
	pad->dest = dest;

	gchar** p_array = g_strsplit(f_array[2], ".", 2);

	if ( (p_array[0] == NULL ) || (p_array[1] == NULL ) ) {
		return NULL;
	}
	if ( g_str_has_suffix(f_array[2], FILE_SUFFIX) == FALSE ) {
		return NULL;
	}
	char *id = g_strdup(p_array[0]);	/* Our ID */
	pad->id = id;

	g_strfreev(p_array);

	g_strfreev(f_array);

	if ( otp_check_id(pad->id) == NULL ) {
		return NULL;
	}

#ifdef HAVEFILE

	pad = otp_seek_start(pad);		/* Try to open the keyfile and get position ans size */
#else
/* 	 Dummy-values for development */
	if (pad != NULL) {
		pad->position = 10000;
		pad->filesize = 100000;
		otp_calc_entropy(pad);
	}
#endif
	return pad;
}
/* destroys an otp object */
void otp_destroy(struct otp* pad) {
	if (pad != NULL) {
		if (pad->src != NULL)
			g_free(pad->src);
		if (pad->dest != NULL)
			g_free(pad->dest);
		if (pad->id != NULL)
			g_free(pad->id);
		if (pad->filename != NULL)
			g_free(pad->filename);
		g_free(pad);
	}
}

/* Creates the actual string of the encrypted message that is given to the application.
returns TRUE if it could encrypt the message 
*/
unsigned int otp_encrypt(struct otp* pad, char **message){

	if(pad == NULL) {
		return FALSE;
	}
	pad->protected_position=0;
	char *pos_str = g_strdup_printf ("%u",pad->position);			/* Our position in the pad*/

#ifdef UCRYPT
	if (otp_uencrypt(message,pad) == FALSE) {			/* Encrypt and base64 */
		return FALSE;
	}
#endif				

	char *new_msg = g_strconcat(pos_str,MSG_DELI,pad->id,MSG_DELI,*message,NULL);	/*Something like "3EF9|34EF4588|M+Rla2w=" */
	g_free(*message);
	g_free(pos_str);
	*message = new_msg;
	return TRUE;
}

/* Strips the encrypted message and decrypts it.
returns TRUE if it could decrypt the message  */
unsigned int otp_decrypt(struct otp* pad, char **message){

	if (pad == NULL) {
		return FALSE;
	}
	pad->protected_position=0;
	gchar** m_array = g_strsplit(*message, MSG_DELI, 3);

	if ( (m_array[0] == NULL) || (m_array[1] == NULL) || (m_array[2] == NULL) ) {
		return FALSE;
	}

	int decryptpos = (unsigned int) g_ascii_strtoll ( strdup (m_array[0]) ,NULL,10); 	/* Our position to decrypt in the pad */
	pad->id = g_strdup(m_array[1]);

	char *new_msg = g_strdup(m_array[2]);
	g_free(*message);
	*message = new_msg;

	g_strfreev(m_array);

#ifdef UCRYPT

	if (otp_udecrypt(message,pad,decryptpos) == FALSE) {		/* Decrypt and debase64 */
		return FALSE;
	}

#endif

	return TRUE;
}
