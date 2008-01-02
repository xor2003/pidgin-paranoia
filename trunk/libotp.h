/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
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

#define OTP_ID_LENGTH 8			/* Size of the ID-string */
#define OTP_PROTECTED_ENTROPY 100	/* The amount of entropy that is only used for "out of entropy" messages */ 

typedef enum {
	OTP_OK	= 0x00000000,

/* function: otp_encrypt, otp_encrypt_warning
 * origin: otp_get_encryptkey_from_file
 * The used entropy failed statistical tests */
	OTP_WARN_KEY_NOT_RANDOM	= 0x00000001,

	OTP_WARN2	= 0x00000002,
	OTP_WARN3	= 0x00000004,
	OTP_WARN4	= 0x00000008,
	OTP_WARN5	= 0x00000010,
	OTP_WARN6	= 0x00000020,
	OTP_WARN7	= 0x00000040,
	OTP_WARN8	= 0x00000080,
	OTP_WARN9	= 0x00000100,
	OTP_WARN10	= 0x00000200,
	OTP_WARN11	= 0x00000400,
	OTP_WARN12	= 0x00000800,
	OTP_WARN13	= 0x00001000,
	OTP_WARN14	= 0x00002000,
	OTP_WARN15	= 0x00004000,
	OTP_WARN16	= 0x00008000,

/* function: all
 * origin: otp_open_keyfile
 * A File can not be opened */
	OTP_ERR_FILE		= 0x00010000,

/* function: otp_encrypt, otp_encrypt_warning
 * origin: otp_get_encryptkey_from_file
 * The message does not fit into the entropy file */
	OTP_ERR_KEY_EMPTY	= 0x00030000,

/* function: otp_decrypt
 * origin: otp_get_decryptkey_from_file 
 * Position in the message does not exist in the entropy file */
	OTP_ERR_KEY_SIZE_MISMATCH	 =0x00040000,

/* function: all
 * origin: the same functions
 * The input into the fuction is not valid i.e. NULL*/
	OTP_ERR_INPUT				=0x00050000,

/* function: otp_decrypt 
 * origin: otp_decrypt
 * The message is not in the format "3234|34EF4588|M+Rla2w=" and can not be splitted */
	OTP_ERR_MSG_FORMAT			=0x00060000,

/* function: otp_decrypt
 * origin: otp_decrypt
 * The ID '34EF4588' does not match with the one in the pad */
	OTP_ERR_ID_MISMATCH		=0x00070000,
	
/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Generation of loop keys not supported */
	OTP_ERR_LOOP_KEY		=0x00110000,
	
/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Error opening the file from where entropy is taken */
	OTP_ERR_FILE_ENTROPY_SOURCE		=0x00120000,
	
/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The file from where entropy is taken is smaller then the requested key size*/
	OTP_ERR_FILE_ENTROPY_SOURCE_SIZE	=0x00130000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The keyfile exists already and can not be created */
	OTP_ERR_FILE_EXISTS	=0x00140000,
	

/* This should be used to check if a error occurred
 * Every syndrome '<=' then this is a warning (or a success of course)
 * Every syndrome '>' then this is a (fatal) error */
	OTP_WARN		= 0x0000FFFF,
} OtpError;

struct otp {
 	char* src; 		/* for pidgin: 'account' like alice@jabber.org */
	char* dest; 		/* for pidgin: 'account' like bob@jabber.org */
	char* id; 		/* 8 digits unique random number of the key pair (hex) */
	char* filename; 	/* The full path and the filename defined in the libotp spec */
	unsigned int position; 	/* start positon for the next encryption */
	unsigned int protected_position;	/* Only used for messages and signals from the protected entropy. Otherwise set to zero */
	unsigned int entropy; 	/* the size (in bytes) of the entropy left for the sender */
	unsigned int filesize; 	/* The size of the file in bytes */
};

/* returns 1 if it could encrypt the message */
OtpError otp_encrypt(struct otp* mypad, char **message);

/* returns 1 if it could decrypt the message */
OtpError otp_decrypt(struct otp* mypad, char **message);

/* creates an otp object with the data from a key file */
struct otp* otp_get_from_file(const char* path, const char* filename);

/* destroys an otp object */
void otp_destroy(struct otp* mypad);

/* extracts and returns the ID from a given encrypted message. 
   Leaves the message constant. Returns NULL if it fails. */
char* otp_get_id_from_message(char **message);

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes. */
OtpError otp_generate_key_pair(const char* alice, const char* bob, const char* path, const char* source, unsigned int size);

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use. 
 The entropy is not consumed by this function. 
 To used the function securely, the signal-messages should not overlap and every signal has to stay constant! 
 When only one signal is used, use protected_pos=0. */
OtpError otp_encrypt_warning(struct otp* mypad, char **message, unsigned int protected_pos);

/* destroys a keyfile by using up all encryption-entropy */
OtpError otp_erase_key(struct otp* mypad);




