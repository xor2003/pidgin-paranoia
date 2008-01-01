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
	OTPSUCCESS	= 0x00000000,
	OTPWARNKEYNOTRANDOM	= 0x00000001,
	OTPWARN2	= 0x00000002,
	OTPWARN3	= 0x00000004,
	OTPWARN4	= 0x00000008,
	OTPWARN5	= 0x00000010,
	OTPWARN6	= 0x00000020,
	OTPWARN7	= 0x00000040,
	OTPWARN8	= 0x00000080,
	OTPWARN9	= 0x00000100,
	OTPWARN10	= 0x00000200,
	OTPWARN11	= 0x00000400,
	OTPWARN12	= 0x00000800,
	OTPWARN13	= 0x00001000,
	OTPWARN14	= 0x00002000,
	OTPWARN15	= 0x00004000,
	OTPWARN16	= 0x00008000,
	OTPERRFILE		= 0x00010000,
	OTPERRMMAP		= 0x00020000,
	OTPERRKEYEMPTY	= 0x00030000,
	OTPERRKEYSIZEMISMATCH	=0x00040000,

	OTPWARN		= 0x0000FFFF,	/* Every syndrome '<=' then this is a warning (or a success of course)
 * Every syndrome '>' then this is a (fatal) error */
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
unsigned int otp_encrypt(struct otp* mypad, char **message);

/* returns 1 if it could decrypt the message */
unsigned int otp_decrypt(struct otp* mypad, char **message);

/* creates an otp object with the data from a key file */
struct otp* otp_get_from_file(const char* path, const char* filename);

/* destroys an otp object */
void otp_destroy(struct otp* mypad);

/* extracts and returns the ID from a given encrypted message. 
   Leaves the message constant. Returns NULL if it fails. */
char* otp_get_id_from_message(char **message);

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes. */
unsigned int otp_generate_key_pair(const char* alice, const char* bob, const char* path, const char* source, unsigned int size);

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use. 
 The entropy is not consumed by this function. 
 To used the function securely, the signal-messages should not overlap and every signal has to stay constant! 
 When only one signal is used, use protected_pos=0. */
unsigned int otp_encrypt_warning(struct otp* mypad, char **message, unsigned int protected_pos);

/* destroys a keyfile by using up all encryption-entropy */
unsigned int otp_erase_key(struct otp* mypad);




