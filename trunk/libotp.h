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

/* ----------------- OTP Crypto Functions API ------------------ */

#define OTP_ID_LENGTH 8			/* Size of the ID-string */
#define OTP_PROTECTED_ENTROPY 100	/* The amount of entropy that is only used for "out of entropy" messages */ 

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

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes. If source is NULL, /dev/urandom is used.*/
unsigned int otp_generate_key_pair(char* alice, char* bob, char* path, char* source, unsigned int size);

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use. 
 The entropy is not consumed by this function. 
 To used the function securely, the signal-messages should not overlap and every signal has to stay constant! 
 When only one signal is used, use protected_pos=0.*/
unsigned int otp_encrypt_warning(struct otp* mypad, char **message, int protected_pos);




