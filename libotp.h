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

// ----------------- TODO: REMOVE ME ------------------

// For Nowic (semistable)
// for testing only
void aaaa_encrypt(char **message);
// for testing only
void aaaa_decrypt(char **message);


// public for development only (for boognu, unstable)
int otp_xor(char **message,char **pad,int len);
int otp_uencrypt(char **message);
int otp_udecrypt(char **message);
int otp_b64enc(char **message, int *len);
int otp_b64dec(char **message, int *len);
int otp_printint(char *m, int len);


// ----------------- OTP Crypto Functions API ------------------

// path to the otp key files
char* global_otp_path;

struct otp {
	char* src; // for pidgin: 'account' like a jabberadr, icq#...
	char* dest; // for pidgin: 'account' like a jabberadr, icq#...
	char* id; // the unique random number of the key pair
	char* filename; // the filename defined in the libotp spec
	unsigned int position; // start positon for the next encryption
	unsigned int size; // the size (in bytes) of the otp (low entropy problem)
//	TODO: maybe a mapped memory object?
};

/* returns 1 if it could encrypt the message */
unsigned int otp_encrypt(struct otp* mypad, char **message);

/* returns 1 if it could decrypt the message */
unsigned int otp_decrypt(struct otp* mypad, char **message);

/* creates an otp object with the data from a key file */
struct otp* otp_get_from_file(const char* filename);

/* searches the position of the first non zero value in the pad (maybe not a public function?) */
unsigned int otp_seek_start(struct otp* mypad);

/* generates a new key pair (two files) with the name alice and bob 
   of 'size' bytes.
*/
unsigned int otp_generate_key_pair(char* alice, char* bob, char* filename_alice, char* filename_bob, unsigned int size);

/* calculates if there is still enought non zero file content left.
   returns a meaningfull numeric value (TODO: details?)
*/
int otp_check_entropy(struct otp* mypad);

/* extracts and returns the ID from a given encrypted message. Leaves the message constant. Returns NULL if it fails.*/
char* otp_get_id_from_message(char **message);




