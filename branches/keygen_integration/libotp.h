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

/*  ------------------- Public Constants (don't change) -------------------
 * Changing this makes your one-time-pad incompatible */

#define OTP_ID_LENGTH 8			/* Size of the ID-string. 4 bytes --> 8 bytes base 16*/
#define OTP_PROTECTED_ENTROPY 100	/* The amount of entropy that is only used for "out of entropy" messages */

/* ------------------ Error Syndrome System  ---------------------- */

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
	OTP_ERR_KEY_SIZE_MISMATCH	 = 0x00040000,

/* function: all
 * origin: the same functions
 * The input into the fuction is not valid i.e. NULL*/
	OTP_ERR_INPUT				= 0x00050000,

/* function: otp_decrypt
 * origin: otp_decrypt
 * The message is not in the format "3234|34EF4588|M+Rla2w=" and can not be splitted */
	OTP_ERR_MSG_FORMAT			= 0x00060000,

/* function: otp_decrypt
 * origin: otp_decrypt
 * The ID '34EF4588' does not match with the one in the pad */
	OTP_ERR_ID_MISMATCH		= 0x00070000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Generation of loop keys not supported */
	OTP_ERR_LOOP_KEY		= 0x00110000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Error opening the file from where entropy is taken */
	OTP_ERR_FILE_ENTROPY_SOURCE		= 0x00120000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The file from where entropy is taken is smaller then the requested key size*/
	OTP_ERR_FILE_ENTROPY_SOURCE_SIZE	= 0x00130000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The keyfile exists already and can not be created */
	OTP_ERR_FILE_EXISTS	= 0x00140000,

/* function: otp_conf_free
 * origin: otp_conf_free
 * There are still some pads registered in this config */
	OTP_ERR_CONFIG_PAD_COUNT	= 0x00200000,

/* This should be used to check if a error occurred
 * Every syndrome '<=' then this is a warning (or a success of course)
 * Every syndrome '>' then this is a (fatal) error */
	OTP_WARN		= 0x0000FFFF,
} OtpError;


// TODO: This will become private
struct otp {
 	char* src; 		/* for pidgin: 'account' like alice@jabber.org */
	char* dest; 		/* for pidgin: 'account' like bob@jabber.org */
	char* id; 		/* 8 digits unique random number of the key pair (hex) */
	char* filename; 	/* The full path and the filename defined in the libotp spec */
	gsize position; 	/* start positon for the next encryption */
	gsize protected_position;	/* Only used for messages and signals from the protected entropy. Otherwise set to zero */
	gsize entropy; 	/* the size (in bytes) of the entropy left for the sender */
	gsize filesize; 	/* The size of the file in bytes */
// TODO: Is this the future?
	OtpError syndrome;
//	struct otp_config* config;
};

/* encrypt the message
 * if it can't encrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_encrypt(struct otp* mypad, char** message);

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use.
 * The entropy is not consumed by this function.
 * To used the function securely, the signal-messages should not overlap
 * and every signal has to stay constant!
 * When only one signal is used, use protected_pos = 0.
 * if it can't encrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_encrypt_warning(struct otp* mypad, char** message, gsize protected_pos);

/* decrypt the message
 * if it can't decrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_decrypt(struct otp* mypad, char** message);

/* extracts and returns the ID from a given encrypted message.
   Leaves the message constant. Returns NULL if it fails. */
char* otp_get_id_from_message(char** message);
// Request API change to:
//char* otp_id_get_from_message(const struct otp_config* myconfig, const char *msg);

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes. */
OtpError otp_generate_key_pair(const char* alice, const char* bob, const char* path, const char* source, gsize size);
// Request API change to (this will change again later):
//OtpError otp_generate_key_pair(otp_config* myconfig, const char* alice,
//		const char* bob, const char* source, gsize size,
//		struct otp* alice_pad, struct otp* bob_pad);
		/* alice and bob is optional. if NULL not created */

/* destroys a keyfile by using up all encryption-entropy */
OtpError otp_erase_key(struct otp* mypad);

/* ------------------ otp_pad ------------------------------ */

/* creates an otp pad with the data from a key file */
struct otp* otp_get_from_file(const char* path, const char* filename);
// Request API change to:
//struct otp* otp_pad_create_from_file(const struct otp_config* myconfig, const char* filename);

/* destroys an otp object */
void otp_destroy(struct otp* mypad);
// Request API change to:
//void otp_pad_destroy(struct otp* mypad);

/* ------------------ otp_pad get functions ------------------- */

/* gets a reference to the source, i.e alice@jabber.org */
const char* otp_pad_get_src(struct otp* mypad);

/* gets a reference to the destination, i.e bob@jabber.org */
const char* otp_pad_get_dest(struct otp* mypad);

/* gets a reference to the ID, 8 digits unique random number of the key pair (hex) */
const char* otp_pad_get_id(struct otp* mypad);

/* gets a reference to the full path and the filename defined in the libotp spec */
const char* otp_pad_get_filename(struct otp* mypad);

/* gets the size (in bytes) of the entropy left for the sender */
gsize otp_pad_get_entropy(struct otp* mypad);

/* gets the current encrypt-position (in bytes) in the keyfile */
gsize otp_pad_get_position(struct otp* mypad);

/* gets the size of the file in bytes */
gsize otp_pad_get_filesize(struct otp* mypad);

/* gets an OtpError that contains information about the status of the pad */
OtpError otp_pad_get_syndrome(struct otp* mypad);

/* gets a reference to the config associated with this pad */
// TODO
//struct otp_config* otp_get_conf(struct otp* mypad);

/* CONF operations (No effect ATM) */
/* ------------------ otp_config ------------------------------ */

/* Creation of the config stucture of the library, sets some parameters
 *
 * client_id:		The name of the application using the library, i.e. 'paranoia-core'
 * path:		The path where the .entropy-files are stored.
 * export_path:		The path where to export new created keys
 * 					for the other converstation partner i.e. 'bob' */
struct otp_config* otp_conf_create(const char* client_id,
				const char* path, const char* export_path);

/* Freeing of the otp_config struct
 * This fails with OTP_ERR_CONFIG_PAD_COUNT if there are any pads open in this config */
OtpError otp_conf_destroy(struct otp_config* myconfig);

/* ------------------ otp_config get functions ------------------- */

/* Gets a reference to the path in the config
 * Does not need to be freed.  */
const char* otp_conf_get_path(const struct otp_config* myconfig);

/* Gets a reference to the export path in the config
 * Does not need to be freed.  */
const char* otp_conf_get_export_path(const struct otp_config* myconfig);

/* Gets random_msg_tail_max_len */
gsize otp_conf_get_random_msg_tail_max_len(const struct otp_config* myconfig);

/* Gets msg_key_improbability_limit */
double otp_conf_get_msg_key_improbability_limit(const struct otp_config* myconfig);

/* ------------------ otp_config set functions ------------------- */

/* Sets the path where the .entropy-files are stored */
OtpError otp_conf_set_path(struct otp_config* myconfig, const char* path);

/* Sets the export path where the .entropy-files are stored */
OtpError otp_conf_set_export_path(struct otp_config* myconfig, const char* export_path);

/* Sets random_msg_tail_max_len:
 * 					The max length of the randomly added tailing charakters
 * 					to prevent 'eve' from knowng the length of the message.
 * 					Disabled if 0. Default is already set to DEFAULT_RNDLENMAX */
OtpError otp_conf_set_random_msg_tail_max_len(struct otp_config* myconfig,
				 gsize random_msg_tail_max_len);

/* Sets msg_key_improbability_limit:
 * 					If the used random entropy shows pattern that are less likely
 * 					then this limit, the entropy is discarded and an other block of
 * 					entropy is used. A warning OTP_WARN_KEY_NOT_RANDOM is given.
 * 					Disabled if 0.0. Default is already set to DEFAULT_IMPROBABILITY. */
OtpError otp_conf_set_msg_key_improbability_limit(struct otp_config* myconfig,
				 double msg_key_improbability_limit);

/* Generate a key-pair alice and bob with size size */
GThread *generate_keys_from_keygen(char *alice, char *bob, unsigned int size, int loop);

/* get a random id for the key filename */
unsigned int otp_get_id();

/* invert:
*				invert writes the bytewise inverse of the src file into the dest
*				file. src and dest must be valid file names
*				this function returns 0 for success, -1 if a failure occures. */
//int otp_invert(char *src, char *dest);

/* loop-invert:
*				append the bytewise inverse of src to src
*				src must be a valide filename with valide path
*				returns 0 for success, -1 if a failure occures */
//int otp_loop_invert(char *src);
