/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2007-2008  Christian Wäckerlin, Simon Wenner
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

/* --------------------------- Note -----------------------------------
 * This is the public ABI of libotp. This is what you need to include in 
 * your application.
 * */
 
/* ------------------- Public Constans (you can change them) ----------------- */
#define PATH_DELI "/"					/* For some reason some strange
				 * operatingsystems use "\" */
#define SIGNALNAME "keygen-status-update"

/*  ------------------- Public Constants (don't change) -------------------
 * Changing this makes your one-time-pad incompatible */

#define OTP_ID_LENGTH 8			/* Size of the ID-string. 4 bytes --> 8 bytes base 16*/

/* ------------------ Error Syndrome System  ---------------------- */
#include "otperror.h"

/* Data structures */
struct otp_config;
struct otp;

/* ------------------ Principal functions ----------------------------*/

/* encrypt the message
 * if it can't encrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_encrypt(struct otp* mypad, gchar** message);

/* encrypts a message with the protected entropy. protected_pos is the position in bytes to use.
 * The entropy is not consumed by this function.
 * To used the function securely, the signal-messages should not overlap
 * and every signal has to stay constant!
 * When only one signal is used, use protected_pos = 0.
 * if it can't encrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_encrypt_warning(struct otp* mypad, gchar** message, gsize protected_pos);

/* decrypt the message
 * if it can't decrypt the message a syndrome > OTP_WARN is returned and
 * the message is left unchanged */
OtpError otp_decrypt(struct otp* mypad, gchar** message);

/* destroys a keyfile by using up all encryption-entropy */
OtpError otp_pad_erase_entropy(struct otp* mypad);

/* extracts and returns the ID from a given encrypted message.
 * Leaves the message constant. Returns NULL if it fails because the ID is not valid
 * or because it could not be extracted form the message */
gchar* otp_id_get_from_message(const struct otp_config* myconfig, const gchar *msg);

/* generates a new key pair (two files) with the name alice and bob of 'size' bytes.
 * if source is NULL (suggested as default), generate with keygen */
OtpError otp_generate_key_pair(struct otp_config* myconfig,
			const gchar* alice, const gchar* bob,
			const gchar* source, gsize size);

/* ------------------ otp_pad ------------------------------ */

/* creates an otp pad with the data from a key file */
struct otp* otp_pad_create_from_file(struct otp_config* myconfig, const gchar* filename);

/* closes the filehandle and the memory map. 
 * You can do this any time you want, it will just save memory */
void otp_pad_use_less_memory(struct otp* mypad);

/* destroys an otp object */
void otp_pad_destroy(struct otp* mypad);

/* ------------------ otp_pad get functions ------------------- */

/* gets a reference to the source, i.e alice@jabber.org */
const gchar* otp_pad_get_src(const struct otp* mypad);

/* gets a reference to the destination, i.e bob@jabber.org */
const gchar* otp_pad_get_dest(const struct otp* mypad);

/* gets a reference to the ID, 8 digits unique random number of the key pair (hex) */
const gchar* otp_pad_get_id(const struct otp* mypad);

/* gets a reference to the full path and the filename defined in the libotp spec */
const gchar* otp_pad_get_filename(const struct otp* mypad);

/* gets the size (in bytes) of the entropy left for the sender */
gsize otp_pad_get_entropy(const struct otp* mypad);

/* gets the current encrypt-position (in bytes) in the keyfile */
gsize otp_pad_get_position(const struct otp* mypad);

/* gets the size of the file in bytes */
gsize otp_pad_get_filesize(const struct otp* mypad);

/* gets an OtpError that contains information about the status of the pad */
OtpError otp_pad_get_syndrome(const struct otp* mypad);

/* gets a reference to the config associated with this pad */
struct otp_config* otp_pad_get_conf(const struct otp* mypad);

/* ------------------ otp_config ------------------------------ */

/* Creation of the config stucture of the library, sets some parameters
 *
 * client_id:		The name of the application using the library, i.e. 'paranoia-core'
 * path:			The path where the .entropy-files are stored. 
 * 					Without tailing path delimiter ('/').
 * export_path:		The path where to export new created keys. 
 * 					Without tailing path delimiter.
 * 					for the other converstation partner i.e. 'bob' 
 *max_keys_in_production:	The maximal number of keys, that can be produced on the same time.
 * 					*/
struct otp_config* otp_conf_create(const gchar* client_id,
				const gchar* path, const gchar* export_path, unsigned int max_keys_in_production);

/* Freeing of the otp_config struct
 * This fails with OTP_ERR_CONFIG_PAD_COUNT if there are any pads open in this config */
OtpError otp_conf_destroy(struct otp_config* myconfig);

/* ------------------ otp_config get functions ------------------- */

/* Gets a reference to the path in the config
 * Does not need to be freed.  */
const gchar* otp_conf_get_path(const struct otp_config* myconfig);

/* Gets a reference to the export path in the config
 * Does not need to be freed.  */
const gchar* otp_conf_get_export_path(const struct otp_config* myconfig);

/* Gets random_msg_tail_max_len */
gsize otp_conf_get_random_msg_tail_max_len(const struct otp_config* myconfig);

/* Gets msg_key_improbability_limit */
double otp_conf_get_msg_key_improbability_limit(const struct otp_config* myconfig);

/* Gets the number of keys in production in the keygen */
unsigned int otp_conf_get_number_of_keys_in_production(const struct otp_config* config);

/* Gets a reference the client id.
 * Does not need to be freed.  */
const gchar* otp_conf_get_client_id(const struct otp_config* myconfig);

/* ------------------ otp_config set functions ------------------- */

/* Sets the path where the .entropy-files are stored */
OtpError otp_conf_set_path(struct otp_config* myconfig, const gchar* path);

/* Sets the export path where the .entropy-files are stored */
OtpError otp_conf_set_export_path(struct otp_config* myconfig, const gchar* export_path);

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

/*	connect to signal with name signal_name. Following a list with available signal names and the 
*	corresponding function structures:
*	"keygen_key_done_signal"  -> my_function(GObject* object, double percent_done, struct otp* alice_pad) */
OtpError otp_signal_connect(struct otp_config* config, gchar *signal_name, gpointer function);
