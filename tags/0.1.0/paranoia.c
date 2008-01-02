/*
 * Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
 * Copyright (C) 2007  Simon Wenner
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

/* GNOMElib */
#include <glib.h>

/* GNUlibc */
#include <string.h>

/* libpurple */
#define PURPLE_PLUGINS
#include "plugin.h"
#include "version.h"
#include "signals.h"
#include "debug.h"
#include "cmds.h"
// debug only:
#include "core.h"

/* Lib One-Time Pad */
#include "libotp.h"

#ifdef HAVE_CONFIG_H
#include "paranoia_config.h"
#endif

// test defines
#define SHOW_STATUS
#define CENSORSHIP

/* ----------------- General Paranoia Stuff ------------------ */
#define PARANOIA_HEADER "*** Encrypted with the Pidgin-Paranoia plugin: "
#define PARANOIA_REQUEST "*** Request for conversation with the Pidgin-\
Paranoia plugin (%s): I'm paranoid, please download the One-Time Pad \
plugin (%s) to communicate encrypted."
#define PARANOIA_REQUEST_LEN 60
#define PARANOIA_STATUS "&lt;otp&gt; "

#define PARANOIA_ACK "%!()!%paranoia ack" // not used atm
#define PARANOIA_EXIT "%!()!%paranoia exit"
#define PARANOIA_START "%!()!%paranoia start"
#define PARANOIA_STOP "%!()!%paranoia stop"
#define PARANOIA_NO_ENTROPY "%!()!%paranoia noent"
#define PARANOIA_PREFIX_LEN 6

#define PARANOIA_PATH "/.paranoia/"
#define ENTROPY_LIMIT 10000 /* has to be bigger then the message size limit */

char* global_otp_path;

void par_add_header(char** message) 
/* adds the paranoia header */
{
	char* new_msg = g_strconcat(PARANOIA_HEADER, *message, NULL);
	g_free(*message);
	*message = new_msg;
	return;
}

static gboolean par_remove_header(char** message)
/* checks the header and removes it if found */
{
	if (strlen(*message) > strlen(PARANOIA_HEADER)) {
		if (strncmp(*message, PARANOIA_HEADER, 
				strlen(PARANOIA_HEADER)) == 0) {
			char* new_msg = g_strdup(*message + strlen(PARANOIA_HEADER));
			g_free(*message);
			*message = new_msg;
			return TRUE;
		}	
	}
	return FALSE;
}

static gboolean par_add_status_str(char** message) 
/* adds a string at the beginning of the message (if encrypted) */
{
	if (strncmp(*message, "/me ", 4) == 0) {
		char* new_msg = g_strconcat(g_strconcat("/me ", 
			PARANOIA_STATUS, NULL), *message+4, NULL);
		g_free(*message);
		*message = new_msg;
	} 
	else {
		char* new_msg = g_strconcat(PARANOIA_STATUS, *message, NULL);
		g_free(*message);
		*message = new_msg;
	}
	return TRUE;
}

static gboolean par_censor_internal_msg(char** message)
/* detects all internal messages */
{
	if (strncmp(*message, PARANOIA_EXIT, PARANOIA_PREFIX_LEN) == 0) {
		return TRUE;
	}
	return FALSE;
}

static char* par_strip_jabber_ressource(const char* acc)
/* Strips the Jabber ressource (/home /mobile ect.) */
{
	gchar** str_array = g_strsplit(acc, "/", 2);
	char* acc_copy = g_strdup(str_array[0]);
	g_strfreev(str_array);
	return acc_copy;
}

/* ----------------- Paranoia Key Management ------------------ */

/* key options struct */
struct options {
	gboolean ack_sent; /* TRUE if a message with ACK was sent */
	gboolean has_plugin; /* the result of the request */
	gboolean otp_enabled; /* otp on/off */
	gboolean auto_enable; /* false to force disable */
	gboolean no_entropy; /* all entropy of one user was used up completely */
};

/* paranoia key struct (a linked list) */
struct key {
	struct otp* pad; /* see libotp.h */
	struct options* opt; /* key options */
	PurpleConversation* conv; /* current conversation (if any) */
	struct key* next;
};

/* paranoia keylist pointer */
struct key* keylist = NULL;

static struct key* par_create_key(const char* filename)
/* creates a key struct from a valid key file or returns NULL */
{
	/* get otp object */
	static struct otp* test_pad;
   	test_pad = otp_get_from_file(global_otp_path, filename);

	if(test_pad == NULL) {
		return NULL;
	}

	/* default option struct */
	static struct options* test_opt;
	test_opt = (struct options *) g_malloc(sizeof(struct options));
	test_opt->ack_sent = TRUE;
	test_opt->has_plugin = FALSE;
	test_opt->otp_enabled = FALSE;
	test_opt->auto_enable = TRUE;
	if(test_pad->entropy <= 0) {
		test_opt->no_entropy = TRUE;
	} else {
		test_opt->no_entropy = FALSE;
	}

	static struct key* key;
	key = (struct key *) g_malloc(sizeof(struct key));
	key->pad = test_pad;
	key->opt = test_opt;
	key->conv = NULL;
	key->next = NULL;
	return key;
}

static int par_count_keys()
/* counts all keys in the list */
{
	int sum = 0;
	struct key* tmp_ptr = keylist;
	while (!(tmp_ptr == NULL)) {
		sum++;
		tmp_ptr = tmp_ptr->next;
	}
	return sum;
}

static gboolean par_init_key_list()
/* loads all valid keys from the global otp folder into the key list */
{
	struct key* prev_key = NULL;
	struct key* tmp_key = NULL;
	GError* error = NULL;
	GDir* directoryhandle = g_dir_open(global_otp_path, 0, &error);
	const gchar* tmp_filename = g_dir_read_name(directoryhandle);
	char* tmp_path = NULL;
	
	if (error) {
		purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
				"Opening \"%s\" failed! %s\n", 
				global_otp_path, error->message);
		g_error_free(error);
		// TODO: return?
	} else {
		/* loop over global key dir */
		while (tmp_filename != NULL) {
			tmp_path = g_strconcat(global_otp_path, tmp_filename, NULL);
			
			if (g_file_test(tmp_path, G_FILE_TEST_IS_REGULAR)) {
				tmp_key = par_create_key(tmp_filename);
				if (tmp_key == NULL) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Could not add the file \"%s\".\n", 
							tmp_filename);
				} else {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Key \"%s\" added.\n", tmp_filename);
					tmp_key->next = prev_key;
					keylist = tmp_key;
					prev_key = tmp_key;
				}
			}
			g_free(tmp_path);
			tmp_filename = g_dir_read_name(directoryhandle);
		}
	}
	g_dir_close(directoryhandle);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
		"Key list of %i keys generated.\n", par_count_keys());

	return TRUE;
}

static void par_free_key_list()
/* frees all memory of the keylist */
{
	struct key* tmp_key = keylist;
	struct key* next_key_ptr = NULL;

	while (tmp_key != NULL) {
		next_key_ptr = tmp_key->next;
		otp_destroy(tmp_key->pad);
		g_free(tmp_key->opt);
		g_free(tmp_key);
		tmp_key = next_key_ptr;
	}
	return;
}

static struct key* par_search_key(const char* src, const char* dest, 
		const char* id)
/* searches a key in the keylist, the id is optional. If no ID is given
 * it searches for the first src/dest match.
 * */
{
	char* src_copy = par_strip_jabber_ressource(src);
	char* dest_copy = par_strip_jabber_ressource(dest);

	struct key* tmp_ptr = keylist;

	while (!(tmp_ptr == NULL)) {
		if ((strcmp(tmp_ptr->pad->src, src_copy) == 0) 
				&& (strcmp(tmp_ptr->pad->dest, dest_copy) == 0)) {

			if (id == NULL) {
				/* takes the first matching key, any id */
				return tmp_ptr;
			} else {
				/* takes the exact key */
				if (strcmp(tmp_ptr->pad->id, id) == 0) {
					return tmp_ptr;
				}
			}
		}
		tmp_ptr = tmp_ptr->next;
	}
	g_free(src_copy);
	g_free(dest_copy);
	return NULL;
}

static struct key* par_search_key_by_conv(PurpleConversation *conv)
/* searches a key in the keylist by PurpleConversation */
{
	struct key* tmp_ptr = keylist;

	while (!(tmp_ptr == NULL)) {
		if (tmp_ptr->conv == conv) {
			return tmp_ptr;
		}
		tmp_ptr = tmp_ptr->next;
	}
	return NULL;
}

/* ----------------- Session Management ------------------ */

static void par_session_request(PurpleConversation *conv)
/* sends an otp encryption request message */
{
	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), PARANOIA_REQUEST, 
			PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW); //PURPLE_MESSAGE_SYSTEM

	return;
}

/*
// sends an otp acknowledge message
void par_session_ack(PurpleConversation *conv) {

	// send PARANOIA_ACK

	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), PARANOIA_ACK, 
		PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW); //PURPLE_MESSAGE_SYSTEM | 

	return;
} */


void par_session_close(PurpleConversation *conv)
/* sends an otp termination message */
{
	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
			PARANOIA_EXIT, 
			PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW);

	return;
}

static gboolean par_session_check_req(const char* alice, const char* bob, 
		PurpleConversation *conv, char** message_no_header)
/* detects request messages and sets the key settings. 
 * Returns TRUE if a request was found.
 * */
{
	if (strncmp(*message_no_header, PARANOIA_REQUEST, 
			PARANOIA_REQUEST_LEN) == 0) {
		/* extract the ID */
		char* tmp_ptr = *message_no_header + PARANOIA_REQUEST_LEN + 2;
		char* id = g_strndup(tmp_ptr, OTP_ID_LENGTH);
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "REQUEST ID extracted: %s\n", id);
		
		struct key* temp_key = par_search_key(alice, bob, id);
		if (temp_key != NULL) {
			temp_key->conv = conv;
			if (temp_key->opt->auto_enable && !temp_key->opt->no_entropy) {
				temp_key->opt->ack_sent = FALSE;
				temp_key->opt->otp_enabled = TRUE;
				purple_conversation_write(conv, NULL, 
						"Encryption enabled.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "REQUEST checked: now otp_enabled = TRUE.\n");
			}
		} else {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "REQUEST failed! No key available.\n");
		}
		g_free(id);
		return TRUE;
	} else {
		return FALSE;
	}
}

static gboolean par_session_check_msg(struct key* used_key, 
		char** message_decrypted, PurpleConversation *conv)
/* detects ack and exit messages and sets the key settings. 
 * Returns TRUE if one of them is found.
 * */
{
	/* check prefix */
	if (!(strncmp(*message_decrypted, PARANOIA_EXIT, 
			PARANOIA_PREFIX_LEN) == 0)) {
		return FALSE;
	}
	/*
	if(strncmp(*message_decrypted, PARANOIA_ACK, strlen(PARANOIA_ACK)) == 0) {
		// TODO: move ACK inside the first sent message
		used_key->opt->has_plugin = TRUE;
		if(used_key->opt->auto_enable) {
			used_key->opt->otp_enabled = TRUE;
			purple_conversation_write(conv, NULL, 
				"Encryption enabled.", 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "PARANOIA_ACK detected! otp_enabled=TRUE \n");
		}
		return TRUE;
	} */
	/* check START, STOP, EXIT and NO_ENTROPY */
	if (strncmp(*message_decrypted, PARANOIA_EXIT, 
			strlen(PARANOIA_EXIT)) == 0) {
		used_key->opt->otp_enabled = FALSE;
		used_key->opt->has_plugin = FALSE;
		purple_conversation_write(conv, NULL, 
				"Encryption disabled (remote).", 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_EXIT detected. otp_enabled = FALSE\n");
		return TRUE;
	}
	if (strncmp(*message_decrypted, PARANOIA_START,
			strlen(PARANOIA_START)) == 0) {
		if(used_key->opt->auto_enable) {
			used_key->opt->has_plugin = TRUE;
			used_key->opt->otp_enabled = TRUE;
			purple_conversation_write(conv, NULL, 
					"Encryption enabled (remote).", 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"PARANOIA_START detected. otp_enabled = TRUE\n");
		} else {
			purple_conversation_write(conv, NULL, 
					"This buddy would like to chat encrypted.", 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		return TRUE;
	}
	if (strncmp(*message_decrypted, PARANOIA_STOP, 
			strlen(PARANOIA_STOP)) == 0) {
		used_key->opt->otp_enabled = FALSE;
		purple_conversation_write(conv, NULL, 
				"Encryption disabled (remote).", 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_STOP detected. otp_enabled = FALSE\n");
		return TRUE;
	}
	if (strncmp(*message_decrypted, PARANOIA_NO_ENTROPY, 
			strlen(PARANOIA_NO_ENTROPY)) == 0) {
		used_key->opt->otp_enabled = FALSE;
		used_key->opt->no_entropy = TRUE;
		used_key->opt->auto_enable = FALSE;
		// TODO: maybe we should destroy our key too. (?)
		purple_conversation_write(conv, NULL, 
				"Your converstation partner is out of entropy. "
				"Encryption disabled (remote).", 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_NO_ENTROPY detected. otp_enabled = FALSE\n");
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/* ----------------- Paranoia CLI ------------------ */

PurpleCmdId par_cmd_id;

#define PARANOIA_HELP_STR "Welcome to the One-Time Pad CLI.\n\
otp help: shows this message \notp genkey &lt;size&gt; &lt;entropy \
source&gt;: generates a key pair of &lt;size&gt; \
kB\notp on: tries to start the encryption\notp off: stops the \
encryption\notp info: shows details about the used key"
#define PARANOIA_ERROR_STR "Wrong argument(s). Type '/otp help' for help."
#define PARANOIA_KEYSIZE_ERROR "Your key size is too large."

static void par_cli_set_default_error(gchar **error)
/* sets the default paranoia cli error */
{
	g_free(*error);
	*error = g_strdup(PARANOIA_ERROR_STR);
	return;
}

static gboolean par_cli_try_enable_enc(PurpleConversation *conv)
/* tries to enable the encryption */
{
	struct key* used_key = par_search_key_by_conv(conv);
	if (used_key != NULL) {
		if (!used_key->opt->no_entropy) {
			if (used_key->opt->has_plugin == TRUE) {
				if (!used_key->opt->otp_enabled) {
					used_key->opt->otp_enabled = TRUE;
					used_key->opt->ack_sent = FALSE;
					purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
							PARANOIA_START, 
							PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG);
					purple_conversation_write(conv, NULL, 
							"Encryption enabled.", 
							PURPLE_MESSAGE_NO_LOG, time(NULL));
				} else {
					purple_conversation_write(conv, NULL, 
							"Encryption already enabled.", 
							PURPLE_MESSAGE_NO_LOG, time(NULL));
				}
			} else {
				purple_conversation_write(conv, NULL, 
						"Trying to enable encryption.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				par_session_request(conv);
			}
			used_key->opt->auto_enable = TRUE;
			return TRUE;
		}
		purple_conversation_write(conv, NULL, 
				"Couldn't enable the encryption. No entropy available.",
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		return FALSE;
	}
	
	purple_conversation_write(conv, NULL, 
			"Couldn't enable the encryption. No key available.",
			PURPLE_MESSAGE_NO_LOG, time(NULL));
	return FALSE;
}

static gboolean par_cli_disable_enc(PurpleConversation *conv)
/* disables the encryption */
{
	struct key* used_key = par_search_key_by_conv(conv);
	if (used_key != NULL) {
		if (used_key->opt->otp_enabled) {
			purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
				PARANOIA_STOP, 
				PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG);
			used_key->opt->otp_enabled = FALSE;
			used_key->opt->auto_enable = FALSE;
			purple_conversation_write(conv, NULL, 
					"Encryption disabled.", 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		} else {
			purple_conversation_write(conv, NULL, 
					"Encryption already disabled.", 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		return TRUE;
	}
	
	purple_conversation_write(conv, NULL, 
		"Couldn't disable the encryption. No key available.",
		PURPLE_MESSAGE_NO_LOG, time(NULL));
	return FALSE;
}

static void par_cli_key_details(PurpleConversation *conv)
/* shows all information about a key of a conversation */
{
	struct key* used_key = par_search_key_by_conv(conv);
	char* disp_string = NULL;
	if(used_key != NULL) {
		disp_string = g_strdup_printf("Key infos:\nSource:\t\t%s\n"
				"Destination:\t%s\nID:\t\t\t%s\nSize:\t\t\t%i\nPosition:\t\t%i\n"
				"Entropy:\t\t%i\nAck sent:\t\t%i\nHas plugin:\t%i\n"
				"OTP enabled:\t%i\nAuto enable:\t%i\nNo entropy:\t%i",
				used_key->pad->src, used_key->pad->dest, used_key->pad->id, 
				used_key->pad->filesize, 
				used_key->pad->position, used_key->pad->entropy, 
				used_key->opt->ack_sent, used_key->opt->has_plugin, 
				used_key->opt->otp_enabled, used_key->opt->auto_enable, 
				used_key->opt->no_entropy); // TODO: show protocol?

	} else {
		disp_string = g_strdup("There is no key available for this conversation.");
	}

	purple_conversation_write(conv, NULL, disp_string, 
			PURPLE_MESSAGE_NO_LOG, time(NULL));
	g_free(disp_string);
	return;
}

static PurpleCmdRet par_cli_check_cmd(PurpleConversation *conv, 
		const gchar *cmd, gchar **args, gchar **error, void *data)
/* checks and executes all otp commads */
{
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
		"An otp command was received. sweet!\n");
		
	if (args[0] == NULL) {
		par_cli_set_default_error(error);
		return PURPLE_CMD_RET_FAILED;
	} else {
		if(strcmp("help", *args) == 0) {
			purple_conversation_write(conv, NULL, 
					PARANOIA_HELP_STR, 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		else if (strcmp("on", *args) == 0) {
			par_cli_try_enable_enc(conv);
		}
		else if (strcmp("off", *args) == 0) {
			par_cli_disable_enc(conv);
		} 
		else if (strcmp("info", *args) == 0) {
			par_cli_key_details(conv);
		} 
		else if (strncmp("genkey ", *args, 7) == 0) {
			gchar** param_array = g_strsplit(*args + 7, " ", 2); /* to skip "genkey " */

			if (param_array[0] == NULL) {
				g_strfreev(param_array);
				par_cli_set_default_error(error);
				return PURPLE_CMD_RET_FAILED;
			}
			
			int size = strtol(param_array[0], NULL, 0);
         	/* overflow detection */
			if (size >= INT_MAX || size <= INT_MIN) {
				purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
						"The size value caused an integer overflow!\n");
				g_strfreev(param_array);
				g_free(*error);
				*error = g_strdup(PARANOIA_KEYSIZE_ERROR);
				return PURPLE_CMD_RET_FAILED;
				
			} else {
				if (size <= 0) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"The size value is not a positive int!\n");
					g_strfreev(param_array);
					par_cli_set_default_error(error);
					return PURPLE_CMD_RET_FAILED;
				} else {
					/* found a positive int */
					// FIXME: additional garbage after the int is just ignored(?)
					purple_conversation_write(conv, NULL, 
							"Please wait. Generating keys...", 
							PURPLE_MESSAGE_NO_LOG, time(NULL));
					const char* my_acc = par_strip_jabber_ressource(
							purple_account_get_username(
							purple_conversation_get_account(conv)));
					const char* other_acc = par_strip_jabber_ressource(
							purple_conversation_get_name(conv));

					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Generate new key: my_acc: %s, other_acc: %s, size: %ikB\n",
							my_acc, other_acc, size);

					if (param_array[1] == NULL) {
						/* default entropy source */
						if (otp_generate_key_pair(my_acc, 
									other_acc, global_otp_path, 
									"/dev/urandom", size*1000)) {
							purple_conversation_write(conv, NULL, 
									"Key files successfully generated.\n"
									"Your own key was stored in the directory '~/.paranoia'.\n"
									"Your buddy's key is stored in your home directory.\n"
									"Please send this key in a secure way to your partner.\n"
									"Please reload the plugin to add your key.\n",
									PURPLE_MESSAGE_NO_LOG, time(NULL));
							purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
									"Generated two entropy files of %ikB size.\n", 
									size);
							// TODO: add key to the list
						} else {
							purple_conversation_write(conv, NULL, 
									"Key files could not be generated.", 
									PURPLE_MESSAGE_NO_LOG, time(NULL));
						}
					} else {
						if (otp_generate_key_pair(my_acc, other_acc,
									global_otp_path, g_strstrip(param_array[1]),
									size*1000)) {
							purple_conversation_write(conv, NULL, 
									"Key files successfully generated.\n"
									"Your own key was stored in the directory '~/.paranoia'.\n"
									"Your buddy's key is stored in your home directory.\n"
									"Please send this key in a secure way to your partner.\n"
									"Please reload the plugin to add your key.\n", 
									PURPLE_MESSAGE_NO_LOG, time(NULL));
							purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
									"Generated two entropy files of %ikB size.\n", 
									size);
						} else {
							purple_conversation_write(conv, NULL, 
									"Key files could not be generated.", 
									PURPLE_MESSAGE_NO_LOG, time(NULL));
							purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
									"Key generation failed!\n");
						}
					}
				}
			}
			g_strfreev(param_array);
		}
		else {
			/* unknown arg */
			par_cli_set_default_error(error);
			return PURPLE_CMD_RET_FAILED;
		}
	}

	return PURPLE_CMD_RET_OK;
}

/* ----------------- Siganl Handlers ------------------ */

void par_conversation_created(PurpleConversation *conv)
/* signal handler for "conversation-created" */
{
	/* Send a request message (always!). 
	 * Will be filtered in par_im_msg_sending. */
	par_session_request(conv);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Conversation created.\n");
}

void par_conversation_deleting(PurpleConversation *conv)
/* signal handler for "deleting-conversation" */
{
	struct key* used_key = par_search_key_by_conv(conv);
	if (used_key != NULL) {
		
		/* send an EXIT message */
		if (used_key->opt->otp_enabled) {
			par_session_close(conv);
		}
		/* reset the pad */
		used_key->conv = NULL;
		used_key->opt->ack_sent = TRUE;
		used_key->opt->has_plugin = FALSE;
		used_key->opt->otp_enabled = FALSE;
		
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Reset conversation in key list. EXIT sent.\n");
	}
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Conversation deleted.\n");
}

static gboolean par_im_msg_receiving(PurpleAccount *account, 
		char **sender, char **message, PurpleConversation *conv,
		PurpleMessageFlags *flags)
/* signal handler for "receiving-im-msg" 
 * return TRUE drops the msg!
 * */
{
	/* if an other plugin destroyed the message */
	if ((message == NULL) || (*message == NULL)) {
		return TRUE;
	}

	/* my account name, i.e. alice@jabber.org */
	const char* my_acc_name = purple_account_get_username(account);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"My account: %s\n", my_acc_name);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"I received a message from %s\n", *sender);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Recived Msg: %s\n", *message);

	// --- Strip all the HTML crap (Jabber, MSN)
	// TODO: only strip, if jabber or msn or ???
	// detect the protcol id:
	// purple_account_get_protocol_id(account)


	char* tmp_message = g_strdup(purple_markup_strip_html(*message));	
	char** stripped_message;
	stripped_message = &tmp_message;
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Stripped Msg: %s\n", *stripped_message);

	/* checks for the Paranoia Header and removes it if found */
	if (!par_remove_header(stripped_message)) {
		if (par_session_check_req(my_acc_name, *sender, conv, 
				stripped_message)) {
			g_free(*stripped_message);
			return FALSE;
		}
		
		struct key* used_key = par_search_key(my_acc_name, *sender, NULL);
		if (used_key != NULL) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"Found a matching key with ID: %s\n", used_key->pad->id);
			/* save conversation ptr */
			used_key->conv = conv;

			/* disable encryption if unencrypted message received but not waiting for ack */
			if (used_key->opt->otp_enabled && used_key->opt->ack_sent) {
				used_key->opt->otp_enabled = FALSE;
				purple_conversation_write(conv, NULL, 
						"Encryption disabled.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
			}
		}
		/* free the jabber/msn strip! */
		g_free(*stripped_message);
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"This is not a paranoia message.\n");
		return FALSE;
	}
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Un-Headered message: %s\n", *stripped_message);

	/* apply jabber and header changes */
	g_free(*message);
	*message = *stripped_message;

	char* recv_id = otp_get_id_from_message(message);

	/* search in key list */
	struct key* used_key = par_search_key(my_acc_name, *sender, recv_id);

	if (used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found a matching key with ID: %s\n", used_key->pad->id);
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		/* save conversation ptr */
		used_key->conv = conv;

#ifdef NO_OTP
		// DISABLE LIBOTP
#else
		// ENABLE LIBOTP
		if (!otp_decrypt(used_key->pad, message)) {
			purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
					"Could not decrypt the message! That's a serious error!.\n");
			// TODO: notify the user
		}
#endif

		// detect START, STOP and EXIT message
		if (par_session_check_msg(used_key, message, conv)) {
			return TRUE;
		}

		// TODO: detect ACK message
		if (!used_key->opt->has_plugin) {
			used_key->opt->has_plugin = TRUE;

			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Encrypted msg received. Now has_plugin = TRUE.\n");
		}

		// encryption not enabled?
		if (!used_key->opt->otp_enabled) {
			//can I activate an encrypted conversation too?
			if(used_key->opt->auto_enable) {
				used_key->opt->has_plugin = TRUE;
				used_key->opt->otp_enabled = TRUE;
				purple_conversation_write(conv, NULL, 
						"Encryption enabled.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "This conversation was already initialized! otp_enabled is now TRUE\n");
				/* detect REQUEST; needed for a auto-init */
				if(strncmp(*message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "He sends us an encrypted REQUEST message. otp_enabled is now TRUE\n");
					return TRUE;
				}
			}
		}

		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Decoded Msg: %s\n", *message);

	} else {
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found no matching key. Couldn't decrypt.\n");
	}
	return FALSE;
}

static void par_im_msg_sending(PurpleAccount *account, 
		const char *receiver, char **message)
/* signal handler for "sending-im-msg" */
{
	const char* my_acc_name = purple_account_get_username(account);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"My account: %s\n", my_acc_name);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"I want to send a message to %s\n", receiver);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Original Msg: %s\n", *message);

	/* search in key list */
	struct key* used_key = par_search_key(my_acc_name, receiver, NULL);

	if (used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found a matching Key with pad ID: %s\n", used_key->pad->id);
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		/* add the ID to the request message */
		if (strncmp(*message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
			/* don't send requests if we have no entropy. */
			if (used_key->opt->no_entropy) {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"No entropy available. Won't sent REQUEST.\n");
				g_free(*message);
				*message = NULL;
				return;
			}
			char *req_msg = g_strdup_printf(*message, used_key->pad->id, PARANOIA_WEBSITE);
			g_free(*message);
			*message = req_msg;
		}

		used_key->opt->ack_sent = TRUE;

		// encryption enabled?
		if (!used_key->opt->otp_enabled) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "This conversation was not initialized! otp_enabled == FALSE.\n");
			return;
		}

		/* check for remaining entropy */
		if (used_key->pad->entropy < ENTROPY_LIMIT) {
			if (used_key->pad->entropy < strlen(*message)) {
				used_key->opt->no_entropy = TRUE;
				used_key->opt->otp_enabled = FALSE;
				used_key->opt->auto_enable = FALSE;
				purple_conversation_write(used_key->conv, NULL, 
						"All your entropy has been used. Encryption disabled. "
						"The last Message could not be sent.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				// TODO: display the message in the msg too
				/* delete the remaining entropy */
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"You have not enought entropy! no_entropy = TRUE\n");
				if (otp_erase_key(used_key->pad)) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Remaining entropy erased!\n");
				}
				/* delete message and send no entropy msg */
				g_free(*message);
				*message = g_strdup(PARANOIA_NO_ENTROPY);
				if (!otp_encrypt_warning(used_key->pad, message, 0)) {
					purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
							"Could not send an entropy warning. That's a serious error!.\n");
				}
				par_add_header(message);
				return;
			} else {
				// TODO: send an entropy warning (inside the real msg)
				char *warning_msg = g_strdup_printf (
						"Your entropy is low! %i bytes left.", 
						used_key->pad->entropy);
				purple_conversation_write(used_key->conv, NULL, 
						warning_msg, PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, warning_msg);
				g_free(warning_msg);
			}
		}
		

#ifdef NO_OTP
		// DISABLE LIBOTP
#else
		// ENABLE LIBOT
		if (!otp_encrypt(used_key->pad, message)) {
			purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
					"Could not encrypt the message. That's a serious error!.\n");
		}
#endif

		/* add the paranoia header string */
		par_add_header(message);

		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Encoded Msg: %s\n", *message);

	} else {
		/* don't send requests to users with no key. */
		if(strncmp(*message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"Found no matching key. Won't sent REQUEST.\n");
			g_free(*message);
			*message = NULL;
			return;
		}
	
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found no matching key. Won't encrypt.\n");
	}
	return;
}

static gboolean par_im_msg_change_display(PurpleAccount *account, 
		const char *who, char **message, PurpleConversation *conv, 
		PurpleMessageFlags flags)
/* signal handler for "writing-im-msg", 
 * needed to change the displayed msg.
 * returns TRUE if the message should be canceled, or FALSE otherwise.
 * */
{
	struct key* used_key = NULL;

	/* save the first conv pounter (if libpurple >= 2.2.0) */
	if (who != NULL) { /* needed to exclude libpurple < 2.2.0 */
		used_key = par_search_key(purple_account_get_username(account), who, NULL);
		if ( used_key != NULL) {
			if (used_key->conv == NULL) {
				used_key->conv = conv;
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Conversation pointer saved!\n");
			}
		}
	}

#ifdef CENSORSHIP

	char* stripped_message = g_strdup(purple_markup_strip_html(*message));

	/* hide session init messages */
	if (strncmp(stripped_message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
		if (used_key != NULL) {
			if (flags & PURPLE_MESSAGE_SEND) { //used_key->opt->has_plugin
				g_free(stripped_message);
				return TRUE;
			} else {
				/* cosmetics */
				g_free(*message);
				*message = g_strndup(stripped_message, PARANOIA_REQUEST_LEN);
				g_free(stripped_message);
				return FALSE;
			}
		}
	}
	g_free(stripped_message);
	
	/* hide internal messages */
	if (par_censor_internal_msg(message)) {
		return TRUE;
	}

#endif

#ifdef SHOW_STATUS
	/* Remove the first fake <otp> string (FIXME: it's a hack) */
	if (used_key == NULL || !used_key->opt->otp_enabled) {
		char* evil = g_strstr_len(*message, (gssize) 200, "&lt;otp&gt;");
		if (evil != NULL) {
			evil += 4;
			*evil = 'N';
			evil++;
			*evil = 'O';
			evil++;
			*evil = '!';
		}
	}

	/* System messages and warnings are not labelled */
	if (!(flags & PURPLE_MESSAGE_NO_LOG || flags & PURPLE_MESSAGE_SYSTEM)) {	
		if (used_key != NULL) {
			if (used_key->opt->otp_enabled && used_key->opt->ack_sent) {
				par_add_status_str(message);
			}
		}
	}
	
#endif
	return FALSE;
}

static gboolean plugin_load(PurplePlugin *plugin)
/* gets called when the plugin gets loaded */
{

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID,
			"Compiled with Purple '%d.%d.%d', running with Purple '%s'.\n",
			PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, 
			PURPLE_MICRO_VERSION, purple_core_get_version());

	/* set the global key folder */
	const gchar* home = g_get_home_dir();
	global_otp_path = g_strconcat(home, PARANOIA_PATH, NULL);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Key Path: %s\n", global_otp_path);

	/* get the conversation handle */
	void *conv_handle;
	conv_handle = purple_conversations_get_handle();

	/* setup the key list */
	par_init_key_list();

	/* connect to signals */
	purple_signal_connect(conv_handle, "receiving-im-msg", plugin,
			PURPLE_CALLBACK(par_im_msg_receiving), NULL);
	purple_signal_connect(conv_handle, "sending-im-msg", plugin,
			PURPLE_CALLBACK(par_im_msg_sending), NULL);
	purple_signal_connect(conv_handle, "writing-im-msg", plugin,
			PURPLE_CALLBACK(par_im_msg_change_display), NULL);
	purple_signal_connect(conv_handle, "conversation-created", plugin,
			PURPLE_CALLBACK(par_conversation_created), NULL);
	purple_signal_connect(conv_handle, "deleting-conversation", plugin, 
			PURPLE_CALLBACK(par_conversation_deleting), NULL);

	/* register commands ("/otp" + a string of args) */
	par_cmd_id = purple_cmd_register ("otp", "s", PURPLE_CMD_P_DEFAULT,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, NULL, 
			PURPLE_CMD_FUNC(par_cli_check_cmd), 
			"otp &lt;command&gt: type /otp to get help", NULL);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Plugin loaded.\n");
	
	return TRUE;
}

gboolean plugin_unload(PurplePlugin *plugin)
/* gets called when disabling the plugin */
{
	/* send PARANOIA_EXIT to all open conversations */
	struct key* key_ptr = keylist;
	while (key_ptr != NULL) {
		if (key_ptr->conv != NULL) {
			par_session_close(key_ptr->conv);
		}
		key_ptr = key_ptr->next;
	}
	/* disconnect all signals */
	purple_signals_disconnect_by_handle(plugin);
	
	/* unregister command(s) */
	purple_cmd_unregister(par_cmd_id);

	/* free the key list */
	par_free_key_list();

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Plugin unloaded.\n");
	return TRUE;
}

static void init_plugin(PurplePlugin *plugin)
/* gets called when libpurple probes the plugin */
{
	return;
}


/* ----------------- Plugin definition & init ------------------ */

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,    /* This must be PURPLE_PLUGIN_MAGIC. */
    PURPLE_MAJOR_VERSION,   /* This is also defined in libpurple. */
    PURPLE_MINOR_VERSION,   /* See previous */
    PURPLE_PLUGIN_STANDARD, /* PurplePluginType */
    NULL,                   /* UI requirement. */
    0,                      /* Plugin flags. */
    NULL,                   	/* GList of plugin dependencies. */
    PURPLE_PRIORITY_DEFAULT,	/* PURPLE_PRIORITY_DEFAULT,
                                   PURPLE_PRIORITY_HIGHEST or
                                   PURPLE_PRIORITY_LOWEST */
    PARANOIA_ID,     			/* plugin id */
    "One-Time Pad Encryption",  /* plugin name */
    PARANOIA_VERSION,           /* version */

    "Paranoia One-Time Pad Encryption Plugin",   
							/* This is the summary of your plugin.  It
                                   should be a short little blurb.  The UI
                                   determines where, if at all, to display
                                   this. */
    "The Paranoia plugin allows you to encrypt your messages with one-time pads.",   
							/* This is the description of your plugin. It
                                   can be as long and as descriptive as you
                                   like.  And like the summary, it's up to the
                                   UI where, if at all, to display this (and
                                   how much to display). */
    PARANOIA_AUTHORS,		/* name and e-mail address */
    PARANOIA_WEBSITE,		/* website */

    plugin_load,            /* This is a pointer to a function for
                                   libpurple to call when it is loading the
                                   plugin.  It should be of the type:

                                   gboolean plugin_load(PurplePlugin *plugin)

                                   Returning FALSE will stop the loading of the
                                   plugin.  Anything else would evaluate as
                                   TRUE and the plugin will continue to load.
                                 */
    plugin_unload,                   /* Same as above except it is called when
                                   libpurple tries to unload your plugin.  */
    NULL,                   /* Similar to the two above members, except
                                   this is called when libpurple tries to
                                   destory the plugin.  This is generally only
                                   called when for some reason or another the
                                   plugin fails to probe correctly.  It should
                                   be of the type:

                                   void plugin_destroy(PurplePlugin *plugin)
                                 */

    NULL,                   /* a pointer to a PidginPluginUiInfo struct */
    NULL,                   /* PurplePluginLoaderInfo or PurplePluginProtocolInfo struct. */
    NULL,                   /* PurplePluginUiInfo struct. */
    NULL,                   /* "plugin actions".  The UI controls how
                                   they're displayed.  It should be of the
                                   type:
                                   GList *function_name(PurplePlugin *plugin, 
                                                        gpointer context)
                                    It must return a GList of
                                    PurplePluginActions.
                                 */
    /* reserved */
    NULL,
    NULL,
    NULL,
    NULL
};

PURPLE_INIT_PLUGIN(paranoia, init_plugin, info)