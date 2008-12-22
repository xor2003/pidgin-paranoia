/*
 * Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
 * Copyright (C) 2007-2008  Simon Wenner
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

#ifdef HAVE_CONFIG_H
#include "paranoia_config.h"
#endif

/* GNOMElib */
#include <glib.h>
#include <glib-object.h>
#include <glib/gi18n-lib.h>

/* libpurple */
#define PURPLE_PLUGINS
#include "plugin.h"
#include "version.h"
#include "signals.h"
#include "debug.h"
#include "cmds.h"
#include "blist.h"
// debug only:
#include "core.h"

/* Our stuff */
#include "libotp.h"
#include "key_management.h"

// test defines
#define SHOW_STATUS
#define CENSORSHIP

/* Requires GNOMElib > 2.14! Bob's keyfile is placed onto the desktop. 
 * If not set, the file is placed in the home directory. */
#define USEDESKTOP

/* ----------------- General Paranoia Stuff ------------------ */
#define PARANOIA_HEADER_MARKER "***"
#define PARANOIA_HEADER "*** Encrypted with the Pidgin-Paranoia plugin: "
#define PARANOIA_REQUEST "*** Request for conversation with the Pidgin-\
Paranoia plugin (%s): I'm paranoid, please download the One-Time Pad \
plugin (%s) for encrypted communication."
#define PARANOIA_REQUEST_LEN 60
#define PARANOIA_STATUS "&lt;otp&gt; "

#define PARANOIA_ACK "%!()!%paranoia ack"
#define PARANOIA_EXIT "%!()!%paranoia exit"
#define PARANOIA_START "%!()!%paranoia start"
#define PARANOIA_STOP "%!()!%paranoia stop"
#define PARANOIA_NO_ENTROPY "%!()!%paranoia noent"
#define PARANOIA_PREFIX "%!()!%"

#define PARANOIA_PATH "/.paranoia"
#define ENTROPY_LIMIT 10000 /* has to be bigger then the message size limit */
#define KEYGEN_POLL_INTERVAL 3

struct otp_config* otp_conf;
struct keylist* klist;
struct kg_data* keygen;

/* Keygen data */
struct kg_data {
	PurpleAccount *owner; /* account that uses the keygen */
	const char *conv_name; /* name of the conversation where the comand was run */
	guint timer_handle; /* handle to remove the timer */
	gdouble status; /* in percent */
	gboolean updated; /* updates since last visit */
	struct otp* new_pad;
};


static void par_add_header(char** message)
/* adds the paranoia header */
{
	char* new_msg = g_strconcat(PARANOIA_HEADER, *message, NULL);
	g_free(*message);
	*message = new_msg;
	return;
}

static gboolean par_has_header(char** message)
/* checks for a paranoia header and removes it if found */
{
	/* cheap check for optimisation */
	if (g_str_has_prefix(*message, PARANOIA_HEADER_MARKER)) {
		if (g_str_has_prefix(*message, PARANOIA_HEADER)) {
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
	if (g_str_has_prefix(*message, "/me ")) {
		char* new_msg = g_strconcat("/me ", PARANOIA_STATUS, 
				*message+4, NULL);
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
	if (g_str_has_prefix(*message, PARANOIA_PREFIX)) {
		return TRUE;
	}
	return FALSE;
}

static char* par_strip_jabber_ressource(const char* acc)
/* Strips the Jabber ressource (/home /mobile etc.) */
{
	gchar** str_array = g_strsplit(acc, "/", 2);
	char* acc_copy = g_utf8_strdown (str_array[0], -1);
	g_strfreev(str_array);
	return acc_copy;
}

/* ----------------- Paranoia custom signal handlers ------------------ */

static void par_keygen_update_status(GObject *my_object, 
			gdouble percent, struct otp* alice_pad)
/* needed to save the keygen status by the keygen thread(s) */
{
	keygen->status = percent;
	
	if (alice_pad != NULL) {
		par_keylist_add_key(klist, alice_pad);
		keygen->new_pad = alice_pad;
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"New key %s->%s (%s) added to the key list.\n", 
				otp_pad_get_src(alice_pad), otp_pad_get_dest(alice_pad),
				otp_pad_get_id(alice_pad));
	}
	
	keygen->updated = TRUE;
	return;
}

static gboolean par_keygen_poll_result(void* data) 
/* checks for an updated keygen status and displays messages if needed */
{
	
	if(keygen->updated) {
		PurpleConversation* conv = purple_find_conversation_with_account (
				PURPLE_CONV_TYPE_IM, keygen->conv_name, keygen->owner);
		char* msg;
		
		if(keygen->new_pad == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"%5.2f percent of the key done.\n", keygen->status);
			if (conv) {
				/* write to conv if available */
				msg = g_strdup_printf(_("%5.2f percent of the key done."), keygen->status);
				purple_conversation_write(conv, NULL, msg,
					PURPLE_MESSAGE_NO_LOG, time(NULL));
				g_free(msg);
			}
		} else {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"100.0 percent of the key done.\n");
			if (conv) {
				/* write to conv if available */
				purple_conversation_write(conv, NULL, 
					_("Key generation completed successfully.\n"
					"Your own key is stored in the directory '~/.paranoia'.\n"
					"Your buddy's key is stored on your desktop.\n"
					"Please send the key on your desktop in a secure way to your partner."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			} else {
				/* show a nice pop-up */
				msg = g_strdup_printf(_("%s->%s (%s), %zu bytes\n\n"
						"Your own key is stored in the directory '~/.paranoia'.\n"
						"Your buddy's key is stored on your desktop.\n"
						"Please send the key on your desktop in a secure way to your partner."), 
						otp_pad_get_src(keygen->new_pad),
						otp_pad_get_dest(keygen->new_pad),
						otp_pad_get_id(keygen->new_pad),
						otp_pad_get_filesize(keygen->new_pad));
				purple_notify_info(NULL, _("Paranoia Key Generator"), 
						_("A new key pair has been created!"), msg);
				g_free(msg);
			}
			/* cleanup */
			purple_timeout_remove(keygen->timer_handle);
			g_free(keygen);
			return FALSE;
		}
		keygen->updated = FALSE;
	}
	return TRUE;
}

/* ----------------- Session Management ------------------ */

static gboolean par_session_send_request(const char* my_acc_name, 
			const char* receiver, PurpleConversation *conv)
/* sends an otp encryption request message */
{
	char* my_acc_name_copy = par_strip_jabber_ressource(my_acc_name);
	char* receiver_copy = par_strip_jabber_ressource(receiver);
	char *ids = par_keylist_search_ids(klist, my_acc_name_copy, receiver_copy);
	g_free(my_acc_name_copy);
	g_free(receiver_copy);
	
	if (ids == NULL) {
		return FALSE;
	}
	
	char *request = g_strdup_printf(PARANOIA_REQUEST, ids, PARANOIA_WEBSITE);
	g_free(ids);

	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), request, 
			PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW);
	
	free(request);
	return TRUE;
}


/* sends an otp acknowledge message */
static void par_session_send_ack(PurpleConversation *conv) 
{

	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), PARANOIA_ACK, 
		PURPLE_MESSAGE_SEND | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW);

	return;
}


static void par_session_send_close(PurpleConversation *conv)
/* sends an otp termination message */
{
	purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
			PARANOIA_EXIT, 
			PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_RAW);

	return;
}

static gboolean par_session_ack_timeout(gpointer a_key)
/* timout handler to send delayed ACK messages */
{
	struct key *my_key = (struct key *)a_key;
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "The ACK timeout passed.\n");
	if (my_key->conv) {
		par_session_send_ack(my_key->conv);
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "ACK message sent.\n");
	}
	
	return FALSE;
}

static gboolean par_session_check_req(const char* alice, const char* bob, 
		PurpleConversation *conv, char** message_no_header)
/* detects request messages and sets the key settings. 
 * Returns TRUE if a request was found.
 * */
{
	if (g_ascii_strncasecmp(*message_no_header, PARANOIA_REQUEST, 
			PARANOIA_REQUEST_LEN) == 0) {
		/* set the ptr to the first id */
		char* tmp_ptr = *message_no_header + PARANOIA_REQUEST_LEN + 2;
		struct key* temp_key = NULL;
		struct key* a_key = NULL;
		int totlen = strlen(*message_no_header);
		
		/* search for all requested IDs */
		while (*tmp_ptr != ':' && temp_key == NULL && totlen > tmp_ptr - *message_no_header) {
			char* id = g_strndup(tmp_ptr, OTP_ID_LENGTH);
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Searching for requested ID: %s\n", id);
			
			char* alice_copy = par_strip_jabber_ressource(alice);
			char* bob_copy = par_strip_jabber_ressource(bob);
			a_key = par_keylist_search_key_by_id(klist, id, alice_copy, bob_copy);
			g_free(alice_copy);
			g_free(bob_copy);
			if (a_key != NULL) {
				if (!a_key->opt->no_entropy) {
						temp_key = a_key;
				}
			}
			g_free(id);
			tmp_ptr += OTP_ID_LENGTH + 1;
		}
		if (temp_key != NULL) {
			/* here we have a matching key with entropy */
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"Found a matching ID with entropy: %s, active = TRUE\n",
					otp_pad_get_id(temp_key->pad));
			temp_key->opt->active = TRUE;
			if(temp_key->conv == NULL) {
				temp_key->conv = conv;
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Conversation pointer saved! (D).\n");
			}
			if (temp_key->opt->auto_enable) {
				temp_key->opt->otp_enabled = TRUE;
				purple_conversation_write(conv, NULL, 
						_("Encryption enabled."), 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"REQUEST checked: otp_enabled = TRUE.\n");
				/* Send an ACK message to confirm */
				/* There are cases where send an encrypted request and an ACK */
				purple_timeout_add_seconds(1, (GSourceFunc)par_session_ack_timeout, 
						(gpointer)temp_key);
			}
		} else {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"REQUEST failed! No key available.\n");
		}
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
	/* check prefix (optimisation) */
	if (!g_str_has_prefix(*message_decrypted, PARANOIA_PREFIX)) {
		return FALSE;
	}
	/* check ACK, START, STOP, EXIT and NO_ENTROPY */
	if (g_strcmp0(*message_decrypted, PARANOIA_ACK) == 0) {
		if(used_key->opt->auto_enable && !used_key->opt->handshake_done) {
			used_key->opt->otp_enabled = TRUE;
			used_key->opt->handshake_done = TRUE;
			purple_conversation_write(conv, NULL, 
					_("Encryption enabled."), PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"PARANOIA_ACK detected! otp_enabled=TRUE\n");
		} else {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"PARANOIA_ACK detected!\n");	
		}
		used_key->opt->active = TRUE;
		return TRUE;
	}
	if (g_strcmp0(*message_decrypted, PARANOIA_EXIT) == 0) {
		used_key->opt->otp_enabled = FALSE;
		purple_conversation_write(conv, NULL, 
				_("Encryption disabled (remote)."), 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_EXIT detected. otp_enabled = FALSE\n");
		return TRUE;
	}
	if (g_strcmp0(*message_decrypted, PARANOIA_START) == 0) {
		if(used_key->opt->auto_enable) {
			used_key->opt->otp_enabled = TRUE;
			purple_conversation_write(conv, NULL, 
					_("Encryption enabled (remote)."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"PARANOIA_START detected. otp_enabled = TRUE\n");
			/* if the other sider has an active key and we don't (FIXME maybe removeable in 0.4) */
			//if (!used_key->opt->active) {
			//	used_key->opt->active = TRUE;
			//}
		} else {
			purple_conversation_write(conv, NULL, 
					_("This buddy would like to chat encrypted."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		return TRUE;
	}
	if (g_strcmp0(*message_decrypted, PARANOIA_STOP) == 0) {
		used_key->opt->otp_enabled = FALSE;
		purple_conversation_write(conv, NULL, 
				_("Encryption disabled (remote)."), 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_STOP detected. otp_enabled = FALSE\n");
		return TRUE;
	}
	if (g_strcmp0(*message_decrypted, PARANOIA_NO_ENTROPY) == 0) {
		used_key->opt->otp_enabled = FALSE;
		used_key->opt->no_entropy = TRUE;
		used_key->opt->auto_enable = FALSE;
		used_key->opt->active = FALSE;
		/* We can't destroy our key too due to the msg injection problem. */
		purple_conversation_write(conv, NULL, 
				_("Your converstation partner is out of entropy. "
				"Encryption disabled (remote)."), 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"PARANOIA_NO_ENTROPY detected. otp_enabled = FALSE, active = FALSE\n");
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static void par_session_reset_conv(PurpleConversation *conv)
/* searches all pointers to conversations and resets them to NULL */
{	
	struct key* tmp_ptr = klist->head;

	while (tmp_ptr != NULL) { //keylist violation
		if (tmp_ptr->conv == conv) {
			tmp_ptr->conv = NULL;
			/* free the mmap of libotp */
			otp_pad_use_less_memory(tmp_ptr->pad);
		}
		tmp_ptr = tmp_ptr->next;
	}
}

/* ----------------- Paranoia CLI ------------------ */

PurpleCmdId par_cmd_id;

#define PARANOIA_HELP_STR _("Welcome to the One-Time Pad CLI.\n\
/otp help: shows this message \n\
/otp genkey &lt;size&gt; &lt;external entropy \
source&gt;: generates a key pair of &lt;size&gt; kiB\n\
/otp on: tries to enable the encryption\n\
/otp off: disables the encryption\n\
/otp info: shows details about the used key\n\
/otp list: shows all keys for this conversation\n\
/otp list-all: shows all available keys\n\
/otp reload: reloads all your key files")
#define PARANOIA_ERROR_STR _("Wrong argument(s). Type '/otp help' for help.")
#define PARANOIA_KEYSIZE_ERROR _("Your key size is too large.")

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
	const char* my_acc = purple_account_get_username(
				purple_conversation_get_account(conv));
	const char* other_acc = purple_conversation_get_name(conv);
	
	char* my_acc_copy = par_strip_jabber_ressource(my_acc);
	char* other_acc_copy = par_strip_jabber_ressource(other_acc);
	struct key* used_key = par_keylist_search_key(klist, my_acc_copy, other_acc_copy);
	g_free(my_acc_copy);
	g_free(other_acc_copy);
	
	if (used_key != NULL) {
		if (used_key->opt->no_entropy) {
			purple_conversation_write(conv, NULL, 
					_("Couldn't enable the encryption. No entropy available."),
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			return FALSE;
		}			
		if (!used_key->opt->otp_enabled) {
			used_key->opt->otp_enabled = TRUE;
			purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
					PARANOIA_START, 
					PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG);
			purple_conversation_write(conv, NULL, 
					_("Encryption enabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			return TRUE;
		} else {
			used_key->opt->auto_enable = TRUE;
			purple_conversation_write(conv, NULL, 
					_("Encryption already enabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			return TRUE;
		}			
	} else {
		if (par_session_send_request(my_acc, other_acc, conv)) {
			purple_conversation_write(conv, NULL, 
					_("Trying to enable encryption."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			return TRUE;
		} else {
			purple_conversation_write(conv, NULL, 
					_("Couldn't enable the encryption. No key available."),
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
	}
	return FALSE;
}

static gboolean par_cli_disable_enc(PurpleConversation *conv)
/* disables the encryption */
{
	const char* my_acc = purple_account_get_username(
				purple_conversation_get_account(conv));
	const char* other_acc = purple_conversation_get_name(conv);
	
	char* my_acc_copy = par_strip_jabber_ressource(my_acc);
	char* other_acc_copy = par_strip_jabber_ressource(other_acc);
	struct key* used_key = par_keylist_search_key(klist, my_acc_copy, other_acc_copy);
	g_free(my_acc_copy);
	g_free(other_acc_copy);
	
	if (used_key != NULL) {
		if (used_key->opt->otp_enabled) {
			purple_conv_im_send_with_flags (PURPLE_CONV_IM(conv), 
				PARANOIA_STOP, 
				PURPLE_MESSAGE_SYSTEM | PURPLE_MESSAGE_NO_LOG);
			used_key->opt->otp_enabled = FALSE;
			used_key->opt->auto_enable = FALSE;
			purple_conversation_write(conv, NULL, 
					_("Encryption disabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		} else {
			purple_conversation_write(conv, NULL, 
					_("Encryption already disabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		return TRUE;
	}
	
	purple_conversation_write(conv, NULL, 
		_("Couldn't disable the encryption. No key available."),
		PURPLE_MESSAGE_NO_LOG, time(NULL));
	return FALSE;
}

static void par_cli_show_key_details(PurpleConversation *conv)
/* shows information about the keys of a conversation */
{
	const char* my_acc = purple_account_get_username(
				purple_conversation_get_account(conv));
	const char* other_acc = purple_conversation_get_name(conv);
	
	char* my_acc_copy = par_strip_jabber_ressource(my_acc);
	char* other_acc_copy = par_strip_jabber_ressource(other_acc);
	struct key* used_key = par_keylist_search_key(klist, my_acc_copy, other_acc_copy);
	int num = par_keylist_count_matching_keys(klist, my_acc_copy, other_acc_copy);
	g_free(my_acc_copy);
	g_free(other_acc_copy);
	
	char* disp_string = NULL;

	if(used_key != NULL) {
		if (num == 1) {
			disp_string = g_strdup_printf(_("There is %i key available for this"
					" conversation.\nCurrently active key infos:\nSource:\t\t%s\n"
					"Destination:\t%s\nID:\t\t\t%s\nSize:\t\t\t%zu\n"
					"Position:\t\t%zu\n"
					"Entropy:\t\t%zu\n"
					"OTP enabled:\t%i\nAuto enable:\t%i\nNo entropy:\t%i"),
					num,
					otp_pad_get_src(used_key->pad), otp_pad_get_dest(used_key->pad), 
					otp_pad_get_id(used_key->pad), 
					otp_pad_get_filesize(used_key->pad), 
					otp_pad_get_position(used_key->pad), 
					otp_pad_get_entropy(used_key->pad), 
					used_key->opt->otp_enabled, used_key->opt->auto_enable, 
					used_key->opt->no_entropy);
		} else {
			disp_string = g_strdup_printf(_("There are %i keys available for this"
					" conversation.\nCurrently active key infos:\nSource:\t\t%s\n"
					"Destination:\t%s\nID:\t\t\t%s\nSize:\t\t\t%zu\n"
					"Position:\t\t%zu\n"
					"Entropy:\t\t%zu\n"
					"OTP enabled:\t%i\nAuto enable:\t%i\nNo entropy:\t%i"), 
					num,
					otp_pad_get_src(used_key->pad), otp_pad_get_dest(used_key->pad), 
					otp_pad_get_id(used_key->pad), 
					otp_pad_get_filesize(used_key->pad), 
					otp_pad_get_position(used_key->pad), 
					otp_pad_get_entropy(used_key->pad), 
					used_key->opt->otp_enabled, used_key->opt->auto_enable, 
					used_key->opt->no_entropy);
		}
	} else {
		if (num > 1) {
			disp_string = g_strdup_printf(_("There are %i keys available for this"
					" conversation, but none is active."), num);
		} else if (num == 1) {
			disp_string = g_strdup(_("There is one key available for this"
					" conversation, but it is not active."));
		} else {
			disp_string = g_strdup(_("There is no key available for this conversation."));
		}
	}
	purple_conversation_write(conv, NULL, disp_string, 
			PURPLE_MESSAGE_NO_LOG, time(NULL));
	g_free(disp_string);
	return;
}

static void par_cli_show_keys(PurpleConversation *conv, gboolean all)
/* shows all keys in the list */
{
	const char* src = purple_account_get_username(
				purple_conversation_get_account(conv));
	const char* dest = purple_conversation_get_name(conv);
	
	char* src_copy = par_strip_jabber_ressource(src);
	char* dest_copy = par_strip_jabber_ressource(dest);
	
	if (all) {
		purple_conversation_write(conv, NULL, _("All your keys:"), 
				PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_NO_LINKIFY, time(NULL));
	} else {
		purple_conversation_write(conv, NULL, _("All your keys for this conversation:"), 
				PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_NO_LINKIFY, time(NULL));
	}
	
	struct key* tmp_ptr = klist->head;
	char* nice_str;
	while (tmp_ptr != NULL) { //keylist violation
		if (all || ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src_copy) == 0) 
					&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest_copy) == 0))) {
			
			nice_str = g_strdup_printf(_("%s -> %s (%s)\n\tSize: %zu bytes, "
					"Bytes left: %zu Active: %i Enabled: %i\n"),
					otp_pad_get_src(tmp_ptr->pad), 
					otp_pad_get_dest(tmp_ptr->pad), 
					otp_pad_get_id(tmp_ptr->pad), 
					otp_pad_get_filesize(tmp_ptr->pad), 
					otp_pad_get_entropy(tmp_ptr->pad), 
					tmp_ptr->opt->active, 
					tmp_ptr->opt->otp_enabled);
					
			purple_conversation_write(conv, NULL, nice_str, 
					PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_NO_LINKIFY, time(NULL));
			g_free(nice_str);
		}
		tmp_ptr = tmp_ptr->next;
	}
	return;
}

static void par_cli_init_keygen(PurpleConversation* conv, int size, gchar** param_array)
/* starts the generation of two keyfiles */
{
	const char* my_acc = purple_account_get_username(
			purple_conversation_get_account(conv));
	const char* other_acc = purple_conversation_get_name(conv);
	
	char* my_acc_stp = par_strip_jabber_ressource(my_acc);
	char* other_acc_stp = par_strip_jabber_ressource(other_acc);
	OtpError syndrome;
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Key generation request received. my_acc: %s, other_acc: %s, size: %ikiB\n",
			my_acc_stp, other_acc_stp, size);

	if (param_array[1] == NULL) {
		/* default entropy source */
		syndrome = otp_generate_key_pair(
				otp_conf, my_acc_stp, other_acc_stp, 
				NULL,
				size*1024);
		
	} else {
		syndrome = otp_generate_key_pair(
				otp_conf, my_acc_stp, other_acc_stp,
				g_strstrip(param_array[1]),
				size*1024);
	}
	g_free(my_acc_stp);
	g_free(other_acc_stp);
	
	if (syndrome > OTP_WARN) {
		// TODO: tell the exact error
		purple_conversation_write(conv, NULL, 
				_("Key files could not be generated!"),
				PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Key files could not be generated! %.8X\n", syndrome);
	} else {
		purple_conversation_write(conv, NULL, 
				_("Key generation successfully started. This will take some "
				"minutes depending on the desired key length."),
				PURPLE_MESSAGE_NO_LOG, time(NULL));
		/* init and start polling for the result */
		keygen = (struct kg_data *) g_malloc(sizeof(struct kg_data));
		keygen->status = 0.0;
		keygen->updated = FALSE;
		keygen->owner = purple_conversation_get_account(conv);
		keygen->conv_name = purple_conversation_get_name(conv);
		keygen->timer_handle = purple_timeout_add_seconds(KEYGEN_POLL_INTERVAL, 
				(GSourceFunc)par_keygen_poll_result, NULL);
		keygen->new_pad = NULL;
		
		if (syndrome == OTP_OK) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"Generation of two entropy files of %ikiB size started.\n", size);
		} else {
			purple_conversation_write(conv, NULL,
					_("There was a warning issued!"), //TODO: wtf?
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"Generation of two entropy files of %ikiB size started with a warning! %.8X\n",
					size, syndrome);
		}
	}
	return;
}

static PurpleCmdRet par_cli_check_cmd(PurpleConversation *conv, 
		const gchar *cmd, gchar **args, gchar **error, void *data)
/* checks and executes all otp commads */
{
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"An otp command was received. Sweet!\n");
	
	if (args[0] == NULL) {
		par_cli_set_default_error(error);
		return PURPLE_CMD_RET_FAILED;
	}
	if(g_strcmp0("help", *args) == 0) {
		purple_conversation_write(conv, NULL, 
				PARANOIA_HELP_STR, 
				PURPLE_MESSAGE_NO_LOG, time(NULL));
	}
	else if (g_strcmp0("on", *args) == 0) {
		par_cli_try_enable_enc(conv);
	}
	else if (g_strcmp0("off", *args) == 0) {
		par_cli_disable_enc(conv);
	}
	else if (g_strcmp0("drop", *args) == 0) {
	// REMOVE ME (just for testing!)
		const char* my_acc = purple_account_get_username(
				purple_conversation_get_account(conv));
		const char* other_acc = purple_conversation_get_name(conv);
		
		char* my_acc_copy = par_strip_jabber_ressource(my_acc);
		char* other_acc_copy = par_strip_jabber_ressource(other_acc);
		struct key* used_key = par_keylist_search_key(klist, my_acc_copy, other_acc_copy);
		g_free(my_acc_copy);
		g_free(other_acc_copy);
		
		if (used_key != NULL) {
			if (used_key->opt->otp_enabled) {
				used_key->opt->otp_enabled = FALSE;
				purple_conversation_write(conv, NULL, 
						"Encryption disabled. (local and temporal)", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
			} else {
				purple_conversation_write(conv, NULL, 
						"Encryption already disabled.", 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
			}
		} else {
			purple_conversation_write(conv, NULL, 
					"Couldn't drop the encryption. No key available.",
					PURPLE_MESSAGE_NO_LOG, time(NULL));	
		}
	} // REMOVE ME end
	else if (g_strcmp0("info", *args) == 0) {
		par_cli_show_key_details(conv);
	}
	else if (g_strcmp0("list", *args) == 0) {
		par_cli_show_keys(conv, FALSE);
	}
	else if (g_strcmp0("list-all", *args) == 0) {
		par_cli_show_keys(conv, TRUE);
	}
	else if (g_strcmp0("reload", *args) == 0) {
		int old_count = par_keylist_count_keys(klist);
		par_keylist_reload(otp_conf, klist);
		char* msg = g_strdup_printf(_("Key list regenerated. Number of available "
					"keys: old list %i, new list %i."), // TODO: show added/removed number of keys
					old_count, par_keylist_count_keys(klist));
		purple_conversation_write(conv, NULL, msg, 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		g_free(msg);
	}
	else if (g_ascii_strncasecmp("genkey ", *args, 7) == 0) {
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
		}
		if (size <= 0) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
					"The size value is not a positive integer!\n");
			g_strfreev(param_array);
			par_cli_set_default_error(error);
			return PURPLE_CMD_RET_FAILED;
		}
		/* found a positive int, do it! */
		// FIXME: additional garbage after the int is just ignored(?)
		par_cli_init_keygen(conv, size, param_array);
		g_strfreev(param_array);
	} else { /* checked for 'genkey' */
		/* unknown arg */
		par_cli_set_default_error(error);
		return PURPLE_CMD_RET_FAILED;
	}
	return PURPLE_CMD_RET_OK;
}

/* ----------------- Siganl Handlers ------------------ */

static void par_conversation_created(PurpleConversation *conv)
/* signal handler for "conversation-created" */
{
	PurpleAccount* account = purple_conversation_get_account(conv);
	const char* my_acc_name = purple_account_get_username(account);
	const char* receiver = purple_conversation_get_name(conv);
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "REQ Debug: my_acc: %s, other_acc: %s\n", my_acc_name, receiver);
	
	/* check buddy status */
	PurplePresence *pres = purple_buddy_get_presence (
			purple_find_buddy (account, receiver));
	gboolean online = purple_presence_is_online (pres);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "This buddy, online == %i\n", online);
	
	char* my_acc_name_copy = par_strip_jabber_ressource(my_acc_name);
	char* receiver_copy = par_strip_jabber_ressource(receiver);
	struct key* active_key = par_keylist_search_key(klist, my_acc_name_copy, receiver_copy);
	g_free(my_acc_name_copy);
	g_free(receiver_copy);
	
	if (active_key != NULL) {
		/* display a nice message if already active */
		if (active_key->opt->otp_enabled) {
			purple_conversation_write(conv, NULL, 
					_("Encryption enabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		if (!active_key->opt->handshake_done && online) {
			/* send a request message (encrypted) */
			if(par_session_send_request(my_acc_name, receiver, conv)) {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"Matching key(s) found. REQUEST sent.\n");
			} else {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"Found no matching key. Won't sent REQUEST.\n");
			}
		}
	} else {
		/* send a request message */
		if (online) {
			if(par_session_send_request(my_acc_name, receiver, conv)) {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"Matching key(s) found. REQUEST sent.\n");
			} else {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"Found no matching key. Won't sent REQUEST.\n");
			}
		}
	}
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Conversation created.\n");
}

static void par_conversation_deleting(PurpleConversation *conv)
/* signal handler for "deleting-conversation" */
{
	/* cleanup all keys with this conversation */
	par_session_reset_conv(conv);
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Conversation deleted.\n");
}

static void par_buddy_signed_off(PurpleBuddy *buddy) 
/* signal handler for "buddy-signed-off" */
{
	const char* src_acc = purple_account_get_username(purple_buddy_get_account(buddy));
	const char* dest_acc = purple_buddy_get_name(buddy);
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"%s went offline.\n", dest_acc);
	
	/* reset all related keys */
	char* src_copy = par_strip_jabber_ressource(src_acc);
	char* dest_copy = par_strip_jabber_ressource(dest_acc);

	struct key* tmp_ptr = klist->head;

	while (tmp_ptr != NULL) { //keylist violation
		if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src_copy) == 0) 
					&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest_copy) == 0)) {
				/* notify enabled keys */
				if (tmp_ptr->conv != NULL && tmp_ptr->opt->otp_enabled) {
					purple_conversation_write(tmp_ptr->conv, NULL, 
						_("Encryption disabled."), 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				}
				// TODO: Maybe just reset active keys?
				par_key_reset(tmp_ptr);
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"Key %s options resetted.\n", otp_pad_get_id(tmp_ptr->pad));
			}
		tmp_ptr = tmp_ptr->next;
	}
	g_free(src_copy);
	g_free(dest_copy);
	return;
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
	
	OtpError syndrome;
	
	/* my account name, i.e. alice@jabber.org */
	const char* my_acc_name = purple_account_get_username(account);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"My account: %s\n", my_acc_name);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"I received a message from %s\n", *sender);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Recived Msg: %s\n", *message);

	// TODO: only strip all the (X)HTML crap on specific protocols (Jabber, MSN, ???)
	// detect the protcol id:
	// purple_account_get_protocol_id(account)

	char* tmp_message = g_strdup(purple_markup_strip_html(*message));
	char** stripped_message;
	stripped_message = &tmp_message;
	
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Stripped Msg: %s\n", *stripped_message);

	/* checks for the Paranoia Header and removes it if found */
	if (!par_has_header(stripped_message)) {
		if (par_session_check_req(my_acc_name, *sender, conv, 
				stripped_message)) {
			g_free(*stripped_message);
			return FALSE;
		}
		
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Unencrypted message received.\n");
		
		/* we received an unencrypted message -> disable the encryption */
		char* src_copy = par_strip_jabber_ressource(my_acc_name);
		char* dest_copy = par_strip_jabber_ressource(*sender);

		struct key* tmp_ptr = klist->head;
		
		while (tmp_ptr != NULL) { //keylist violation
			if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src_copy) == 0) 
						&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest_copy) == 0)) {
							
				// TODO: Maybe just check active keys?
				
				if (tmp_ptr->opt->otp_enabled) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Found an enabled key with ID: %s. otp_enabled = FALSE\n", 
							otp_pad_get_id(tmp_ptr->pad));
					tmp_ptr->opt->otp_enabled = FALSE;
					purple_conversation_write(conv, NULL, 
							_("Encryption disabled."), 
							PURPLE_MESSAGE_NO_LOG, time(NULL));
				}
			}
			tmp_ptr = tmp_ptr->next;
		}

		g_free(src_copy);
		g_free(dest_copy);
		
		/* free the jabber/msn strip! */
		g_free(*stripped_message);

		return FALSE;
	}

	/* apply jabber and header changes */
	g_free(*message);
	*message = *stripped_message;

	/* search in key list */
	struct key* used_key = NULL;
	char* recv_id = otp_id_get_from_message(otp_conf, *message);
	if (recv_id != NULL) {
		char* my_acc_name_copy = par_strip_jabber_ressource(my_acc_name);
		char* sender_copy = par_strip_jabber_ressource(*sender);
		used_key = par_keylist_search_key_by_id(klist, recv_id, my_acc_name_copy, sender_copy);
		g_free(my_acc_name_copy);
		g_free(sender_copy);
		g_free(recv_id);
	}

	if (used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found a matching key with ID: %s\n", otp_pad_get_id(used_key->pad));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		/* save conversation ptr */
		if (used_key->conv == NULL) {
			used_key->conv = conv;
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Conversation pointer saved! (B)\n");
		}

#ifdef NO_OTP
		// DISABLE LIBOTP
#else
		// ENABLE LIBOTP
		syndrome = otp_decrypt(used_key->pad, message);
		if (syndrome > OTP_WARN) {
			purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
					"Could not decrypt the message! This is a serious error! %.8X\n", syndrome);
			/* notify the user */
			*flags = *flags | PURPLE_MESSAGE_ERROR;
			g_free(*message);
			*message = g_strdup(_("The last incoming message could not be decrypted. This is a serious error!"));
			return FALSE;
		} else {
			if (syndrome != OTP_OK) {
				purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
						"Message decrypted but there was a warning! %.8X\n", syndrome);
				// TODO: Warn the user?
			}
			if (syndrome == OTP_WARN_MSG_CHECK_COMPAT) {
				purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
						"Info: The message was not checked for consitency since your buddy uses 0.2\n");
			} else if (syndrome == OTP_WARN_MSG_CHECK_FAIL) {
				purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
						"Warning: The consistency check of the next message failed!\n");
				purple_conversation_write(conv, NULL, 
						_("The consistency check of the next message failed!"), 
						PURPLE_MESSAGE_NO_LOG | PURPLE_MESSAGE_ERROR, time(NULL));
			}
		}
#endif

		/* detect START, STOP and EXIT message */
		if (par_session_check_msg(used_key, message, conv)) {
			return TRUE;
		}
		
		/* activate this key? */
		if(!used_key->opt->handshake_done) {
			used_key->opt->handshake_done = TRUE;
			used_key->opt->active = TRUE;
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Key Activated! active and handshake_done are now TRUE;\n");
		}

		/* (Auto) enable the encryption? */
		if (!used_key->opt->otp_enabled && used_key->opt->auto_enable) {
			used_key->opt->otp_enabled = TRUE;
			purple_conversation_write(conv, NULL, 
					_("Encryption enabled."), 
					PURPLE_MESSAGE_NO_LOG, time(NULL));
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "This conversation was already initialized! otp_enabled is now TRUE\n");
			/* detect REQUEST; needed for a auto-init (was encryptet, TODO: maybe replaceble with ACK) */
			if(g_ascii_strncasecmp(*message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "He sends us an encrypted REQUEST message. otp_enabled is now TRUE\n");
				return TRUE;
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
	OtpError syndrome;

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"My account: %s\n", my_acc_name);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"I want to send a message to %s\n", receiver);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Original Msg: %s\n", *message);

	/* search in key list for a matching or initialised key */
	char* my_acc_name_copy = par_strip_jabber_ressource(my_acc_name);
	char* receiver_copy = par_strip_jabber_ressource(receiver);
	struct key* used_key = par_keylist_search_key(klist, my_acc_name_copy, receiver_copy);
	g_free(my_acc_name_copy);
	g_free(receiver_copy);

	if (used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Found an active key with pad ID: %s\n", otp_pad_get_id(used_key->pad));
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		/* encryption enabled? */
		if (!used_key->opt->otp_enabled) {
			purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Encryption not enabled!\n");
			return;
		}

		/* check for remaining entropy */
		// TODO 0.4 first try to encrypt and act afterwards (?)
		if (otp_pad_get_entropy(used_key->pad) < ENTROPY_LIMIT) {
			if (otp_pad_get_entropy(used_key->pad) < strlen(*message) 
						+ otp_conf_get_random_msg_tail_max_len(otp_conf)) {
				used_key->opt->no_entropy = TRUE;
				used_key->opt->otp_enabled = FALSE;
				used_key->opt->auto_enable = FALSE;
				used_key->opt->active = FALSE;
				purple_conversation_write(used_key->conv, NULL, 
						_("All your entropy has been used. Encryption disabled. "
						"The last message could not be sent."), 
						PURPLE_MESSAGE_NO_LOG, time(NULL));
				// TODO: display the message in the msg too and hide the real one
				/* delete the remaining entropy */
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
						"You have not enough entropy! no_entropy = TRUE\n");
				syndrome = otp_pad_erase_entropy(used_key->pad);
				if (syndrome == OTP_OK) {
					purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
							"Remaining entropy erased!\n");
					if (syndrome <= OTP_WARN) {
						purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
								"Warning erasing entropy! %.8X\n", syndrome);
					} else {
						purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
								"Error while erasing entropy! %.8X\n", syndrome);
					}
				}
				/* delete message and send no entropy msg */
				g_free(*message);
				*message = g_strdup(PARANOIA_NO_ENTROPY);
				
				syndrome = otp_encrypt_warning(used_key->pad, message, 0);
				if (syndrome > OTP_WARN) {
					purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
							"Could not send an entropy warning. This is a serious error! %.8X\n", syndrome);
				// TODO: notify the user?
				} else {
					if (syndrome != OTP_OK) {
						purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
								"Entropy warning sent but there was a warning! %.8X\n", syndrome);
					}
				}
				
				par_add_header(message);
				return;
			} else {
				// TODO: send an entropy warning (with timer)
				char *warning_msg = g_strdup_printf (
						_("Your entropy is low! %zu bytes left."),
						otp_pad_get_entropy(used_key->pad));
				purple_conversation_write(used_key->conv, NULL, 
						warning_msg, PURPLE_MESSAGE_NO_LOG, time(NULL));
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "%s\n", warning_msg);
				g_free(warning_msg);
			}
		}
		

#ifdef NO_OTP
		// DISABLE LIBOTP
#else
		// ENABLE LIBOP
		
		syndrome = otp_encrypt(used_key->pad, message);
		if (syndrome > OTP_WARN) {
			purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
					"Could not encrypt the message. This is a serious error! %.8X\n", syndrome);
			/* notify the user */
			purple_conversation_write(used_key->conv, NULL, 
						_("The last outgoing message could not be encrypted. "
						"This is a serious error!"), 
						PURPLE_MESSAGE_ERROR, time(NULL));
			return;
		} else {
			if (syndrome != OTP_OK) {
				purple_debug(PURPLE_DEBUG_ERROR, PARANOIA_ID, 
						"Message encrypted but there was a warning! %.8X\n", syndrome);
			}
		}
#endif
		/* add the paranoia header string */
		par_add_header(message);

		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"Encoded Msg: %s\n", *message);

	} else {
	
		purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
				"No active key found. Won't encrypt.\n");
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
		char* my_acc_copy = par_strip_jabber_ressource(
					purple_account_get_username(account));
		char* who_copy = par_strip_jabber_ressource(who);
		used_key = par_keylist_search_key(klist, my_acc_copy, who_copy);
		g_free(my_acc_copy);
		g_free(who_copy);
		
		if ( used_key != NULL) {
			if (used_key->conv == NULL) {
				used_key->conv = conv;
				purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Conversation pointer saved! (C)\n");
			}
		}
	}

#ifdef CENSORSHIP

	char* stripped_message = g_strdup(purple_markup_strip_html(*message));

	if (g_ascii_strncasecmp(stripped_message, PARANOIA_REQUEST, PARANOIA_REQUEST_LEN) == 0) {
		if (flags & PURPLE_MESSAGE_SEND) {
			/* hide outgoing session init messages */
			g_free(stripped_message);
			return TRUE;
		} else {
			/* session init message cosmetics */
			g_free(*message);
			*message = g_strndup(stripped_message, PARANOIA_REQUEST_LEN);
			g_free(stripped_message);
			return FALSE;
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
			if (used_key->opt->otp_enabled) {
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
	char* otp_path = g_strconcat(home, PARANOIA_PATH, NULL);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Otp path: %s\n", otp_path);
	
#ifdef USEDESKTOP
	const char *desktoppath = g_get_user_special_dir(G_USER_DIRECTORY_DESKTOP);
#else
	const char *desktoppath = g_get_home_dir();
#endif
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Export path: %s\n", desktoppath);
	
	/* Create global libotp config */
	otp_conf = otp_conf_create(PARANOIA_ID, otp_path, desktoppath, 1);
	g_free (otp_path);

	/* get the conversation handle */
	void *conv_handle = purple_conversations_get_handle();
	
	/* get the buddy list handle */
	void* blist_handle = purple_blist_get_handle();

	/* setup the key list */
	klist = par_keylist_init(otp_conf);
	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, 
			"Key list of %i keys created.\n", par_keylist_count_keys(klist));
	
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
	purple_signal_connect(blist_handle, "buddy-signed-off", plugin, 
			PURPLE_CALLBACK(par_buddy_signed_off), NULL);
			
	otp_signal_connect(otp_conf, "keygen-status-update", &par_keygen_update_status);

	/* register commands ("/otp" + a string of args) */
	par_cmd_id = purple_cmd_register ("otp", "s", PURPLE_CMD_P_DEFAULT,
			PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, NULL, 
			PURPLE_CMD_FUNC(par_cli_check_cmd), 
			_("otp &lt;command&gt: type /otp to get help"), NULL);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Plugin loaded.\n");
	
	return TRUE;
}

gboolean plugin_unload(PurplePlugin *plugin)
/* gets called when disabling the plugin */
{
	/* send PARANOIA_EXIT to all open conversations */
	struct key* key_ptr = klist->head;
	while (key_ptr != NULL) { // keylist violation
		if (key_ptr->conv != NULL) {
			par_session_send_close(key_ptr->conv);
		}
		key_ptr = key_ptr->next;
	}
	/* disconnect all signals */
	purple_signals_disconnect_by_handle(plugin);
	
	/* unregister command(s) */
	purple_cmd_unregister(par_cmd_id);

	/* free the key list */
	par_keylist_free(klist);

	/* destoy libotp config */
	otp_conf_destroy(otp_conf);

	purple_debug(PURPLE_DEBUG_INFO, PARANOIA_ID, "Plugin unloaded.\n");
	return TRUE;
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
    NULL, /* set in plugin_init due to translation */ /* plugin name */
    PARANOIA_VERSION,           /* version */
    NULL, /* set in plugin_init due to translation */
							/* This is the summary of your plugin.  It
                                   should be a short little blurb.  The UI
                                   determines where, if at all, to display
                                   this. */
    NULL, /* set in plugin_init due to translation */
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


static void plugin_init(PurplePlugin *plugin)
/* gets called when libpurple probes the plugin */
{
#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif /* ENABLE_NLS */
    info.name        = _("One-Time Pad Encryption");
    info.summary     = _("Paranoia One-Time Pad Encryption Plugin");
    info.description = _("The Paranoia plugin allows you to encrypt your messages with one-time pads.");

	return;
}

PURPLE_INIT_PLUGIN(paranoia, plugin_init, info)
