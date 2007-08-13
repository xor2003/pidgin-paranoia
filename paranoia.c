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

// GNOMElib
#include <glib.h>

// GNUlibc stuff
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>

extern char *stpncpy (char *restrict, const char *restrict, size_t);

// libpurple
#define PURPLE_PLUGINS
#include "notify.h"
#include "plugin.h"
#include "version.h"
#include "signals.h"
#include "debug.h"
// commands
#include "cmds.h"
//debug only:
#include "core.h"

// great stuff
#include "libotp.h"

#ifdef HAVE_CONFIG_H
#include "paranoia_config.h"
#endif

// ----------------- General Paranoia Stuff ------------------
#define PARANOIA_HEADER "*** Encrypted with the Pidgin-Paranoia plugin: "
#define PARANOIA_PATH "/.paranoia"

/* adds the paranoia header */
void par_add_header(char** message) {

	char* new_msg = (char *) malloc((strlen(*message) + strlen(PARANOIA_HEADER) + 1) * sizeof(char));
	strcpy(new_msg, PARANOIA_HEADER);
	strcat(new_msg, *message);

	free(*message);
	*message = new_msg;
	//printf("paranoia:\t\tHeader+Message:\t%s\n", *message);
	return;
}

/* checks the header and removes it if found */
static gboolean par_remove_header(char** message) {
	if(strlen(*message) > strlen(PARANOIA_HEADER)) {
		if(strncmp(*message, PARANOIA_HEADER, strlen(PARANOIA_HEADER)) == 0) {
			char* new_msg = (char *) malloc((strlen(*message) - strlen(PARANOIA_HEADER) + 1) * sizeof(char));
			char* ptr = *message + strlen(PARANOIA_HEADER);
			strcpy(new_msg, ptr);

			free(*message);
			*message = new_msg;
			//printf("paranoia:\t\tMessage only:\t%s\n", *message);
			return TRUE;
		}	
	}
	return FALSE;
}

// ----------------- Paranoia Key Management ------------------

// needs to be reseted for every chat session
struct options {
	gboolean asked; // already asked for plugin support?
	gboolean has_plugin; // the result
	gboolean otp_enabled; // on/off
	gboolean auto_enable; // needed to be able to force disable
	gboolean no_entropy; // if it is used completely: TRUE
};

// paranoia key struct (a linked list)
struct key {
	struct otp* pad; // an otp struct
	struct options* opt; // key options
	struct key* next;
};

// paranoia keylist pointer
struct key* keylist = NULL;


// ----------------- Test Functions (should be removed) --------------------------
struct key* HELP_make_key(const char* filename) {

	// a test otp object
	static struct otp* test_pad;
   	test_pad = otp_get_from_file(filename);

	//a test option struct
	static struct options* test_opt;
   	test_opt = (struct options *) malloc(sizeof(struct options));
	test_opt->asked = TRUE; // shoud be FALSE
	test_opt->has_plugin = TRUE; // shoud be FALSE
	test_opt->otp_enabled = FALSE;
	test_opt->auto_enable = TRUE;
	test_opt->no_entropy = FALSE;

	static struct key* key;
   	key = (struct key *) malloc(sizeof(struct key));
	key->pad = test_pad;
	key->opt = test_opt;
	key->next = NULL;

	return key;
}



// loads all available keys from the global otp folder into the keylist
static gboolean par_init_key_list() {
	
	// just a test TODO: read from files!
	struct key* test_key1 = NULL;
	test_key1 = HELP_make_key("simon.wenner@gmail.com simon.wenner@gmail.com 01010101.otp"); // nowic loop

	keylist = test_key1;

	struct key* test_key2 = NULL;
	test_key2 = HELP_make_key("alexapfel@swissjabber.ch alexapfel@swissjabber.ch 02020202.otp"); //chri loop
	test_key1->next = test_key2;

	struct key* test_key3 = NULL;
	test_key3 = HELP_make_key("simon.wenner@gmail.com alexapfel@swissjabber.ch 03030303.otp");
	test_key2->next = test_key3;

	struct key* test_key4 = NULL;
	test_key4 = HELP_make_key("alexapfel@swissjabber.ch simon.wenner@gmail.com 04040404.otp");
	test_key3->next = test_key4;

	struct key* test_key5 = NULL;
	test_key5 = HELP_make_key("simon.wenner@gmail.com alexapfel@gmail.com 05050505.otp");
	test_key4->next = test_key5;

	struct key* test_key6 = NULL;
	test_key6 = HELP_make_key("alexapfel@gmail.com simon.wenner@gmail.com 06060606.otp");
	test_key5->next = test_key6;

	struct key* test_key7 = NULL;
	test_key7 = HELP_make_key("76239710 76239710 07070707.otp"); //nowic loop
	test_key6->next = test_key7;

	struct key* test_key8 = NULL;
	test_key8 = HELP_make_key("112920906 112920906 08080808.otp"); //chri loop
	test_key7->next = test_key8;

	struct key* test_key9 = NULL;
	test_key9 = HELP_make_key("76239710 112920906 09090909.otp"); //nowic->chri
	test_key8->next = test_key9;

	struct key* test_key10 = NULL;
	test_key10 = HELP_make_key("112920906 76239710 10101010.otp"); //chri->nowic
	test_key9->next = test_key10;

	struct key* test_key11 = NULL;
	test_key11 = HELP_make_key("alexapfel@gmail.com alexapfel@swissjabber.ch 11111111.otp"); //chri->chri
	test_key10->next = test_key11;

	struct key* test_key12 = NULL;
	test_key12 = HELP_make_key("alexapfel@swissjabber.ch alexapfel@gmail.com 12121212.otp"); //chri->chri
	test_key11->next = test_key12;

	struct key* test_key13 = NULL;
	test_key13 = HELP_make_key("fredibraatsmaal@hotmail.com fredibraatsmaal@hotmail.com 13131313.otp"); //chri->chri
	test_key12->next = test_key13;

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Key list generated! YEEHAAA!\n");

	return TRUE;
}

// frees all memory of the keylist
static gboolean par_free_key_list() {

	// TODO
	return TRUE;
}

// searches a key in the keylist, ID is optional, if no ID: searches first src/dest match
static struct key* par_search_key(const char* src, const char* dest, const char* id) {

	// TODO only for jabber?
	// strip the jabber resource from src (/home /mobile etc.)
	const char d[] = "/";
	char *src_copy, *token;
     
	src_copy = strdup(src);   // Make writable copy.
	token = strsep(&src_copy, d);
	//printf("paranoia !!!!!!!!!!:\tResource remover: my_acc\t%s\n", token);
	
	if(token != NULL) {
		src = token;
		free(src_copy);
	}

	// strip the jabber resource from dest (/home /mobile etc.)
	char *dest_copy;
     	token = NULL;

	dest_copy = strdup(dest);   // Make writable copy.
	token = strsep(&dest_copy, d);
	//printf("paranoia !!!!!!!!!!:\tResource remover: other_acc\t%s\n", token);
	
	if(token != NULL) {
		dest = token;
		free(dest_copy);
	}

	// ---- end stripping -----


	struct key* tmp_ptr = keylist;

	while(!(tmp_ptr == NULL)) {
	// possible edless loop! make sure the last otp->next == NULL
		if ((strcmp(tmp_ptr->pad->src, src) == 0) && (strcmp(tmp_ptr->pad->dest, dest) == 0) 
			&& !tmp_ptr->opt->no_entropy) {
			//  check ID too?
			if (id == NULL) {
				// takes the first matching key, any id
				return tmp_ptr;
			} else {
				//takes the exact key
				if (strcmp(tmp_ptr->pad->id, id) == 0) {
					return tmp_ptr;
				}
			}
		}
		tmp_ptr = tmp_ptr->next;
	}

	return NULL;
}

// lists all keys in the im window for a certain src/dest combination 
static gboolean par_list_keys(const char* src, const char* dest) {

	// TODO
	return FALSE;
}

static gboolean par_ask_for_plugin(struct key* used_key) {

	return TRUE;
}

static gboolean par_check_for_plugin_request(char** message_no_header) {

	return TRUE;
}

static gboolean try_to_enable_enc(struct key* used_key) {

	return TRUE;
}

static gboolean disable_enc(struct key* used_key) {

	return TRUE;
}

// ----------------- Paranoia CLI ------------------

PurpleCmdId otp_cmd_id;

#define OTP_HELP_STR "Welcome to the One-Time Pad CLI.\notp help: shows this message \notp genkey &lt;size&gt;: generates a key pair of &lt;size&gt; MB\notp start: tries to start the encryption\notp stop: stops the encryption\notp keys: lists all available keys"

#define OTP_ERROR_STR "Wrong argument(s). Type '/otp help' for help."

/* sets the default paranoia cli error */
static void set_default_cli_error(gchar **error) {
	char *tmp_error = (char *) malloc((strlen(OTP_ERROR_STR) + 1) * sizeof(char));
	strcpy(tmp_error, OTP_ERROR_STR);
	free(*error);
	*error = tmp_error;
	return;
}

/* otp commads check function */
static PurpleCmdRet par_check_command(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data) {

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "the otp command was recived! sweet!\n");

	if(args[0] == NULL){
		// no arguments
		set_default_cli_error(error);
		return PURPLE_CMD_RET_FAILED;
	}
	else {
		if(strcmp("help", *args) == 0){
			// otp help
			//HELP: void purple_conversation_write (PurpleConversation *conv, const char *who, const char *message, PurpleMessageFlags flags, time_t mtime)
			purple_conversation_write(conv, NULL, OTP_HELP_STR, PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		else if(strncmp("genkey ", *args, 7) == 0){
			// otp genkey

			//skip "genkey "
			*args += 7;
			int size;
         		// Parse it
			errno = 0;
         		size = strtol(*args, 0, 0);
         		// overflow detection
			if (errno){
				// OVERFLOW!
				// TODO: Display a special error?
				// debug
				purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "The size value caused an int overflow!\n");
				set_default_cli_error(error);
				return PURPLE_CMD_RET_FAILED;

			} else {
				// integer detection
				if (size <= 0) {
					// no positive integer found!
					// debug
					purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "The size value is not a positive int!\n");
					set_default_cli_error(error);
					return PURPLE_CMD_RET_FAILED;
				} else {
					// found a positive int -> DO IT!
					// FIXME: additional garbage is just ignored
					// FIXME: size limit?
					purple_conversation_write(conv, NULL, "This should generate two key files.", PURPLE_MESSAGE_NO_LOG, time(NULL));
					// debug
					purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Generate two otp files of %d MB size.\n", (gint) size);
				}
			}

		}
		else if(strcmp("start", *args) == 0){
			// otp start
			purple_conversation_write(conv, NULL, "This should start the encryption.", PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		else if(strcmp("stop", *args) == 0){
			// otp stop
			purple_conversation_write(conv, NULL, "This should stop the encryption.", PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		else if(strcmp("keys", *args) == 0){
			// otp keys
			purple_conversation_write(conv, NULL, "This should list all available keys.", PURPLE_MESSAGE_NO_LOG, time(NULL));
		}
		// TODO: add more commands
		else {
			// unknown arg
			set_default_cli_error(error);
			return PURPLE_CMD_RET_FAILED;
		}
	}

	return PURPLE_CMD_RET_OK;
}


// ----------------- Siganl Handlers ------------------

/* ---- signal handler for "receiving-im-msg" ---- */
static gboolean par_receiving_im_msg(PurpleAccount *account, char **sender,
                             char **message, PurpleConversation *conv,
                             PurpleMessageFlags *flags) {

	// if an other plugin destroyed the message
	if ((message == NULL) || (*message == NULL)) {
		return TRUE;
	}

	// my account name, alice@jabber.org
	const char* my_acc_name = purple_account_get_username(account);

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "My account: %s\n", purple_account_get_username(account));
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "I received a message from %s\n", *sender);
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Rcv.Msg: %s\n", *message);

	// --- Strip all the HTML crap (Jabber) ---
	// TODO: does that hurt?
	// TODO: only strip, if jabber or msn or ???
	// HELP: To detect the protcol id:
	// purple_account_get_protocol_id(account)

	const char *tmp_message = purple_markup_strip_html(*message);
	char* the_message = (char *) malloc((strlen(tmp_message) + 1) * sizeof(char));
	strcpy(the_message, tmp_message);

	char** stripped_message;
	stripped_message = &the_message;
	
	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Stripped Msg: %s\n", *stripped_message);

	// TODO: disable encryption if active key is found and unencrypted message received

	// --- checks for the Paranoia Header ---
	// and removes it if found
	if(!par_remove_header(stripped_message)) {

		// free the jabber strip!
		g_free(*stripped_message);
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "This is not a paranoia message.\n");
		return FALSE;
	}

	// apply jabber and header changes
	g_free(*message);
	*message = *stripped_message;

	// get ID from message
	char* recv_id = otp_get_id_from_message(message);

	// search in Key list
	struct key* used_key = par_search_key(my_acc_name, *sender, recv_id);

	// Key in key list?
	if(used_key != NULL) {
		// debug
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found a matching Key with pad ID: %s\n", used_key->pad->id);
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		// encryption not enabled?
		if (!used_key->opt->otp_enabled) {
			//can I activate an encrypted conversation too?
			if (used_key->opt->has_plugin && used_key->opt->auto_enable) {
				used_key->opt->otp_enabled = TRUE;
				purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "This conversation was already initialized! otp_enabled is now TRUE\n");
			} else {
				purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "He sends us an encrypted message, but has no plugin? strange!\n");
				// TODO: enable it anyway?
			}
		}

#ifdef REALOTP
		// ENABLE LIBOTP
		otp_decrypt(used_key->pad, message);
#else
		// Test function
		aaaa_decrypt(message);
#endif

		// debug
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Dec.Msg: %s\n", *message);

	} else {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found NO matching Key. Couldn't decrypt.\n");
	}

	return FALSE; // TRUE drops the msg!
}




/* ---- signal handler for "sending-im-msg" ---- */
void par_sending_im_msg(PurpleAccount *account, const char *receiver,
                             char **message) {

	// some vars
	const char* my_acc_name = purple_account_get_username(account);

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "My account: %s\n", my_acc_name);
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "I want to send a message to %s\n", receiver);
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Orig Msg: %s\n", *message);

	// search in Key list
	struct key* used_key = par_search_key(my_acc_name, receiver, NULL);

	// Key in key list?
	if(used_key != NULL) {
		// debug
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found a matching Key with pad ID: %s\n", used_key->pad->id);
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "otp_enabled == %i\n", used_key->opt->otp_enabled);

		// encryption enabled?
		if (!used_key->opt->otp_enabled) {
			//TODO: initialize an encrypted conversation. already asked?
			purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "This conversation was not initialized! otp_enabled == FALSE. But we encrypt it anyway...(FIXME) \n");		
			//return; DISABLED FOR TESTING ONLY
		}

		// TODO: check for remaining entropy

#ifdef REALOTP
		// ENABLE LIBOTP
		otp_encrypt(used_key->pad, message);
#else
		// Test function
		aaaa_encrypt(message);
#endif

		// add the paranoia header string
		par_add_header(message);

		// debug
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Enc.Msg: %s\n", *message);

	} else {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found NO matching Key. Won't encrypt.\n");
	}

	return;
}






/* ---- signal handler for "writing-im-msg", needed to change the displayed msg ---- */
static gboolean par_change_displayed_msg(PurpleAccount *account, const char *who,
                           char **message, PurpleConversation *conv,
                           PurpleMessageFlags flags) {

	// TODO: add "<secure>" to the message

	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "WritMsg: %s\n", *message);
	// debug
	//purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "wrote msg, here we could do usefull stuff.\n");

	//TRUE if the message should be canceled, or FALSE otherwise.
	return FALSE;
}


/* gets called when loading the plugin */
static gboolean plugin_load(PurplePlugin *plugin) {
	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID,
		"Compiled with Purple '%d.%d.%d', running with Purple '%s'.\n",
		PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, PURPLE_MICRO_VERSION, purple_core_get_version());

	// set the global key folder
	const gchar* home = g_get_home_dir();
	char* global_otp_path = (char *) malloc((strlen(home) + strlen(PARANOIA_PATH) + 1) * sizeof(char));
	strcpy(global_otp_path, (char*) home);
	strcat(global_otp_path, PARANOIA_PATH);

	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Key Path: %s\n", global_otp_path);

	// stuff I don't understand yet TODO: read doc!
	void *conv_handle;
	conv_handle = purple_conversations_get_handle();


	// Setup the Key List
	par_init_key_list();

	// connect to signals
	// HELP: gulong purple_signal_connect (void *instance, const char *signal, void *handle, PurpleCallback func, void *data)
	purple_signal_connect(conv_handle, "receiving-im-msg", plugin,
		PURPLE_CALLBACK(par_receiving_im_msg), NULL);
	purple_signal_connect(conv_handle, "sending-im-msg", plugin,
		PURPLE_CALLBACK(par_sending_im_msg), NULL);
	/* purple_signal_connect(conv_handle, "writing-im-msg", plugin,
		PURPLE_CALLBACK(par_change_displayed_msg), NULL); */

	// register command(s)
	// "/otp" + a string of args
	otp_cmd_id = purple_cmd_register ("otp", "s", PURPLE_CMD_P_DEFAULT,
		PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, NULL, PURPLE_CMD_FUNC(par_check_command), 
		"otp &lt;command&gt: type /otp to get help", NULL);

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "done loading\n");
	
	return TRUE;
}

/* gets called when disabling the plugin */
gboolean plugin_unload(PurplePlugin *plugin) {

	// Disconnect all signals
	purple_signals_disconnect_by_handle(plugin);
	
	// unregister command(s)
	purple_cmd_unregister(otp_cmd_id);

	// TODO: free key list

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "done unloading\n");

	return TRUE;
}

/* gets called when libpurple probes the plugin. */
static void init_plugin(PurplePlugin *plugin)
{
	// TODO: needed?
}


// ----------------- Plugin definition & init ------------------

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,    /* Plugin magic, this must be PURPLE_PLUGIN_MAGIC. */
    PURPLE_MAJOR_VERSION,   /* This is also defined in libpurple. */
    PURPLE_MINOR_VERSION,   /* See previous */
    PURPLE_PLUGIN_STANDARD, /* PurplePluginType: There are 4 different
                                   values for this field.  The first is
                                   PURPLE_PLUGIN_UNKNOWN, which should not be
                                   used.  The second is PURPLE_PLUGIN_STANDARD;
                                   this is the value most plugins will use.
                                   Next, we have PURPLE_PLUGIN_LOADER; this is
                                   the type you want to load if your plugin
                                   is going to make it possible to load non-
                                   native plugins.  For example, the Perl and
                                   Tcl loader plugins are of this type.
                                   Last, we have PURPLE_PLUGIN_PROTOCOL.  If
                                   your plugin is going to allow the user to
                                   connect to another network, this is the
                                   type you'd want to use.
                                 */
    NULL,                   /* This field is the UI requirement.  If you're
                                   writing a core plugin, this must be NULL
                                   and the plugin must not contain any UI
                                   code.  If you're writing a Pidgin plugin,
                                   you need to use PIDGIN_PLUGIN_TYPE.  If you
                                   are writing a Finch plugin, you would use
                                   FINCH_PLUGIN_TYPE.
                                 */
    0,                      /* This field is for plugin flags.  Currently,
                                   the only flag available to plugins is
                                   invisible (PURPLE_PLUGIN_FLAG_INVISIBLE).
                                   It causes the plugin to NOT appear in the
                                   list of plugins.
                                 */
    NULL,                   	/* This is a GList of plugin dependencies. */
    PURPLE_PRIORITY_DEFAULT,	/* This is the priority libpurple with give your
                                   plugin.  There are three possible values
                                   for this field, PURPLE_PRIORITY_DEFAULT,
                                   PURPLE_PRIORITY_HIGHEST, and
                                   PURPLE_PRIORITY_LOWEST
                                 */

    OTP_ID,     		/* plugin id */
    "One-Time Pad Encryption",         /* plugin name */
    OTP_VERSION,                /* version */

    "One-Time Pad Encryption Plugin",   /* This is the summary of your plugin.  It
                                   should be a short little blurb.  The UI
                                   determines where, if at all, to display
                                   this.
                                 */
    "One-Time Pad Encryption Plugin. Bla bla... TODO",   /* This is the description of your plugin. It
                                   can be as long and as descriptive as you
                                   like.  And like the summary, it's up to the
                                   UI where, if at all, to display this (and
                                   how much to display).
                                 */
    OTP_AUTHORS,		/* name and e-mail address */
    OTP_WEBSITE,		/* website */

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

    NULL,                   /* This is a pointer to a UI-specific struct.
                                   For a Pidgin plugin it will be a pointer to a
                                   PidginPluginUiInfo struct, for example.
                                 */
    NULL,                   /* This is a pointer to either a 
                                   PurplePluginLoaderInfo struct or a
                                   PurplePluginProtocolInfo struct.
                                 */
    NULL,                   /* This is a pointer to a PurplePluginUiInfo
                                   struct.  It is a core/ui split way for
                                   core plugins to have a UI configuration
                                   frame.  You can find an example of this
                                   code in:
                                     libpurple/plugins/pluginpref_example.c
                                 */
    NULL,                    /* Finally, the last member of the structure
                                   is a function pointer where you can define
                                   "plugin actions".  The UI controls how
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
