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

// ----------------- Paranoia Key Management ------------------

// TODO: set global key folder
// g_get_home_dir()

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
struct key* HELP_make_key(const char* src, const char* dest, const char* id) {

	static struct key* key;
   	key = (struct key *)malloc(sizeof(struct key));

	// a test otp object
	static struct otp* test_pad;
   	test_pad = (struct otp *)malloc(sizeof(struct otp));

	//a test option struct
	static struct options* test_opt;
   	test_opt = (struct options *)malloc(sizeof(struct options));

	key->pad = test_pad;
	key->opt = test_opt;
	key->next = NULL;

	char* test_src;
	test_src = (char *) malloc((strlen(src) + 1) * sizeof(char));
	strcpy(test_src, src);

	char* test_dest;
	test_dest = (char *) malloc((strlen(dest) + 1) * sizeof(char));
	strcpy(test_dest, dest);

	char* test_id;
	test_id = (char *) malloc((strlen(id) + 1) * sizeof(char));
	strcpy(test_id, id);

	key->pad->src = test_src;
	key->pad->dest = test_dest;
	key->pad->id = test_id;
	key->pad->size = 1024;

	return key;
}



// loads all available keys from the global otp folder into the keylist
static gboolean par_init_key_list() {
	
	// just a test TODO: read from files!
	struct key* test_key1 = NULL;
	test_key1 = HELP_make_key("simon.wenner@gmail.com", "nowic@swissjabber.ch", "AAAAAAAA");

	keylist = test_key1;

	struct key* test_key2 = NULL;
	test_key2 = HELP_make_key("alexapfel@swissjabber.ch", "alexapfel@swissjabber.ch", "BBBBBBBB");
	test_key1->next = test_key2;

	struct key* test_key3 = NULL;
	test_key3 = HELP_make_key("simon.wenner@gmail.com", "alexapfel@swissjabber.ch", "CCCCCCCC");
	test_key2->next = test_key3;

	struct key* test_key4 = NULL;
	test_key4 = HELP_make_key("simon.wenner@gmail.com", "simon.wenner@gmail.com", "DDDDDDDD");
	test_key3->next = test_key4;

	struct key* test_key5 = NULL;
	test_key5 = HELP_make_key("simon.wenner@gmail.com", "alexapfel@gmail.com", "EEEEEEEE");
	test_key4->next = test_key5;

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Key list generated! YEEHAAA!\n");

	return TRUE;
}

// frees all memory of the keylist
static gboolean par_free_key_list() {

	return TRUE;
}

// searches a key in the keylist, ID is optional, if no ID: searches first src/dest match
static struct key* par_search_key(const char* src, const char* dest, const char* id) {

	// strip the jabber resource from src (/home etc.)
	const char d[] = "/";
	char *src_copy, *token;
     
	src_copy = strdup(src);   // Make writable copy.
	token = strsep(&src_copy, d);
	printf("paranoia !!!!!!!!!!:\tResource remover: my_acc\t%s\n", token);
	
	if(token != NULL) {
		src = token;
		free(src_copy);
	}

	// strip the jabber resource from dest (/home etc.)
	char *dest_copy;
     	token = NULL;

	dest_copy = strdup(dest);   // Make writable copy.
	token = strsep(&dest_copy, d);
	printf("paranoia !!!!!!!!!!:\tResource remover: other_acc\t%s\n", token);
	
	if(token != NULL) {
		dest = token;
		free(dest_copy);
	}

	// ---- end stripping -----


	struct key* tmp_ptr = keylist;

	while(!(tmp_ptr == NULL)) {
	// possible edless loop! make sure the last otp->next == NULL
		if ((strcmp(tmp_ptr->pad->src, src) == 0) && (strcmp(tmp_ptr->pad->dest, dest) == 0)) {
			// TODO: add ID check
			return tmp_ptr;
		}
		tmp_ptr = tmp_ptr->next;
	}

	return NULL;
}

// lists all keys in the im window for a certain src/dest combination 
static gboolean par_list_keys(const char* src, const char* dest) {

	return FALSE;
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

	// TODO: if an other plugin destroyed the message
	//if ((message == NULL) || (*message == NULL)) {
	//	return TRUE;
	//}

	// some vars
	const char* my_acc_name = purple_account_get_username(account);

	// TODO: detect jabber? or any protcol id
	// purple_account_get_protocol_id(account)

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "My account: %s\n", purple_account_get_username(account));
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "I received a message from %s\n", *sender);
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Rcv.Msg: %s\n", *message);

	// search in Key list
	struct key* used_key = NULL;
	used_key = par_search_key(my_acc_name, *sender, NULL);

	// DEBUG
	if(used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found a matching Key with pad ID: %s\n", used_key->pad->id);
	} else {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found NO matching Key.\n");
	}
	// DEBUG end

	// Strip all the HTML crap (Jabber)
//Jabber: <html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>hi</body></html>
	// TODO: does that hurt?
	// TODO: only strip if ist is encryptet!!! Otherwise we loose links ect...
	char *stripped_message = purple_markup_strip_html(*message);
	char *tmp_message = (char *) malloc((strlen(stripped_message) + 1) * sizeof(char));
	strcpy(tmp_message, stripped_message);

	g_free(*message);

	*message = tmp_message;

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Stripped Msg: %s\n", *message);

	// TODO: check key options

	// TODO: remove the paranoia header string

#ifdef REALOTP
	// ENABLE LIBOTP
	otp_decrypt(NULL, message);
#else

	aaaa_decrypt(message);
#endif

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Dec.Msg: %s\n", *message);

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

	// search in Key list, TODO: strip jabber ressources from own account (in search fn?)
	struct key* used_key = NULL;
	used_key = par_search_key(my_acc_name, receiver, NULL);

	// DEBUG
	if(used_key != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found a matching Key with pad ID: %s\n", used_key->pad->id);
	} else {
		purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Found NO matching Key.\n");
	}
	// DEBUG end

	// TODO: check key options

#ifdef REALOTP
	// ENABLE LIBOTP
	otp_encrypt(NULL, message);
#else
	
	aaaa_encrypt(message);
#endif

	// TODO: add a paranoia header string

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Enc.Msg: %s\n", *message);

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
