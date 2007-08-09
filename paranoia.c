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

// set global key folder
// g_get_home_dir()

// needs to be reseted for every chat session
struct options {
	gboolean asked; // already asked for plugin support?
	gboolean has_plugin; // the result
	gboolean otp_enabled; // on/off
	gboolean auto_enable; // needed to be able to force disable
};

// paranoia key struct (a linked list)
struct key {
	struct otp* pad; // an otp struct
	struct options* opt; // key options
	struct key* next;
};

// paranoia keylist pointer
struct key* keylist = NULL;

// loads all available keys from the global otp folder into the keylist
static gboolean generate_key_list() {

	//REM: a test option struct
	struct options {
		gboolean asked; 
		gboolean has_plugin; 
		gboolean otp_enabled; 
		gboolean auto_enable; 
	} *test_opt;

	test_opt->asked = FALSE;
	test_opt->has_plugin = FALSE;
	test_opt->otp_enabled = FALSE;
	test_opt->auto_enable = TRUE;

	//REM: make a test key struct
	struct key {
		struct otp* pad; 
		struct options* opt;
		struct key* next;
	} *test_key1;

	test_key1->pad = NULL;
	test_key1->opt = test_opt;
	test_key1->next = NULL;

	//keylist = test_key1;

	return TRUE;
}

// frees all memory of the keylist
static gboolean free_key_list() {

	return TRUE;
}

// searches a key in the keylist
static struct key* search_key(char* account, char* id) {

	return NULL;
}

// ----------------- Paranoia CLI ------------------

PurpleCmdId otp_cmd_id;

#define OTP_HELP_STR "Welcome to the One-Time Pad CLI.\notp help: shows this message \notp genkey &lt;size&gt;: generates a key pair of &lt;size&gt; MB\notp start: tries to start the encryption\notp stop: stops the encryption\notp keys: lists all available keys"

#define OTP_ERROR_STR "Wrong argument(s). Type '/otp help' for help."

/* sets the default otp cli error */
static void set_default_cli_error(gchar **error) {
	char *tmp_error = (char *) malloc((strlen(OTP_ERROR_STR) + 1) * sizeof(char));
	strcpy(tmp_error, OTP_ERROR_STR);
	free(*error);
	*error = tmp_error;
	return;
}

/* otp commads check function */
static PurpleCmdRet OTP_check_command(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data) {

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

/* signal handler for "receiving-im-msg" */
static gboolean OTP_receiving_im_msg(PurpleAccount *account, char **sender,
                             char **message, PurpleConversation *conv,
                             PurpleMessageFlags *flags) {

	// TODO: many many checks!

	// TODO: remove the paranoia string

#ifdef REALOTP
	// ENABLE LIBOTP
	otp_decrypt(NULL, message);
#else

	aaaa_decrypt(message);
#endif

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "received a message!!! we should decrypt it.\n");
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Dec.Msg: %s\n", *message);

	return FALSE; // TRUE drops the msg!
}

/* signal handler for "sending-im-msg" */
static gboolean OTP_sending_im_msg(PurpleAccount *account, char **sender,
                             char **message, PurpleConversation *conv,
                             PurpleMessageFlags *flags) {
	// TODO: many many checks!


#ifdef REALOTP
	// ENABLE LIBOTP
	otp_encrypt(NULL, message);
#else
	
	aaaa_encrypt(message);
#endif

	// TODO: add a paranoia string

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "we want to send a message!!! we should encrypt it.\n");	
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "Enc.Msg: %s\n", *message);

	return FALSE; // TRUE drops the msg!
}

/* signal handler for "writing-im-msg", needed to change the displayed msg 
static gboolean OTP_change_displayed_msg(PurpleAccount *account, char **sender,
                             char **message, PurpleConversation *conv,
                             PurpleMessageFlags *flags) {

	// TODO: add "<secure>" to the message

	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID, "wrote msg, here we could do usefull stuff.\n");

	//TRUE if the message should be canceled, or FALSE otherwise.
	return FALSE;
}
*/

/* gets called when loading the plugin */
static gboolean plugin_load(PurplePlugin *plugin) {
	// debug
	purple_debug(PURPLE_DEBUG_INFO, OTP_ID,
		"Compiled with Purple '%d.%d.%d', running with Purple '%s'.\n",
		PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION, PURPLE_MICRO_VERSION, purple_core_get_version());

	// stuff I don't understand yet TODO: read doc!
	void *conv_handle;
	conv_handle = purple_conversations_get_handle();

	// connect to signals
	// HELP: gulong purple_signal_connect (void *instance, const char *signal, void *handle, PurpleCallback func, void *data)
	purple_signal_connect(conv_handle, "receiving-im-msg", plugin,
		PURPLE_CALLBACK(OTP_receiving_im_msg), NULL);
	purple_signal_connect(conv_handle, "sending-im-msg", plugin,
		PURPLE_CALLBACK(OTP_sending_im_msg), NULL);
	/* purple_signal_connect(conv_handle, "writing-im-msg", plugin,
		PURPLE_CALLBACK(OTP_change_displayed_msg), NULL); */

	// register command(s)
	// "/otp" + a string of args
	otp_cmd_id = purple_cmd_register ("otp", "s", PURPLE_CMD_P_DEFAULT,
		PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS, NULL, PURPLE_CMD_FUNC(OTP_check_command), 
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
