/*
 * Pidgin-Paranoia Libotp Tester Application - Useful for the development of libotp.
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

/* --------------------------- Note -----------------------------------
 * This is a test application for libotp and the keygen.
 * */

/* GNOMElib */
#include <glib.h>
#include <glib-object.h>
#include <glib/gstdio.h>

/* GNUlibc stuff */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

//#define USEDESKTOP
/* Requires GNOMElib 2.14! Bob's
 * keyfile is placed onto the desktop. If not set, the
 * file is placed in the home directory.*/

/* great stuff */
#include "../libotp.h"
#include "../libotp-internal.h"

#define LINE "-----------------------------------------------------------------------\n"
#define PARANOIA_PATH "otptester-keys"
#define DESKTOP_PATH "otptester-desktop"

gboolean verbose = FALSE;
gboolean results = FALSE;
gchar **pmessage;
gchar **pwarning;
gchar *startmessage = "Bruce Schneier can crack a one-time pad before it's used.";
gchar *startwarning = "%!()!%paranoia noent";
gchar **palice;
gchar **pbob;
gchar **palicefile = NULL;
gchar **pbobfile = NULL;
gint genkeysize = 1000;
gchar *source = NULL;
struct otp_config* config;
gboolean block_genkey = TRUE;
struct otp* encryptpad = NULL;
struct otp* decryptpad = NULL;

/* Signal */
static void keygen_update_status(GObject *my_object, gdouble percent, struct otp* a_pad)
{
	if (results) 
		g_printf(" + %5.0f/%u bytes (%5.2f %%) of the key done\n", percent*genkeysize/100, genkeysize, percent);
	else
		if (verbose) 
			g_printf(" * %5.2f percent of the key done\n", percent);

	if ( percent >= 100.0 ) {

		if (a_pad != NULL) {
			if (encryptpad != NULL) otp_pad_destroy(encryptpad);
			encryptpad = a_pad;
			if (*pbobfile != NULL) g_free(*pbobfile);
			*pbobfile = g_strconcat(otp_pad_get_dest(encryptpad), FILE_DELI, otp_pad_get_src(encryptpad), FILE_DELI, otp_pad_get_id(encryptpad), FILE_SUFFIX_DELI, FILE_SUFFIX, NULL);
			gchar *fullbobfile = g_strconcat(otp_conf_get_export_path(config), PATH_DELI, *pbobfile, NULL);
			gchar *newbobfile = g_strconcat(otp_conf_get_path(config), PATH_DELI,  *pbobfile, NULL);
			g_printf("%s %s\n", fullbobfile, newbobfile);
			g_rename(fullbobfile, newbobfile);
			g_free(fullbobfile);
			g_free(newbobfile);
			block_genkey = FALSE;
		}
	}
	return;
}


/* Prepare */
OtpError create_config() 
{
	g_printf("------------------------- Create Config -------------------------------------\n");
	config = otp_conf_create("otptester", 
			PARANOIA_PATH, DESKTOP_PATH, 1);
	otp_signal_connect(config, 
			SIGNALNAME, &keygen_update_status);
	return OTP_OK;
}

/* Clean Up */
OtpError destroy_config() 
{
	g_printf("------------------------- Destroy Config -------------------------------------\n");
	OtpError syndrome;
	if (encryptpad != NULL) 
		otp_pad_destroy(encryptpad);
	if (decryptpad != NULL)
		otp_pad_destroy(decryptpad);
	syndrome = otp_conf_destroy(config);
	if (syndrome > OTP_WARN)
		g_printf(" ! freeing config       : %.8X\n",syndrome);
	return syndrome;
}

/* Simple Operations */
OtpError genkey() 
{
	g_printf("------------------------- Genkey -------------------------------------\n");
	if ( verbose ) {
		g_printf(" * Alice                : '%s'\n", *palice);
		g_printf(" * Bob                  : '%s'\n", *pbob);
		g_printf(" * Sourcefile           : '%s'\n", (source == NULL? "<using keygen>" : source));
		g_printf(" * Keysize to generate  : %i\n", genkeysize);
		g_printf(" * Keypath              : '%s'\n",otp_conf_get_path(config));
		g_printf(" * Exportpath:          : '%s'\n",otp_conf_get_export_path(config));
	}
	OtpError syndrome;
	syndrome = otp_generate_key_pair(config,
			*palice, *pbob,
			source, genkeysize);
	if (syndrome > OTP_WARN) {
		g_printf(" ! genkey              : %.8X\n",syndrome);
	} else
		if ( verbose && syndrome >  OTP_OK) 
				g_printf(" * Syndrome             : %.8X\n",syndrome);
				
	while (block_genkey) usleep(1000*100);

	block_genkey = TRUE;
	
	if (verbose) {
			g_printf(" * Pad:    Pos          : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_position(encryptpad));
			g_printf(" * Pad:    Entropy      : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_entropy(encryptpad));
			g_printf(" * Pad:    src          : '%s'\n",otp_pad_get_src(encryptpad));
			g_printf(" * Pad:    dest         : '%s'\n",otp_pad_get_dest(encryptpad));
			g_printf(" * Pad:    id           : '%s'\n",otp_pad_get_id(encryptpad));
			g_printf(" * Pad:    filesize:    : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_filesize(encryptpad));
		}
	if (results) g_printf(" + Key generated       : '%s'\n", otp_pad_get_filename(encryptpad));

	
	return syndrome;
}

OtpError encrypt() 
{
	g_printf("------------------------- Encrypt -------------------------------------\n");
	if (encryptpad == NULL) {
		encryptpad = otp_pad_create_from_file(config, *palicefile);
		if (encryptpad == NULL) {
			g_printf(" ! create pad from '%s'\n",*palicefile);
			return OTP_ERR_OTPTESTER;
		}
		if (verbose) {
			g_printf(" * Pad:    Filename     : '%s'\n",otp_pad_get_filename(encryptpad));
			g_printf(" * Pad:    Pos          : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_position(encryptpad));
			g_printf(" * Pad:    Entropy      : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_entropy(encryptpad));
			g_printf(" * Pad:    src          : '%s'\n",otp_pad_get_src(encryptpad));
			g_printf(" * Pad:    dest         : '%s'\n",otp_pad_get_dest(encryptpad));
			g_printf(" * Pad:    id           : '%s'\n",otp_pad_get_id(encryptpad));
			g_printf(" * Pad:    filesize:    : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_filesize(encryptpad));
		}
	}
	OtpError syndrome = otp_encrypt(encryptpad, pmessage);
	if (syndrome > OTP_WARN) {
		g_printf(" ! encrypt              : %.8X\n",syndrome);
		g_printf(" * Message              : '%s'\n", *pmessage);
	} else {
		if ( verbose && syndrome >  OTP_OK) 
				g_printf(" * Syndrome             : %.8X\n",syndrome);
		if (results) g_printf(" + Message              : '%s'\n", *pmessage);
	}
	return syndrome;
}


OtpError warning_encrypt()
{
	g_printf("------------------------- Encrypt warning -------------------------------------\n");
	if (encryptpad == NULL) {
		encryptpad = otp_pad_create_from_file(config, *palicefile);
		if (encryptpad == NULL) {
			g_printf(" ! create pad from '%s'\n",*palicefile);
			return OTP_ERR_OTPTESTER;
		}
		if (verbose) {
			g_printf(" * Pad:    Filename     : '%s'\n",otp_pad_get_filename(encryptpad));
			g_printf(" * Pad:    Pos          : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_position(encryptpad));
			g_printf(" * Pad:    Entropy      : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_entropy(encryptpad));
			g_printf(" * Pad:    src          : '%s'\n",otp_pad_get_src(encryptpad));
			g_printf(" * Pad:    dest         : '%s'\n",otp_pad_get_dest(encryptpad));
			g_printf(" * Pad:    id           : '%s'\n",otp_pad_get_id(encryptpad));
			g_printf(" * Pad:    filesize:    : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_filesize(encryptpad));
		}
	}
	OtpError syndrome = otp_encrypt_warning(encryptpad, pwarning,0);
	if (syndrome > OTP_WARN) {
		g_printf(" ! encrypt              : %.8X\n",syndrome);
		g_printf(" * Warning              : '%s'\n", *pwarning);
	} else {
		if ( verbose && syndrome >  OTP_OK) 
				g_printf(" * Syndrome             : %.8X\n",syndrome);
		if (results) g_printf(" + Warning              : '%s'\n", *pwarning);
	}
	return syndrome;
}

OtpError decrypt() 
{
	g_printf("------------------------- Decrypt -------------------------------------\n");
	if (decryptpad == NULL) {
		decryptpad = otp_pad_create_from_file(config, *pbobfile);
		if (decryptpad == NULL) {
			g_printf(" ! create pad from '%s'\n",*pbobfile);
			return OTP_ERR_INPUT;
		}
		if (verbose) {
			g_printf(" * Pad:    Filename     : '%s'\n",otp_pad_get_filename(decryptpad));
			g_printf(" * Pad:    Pos          : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_position(decryptpad));
			g_printf(" * Pad:    Entropy      : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_entropy(decryptpad));
			g_printf(" * Pad:    src          : '%s'\n",otp_pad_get_src(decryptpad));
			g_printf(" * Pad:    dest         : '%s'\n",otp_pad_get_dest(decryptpad));
			g_printf(" * Pad:    id           : '%s'\n",otp_pad_get_id(decryptpad));
			g_printf(" * Pad:    filesize:    : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_filesize(decryptpad));
		}
	}
	OtpError syndrome = otp_decrypt(decryptpad, pmessage);
	if (syndrome > OTP_WARN) {
		g_printf(" ! decrypt              : %.8X\n",syndrome);
		g_printf(" * Message              : '%s'\n", *pmessage);
	} else {
		if ( verbose && syndrome >  OTP_OK) 
				g_printf(" * Syndrome             : %.8X\n",syndrome);
		if (results) g_printf(" + Message              : '%s'\n", *pmessage);
	}
	return syndrome;
}

OtpError erasekey()
{
	g_printf("------------------------- Erasekey -------------------------------------\n");
	if (encryptpad == NULL) {
		encryptpad = otp_pad_create_from_file(config, *palicefile);
		if (encryptpad == NULL) {
			g_printf(" ! create pad from '%s'\n",*palicefile);
			return OTP_ERR_OTPTESTER;
		}
		if (verbose) {
			g_printf(" * Pad:    Filename     : '%s'\n",otp_pad_get_filename(encryptpad));
			g_printf(" * Pad:    Pos          : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_position(encryptpad));
			g_printf(" * Pad:    Entropy      : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_entropy(encryptpad));
			g_printf(" * Pad:    src          : '%s'\n",otp_pad_get_src(encryptpad));
			g_printf(" * Pad:    dest         : '%s'\n",otp_pad_get_dest(encryptpad));
			g_printf(" * Pad:    id           : '%s'\n",otp_pad_get_id(encryptpad));
			g_printf(" * Pad:    filesize:    : %" G_GSIZE_FORMAT "\n",
					otp_pad_get_filesize(encryptpad));
		}
	}
	OtpError syndrome = otp_pad_erase_entropy(encryptpad);
	if (syndrome > OTP_WARN) {
		g_printf(" ! erasekey            : %.8X\n",syndrome);
	} else {
		if ( verbose && syndrome >  OTP_OK) 
				g_printf(" * Syndrome             : %.8X\n",syndrome);
	}
	return syndrome;
}

/* Tests */
OtpError usekeyup() 
{
	g_printf("------------------------- Test: Use key up -------------------------------------\n");
	OtpError syndrome = OTP_OK;
	while ( TRUE ) {
		syndrome = encrypt();
		if (syndrome > OTP_WARN) break;
		syndrome = decrypt();
		if ((syndrome > OTP_WARN) || (strcmp(startmessage, *pmessage) != 0)) break;
	}
	if (syndrome == OTP_ERR_KEY_EMPTY) {
		g_printf(" @ Key is empty, sending signal ...\n");
		syndrome = warning_encrypt();
		if (syndrome < OTP_WARN) {
			g_free(*pmessage);
			pmessage = pwarning;
			syndrome = decrypt();
			if ((syndrome < OTP_WARN) && (strcmp(startwarning, *pmessage) == 0) )  {
				g_printf(" @ Signal sent, destroying key ...\n");
				syndrome = erasekey();
				if (syndrome < OTP_WARN) 
					g_printf(" @ Key is used up!\n");
				} else {
					g_printf(" ! sending signal!\n");
					syndrome = OTP_ERR_OTPTESTER;
				}
			}
		}
	g_free(*pmessage);
	*pmessage = g_strdup(startmessage);
	g_free(*pwarning);
	*pwarning = g_strdup(startwarning);
	return syndrome;
}

OtpError genusekeyup() {
	if ( genkey() > OTP_WARN ) return 1;
	if (usekeyup() > OTP_WARN) return 1;
	return OTP_OK;
}


OtpError testlibotp()
{
	
	
	return OTP_OK;
}

/* Done */
void test_done() 
{
	g_printf("------------------------- Done ---------------------------------------\n");
}

int main(int argc, gchar *argv[])
{
	gchar *alice = "alice@jabber.org";
	gchar *bob = "bob@jabber.org";
	gchar *alicefile = NULL;
	gchar *bobfile = NULL;
	gchar *commands = NULL;
	gboolean doalltests = FALSE;
	gboolean dousekeyup = FALSE;
	gboolean dogenusekeyup = FALSE;
	
	GOptionEntry values[] = {
			{ "source", 0, 0, G_OPTION_ARG_STRING, &source, "The name of the source file for keygeneration", "filename" },
			{ "alice", 0, 0, G_OPTION_ARG_STRING, &alice, "The name of alice", "string"},
			{ "bob", 0, 0, G_OPTION_ARG_STRING, &bob, "The name of bob", "string"},
			{ "alicefile", 0, 0, G_OPTION_ARG_STRING, &alicefile, "The filename of alice's key", "filename"},
			{ "bobfile", 0, 0, G_OPTION_ARG_STRING, &bobfile, "The filename of bob's key", "filename"},
			{ "keysize", 0, 0, G_OPTION_ARG_INT, &genkeysize, "Generate a key with size N bytes", "N" },
			{ "message", 0, 0, G_OPTION_ARG_STRING, &startmessage, "The message to encrypt/decrypt", "message"},
			{ NULL }
	};
	
	GOptionEntry flags[] = {
			{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
			{ "results", 'r', 0, G_OPTION_ARG_NONE, &results, "Show results", NULL },
			{ NULL }
	};
	
	GOptionEntry simple[] = {
			{ "commands", 0, 0, G_OPTION_ARG_STRING, &commands, "A list of simple operations\n\
\tg : generate key\n\
\te : encrypt\n\
\tw : encrypt warning\n\
\td : decrypt\n\
\tk : erase key\
","string" },
			{ NULL }
	};
	
	GOptionEntry tests[] = {
			{ "alltests", 0, 0, G_OPTION_ARG_NONE, &doalltests, "Run all tests" },
			{ "usekey", 0, 0, G_OPTION_ARG_NONE, &dousekeyup, "Use the key up" },
			{ "genusekey", 0, 0, G_OPTION_ARG_NONE, &dogenusekeyup, "Generate, Use the key up" },
			{ NULL }
	};
	GOptionContext *ctx;

	ctx = g_option_context_new("- OtpTester");
	g_option_context_add_main_entries(ctx, values, "example1");
	g_option_context_add_main_entries(ctx, simple, "example1");
	g_option_context_add_main_entries(ctx, tests, "example1");
	g_option_context_add_main_entries(ctx, flags, "example1");
	g_option_context_parse(ctx, &argc, &argv, NULL);
	g_option_context_free(ctx);
	
/* Values */

	pmessage = g_malloc(sizeof(gchar*));
	*pmessage = g_strdup(startmessage);
	pwarning = g_malloc(sizeof(gchar*));
	*pwarning = g_strdup(startwarning);
	
	palice = &alice;
	pbob = &bob;
	palicefile = &alicefile;
	pbobfile = &bobfile;

/* Verbose */

	if (verbose) {
		g_printf(" * Message              : '%s'\n", *pmessage);
	}

/* Prepare */
	if (create_config() > OTP_WARN )
		return 1;
	
	
/* Simple operations */
	int c=0;
	while(commands != NULL && commands[c] != 0) {
		gchar command = commands[c];
		//g_printf("\t'commands[%d]' == '%c'\n", c, command);
		
		if ( command == 'g' ) 
			if ( genkey() > OTP_WARN ) return 1;
			
		if ( command == 'w' )
			if ( warning_encrypt() > OTP_WARN ) return 1;
			
		if ( command == 'e' )
			if ( encrypt() > OTP_WARN ) return 1;
			
		if ( command == 'd' )
			if ( decrypt() > OTP_WARN ) return 1;
			
		if ( command == 'k' )
			if ( erasekey() > OTP_WARN ) return 1;
		c++;
	}
		
/* Tests */
	if (doalltests) {
		dousekeyup = TRUE;
	}
	if (dousekeyup) 
		if ( usekeyup() > OTP_WARN )
			return 1;
			
	if (dogenusekeyup) 
		if ( genusekeyup() > OTP_WARN )
			return 1;
	
/* Clean up */
	if ( destroy_config() > OTP_WARN )
		return 1;
	
/* Done */
	test_done();
	return 0;
}
