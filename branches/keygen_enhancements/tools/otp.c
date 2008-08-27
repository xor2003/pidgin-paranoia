/*
 * Pidgin-Paranoia OTP CLI Application
 * Copyright (C) 2008  Christian Wäckerlin
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
 * This is the commandline client
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

/* great stuff */
#include "../libotp.h"
#include "../libotp-internal.h"
#include "../key_management.h"

#define LINE "-----------------------------------------------------------------------\n"
#define PARANOIA_PATH "otptester-keys"
#define DESKTOP_PATH "otptester-desktop"

gboolean verbose = FALSE;
struct otp_config* config;
struct key* keylist = NULL;



/* Signal */
static void key_generation_done(GObject *my_object, gdouble percent, struct otp* a_pad) 
{
	return;
}

/* Prepare */
OtpError create_config() 
{
	g_printf("------------------------- Create Config -------------------------------------\n");
	config = otp_conf_create("otptester", 
			PARANOIA_PATH, DESKTOP_PATH, 1);
	otp_signal_connect(config, 
			"keygen_key_done_signal", &key_generation_done);
	par_init_key_list(config);
	return OTP_OK;
}



/* Clean Up */
OtpError destroy_config() 
{
	g_printf("------------------------- Destroy Config -------------------------------------\n");
	OtpError syndrome;
	syndrome = otp_conf_destroy(config);
	if (syndrome > OTP_WARN)
		g_printf(" ! freeing config       : %.8X\n",syndrome);
	return syndrome;
}


int main(int argc, gchar *argv[])
{
//	GOptionEntry values[] = {
//		{ NULL }
//	};
	
	GOptionEntry flags[] = {
			{ "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
			{ NULL }
	};
	
	GOptionContext *ctx;

	ctx = g_option_context_new("- OTP");
//	g_option_context_add_main_entries(ctx, values, "example1");
	g_option_context_add_main_entries(ctx, flags, "example1");
	g_option_context_parse(ctx, &argc, &argv, NULL);
	g_option_context_free(ctx);
	
/* Values */

/* Verbose */

	if (verbose) {
		g_printf("I am verbose!\n");
	}
	

/* Prepare */
	if (create_config() > OTP_WARN )
		return 1;
	
	if (verbose) {
		g_printf("Keys: %u\n", par_count_keys());
	}
/* Clean up */
	if ( destroy_config() > OTP_WARN )
		return 1;
	
/* Done */
	return 0;
}
