/*
 * Pidgin-Paranoia Plug-in - Encrypts your messages with a one-time pad.
 * Copyright (C) 2008  Simon Wenner
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
#include <glib/gstdio.h>

/* Our stuff */
#include "libotp.h"
#include "key_management.h"

/* ----------------- Paranoia Key Management ------------------ */

struct key* par_key_create(const char* filename, struct otp_config* otp_conf)
/* creates a key struct from a valid key file or returns NULL */
{
	/* get otp object */
	static struct otp* a_pad;
	a_pad = otp_pad_create_from_file(otp_conf, filename);

	if(a_pad == NULL) {
		return NULL;
	}

	/* default option struct */
	static struct options* a_opt;
	a_opt = (struct options *) g_malloc(sizeof(struct options));
	a_opt->otp_enabled = FALSE;
	a_opt->auto_enable = TRUE;
	a_opt->handshake_done = FALSE;
	a_opt->active = FALSE;
	if(otp_pad_get_entropy(a_pad) <= 0) {
		a_opt->no_entropy = TRUE;
	} else {
		a_opt->no_entropy = FALSE;
	}

	static struct key* key;
	key = (struct key *) g_malloc(sizeof(struct key));
	key->pad = a_pad;
	key->opt = a_opt;
	key->conv = NULL;
	key->next = NULL;
	return key;
}

void par_key_reset(struct key* a_key) 
/* resets all option values of a key to default */
{
	a_key->opt->otp_enabled = FALSE;
	a_key->opt->auto_enable = TRUE;
	a_key->opt->handshake_done = FALSE;
	a_key->opt->active = FALSE;
	if(otp_pad_get_entropy(a_key->pad) <= 0) {
		a_key->opt->no_entropy = TRUE;
	} else {
		a_key->opt->no_entropy = FALSE;
	}
	return;
}

struct keylist* par_keylist_new()
/* returns an empty list */
{
	struct keylist* new_list = (struct keylist *) g_malloc(sizeof(struct keylist));
	new_list->head = NULL;
	return new_list;
}

struct keylist* par_keylist_init(struct otp_config* otp_conf)
/* loads all valid keys from the global otp folder into the key list */
{
	struct keylist* new_list;
	new_list = (struct keylist *) g_malloc(sizeof(struct keylist));
	new_list->head = NULL;
	struct key* tmp_key = NULL;
	
	GError* error = NULL;
	GDir* directoryhandle = g_dir_open(otp_conf_get_path(otp_conf), 0, &error);
	const gchar* tmp_filename = g_dir_read_name(directoryhandle);
	char* tmp_path = NULL;
	
	if (error) {
		g_printf("paranoia-key-management error: Opening \"%s\" failed! %s\n", 
				otp_conf_get_path(otp_conf), error->message);
		g_error_free(error);
	} else {
		/* loop over global key dir */
		// TODO: detect dublicate id's?
		while (tmp_filename != NULL) {
			tmp_path = g_strconcat(otp_conf_get_path(otp_conf), "/", tmp_filename, NULL);
			
			if (g_file_test(tmp_path, G_FILE_TEST_IS_REGULAR)) {
				tmp_key = par_key_create(tmp_filename, otp_conf);
				if (tmp_key == NULL) {
					//g_printf("paranoia-core: Could not add the file \"%s\".\n", tmp_filename);
				} else {
					//g_printf("paranoia-core: Key \"%s\" added.\n", tmp_filename);
					tmp_key->next = new_list->head;
					new_list->head = tmp_key;
				}
			}
			g_free(tmp_path);
			tmp_filename = g_dir_read_name(directoryhandle);
		}
	}
	g_dir_close(directoryhandle);
	
	return new_list;
}

void par_keylist_free(struct keylist* list)
/* frees all memory of the keylist */
{
	struct key* tmp_key = list->head;
	struct key* next_key_ptr = NULL;

	while (tmp_key != NULL) {
		next_key_ptr = tmp_key->next;
		otp_pad_destroy(tmp_key->pad);
		g_free(tmp_key->opt);
		g_free(tmp_key);
		tmp_key = next_key_ptr;
	}
	g_free(list);
	return;
}

void par_keylist_add_key(struct keylist* list, struct otp* a_pad)
/* adds a key created from a pad at the first position of the key list */
{
	/* default option struct */
	static struct options* a_opt;
	a_opt = (struct options *) g_malloc(sizeof(struct options));
	a_opt->otp_enabled = FALSE;
	a_opt->auto_enable = TRUE;
	a_opt->handshake_done = FALSE;
	a_opt->active = FALSE;
	if(otp_pad_get_entropy(a_pad) <= 0) {
		a_opt->no_entropy = TRUE;
	} else {
		a_opt->no_entropy = FALSE;
	}

	static struct key* key;
	key = (struct key *) g_malloc(sizeof(struct key));
	key->pad = a_pad;
	key->opt = a_opt;
	key->conv = NULL;
	key->next = list->head;
	
	list->head = key;
	return;
}

/* --------- Counting ---------- */

int par_keylist_count_keys(struct keylist* list)
/* counts all keys in the list */
{
	int sum = 0;
	struct key* tmp_ptr = list->head;
	while (tmp_ptr != NULL) {
		sum++;
		tmp_ptr = tmp_ptr->next;
	}
	return sum;
}

int par_keylist_count_matching_keys(struct keylist* list, const char* src, const char* dest)
/* counts all keys in the list with matching src and dest */
{
	int sum = 0;
	struct key* tmp_ptr = list->head;
	while (tmp_ptr != NULL) {
		if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src) == 0) 
				&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest) == 0)) {
			sum++;
		}
		tmp_ptr = tmp_ptr->next;
	}
	return sum;
}

/* --------- Searching ---------- */

char* par_keylist_search_ids(struct keylist* list, const char* src, const char* dest)
/* searches all ids for a src/dest pair in the keylist (comma separated).
 * Returns NULL if none found.
 * */
{
	char* ids = NULL;
	struct key* tmp_ptr = list->head;
	
	while (tmp_ptr != NULL) {
		if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src) == 0) 
				&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest) == 0)
				&& (!tmp_ptr->opt->no_entropy)) {
			if (ids == NULL) {
				ids = g_strdup(otp_pad_get_id(tmp_ptr->pad));
			} else {
				ids = g_strconcat(ids, ",", otp_pad_get_id(tmp_ptr->pad), NULL);
			}
		}
		tmp_ptr = tmp_ptr->next;
	}
	return ids;
}

struct key* par_keylist_search_key_by_id(struct keylist* list, const char* id, 
		const char* src, const char* dest)
/* Searches for the first key with a matching id.
 * Source and destination have to match too.
 * Returns NULL if none was found
 * */
{
	struct key* tmp_ptr = list->head;

	while (tmp_ptr != NULL) {
		if (g_strcmp0(otp_pad_get_id(tmp_ptr->pad), id) == 0) {
			if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src) == 0) 
					&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest) == 0)) {
				return tmp_ptr;
			}
		}
		tmp_ptr = tmp_ptr->next;
	}
	return NULL;
}

struct key* par_keylist_search_key(struct keylist* list, const char* src, const char* dest)
/* Searches for the first initialised key with matching source and destination.
 * Returns NULL if none was found.
 * */
{
	struct key* tmp_ptr = list->head;

	while (tmp_ptr != NULL) {
		if ((g_strcmp0(otp_pad_get_src(tmp_ptr->pad), src) == 0) 
					&& (g_strcmp0(otp_pad_get_dest(tmp_ptr->pad), dest) == 0)
					&& tmp_ptr->opt->active) {
				return tmp_ptr;
			}
		tmp_ptr = tmp_ptr->next;
	}
	return NULL;
}
