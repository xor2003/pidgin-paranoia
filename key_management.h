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

/* ----------------- Paranoia Key Management ------------------ */

/* key options struct */
struct options {
	gboolean otp_enabled; /* otp on/off */
	gboolean auto_enable; /* false to force disable */
	gboolean no_entropy; /* all entropy of one user was used up completely */
	gboolean handshake_done; /* key ids have been exchanged */
	gboolean active; /* an initialised key */
};

/* paranoia key struct (a linked list) */
struct key {
	struct otp* pad; /* see libotp.h */
	struct options* opt; /* key options */
	void* conv; /* current conversation (if any) */
	struct key* next;
};

/* paranoia keylist pointer */
// FIXME: replace keylist ptr with get/set fn
struct key* keylist;

/* --------- Core ---------- */

gboolean par_init_key_list(struct otp_config* otp_conf);

void par_free_key_list();

struct key* par_create_key(const char* filename, struct otp_config* otp_conf);

void par_reset_key(struct key* a_key);

void par_add_key(struct otp* a_pad);

/* --------- Counting ----------*/

int par_count_keys();

int par_count_matching_keys(const char* src, const char* dest);

/* --------- Searching ---------- */

char* par_search_ids(const char* src, const char* dest);

struct key* par_search_key_by_id(const char* id, const char* src, 
		const char* dest);
		
struct key* par_search_key(const char* src, const char* dest);
