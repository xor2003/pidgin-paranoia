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

/* NOTE: These functions are not thread-safe! */

/* the list */
struct keylist {
	struct key* head;
	// for future use
};

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

/* --------- List Element (Key) ---------- */

struct key* par_key_create(const char* filename, struct otp_config* otp_conf);

void par_key_reset(struct key* a_key);

/* --------- List ---------- */

struct keylist* par_keylist_new();
/* returns an empty list */

struct keylist* par_keylist_init(struct otp_config* otp_conf);
/* reads all keys from a config into a new list */

void par_keylist_free(struct keylist* list);
/* destroy the key list */

void par_keylist_add_key(struct keylist* list, struct otp* a_pad);

/* --- Counting --- */

int par_keylist_count_keys(struct keylist* list);

int par_keylist_count_matching_keys(struct keylist* list, const char* src, const char* dest);

/* --- Searching --- */

char* par_keylist_search_ids(struct keylist* list, const char* src, const char* dest);

struct key* par_keylist_search_key_by_id(struct keylist* list, const char* id, 
		const char* src, const char* dest);
		
struct key* par_keylist_search_key(struct keylist* list, const char* src, const char* dest);

/* -- end -- */
