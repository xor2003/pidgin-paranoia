/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2007-2008  Christian Wäckerlin --> Pascal Sachs??
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


/* Generate a key-pair alice and bob with size size */
GThread *keygen_keys_generate(char *alice_file, char *bob_file,
		gsize size, gboolean is_loopkey);

/* get a random id for the key filename */
unsigned int keygen_id_get();

/* Generate a key-pair alice and bob with size size out of the entropy in file */
GThread *keygen_keys_generate_from_file(const char *alice_file,
		const char *bob_file, const char *entropy_src_file,
		gsize size, gboolean is_loopkey);
		
