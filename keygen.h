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
unsigned int keygen_get_id();

GThread *keygen_keys_generate_from_file(const char *alice_file, 
		const char *bob_file, const char *entropy_src_file, 
		gsize size, gboolean is_loopkey);

/* invert:
*				invert writes the bytewise inverse of the src file into the dest
*				file. src and dest must be valid file names
*				this function returns 0 for success, -1 if a failure occures. */
//OtpError keygen_key_invert(const char *src_file, const char *dest_file);

/* loop-invert:
*				append the bytewise inverse of src to src
*				src must be a valide filename with valide path
*				returns 0 for success, -1 if a failure occures */
//OtpError keygen_loopkey_invert(const char *file);
