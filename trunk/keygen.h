/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2008  Pascal Sachs
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

/*
*	Generate the keyfiles alice and bob from the source entropy_source, which
*	can be either a regular entropy file, a character device or NULL for the
*	internal key generator
*/
OtpError keygen_keys_generate(char *alice_file, char *bob_file,
		gsize size, const char *entropy_source, void *config);

/* get a random id for the key filename */
unsigned int keygen_id_get();		
		
