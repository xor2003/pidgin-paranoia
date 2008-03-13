/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2007-2008  Christian Wäckerlin, Simon Wenner
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
 * This header is used by the keygen. Don't use in your application! 
 * */

/*  ------------------- Public Constants (don't change) -------------------
 * Changing this makes your one-time-pad incompatible */

#define OTP_PROTECTED_ENTROPY 100	/* The amount of entropy that is only used for "out of entropy" messages */
#define ID_SIZE		4	/* The size in bytes of the ID. */
#define FILE_DELI " "            /* Delimiter in the filename, separating alice, bob and id*/
#define MSG_DELI "|"             /* Delimiter in the encrypted message */
#define FILE_SUFFIX "entropy"   /* The keyfiles have to end with
				 * this string to be valid. . */
#define FILE_SUFFIX_DELI "."	/* Separates FILE_SUFFIX from the rest */

/* ------------------ otp_config set functions ------------------- */

/* Increments the number of keys in production in the keygen
 * This function makes only sense if used in the keygen itself */
OtpError otp_conf_increment_number_of_keys_in_production(struct otp_config* config);

/* Increments the number of keys in production in the keygen
 * This function makes only sense if used in the keygen itself */
OtpError otp_conf_decrement_number_of_keys_in_production(struct otp_config* config);

