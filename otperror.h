/*
 * One-Time Pad Library - Encrypts strings with one-time pads.
 * Copyright (C) 2008  Christian Wäckerlin, Pascal Sachs
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
 * This header defines the meaning of the error numbers. It is included 
 * in libotp.h.
 * */


/* ------------------ Error Syndrome System  ---------------------- */

typedef enum {
/* ---------------------- general ------------------- */

/* Success */
	OTP_OK	= 0x00000000,

/* This should be used to check if a error occurred
 * Every syndrome '<=' then this is a warning (or a success of course)
 * Every syndrome '>' then this is a (fatal) error */
	OTP_WARN		= 0x0000FFFF,

/* ------------------------ libotp ------------------------------ */

/* function: otp_encrypt, otp_encrypt_warning
 * origin: otp_get_encryptkey_from_file
 * The used entropy failed statistical tests */
	OTP_WARN_KEY_NOT_RANDOM	= 0x00000001,

	OTP_WARN2	= 0x00000002,
	OTP_WARN3	= 0x00000004,
	OTP_WARN4	= 0x00000008,
	OTP_WARN5	= 0x00000010,
	OTP_WARN6	= 0x00000020,
	OTP_WARN7	= 0x00000040,
	OTP_WARN8	= 0x00000080,

/* function: all
 * origin: otp_open_keyfile
 * A File can not be opened */
	OTP_ERR_FILE		= 0x00010000,

/* function: otp_encrypt, otp_encrypt_warning
 * origin: otp_get_encryptkey_from_file
 * The message does not fit into the entropy file */
	OTP_ERR_KEY_EMPTY	= 0x00030000,

/* function: otp_decrypt
 * origin: otp_get_decryptkey_from_file
 * Position in the message does not exist in the entropy file */
	OTP_ERR_KEY_SIZE_MISMATCH	 = 0x00040000,

/* function: all
 * origin: the same functions
 * The input into the fuction is not valid i.e. NULL*/
	OTP_ERR_INPUT				= 0x00050000,

/* function: otp_decrypt
 * origin: otp_decrypt
 * The message is not in the format "3234|34EF4588|M+Rla2w=" and can not be splitted */
	OTP_ERR_MSG_FORMAT			= 0x00060000,

/* function: otp_decrypt
 * origin: otp_decrypt
 * The ID '34EF4588' does not match with the one in the pad */
	OTP_ERR_ID_MISMATCH		= 0x00070000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Generation of loop keys not supported */
	OTP_ERR_LOOP_KEY		= 0x00110000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * Error opening the file from where entropy is taken */
	OTP_ERR_FILE_ENTROPY_SOURCE		= 0x00120000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The file from where entropy is taken is smaller then the requested key size*/
	OTP_ERR_FILE_ENTROPY_SOURCE_SIZE	= 0x00130000,

/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The keyfile exists already and can not be created */
	OTP_ERR_FILE_EXISTS	= 0x00140000,

/* function: many
 * origin: many
 * The keyfile is locked! */
	OTP_ERR_FILE_LOCKED	= 0x00150000,

/* function: otp_conf_free
 * origin: otp_conf_free
 * There are still some pads registered in this config */
	OTP_ERR_CONFIG_PAD_COUNT	= 0x00200000,
	
/* function: otp_generate_key_pair
 * origin: otp_generate_key_pair
 * The keygen is already in use and is blocked (TODO) */
	OTP_ERR_GENKEY_KEYGEN_IN_USE	= 0x00300000,
	
/* ------------------------ keygen ------------------------------ */

/* function: keygen
 * origin: keygen
 * TODO: a example for a error from keygen.c */
	OTP_ERR_KEYGEN_ERROR1	= 0x80000000,
	OTP_ERR_KEYGEN_ERROR2	= 0x80000001,
	OTP_ERR_KEYGEN_ERROR3	= 0x80000002,
	
	
	OTP_KEYGEN_WARN1	= 0x00000100,
	OTP_KEYGEN_WARN2	= 0x00000200,
	OTP_KEYGEN_WARN3	= 0x00000400,
	OTP_KEYGEN_WARN4	= 0x00000800,
	OTP_KEYGEN_WARN5	= 0x00001000,
	OTP_KEYGEN_WARN6	= 0x00002000,
	OTP_KEYGEN_WARN7	= 0x00004000,
	OTP_KEYGEN_WARN8	= 0x00008000,
	
} OtpError;
