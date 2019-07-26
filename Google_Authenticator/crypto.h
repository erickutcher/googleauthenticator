/*
	Google Authenticator generates one-time passwords for Google accounts.
	Copyright (C) 2019 Eric Kutcher

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CRYPTO_H
#define _CRYPTO_H

#define STRICT
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>

struct AES_256_KEY_BLOB
{
	BLOBHEADER header;
	DWORD len;
	BYTE key[ 32 ];
};

struct KEY_BLOB
{
	BLOBHEADER header;
	DWORD len;
	BYTE *key;
};

void InitializeCrypto();
void CleanupCrypto();

void GenerateKeyFile( char *file_path );
bool LoadKeyFile( char *file_path );
void EncryptData( char *file_path );
void DecryptData( char *file_path );

unsigned long GetTOTP( char *key, unsigned int key_length );

#endif
