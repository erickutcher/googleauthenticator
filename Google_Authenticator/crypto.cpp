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

#include "crypto.h"

#include "globals.h"
#include "utilities.h"

#define ENCRYPT_BLOCK_SIZE 16

HCRYPTKEY g_hKey = NULL;
HCRYPTPROV g_hCryptProv = NULL;

void CleanupCrypto()
{
	if ( g_hKey != NULL )
	{
		CryptDestroyKey( g_hKey );
	}

	if ( g_hCryptProv != NULL )
	{
		CryptReleaseContext( g_hCryptProv, 0 );
	}
}

void InitializeCrypto()
{
	CryptAcquireContext( &g_hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT );
}

void GenerateKeyFile( char *file_path )
{
	AES_256_KEY_BLOB aes256kb;

	if ( g_hKey != NULL )
	{
		CryptDestroyKey( g_hKey );
		g_hKey = NULL;
	}

	if ( CryptGenKey( g_hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &g_hKey ) )
	{
		DWORD kb_length;
		if ( CryptExportKey( g_hKey, NULL, PLAINTEXTKEYBLOB, 0, ( BYTE * )&aes256kb, &kb_length ) )
		{
			HANDLE hFile = CreateFileA( file_path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );
			if ( hFile != INVALID_HANDLE_VALUE )
			{
				if ( aes256kb.len == 32 )
				{
					DWORD write;
					WriteFile( hFile, aes256kb.key, aes256kb.len, &write, NULL );
				}
				/*else
				{
					_printf( "Invalid key length.\r\n" );
				}*/

				CloseHandle( hFile );
			}
			/*else
			{
				_printf( "Unable to open key file for writing.\r\n" );
			}*/
		}
		/*else
		{
			_printf( "Unable to export key file.\r\n" );
		}*/
	}
	/*else
	{
		_printf( "Unable to generate key value.\r\n" );
	}*/
}

bool LoadKeyFile( char *file_path )
{
	bool ret = false;

	HANDLE hFile = CreateFileA( file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		if ( GetFileSize( hFile, NULL ) == 32 )
		{
			AES_256_KEY_BLOB aes256kb;
			aes256kb.header.bType = PLAINTEXTKEYBLOB;
			aes256kb.header.bVersion = CUR_BLOB_VERSION;
			aes256kb.header.reserved = 0;
			aes256kb.header.aiKeyAlg = CALG_AES_256;
			
			ReadFile( hFile, aes256kb.key, 32, &aes256kb.len, NULL );

			if ( g_hKey != NULL )
			{
				CryptDestroyKey( g_hKey );
				g_hKey = NULL;
			}

			if ( CryptImportKey( g_hCryptProv, ( BYTE * )&aes256kb, sizeof( AES_256_KEY_BLOB ), NULL, 0, &g_hKey ) )
			{
				ret = true;
			}
			/*else
			{
				_printf( "Unable to import key file.\r\n" );
			}*/
		}
		/*else
		{
			_printf( "Invalid key length.\r\n" );
		}*/

		CloseHandle( hFile );
	}

	return ret;
}

void DecryptData( char *file_path )
{
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

	dwBlockLen = 1023 * ENCRYPT_BLOCK_SIZE;

	dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;

	HANDLE hFile = CreateFileA( file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		DWORD read;

		pbBuffer = ( BYTE * )GlobalAlloc( GMEM_FIXED, dwBufferLen );
		if ( pbBuffer != NULL )
		{
			DoublyLinkedList *list_item = g_list;
			DoublyLinkedList *last_list_item = g_list;
			DWORD dwBufferOffset = 0;

			pbBuffer = ( BYTE * )GlobalAlloc( GMEM_FIXED, dwBufferLen );
			if ( pbBuffer != NULL )
			{
				BOOL fEOF = FALSE;
				do
				{
					ReadFile( hFile, pbBuffer, dwBufferLen, &read, NULL );

					if ( read < dwBufferLen )
					{
						fEOF = TRUE;
					}

					if ( !CryptDecrypt( g_hKey, NULL, fEOF, 0, pbBuffer, &read ) )
					{
						break;
					}

					BYTE *p = pbBuffer;
					dwBufferOffset = 0;

					while ( dwBufferOffset < read )
					{
						AUTH_INFO *ai = ( AUTH_INFO * )GlobalAlloc( GPTR, sizeof( AUTH_INFO ) );

						dwBufferOffset += sizeof( unsigned int );
						if ( dwBufferOffset >= read ) { goto CLEANUP; }
						memcpy_s( &ai->username_length, sizeof( unsigned int ), p, sizeof( unsigned int ) );
						p += sizeof( unsigned int );

						dwBufferOffset += ai->username_length;
						if ( dwBufferOffset >= read ) { goto CLEANUP; }
						ai->username = ( char * )GlobalAlloc( GMEM_FIXED, ai->username_length + 1 );
						memcpy_s( ai->username, ai->username_length + 1, p, ai->username_length );
						ai->username[ ai->username_length ] = 0; // Sanity.
						p += ai->username_length;

						dwBufferOffset += sizeof( unsigned int );
						if ( dwBufferOffset >= read ) { goto CLEANUP; }
						memcpy_s( &ai->key_length, sizeof( unsigned int ), p, sizeof( unsigned int ) );
						p += sizeof( unsigned int );

						dwBufferOffset += ai->key_length;
						if ( dwBufferOffset > read ) { goto CLEANUP; }
						ai->key = ( char * )GlobalAlloc( GMEM_FIXED, ai->key_length + 1 );
						memcpy_s( ai->key, ai->key_length + 1, p, ai->key_length );
						ai->key[ ai->key_length ] = 0; // Sanity.
						p += ai->key_length;

						ai->code = -1;

						DoublyLinkedList *dll = DLL_CreateNode( ( void * )ai );
						DLL_AddNode( &g_list, dll, -1 );

						++g_list_count;

						continue;

					CLEANUP:

						GlobalFree( ai->username );
						GlobalFree( ai->key );
						GlobalFree( ai );
					}
				}
				while ( !fEOF );

				GlobalFree( pbBuffer );
			}

			CloseHandle( hFile );
		}
	}
}

void EncryptData( char *file_path )
{
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

	dwBlockLen = 1023 * ENCRYPT_BLOCK_SIZE;
	dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;

	HANDLE hFile = CreateFileA( file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		DWORD write;

		pbBuffer = ( BYTE * )GlobalAlloc( GMEM_FIXED, dwBufferLen );
		if ( pbBuffer != NULL )
		{
			DoublyLinkedList *list_item;
			DoublyLinkedList *last_list_item = g_list;
			DWORD dwBufferOffset = 0;

			BOOL fEOF = FALSE;
			do
			{
				list_item = last_list_item;

				while ( list_item != NULL )
				{
					AUTH_INFO *ai = ( AUTH_INFO * )list_item->data;
					if ( ai != NULL )
					{
						if ( dwBufferOffset + sizeof( unsigned int ) + ai->username_length + sizeof( unsigned int ) + ai->key_length <= dwBlockLen )
						{
							memcpy_s( pbBuffer + dwBufferOffset, dwBufferLen - dwBufferOffset, &ai->username_length, sizeof( unsigned int ) );
							dwBufferOffset += sizeof( unsigned int );
							if ( ai->username_length > 0 )
							{
								memcpy_s( pbBuffer + dwBufferOffset, dwBufferLen - dwBufferOffset, ai->username, ai->username_length );
								dwBufferOffset += ai->username_length;
							}
							memcpy_s( pbBuffer + dwBufferOffset, dwBufferLen - dwBufferOffset, &ai->key_length, sizeof( unsigned int ) );
							dwBufferOffset += sizeof( unsigned int );
							if ( ai->key_length > 0 )
							{
								memcpy_s( pbBuffer + dwBufferOffset, dwBufferLen - dwBufferOffset, ai->key, ai->key_length );
								dwBufferOffset += ai->key_length;
							}
						}
						else
						{
							break;
						}
					}

					list_item = list_item->next;
					last_list_item = list_item;
				}

				if ( list_item == NULL )
				{
					fEOF = TRUE;
				}

				if ( !CryptEncrypt( g_hKey, NULL, fEOF, 0, pbBuffer, &dwBufferOffset, dwBufferLen ) )
				{
					break;
				}

				WriteFile( hFile, pbBuffer, dwBufferOffset, &write, NULL );

				dwBufferOffset = 0;
			}
			while( !fEOF );

			GlobalFree( pbBuffer );
		}

		CloseHandle( hFile );
	}
}

unsigned long GetTOTP( char *key, unsigned int key_length )
{
	unsigned long code = -1;

	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHmacHash = NULL;
	PBYTE pbHash = NULL;
	DWORD dwDataLen = 0;
	HMAC_INFO HmacInfo;

	KEY_BLOB *kb = NULL;

	unsigned char *dkey = ( unsigned char * )GlobalAlloc( GMEM_FIXED, sizeof( unsigned char ) * key_length );
	unsigned int dkey_length = base32_decode( ( unsigned char * )key, dkey );

	if ( dkey_length == 0 )
	{
		goto CLEANUP;
	}

	ZeroMemory( &HmacInfo, sizeof( HmacInfo ) );
	HmacInfo.HashAlgid = CALG_SHA1;

	if ( !CryptAcquireContext( &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET ) )
	{
		goto CLEANUP;
	}

	DWORD kbSize = sizeof( KEY_BLOB ) + dkey_length;

	kb = ( KEY_BLOB * )GlobalAlloc( GMEM_FIXED, kbSize );
	kb->header.bType = PLAINTEXTKEYBLOB;
	kb->header.bVersion = CUR_BLOB_VERSION;
	kb->header.reserved = 0;
	kb->header.aiKeyAlg = CALG_RC2;
	memcpy( &kb->key, dkey, dkey_length );
	kb->len = dkey_length;

	if ( !CryptImportKey( hProv, ( BYTE * )kb, kbSize, 0, CRYPT_IPSEC_HMAC_KEY, &hKey ) )
	{
		goto CLEANUP;
	}

	if ( !CryptCreateHash( hProv, CALG_HMAC, hKey, 0, &hHmacHash ) )
	{
		goto CLEANUP;
	}

	if ( !CryptSetHashParam( hHmacHash, HP_HMAC_INFO, ( BYTE * )&HmacInfo, 0 ) )
	{
		goto CLEANUP;
	}

	unsigned long data = GetUnixTimestamp() / 30;

	BYTE cdata[ 8 ];
	ZeroMemory( &cdata, sizeof( cdata ) );

	cdata[ 7 ] = ( BYTE )( data & 0xFF );
	cdata[ 6 ] = ( BYTE )( ( data & 0xFF00 ) >> 8 );
	cdata[ 5 ] = ( BYTE )( ( data & 0xFF0000 ) >> 16 );
	cdata[ 4 ] = ( BYTE )( ( data & 0xFF000000 ) >> 24 );

	if ( !CryptHashData( hHmacHash, cdata, sizeof( cdata ), 0 ) )
	{
		goto CLEANUP;
	}

	if ( !CryptGetHashParam( hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0 ) )
	{
		goto CLEANUP;
	}

	pbHash = ( BYTE * )GlobalAlloc( GMEM_FIXED, dwDataLen );
	if ( pbHash == NULL ) 
	{
		goto CLEANUP;
	}

	if ( !CryptGetHashParam( hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0 ) )
	{
		goto CLEANUP;
	}

	unsigned char offset = pbHash[ dwDataLen - 1 ] & 0x0F;

	code = ( ( pbHash[ offset + 0 ] & 0x7F ) << 24 ) |
		   ( ( pbHash[ offset + 1 ] & 0xFF ) << 16 ) |
		   ( ( pbHash[ offset + 2 ] & 0xFF ) <<  8 ) |
		     ( pbHash[ offset + 3 ] & 0xFF );

	code %= 1000000;

CLEANUP:

	// Free resources.
	if ( hHmacHash ) { CryptDestroyHash( hHmacHash ); }
	if ( hKey ) { CryptDestroyKey( hKey ); }
	if ( hHash ) { CryptDestroyHash( hHash ); }
	if ( hProv ) { CryptReleaseContext( hProv, 0 ); }
	if ( pbHash ) { GlobalFree( pbHash ); }
	if ( dkey ) { GlobalFree( dkey ); }
	if ( kb ) { GlobalFree( kb ); }

	return code;
}
