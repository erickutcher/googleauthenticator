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

#include "globals.h"
#include "utilities.h"

#include <stdio.h>

#define FILETIME_TICKS_PER_SECOND	10000000LL

#define decode_char( c ) ( ( c >= 'A' && c <= 'Z' ) ? c - 'A' : ( ( c >= '2' && c <= '7' ) ? ( c - '2' ) + 26 : -1 ) )

int decode_sequence( unsigned char *str_in, unsigned char *str_out )
{
	static char offset_map[] = { 3, -2, 1, -4, -1, 2, -3, 0 };

	str_out[ 0 ] = 0;

	for ( char block = 0, octet = 0; block < 8; ++block, octet = ( block * 5 ) / 8 )
	{
		int c = decode_char( str_in[ block ] );
		if ( c < 0 )
		{
			return octet;
		}

		if ( offset_map[ block ] < 0 )
		{
			str_out[ octet ] |= ( c >> -offset_map[ block ] );
			str_out[ octet + 1 ] = c << ( 8 + offset_map[ block ] );
		}
		else
		{
			str_out[ octet ] |= ( c << offset_map[ block ] );
		}
	}

	return 5;
}

unsigned int base32_decode( unsigned char *str_in, unsigned char *str_out )
{
	unsigned int written = 0;

	if ( str_in != NULL )
	{
		for ( unsigned int i = 0, j = 0; ; i += 8, j += 5 )
		{
			int n = decode_sequence( &str_in[ i ], &str_out[ j ] );

			written += n;

			if ( n < 5 )
			{
				break;
			}
		}
	}

	return written;
}

unsigned long GetUnixTimestamp()
{
	FILETIME ft;
	GetSystemTimeAsFileTime( &ft );

	// Convert the time into a 32bit Unix timestamp.
	ULARGE_INTEGER ts;
	ts.HighPart = ft.dwHighDateTime;
	ts.LowPart = ft.dwLowDateTime;

	return ( unsigned long )( ( ts.QuadPart - ( 11644473600000 * 10000 ) ) / FILETIME_TICKS_PER_SECOND );
}

void UnixTimeToSystemTime( DWORD t, SYSTEMTIME *st )
{
	FILETIME ft;
	LARGE_INTEGER li;
	li.QuadPart = Int32x32To64( t, 10000000 ) + 116444736000000000;

	ft.dwLowDateTime = li.LowPart;
	ft.dwHighDateTime = li.HighPart;

	FileTimeToSystemTime( &ft, st );
}

int _printf( const char *_Format, ... )
{
	int ret = -1;

	DWORD written;
	va_list arglist;

	va_start( arglist, _Format );

	char buffer[ 8192 ];

	int buffer_length = _vsnprintf_s( buffer, 8192, _Format, arglist );

	va_end( arglist );

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

	csbi.dwCursorPosition.X += LEFT_PADDING;
	SetConsoleCursorPosition( g_hOutput[ current_console ], csbi.dwCursorPosition );

	if ( buffer_length >= 0 && WriteConsoleA( g_hOutput[ current_console ], buffer, buffer_length, &written, NULL ) )
	{
		ret = written;
	}

	return ret;
}
