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

#include <stdio.h>

#include "globals.h"
#include "utilities.h"

#include "crypto.h"

HANDLE g_hInput = NULL;
HANDLE g_hOutput[ 2 ] = { NULL };
unsigned char current_console = 0;

char g_console_buffer[ CONSOLE_BUFFER_SIZE + 1 ];

unsigned char g_status = 0;

bool g_timers_running = false;
HANDLE g_timer_semaphore = NULL;

CRITICAL_SECTION console_cs;

DoublyLinkedList *g_list = NULL;
DoublyLinkedList *g_first_visible = NULL;
DoublyLinkedList *g_selected_item = NULL;

short g_selection_offset = 0;
int g_selected_index = 0;
int g_list_count = 0;

char g_save_path[ MAX_PATH ];
char g_key_path[ MAX_PATH ];

// Ordered by month.
wchar_t *month_string_table[ 12 ] =
{
	L"January",
	L"February",
	L"March",
	L"April",
	L"May",
	L"June",
	L"July",
	L"August",
	L"September",
	L"October",
	L"November",
	L"December"
};

// Ordered by day.
wchar_t *day_string_table[ 7 ] =
{
	L"Sunday",
	L"Monday",
	L"Tuesday",
	L"Wednesday",
	L"Thursday",
	L"Friday",
	L"Saturday"
};

void WriteCharInfo( HANDLE output, char *str, WORD width, SHORT x, SHORT y, WORD attributes )
{
	CHAR_INFO ci[ 64 * VISIBLE_LINES ] = { NULL };

	WORD lines = 0;

	if ( str != NULL && width > 0 )
	{
		for ( WORD i = 0; i < width; )
		{
			if ( *str != NULL )
			{
				if ( *str == '\n' )
				{
					if ( *( str + 1 ) == NULL )
					{
						break;
					}

					i = 0;
					++lines;
					++str;

					continue;
				}
				else
				{
					ci[ ( lines * width ) + i ].Char.AsciiChar = *str++;
					ci[ ( lines * width ) + i ].Attributes = attributes;
				}
			}
			else
			{
				break;
			}

			++i;
		}

		COORD bs;
		bs.X = width;
		bs.Y = 1 + lines;

		COORD bc;
		bc.X = 0;
		bc.Y = 0;

		SMALL_RECT sr;
		sr.Left = x;
		sr.Top = y;
		sr.Right = x + ( width - 1 );
		sr.Bottom = y + lines;

		WriteConsoleOutputA( output, ci, bs, bc, &sr );
	}
}

BOOL WINAPI ConsoleHandler( DWORD signal )
{
    if ( signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || CTRL_LOGOFF_EVENT || CTRL_SHUTDOWN_EVENT )
	{
		g_status = 1;
	}

    return TRUE;
}

void ClearConsole( HANDLE hConsole )
{
	COORD ccp = { 0, 0 };
	DWORD written;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo( hConsole, &csbi );

	FillConsoleOutputCharacterA( hConsole, ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

	SetConsoleCursorPosition( hConsole, ccp );
}

void UpdateList()
{
	DoublyLinkedList *dll = g_list;

	while ( dll != NULL )
	{
		AUTH_INFO *ai = ( AUTH_INFO * )dll->data;

		if ( ai != NULL )
		{
			ai->code = GetTOTP( ai->key, ai->key_length );
		}

		dll = dll->next;
	}
}

void CleanupList()
{
	while ( g_list != NULL )
	{
		DoublyLinkedList *del_node = g_list;

		g_list = g_list->next;

		AUTH_INFO *ai = ( AUTH_INFO * )del_node->data;
		if ( ai != NULL )
		{
			GlobalFree( ai->username );
			GlobalFree( ai->key );
			GlobalFree( ai );
		}

		GlobalFree( del_node );
	}

	g_list_count = 0;
	g_selection_offset = 0;
	g_selected_index = 0;
	g_first_visible = NULL;
	g_selected_item = NULL;
}

void EnableTimer( bool timer_state )
{
	// Trigger the timers out of their infinite wait.
	if ( timer_state )
	{
		if ( !g_timers_running )
		{
			g_timers_running = true;

			if ( g_timer_semaphore != NULL )
			{
				ReleaseSemaphore( g_timer_semaphore, 1, NULL );
			}
		}
	}
	else	// Let the timers complete their current task and then wait indefinitely.
	{
		g_timers_running = false;
	}
}

void PrintFrame( HANDLE hOutput, WORD attributes )
{
	DWORD written;

	COORD ccp;
	ccp.X = 0;
	ccp.Y = TOP_PADDING;
	SetConsoleCursorPosition( hOutput, ccp );

	_printf( "\xC9\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBB\r\n" );
	_printf( "\xBA%*s\xBA\r\n", 62, "" );
	_printf( "\xBA                     " );
	SetConsoleTextAttribute( hOutput, FOREGROUND_BLUE | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "G", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "o", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "o", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, FOREGROUND_BLUE | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "g", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "l", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
	WriteConsoleA( hOutput, "e", 1, &written, NULL );
	SetConsoleTextAttribute( hOutput, attributes );
	WriteConsoleA( hOutput, " Authenticator", 14, &written, NULL );
	_printf( "                \xBA\r\n" );
	_printf( "\xBA%*s\xBA\r\n", 62, "" );
	_printf( "\xCC\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xB9\r\n" );
	_printf( "\xBA Ctrl + [N]ew \xB3 Ctrl + [O]pen \xB3 Ctrl + [S]ave \xB3 Ctrl + [Q]uit \xBA\r\n" );
	_printf( "\xCC\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xB9\r\n" );

	for ( char i = 0; i < VISIBLE_LINES + 6; ++i )
	{
		_printf( "\xBA%62s\xBA\r\n", "" );
	}

	_printf( "\xCC\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xD1" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xB9\r\n" );
	_printf( "\xBA    [A]dd    \xB3   [E]dit   \xB3   [R]emove   \xB3   Ctrl + [C]opy    \xBA\r\n" );
	_printf( "\xC8\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCF" \
			 "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xBC" );
}

void PrintList()
{
	DWORD written;

	char buffer[ 255 ];
	int buffer_length;

	DoublyLinkedList *dll = g_first_visible;

	COORD ccp;
	ccp.X = LEFT_PADDING + 1;

	CONSOLE_CURSOR_INFO cci;
	GetConsoleCursorInfo( g_hOutput[ 0 ], &cci );
	if ( cci.bVisible == FALSE )
	{
		current_console = ( current_console == 0 ? 1 : 0 );
	}

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

	if ( g_list_count > 0 )
	{
		EnableTimer( true );

		WriteCharInfo( g_hOutput[ current_console ], "Username", 8, LEFT_PADDING + 5, LIST_OFFSET, FOREGROUND_INTENSITY );
		WriteCharInfo( g_hOutput[ current_console ], "One-Time Password", 17, LEFT_PADDING + 42, LIST_OFFSET, FOREGROUND_INTENSITY );

		ccp.Y = SELECTION_OFFSET;

		for ( char i = 0; i < VISIBLE_LINES; ++i )
		{
			ccp.X = LEFT_PADDING + 1;
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 60, ccp, &written );

			if ( dll != NULL )
			{
				AUTH_INFO *ai = ( AUTH_INFO * )dll->data;

				if ( ai != NULL )
				{
					if ( dll == g_selected_item )
					{
						ccp.X = LEFT_PADDING + 2;
						FillConsoleOutputCharacterA( g_hOutput[ current_console ], '>', 1, ccp, &written );
					}

					buffer_length = sprintf_s( buffer, 255, "%s", ai->username );
					if ( buffer_length > 32 )
					{
						memcpy_s( buffer + 32, 255 - 32, "...", 3 );
						buffer_length = 35;
					}

					ccp.X = LEFT_PADDING + 5;

					WriteCharInfo( g_hOutput[ current_console ], buffer, buffer_length, ccp.X, ccp.Y, ( dll == g_selected_item ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : csbi.wAttributes ) );

					// MSB should not be set.
					if ( ai->code & 0xF0000000 )
					{
						memcpy_s( buffer, 255, "BAD KEY", 7 );
						buffer_length = 7;

						ccp.X = LEFT_PADDING + 52;
					}
					else
					{
						buffer_length = sprintf_s( buffer, 255, "%06lu", ai->code );
						ccp.X = LEFT_PADDING + 53;
					}

					WriteCharInfo( g_hOutput[ current_console ], buffer, buffer_length, ccp.X, ccp.Y, ( dll == g_selected_item ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : csbi.wAttributes ) );
				}

				dll = dll->next;
			}

			++ccp.Y;
		}

		ccp.X = LEFT_PADDING + 61;
		ccp.Y = SELECTION_OFFSET;
		//if ( ( g_selected_index + 1 ) > VISIBLE_LINES || ( g_selected_index > 0 && g_selection_offset == 0 ) )
		if ( g_first_visible != g_list )
		{
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ':', 1, ccp, &written );
		}
		else
		{
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 1, ccp, &written );
		}

		ccp.Y = SELECTION_OFFSET + VISIBLE_LINES - 1;
		int offset = g_list_count - g_selected_index;
		if ( g_list_count <= VISIBLE_LINES ||
		   ( offset <= VISIBLE_LINES && ( VISIBLE_LINES - offset ) == g_selection_offset ) )
		{
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 1, ccp, &written );
		}
		else
		{
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ':', 1, ccp, &written );
		}
	}
	else
	{
		EnableTimer( false );

		// Clear the line that shows the time.
		ccp.Y = TIMER_OFFSET;
		FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 60, ccp, &written );

		// Clear the line that shows Username and One-Time Password.
		ccp.Y = LIST_OFFSET;
		FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 60, ccp, &written );

		// Clear the usernames and passwords.
		ccp.Y = SELECTION_OFFSET;
		for ( char i = 0; i < VISIBLE_LINES; ++i )
		{
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 60, ccp, &written );
			++ccp.Y;
		}
	}

	SetConsoleActiveScreenBuffer( g_hOutput[ current_console ] );
}

void RefreshLine( AUTH_INFO *ai, short line, bool selected )
{
	if ( ai != NULL )
	{
		char buffer[ 255 ];
		COORD ccp;
		DWORD written;
		CONSOLE_SCREEN_BUFFER_INFO csbi;

		GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

		ccp.X = LEFT_PADDING + 1;
		ccp.Y = line;
		FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', 60, ccp, &written );

		int buffer_length = sprintf_s( buffer, 255, "%s", ai->username );
		if ( buffer_length > 32 )
		{
			memcpy_s( buffer + 32, 255 - 32, "...", 3 );
			buffer_length = 35;
		}

		WriteCharInfo( g_hOutput[ current_console ], buffer, buffer_length, LEFT_PADDING + 5, line, ( selected ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : csbi.wAttributes ) );

		// MSB should not be set.
		if ( ai->code & 0xF0000000 )
		{
			memcpy_s( buffer, 255, "BAD KEY", 7 );
			buffer_length = 7;
			ccp.X = LEFT_PADDING + 52;
		}
		else
		{
			buffer_length = sprintf_s( buffer, 255, "%06lu", ai->code );
			ccp.X = LEFT_PADDING + 53;
		}

		WriteCharInfo( g_hOutput[ current_console ], buffer, buffer_length, ccp.X, line, ( selected ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : csbi.wAttributes ) );

		if ( selected )
		{
			ccp.X = LEFT_PADDING + 2;
			ccp.Y = SELECTION_OFFSET + g_selection_offset;
			FillConsoleOutputCharacterA( g_hOutput[ current_console ], '>', 1, ccp, &written );
		}
	}
}

DWORD WINAPI UpdateWindow( LPVOID WorkThreadContext )
{
	bool run_timer = g_timers_running;
	bool updated = false;

	char time_buf[ 11 ];

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

	while ( g_status != 1 )
	{
		WaitForSingleObject( g_timer_semaphore, ( run_timer ? 1000 : INFINITE ) );

		if ( g_status == 1 )
		{
			break;
		}

		EnterCriticalSection( &console_cs );

		// This will allow the timer to go through at least one loop after it's been disabled (g_timers_running == false).
		run_timer = g_timers_running;

		if ( run_timer )
		{
			COORD ccp;
			ccp.X = LEFT_PADDING + 1;
			ccp.Y = TIMER_OFFSET;

			if ( g_list_count > 0 )
			{
				unsigned long ts = 30 - ( GetUnixTimestamp() % 30 );

				if ( run_timer )
				{
					WriteCharInfo( g_hOutput[ 0 ], "Time remaining: ", 16, LEFT_PADDING + 19, TIMER_OFFSET, csbi.wAttributes );
					WriteCharInfo( g_hOutput[ 1 ], "Time remaining: ", 16, LEFT_PADDING + 19, TIMER_OFFSET, csbi.wAttributes );

					WORD attributes = FOREGROUND_INTENSITY;
					if ( ts > 5 && ts <= 10 )
					{
						attributes |= FOREGROUND_RED | FOREGROUND_GREEN;
					}
					else if ( ts > 0 && ts <= 5 )
					{
						attributes |= FOREGROUND_RED;
					}
					else
					{
						attributes |= FOREGROUND_GREEN;
					}
					int time_buf_length = sprintf_s( time_buf, 11, "%02lu", ts );
					WriteCharInfo( g_hOutput[ 0 ], time_buf, time_buf_length, LEFT_PADDING + 19 + 16, TIMER_OFFSET, attributes );
					WriteCharInfo( g_hOutput[ 1 ], time_buf, time_buf_length, LEFT_PADDING + 19 + 16, TIMER_OFFSET, attributes );

					WriteCharInfo( g_hOutput[ 0 ], " seconds", 8, LEFT_PADDING + 19 + 16 + time_buf_length, TIMER_OFFSET, csbi.wAttributes );
					WriteCharInfo( g_hOutput[ 1 ], " seconds", 8, LEFT_PADDING + 19 + 16 + time_buf_length, TIMER_OFFSET, csbi.wAttributes );
				}

				// Attempt to update the list in case the timer skipped a second.
				if ( ts >= 25 )
				{
					if ( !updated )
					{
						updated = true;

						UpdateList();

						PrintList();
					}
				}
				else
				{
					updated = false;
				}
			}
			else
			{
				run_timer = g_timers_running = false;
			}
		}

		LeaveCriticalSection( &console_cs );
	}

	CloseHandle( g_timer_semaphore );
	g_timer_semaphore = NULL;

	ExitThread( 0 );
	return 0;
}

void EnableCursor( BOOL enable )
{
	CONSOLE_CURSOR_INFO cci;

	GetConsoleCursorInfo( g_hOutput[ 0 ], &cci );
	cci.bVisible = enable;
	SetConsoleCursorInfo( g_hOutput[ 0 ], &cci );

	GetConsoleCursorInfo( g_hOutput[ 1 ], &cci );
	cci.bVisible = enable;
	SetConsoleCursorInfo( g_hOutput[ 1 ], &cci );
}

void FillConsoleInputLine( char *input )
{
	if ( input != NULL )
	{
		size_t input_length = strlen( input );
		INPUT_RECORD *pir = ( INPUT_RECORD * )GlobalAlloc( GMEM_FIXED, sizeof( INPUT_RECORD ) * input_length );

		char *c = input;
		INPUT_RECORD *tir = pir;
		for ( unsigned int i = 0; i < input_length; ++i )
		{
			tir->EventType = KEY_EVENT;
			tir->Event.KeyEvent.bKeyDown = TRUE;
			tir->Event.KeyEvent.dwControlKeyState = 0;
			tir->Event.KeyEvent.wRepeatCount = 1;
			tir->Event.KeyEvent.uChar.AsciiChar = *c;
			tir->Event.KeyEvent.wVirtualKeyCode = VkKeyScanA( *c );
			tir->Event.KeyEvent.wVirtualScanCode = MapVirtualKey( tir->Event.KeyEvent.wVirtualKeyCode, MAPVK_VK_TO_VSC );

			++tir;
			++c;
		}

		DWORD write;
		WriteConsoleInputA( g_hInput, pir, ( DWORD )input_length, &write );

		GlobalFree( pir );
	}
}

int main( int argc, char *argv[] )
{
	SYSTEMTIME compile_time;
	memset( &compile_time, 0, sizeof( SYSTEMTIME ) );
	HINSTANCE hInstance = GetModuleHandle( NULL );
	if ( hInstance != NULL )
	{
		IMAGE_DOS_HEADER *idh = ( IMAGE_DOS_HEADER * )hInstance;
		IMAGE_NT_HEADERS *inth = ( IMAGE_NT_HEADERS * )( ( BYTE * )idh + idh->e_lfanew );

		UnixTimeToSystemTime( inth->FileHeader.TimeDateStamp, &compile_time );
	}

	InitializeCrypto();

	g_timer_semaphore = CreateSemaphore( NULL, 0, 1, NULL );

	HANDLE timer_handle = CreateThread( NULL, 0, UpdateWindow, NULL, 0, NULL );
	SetThreadPriority( timer_handle, THREAD_PRIORITY_LOWEST );
	CloseHandle( timer_handle );


	g_first_visible = g_list;
	g_selected_item = g_list;

	DWORD written;
	DWORD read;
	COORD ccp;
	INPUT_RECORD ir[ 1 ];
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	InitializeCriticalSection( &console_cs );

	// Set our console to receive Ctrl + x key presses.
	CONSOLE_READCONSOLE_CONTROL crcc;
	crcc.nLength = sizeof( CONSOLE_READCONSOLE_CONTROL );
	crcc.nInitialChars = 0;
	crcc.dwCtrlWakeupMask = 0xFFFFFFFF;
	crcc.dwControlKeyState = 0;

	SetConsoleCtrlHandler( ConsoleHandler, TRUE );

	g_hInput = GetStdHandle( STD_INPUT_HANDLE );

	// Save the current console buffer. We'll restore it when we're done.
	HANDLE g_hOutput_old = GetStdHandle( STD_OUTPUT_HANDLE );

	g_hOutput[ 0 ] = CreateConsoleScreenBuffer( GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL );
	g_hOutput[ 1 ] = CreateConsoleScreenBuffer( GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL );

	SHORT width = LEFT_PADDING + LEFT_PADDING + 64;
	SHORT height = INPUT_OFFSET + TOP_PADDING;

	// Window size
	SMALL_RECT src;
	src.Top = 0;
	src.Left = 0;
	src.Right = width;
	src.Bottom = height;

	// Buffer size
	COORD csize;
	csize.X = width + 1;
	csize.Y = height + 1;

	csize.X += 1000;
	csize.Y += 1000;
	BOOL test2 = SetConsoleScreenBufferSize( g_hOutput[ 0 ], csize );
	SetConsoleScreenBufferSize( g_hOutput[ 1 ], csize );

	BOOL test = SetConsoleWindowInfo( g_hOutput[ 0 ], TRUE, &src );
	SetConsoleWindowInfo( g_hOutput[ 1 ], TRUE, &src );
	
	csize.X -= 1000;
	csize.Y -= 1000;
	test = SetConsoleScreenBufferSize( g_hOutput[ 0 ], csize );
	SetConsoleScreenBufferSize( g_hOutput[ 1 ], csize );


	HWND hWnd_console = GetConsoleWindow(); 
	SetWindowLongPtr( hWnd_console, GWL_STYLE, GetWindowLongPtr( hWnd_console, GWL_STYLE ) & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX );


	/////

	GetConsoleScreenBufferInfo( g_hOutput[ 0 ], &csbi );

	PrintFrame( g_hOutput[ 0 ], csbi.wAttributes );
	current_console = 1;
	PrintFrame( g_hOutput[ 1 ], csbi.wAttributes );
	current_console = 0;

	SetConsoleActiveScreenBuffer( g_hOutput[ 0 ] );

	char loaded_args = 0;	// 1 = key and database loaded, 2 = key loaded
	if ( argc > 1 )
	{
		if ( GetFileAttributesA( argv[ 1 ] ) != INVALID_FILE_ATTRIBUTES )
		{
			GetFullPathNameA( argv[ 1 ], MAX_PATH, g_save_path, NULL );

			loaded_args = 1;
		}
	}

	if ( loaded_args == 1 && argc > 2 )
	{
		if ( GetFileAttributesA( argv[ 2 ] ) != INVALID_FILE_ATTRIBUTES )
		{
			GetFullPathNameA( argv[ 2 ], MAX_PATH, g_key_path, NULL );

			if ( LoadKeyFile( g_key_path ) )
			{
				DecryptData( g_save_path );

				g_selection_offset = 0;
				g_selected_index = 0;
				g_first_visible = g_list;
				g_selected_item = g_list;

				loaded_args = 2;
			}
		}
	}

	///////////////////////////////

	do
	{
		g_status = 0;

		EnterCriticalSection( &console_cs );

		ClearConsole( g_hOutput[ current_console ] );
		PrintFrame( g_hOutput[ current_console ], csbi.wAttributes );

		if ( loaded_args == 2 )
		{
			UpdateList();

			PrintList();
		}
		else
		{
			g_save_path[ 0 ] = 0;	// Sanity.
			g_key_path[ 0 ] = 0;	// Sanity.
		}

		LeaveCriticalSection( &console_cs );

		loaded_args = 0;

		EnableCursor( FALSE );

		BOOL read_console;
		do
		{
			SetConsoleMode( g_hInput, ENABLE_WINDOW_INPUT );
			read_console = ReadConsoleInputW( g_hInput, ir, 1, &read );

			if ( ir[ 0 ].EventType == KEY_EVENT )
			{
				KEY_EVENT_RECORD ker = ir[ 0 ].Event.KeyEvent;

				DWORD ctrl_down = ( ker.dwControlKeyState & ( LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED ) );

				if ( ker.bKeyDown )
				{
					if ( ctrl_down )
					{
						if ( ker.wVirtualKeyCode == 'A' )
						{
							wchar_t msg[ 512 ];
							_snwprintf_s( msg, 512, L"Google Authenticator is made free under the GPLv3 license.\r\n\r\n" \
													L"Version 1.0.0.1 (%u-bit)\r\n\r\n" \
													L"Built on %s, %s %d, %04d %d:%02d:%02d %s (UTC)\r\n\r\n" \
													L"Copyright \xA9 2019 Eric Kutcher",
#ifdef _WIN64
						   64,
#else
						   32,
#endif
						   ( compile_time.wDayOfWeek > 6 ? L"" : day_string_table[ compile_time.wDayOfWeek ] ),
						   ( ( compile_time.wMonth > 12 || compile_time.wMonth < 1 ) ? L"" : month_string_table[ compile_time.wMonth - 1 ] ),
						   compile_time.wDay,
						   compile_time.wYear,
						   ( compile_time.wHour > 12 ? compile_time.wHour - 12 : ( compile_time.wHour != 0 ? compile_time.wHour : 12 ) ),
						   compile_time.wMinute,
						   compile_time.wSecond,
						   ( compile_time.wHour >= 12 ? L"PM" : L"AM" ) );

							MessageBoxW( hWnd_console, msg, L"Google Authenticator", MB_APPLMODAL | MB_ICONINFORMATION );
						}
						else if ( ker.wVirtualKeyCode == 'N' )
						{
							g_status = 2;	// New instance

							break;
						}
						else if ( ker.wVirtualKeyCode == 'Q' )
						{
							g_status = 1;	// Quit

							break;
						}
						else if ( ker.wVirtualKeyCode == 'O' )
						{
							EnableCursor( TRUE );

							ccp.X = 2;
							ccp.Y = INPUT_OFFSET;
							SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

							GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );
							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

							_printf( "Open database file: " );

							SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
							ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

							if ( read > 2 )
							{
								read -= 2;

								g_console_buffer[ read ] = 0;

								if ( GetFileAttributesA( g_console_buffer ) != INVALID_FILE_ATTRIBUTES )
								{
									GetFullPathNameA( g_console_buffer, MAX_PATH, g_save_path, NULL );

									ccp.X = 2;
									ccp.Y = INPUT_OFFSET;
									SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

									_printf( "Load key file: " );

									SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
									ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

									FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

									bool read_key = false;

									if ( read > 2 )
									{
										read -= 2;

										g_console_buffer[ read ] = 0;

										if ( GetFileAttributesA( g_console_buffer ) != INVALID_FILE_ATTRIBUTES )
										{
											GetFullPathNameA( g_console_buffer, MAX_PATH, g_key_path, NULL );

											if ( LoadKeyFile( g_key_path ) )
											{
												read_key = true;

												CleanupList();

												DecryptData( g_save_path );

												g_selection_offset = 0;
												g_selected_index = 0;
												g_first_visible = g_list;
												g_selected_item = g_list;

												EnterCriticalSection( &console_cs );

												PrintList();

												LeaveCriticalSection( &console_cs );
											}
										}
									}

									if ( !read_key )
									{
										g_save_path[ 0 ] = 0;	// Sanity.
										g_key_path[ 0 ] = 0;	// Sanity.
									}
								}
							}

							EnableCursor( FALSE );
						}
						else if ( ker.wVirtualKeyCode == 'S' )
						{
							EnableCursor( TRUE );

							ccp.X = 2;
							ccp.Y = INPUT_OFFSET;
							SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

							GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );
							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

							if ( g_key_path[ 0 ] == NULL )
							{
								_printf( "Generate key file: " );

								SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
								ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

								if ( read > 2 )
								{
									read -= 2;

									g_console_buffer[ read ] = 0;

									GetFullPathNameA( g_console_buffer, MAX_PATH, g_key_path, NULL );

									GenerateKeyFile( g_key_path );
								}

								ccp.X = 2;
								ccp.Y = INPUT_OFFSET;
								SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

								GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );
								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );
							}

							if ( g_key_path[ 0 ] != NULL )
							{
								_printf( "Save database file: " );

								FillConsoleInputLine( g_save_path );

								SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
								ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

								if ( read > 2 )
								{
									read -= 2;

									g_console_buffer[ read ] = 0;

									GetFullPathNameA( g_console_buffer, MAX_PATH, g_save_path, NULL );

									EncryptData( g_save_path );
								}
							}

							EnableCursor( FALSE );
						}
						else if ( ker.wVirtualKeyCode == 'C' )
						{
							if ( g_selected_item != NULL && g_selected_item->data != NULL )
							{
								AUTH_INFO *ai = ( AUTH_INFO * )g_selected_item->data;

								if ( OpenClipboard( NULL ) )
								{
									EmptyClipboard();

									// Allocate a global memory object for the text.
									HGLOBAL hglbCopy = GlobalAlloc( GMEM_MOVEABLE, sizeof( char ) * 11 );
									if ( hglbCopy != NULL )
									{
										// Lock the handle and copy the text to the buffer. lptstrCopy doesn't get freed.
										char *lptstrCopy = ( char * )GlobalLock( hglbCopy );
										if ( lptstrCopy != NULL )
										{
											if ( ai->code >= 1000000 )
											{
												memcpy_s( lptstrCopy, 11, "BAD KEY\0", 8 );
											}
											else
											{
												sprintf_s( lptstrCopy, 11, "%06lu", ai->code );
											}
										}

										GlobalUnlock( hglbCopy );

										if ( SetClipboardData( CF_TEXT, hglbCopy ) == NULL )
										{
											GlobalFree( hglbCopy );	// Only free this Global memory if SetClipboardData fails.
										}

										CloseClipboard();
									}
								}
							}
						}
					}
					else if ( ker.wVirtualKeyCode == VK_UP )
					{
						if ( g_selected_index > 0 )
						{
							--g_selected_index;
							DoublyLinkedList *last_selected_item = g_selected_item;
							g_selected_item = g_selected_item->prev;

							GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

							EnterCriticalSection( &console_cs );

							if ( g_selection_offset == 0 )
							{
								g_first_visible = g_first_visible->prev;
								PrintList();
							}

							RefreshLine( ( AUTH_INFO * )last_selected_item->data, SELECTION_OFFSET + g_selection_offset, false );

							if ( g_selection_offset > 0 )
							{
								--g_selection_offset;
							}

							RefreshLine( ( AUTH_INFO * )g_selected_item->data, SELECTION_OFFSET + g_selection_offset, true );

							LeaveCriticalSection( &console_cs );
						}
					}
					else if ( ker.wVirtualKeyCode == VK_DOWN )
					{
						if ( g_selected_index < g_list_count - 1 )
						{
							++g_selected_index;
							DoublyLinkedList *last_selected_item = g_selected_item;
							g_selected_item = g_selected_item->next;

							GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

							EnterCriticalSection( &console_cs );

							if ( g_selection_offset >= VISIBLE_LINES - 1 )
							{
								g_first_visible = g_first_visible->next;
								PrintList();
							}

							RefreshLine( ( AUTH_INFO * )last_selected_item->data, SELECTION_OFFSET + g_selection_offset, false );

							if ( g_selection_offset < VISIBLE_LINES - 1 )
							{
								++g_selection_offset;
							}

							RefreshLine( ( AUTH_INFO * )g_selected_item->data, SELECTION_OFFSET + g_selection_offset, true );

							LeaveCriticalSection( &console_cs );
						}
					}
					else if ( ker.wVirtualKeyCode == 'A' )
					{
						EnableCursor( TRUE );

						GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

						ccp.X = 2;
						ccp.Y = INPUT_OFFSET;
						SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

						_printf( "Add username: " );

						SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
						ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

						if ( read > 2 )
						{
							read -= 2;

							unsigned int username_length = min( read, 254 );
							char *username = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( username_length + 1 ) );
							memcpy_s( username, sizeof( char ) * ( username_length + 1 ), g_console_buffer, username_length );
							username[ username_length ] = 0;	// Sanity.

							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

							ccp.X = 2;
							ccp.Y = INPUT_OFFSET;
							SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

							_printf( "Add key: " );

							SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
							ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

							if ( read > 2 )
							{
								read -= 2;

								unsigned int key_length = min( read, 254 );
								char *key = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( key_length + 1 ) );
								memcpy_s( key, sizeof( char ) * ( key_length + 1 ), g_console_buffer, key_length );
								key[ key_length ] = 0;	// Sanity.

								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

								EnterCriticalSection( &console_cs );

								AUTH_INFO *ai = ( AUTH_INFO * )GlobalAlloc( GMEM_FIXED, sizeof( AUTH_INFO ) );
								ai->username = username;
								ai->username_length = username_length;
								ai->key = key;
								ai->key_length = key_length;
								ai->code = GetTOTP( ai->key, ai->key_length );

								DoublyLinkedList *dll = DLL_CreateNode( ( void * )ai );
								DLL_AddNode( &g_list, dll, -1 );

								if ( g_list_count == 0 )
								{
									g_first_visible = g_list;
									g_selected_item = g_list;
								}

								++g_list_count;

								PrintList();

								LeaveCriticalSection( &console_cs );
							}
							else
							{
								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

								GlobalFree( username );
							}
						}
						else
						{
							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );
						}

						EnableCursor( FALSE );
					}
					else if ( ker.wVirtualKeyCode == 'E' )
					{
						if ( g_selected_item != NULL && g_selected_item->data != NULL )
						{
							AUTH_INFO *ai = ( AUTH_INFO * )g_selected_item->data;

							EnableCursor( TRUE );

							GetConsoleScreenBufferInfo( g_hOutput[ current_console ], &csbi );

							ccp.X = 2;
							ccp.Y = INPUT_OFFSET;
							SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

							_printf( "Edit username: " );

							FillConsoleInputLine( ai->username );

							SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
							ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

							if ( read > 2 )
							{
								read -= 2;

								unsigned int username_length = min( read, 254 );
								char *username = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( username_length + 1 ) );
								memcpy_s( username, sizeof( char ) * ( username_length + 1 ), g_console_buffer, username_length );
								username[ username_length ] = 0;	// Sanity.

								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

								ccp.X = 2;
								ccp.Y = INPUT_OFFSET;
								SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

								_printf( "Edit key: " );

								FillConsoleInputLine( ai->key );

								SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
								ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

								if ( read > 2 )
								{
									read -= 2;

									unsigned int key_length = min( read, 254 );
									char *key = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( key_length + 1 ) );
									memcpy_s( key, sizeof( char ) * ( key_length + 1 ), g_console_buffer, key_length );
									key[ key_length ] = 0;	// Sanity.

									FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

									EnterCriticalSection( &console_cs );

									char *tmp = ai->username;
									ai->username = username;
									GlobalFree( tmp );
									ai->username_length = username_length;

									tmp = ai->key;
									ai->key = key;
									GlobalFree( tmp );
									ai->key_length = key_length;
									ai->code = GetTOTP( ai->key, ai->key_length );

									RefreshLine( ai, SELECTION_OFFSET + g_selection_offset, true );

									LeaveCriticalSection( &console_cs );
								}
								else
								{
									FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );
								}
							}
							else
							{
								FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );
							}

							EnableCursor( FALSE );
						}
					}
					else if ( ker.wVirtualKeyCode == 'R' )
					{
						if ( g_selected_item != NULL )
						{
							EnableCursor( TRUE );

							ccp.X = 2;
							ccp.Y = INPUT_OFFSET;
							SetConsoleCursorPosition( g_hOutput[ current_console ], ccp );

							_printf( "Are you sure you want to remove the selected entry? (Y/N): " );

							SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
							ReadConsoleA( g_hInput, g_console_buffer, CONSOLE_BUFFER_SIZE + 1, &read, NULL );

							EnableCursor( FALSE );

							FillConsoleOutputCharacterA( g_hOutput[ current_console ], ' ', csbi.dwSize.X * csbi.dwSize.Y, ccp, &written );

							if ( read == 3 && g_console_buffer[ 0 ] == 'Y' || g_console_buffer[ 0 ] == 'y' )
							{
								EnterCriticalSection( &console_cs );

								DoublyLinkedList *tmp_dll = NULL;

								if ( g_first_visible != g_list )
								{
									int offset = g_list_count - g_selected_index;
									if ( offset <= VISIBLE_LINES &&
									   ( VISIBLE_LINES - offset ) == g_selection_offset )
									{
										tmp_dll = g_selected_item->prev;

										--g_selected_index;

										g_first_visible = g_first_visible->prev;
									}
									else
									{
										tmp_dll = g_selected_item->next;
									}
								}
								else
								{
									if ( g_selected_item == g_first_visible )
									{
										g_first_visible = g_first_visible->next;
									}

									if ( g_selected_item->next == NULL )
									{
										if ( g_selected_index > 0 )
										{
											--g_selected_index;
											--g_selection_offset;
										}

										tmp_dll = g_selected_item->prev;
									}
									else
									{
										tmp_dll = g_selected_item->next;
									}
								}

								--g_list_count;
								DLL_RemoveNode( &g_list, g_selected_item );

								AUTH_INFO *ai = ( AUTH_INFO * )g_selected_item->data;
								GlobalFree( ai->username );
								GlobalFree( ai->key );
								GlobalFree( ai );
								GlobalFree( g_selected_item );

								g_selected_item = tmp_dll;

								PrintList();

								LeaveCriticalSection( &console_cs );
							}
						}
					}
				}
			}
		}
		while ( read_console );

		// Show the console cursor position.
		EnableCursor( TRUE );

		EnterCriticalSection( &console_cs );
		EnableTimer( false );

		CleanupList();

		LeaveCriticalSection( &console_cs );
	}
	while ( g_status == 2 );

	// Exit our timer thread if it's active.
	if ( g_timer_semaphore != NULL )
	{
		ReleaseSemaphore( g_timer_semaphore, 1, NULL );
	}

	// Restore the old buffer.
	SetConsoleActiveScreenBuffer( g_hOutput_old );

	CloseHandle( g_hOutput[ 0 ] );
	CloseHandle( g_hOutput[ 1 ] );

	DeleteCriticalSection( &console_cs );

	CleanupCrypto();

	return 0;
}
