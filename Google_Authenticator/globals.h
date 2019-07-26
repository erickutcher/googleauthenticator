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

#ifndef _GLOBALS_H
#define _GLOBALS_H

// Pretty window.
#pragma comment( linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"" )

#define STRICT
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>

#include "doublylinkedlist.h"

#define CONSOLE_BUFFER_SIZE			MAX_PATH

#define LEFT_PADDING				5
#define TOP_PADDING					5

#define HEADER_HEIGHT				( TOP_PADDING + 7 )
#define TIMER_OFFSET				( HEADER_HEIGHT + 1 )
#define LIST_OFFSET					( TIMER_OFFSET + 2 )
#define SELECTION_OFFSET			( LIST_OFFSET + 2 )
#define LIST_MOD_HEIGHT				3

#define VISIBLE_LINES				10

#define FRAME_HEIGHT	 			( SELECTION_OFFSET + VISIBLE_LINES + LIST_MOD_HEIGHT )

#define INPUT_OFFSET				( FRAME_HEIGHT + 2 )

struct AUTH_INFO
{
	char *key;
	char *username;
	unsigned int code;
	unsigned int key_length;
	unsigned int username_length;
};

extern DoublyLinkedList *g_list;
extern int g_list_count;

extern HANDLE g_hInput;
extern HANDLE g_hOutput[ 2 ];
extern unsigned char current_console;

#endif
