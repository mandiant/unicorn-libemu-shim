/********************************************************************************
 *                               libemu
 *
 *                    - x86 shellcode emulation -
 *
 *
 * Copyright (C) 2007  Paul Baecher & Markus Koetter
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 * 
 *             contact nepenthesdev@users.sourceforge.net  
 *
 *******************************************************************************/

#ifndef HAVE_EMU_ENV_W32_DLL_H
#define HAVE_EMU_ENV_W32_DLL_H

#include <stdint.h>
#include <string>
#include <hash_map>

struct emu_env_w32_dll_export;

struct emu_env_w32_dll
{
	char 		*dllname;
	char        *version;
	char 		*image;
	uint32_t	imagesize;
	uint32_t	baseaddr;
	struct emu_env_w32_dll_export *exportx;
	stdext::hash_map <uint32_t, void*>    *exports_by_fnptr;
	stdext::hash_map <std::string, void*> *exports_by_fnname;
	stdext::hash_map <uint32_t, void*>    *exports_by_ordinal;
};

struct emu_env_w32_dll *emu_env_w32_dll_new();
//void emu_env_w32_dll_free(struct emu_env_w32_dll *dll);
void emu_env_w32_dll_exports_copy(struct emu_env_w32_dll *to, struct emu_env_w32_dll_export *from);


struct emu_env_w32_known_dll_segment
{
	uint32_t address;
	const char *segment;
	uint32_t	segment_size;
};

struct emu_env_w32_known_dll
{
	const char *dllname;
	const char *version;
	uint32_t 	baseaddress;
	uint32_t	imagesize;
	struct emu_env_w32_dll_export *exports;
	struct emu_env_w32_known_dll_segment *memory_segments;
};

#endif
