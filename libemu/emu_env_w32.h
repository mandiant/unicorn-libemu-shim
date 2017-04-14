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

#ifndef HAVE_EMU_ENV_W32
#define HAVE_EMU_ENV_W32

#include <stdint.h>
#include <unicorn.h>

struct emu_env_w32_dll;
struct emu_env_w32_dll_export;

/**
 * the emu win32 enviroment struct
 * 
 * @see emu_env_w32_new
 */
struct emu_env_w32
{
	uc_engine *uc;
	struct emu_env_w32_dll **loaded_dlls;
	uint32_t	baseaddr;
	char*		lastApiCalled;   //used for filtering spammy calls dzzie 5.18.11
	uint32_t    lastApiHitCount;
	uint32_t	totalApiHits;
};

/**
 * Create a new emu_env_w32 environment
 * 
 * @param e      the emulation to create the w32 process environment in
 * 
 * @return on success: pointer to the emu_env_w32 create
 *         on failure: NULL
 */
struct emu_env_w32 *emu_env_w32_new(uc_mode mode = uc_mode::UC_MODE_32);


/**
 * Free the emu_env_w32, free all dlls etc
 * 
 * @param env    the env to free
 */
void emu_env_w32_free(struct emu_env_w32 *env);

int32_t emu_env_w32_load_dll(struct emu_env_w32 *env, char *path);


//added dzzie 5.10.11
int32_t emu_env_w32_export_new_hook_ordinal(struct emu_env_w32 *env,
								const char *dllname,
								uint32_t ordinal,
								int32_t	(__stdcall *fnhook)(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
								);
//added dzzie 1-23-11
int32_t emu_env_w32_export_new_hook(struct emu_env_w32 *env,
								const char *exportname, 
								int32_t (__stdcall *fnhook)(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex),
								void *userdata);
//added dzzie 5.15.12
void emu_env_w32_set_hookDetect_monitor(uint32_t lpfnCallback);

//added dzzie 2.24.13
//void emu_env_w32_set_syscall_monitor(uint32_t lpfnCallback);
//char* emu_env_w32_getSyscall_service_name(uint32_t service);

/**
 * Check if eip is within a loaded dll,
 *  - call the dll's export function
 * 
 * @param env    the env
 * 
 * @return on success: pointer to the dll_export
 *         on failure: NULL
 */
struct emu_env_w32_dll_export *emu_env_w32_eip_check(struct emu_env_w32 *env);


#endif

