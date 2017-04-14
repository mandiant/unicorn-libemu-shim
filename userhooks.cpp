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

#pragma warning(disable: 4311)
#pragma warning(disable: 4312)
#pragma warning(disable: 4267)
#pragma warning(disable: 4482)

#include "lib.h"

int32_t	__stdcall hook_LoadLibrary(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
/* 
   LoadLibraryA(LPCTSTR lpFileName); 
   LoadLibraryExA(LPCTSTR lpFileName, hFile, flags)
*/
	uint32_t eip_save = popd();
	struct emu_string *dllstr = isWapi(ex->fnname) ? popwstring() :  popstring();

	int i=0;
	int found_dll = 0;
	uint32_t dummy;

	char* func = ex->fnname;
    	
	if(strcmp(func, "LoadLibraryExA") ==0 ){
		dummy = popd();
		dummy = popd();
	}

	char *dllname = dllstr->data;

	if (found_dll == 0)
	{
		for (i=0; win->loaded_dlls[i] != NULL; i++)
		{
			if( _strnicmp(dllname, win->loaded_dlls[i]->dllname, strlen(win->loaded_dlls[i]->dllname)) == 0)
			//if (strstr(win->loaded_dlls[i]->dllname, dllname) == 0) //internal name array doesnt have dll extension, sc one can..5.9.15
			{
				cpu->reg[eax] = win->loaded_dlls[i]->baseaddr;
				found_dll = 1;
				break;
			}
		}
	}
	
	if (found_dll == 0)
	{
        if (emu_env_w32_load_dll(win, dllname) == 0)
        {
            cpu->reg[eax] = win->loaded_dlls[i]->baseaddr;
			found_dll = 1;
        }
        else
        {
            cpu->reg[eax] = 0;
        }
	}

	printf("%x\t%s(%s)\n",eip_save, func, dllname);
	if(found_dll == 0) printf("\tUnknown Dll - Not implemented by libemu\n");

	emu_string_free(dllstr);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_URLDownloadToFile(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{
	
/*
HRESULT URLDownloadToFile(
  LPUNKNOWN pCaller,
  LPCTSTR szURL,
  LPCTSTR szFileName,
  DWORD dwReserved,
  LPBINDSTATUSCALLBACK lpfnCB
);
*/
	uint32_t eip_save = popd();
	uint32_t p_caller = popd();
	struct emu_string *url = isWapi(ex->fnname) ? popwstring() : popstring();
	struct emu_string *filename = isWapi(ex->fnname) ? popwstring() : popstring();
	uint32_t reserved = popd();
	uint32_t statuscallbackfn = popd();

	printf("%x\t%s(%s, %s)\n",eip_save, ex->fnname, url->data , filename->data);

	cpu->reg[eax] = 0;
	emu_string_free(url);
	emu_string_free(filename);
    emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_WinExec(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* UINT WINAPI WinExec( LPCSTR lpCmdLine, UINT uCmdShow);*/
	uint32_t eip_save = popd();
	struct emu_string *cmdstr = popstring();
	uint32_t show = popd();
	 
	printf("%x\tWinExec(%s)\n",eip_save, cmdstr->data);

	emu_string_free(cmdstr);
	set_ret(32);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}


int32_t	__stdcall hook_ExitProcess(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{   /* VOID WINAPI ExitProcess(UINT uExitCode); */
	/* VOID ExitThread(DWORD dwExitCode); */
	uint32_t eip_save = popd();
	uint32_t exitcode = popd();
	printf("%x\t%s(%i)\n", eip_save, ex->fnname, exitcode);
	set_ret(0);
	emu_cpu_eip_set(cpu, eip_save);
	opts.steps = 0;
	return 0;
}


int32_t	__stdcall hook_GetProcAddress(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{ /* FFARPROC WINAPI GetProcAddress(  HMODULE hModule,  LPCSTR lpProcName);*/
	uint32_t eip_save = popd();
	uint32_t module = popd();
	struct emu_string *procname = popstring();

	uint32_t ordinal = 0;
	uint32_t index  = 0;
	int i;
	bool invalid = false;
	set_ret(0); //set default value of 0 (not found) //dzzie		

	for ( i=0; win->loaded_dlls[i] != NULL; i++ )
	{
		struct emu_env_w32_dll* dll = win->loaded_dlls[i];

		if ( dll->baseaddr == module )
		{
			if( procname->size == 0 ){ //either an error or an ordinal
				ordinal = procname->emu_offset;
				void* ehi = (*dll->exports_by_ordinal)[ordinal];
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}else{
				void* ehi = (*dll->exports_by_fnname)[emu_string_char(procname)];
				if ( ehi == NULL ) break;
				struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
				//logDebug(win->emu, "found %s at addr %08x\n",emu_string_char(procname), dll->baseaddr + hook->hook.win->virtualaddr );
				set_ret(dll->baseaddr + ex->virtualaddr);
				break;
			}
		}	
	}

	if(ordinal==0){
		printf("%x\tGetProcAddress(%s)\n",eip_save, emu_string_char(procname));
	}else{
		char buf[255]={0};
		fulllookupAddress(cpu->reg[eax], &buf[0]); 
		printf("%x\tGetProcAddress(%s.0x%x) - %s \n",eip_save, dllFromAddress(module), ordinal, buf);
	}

	if(module == 0 || cpu->reg[eax] == 0 ) printf("\tLookup not found: module base=%x dllName=%s\n", module, dllFromAddress(module) );  

	emu_string_free(procname);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

int32_t	__stdcall hook_GetSystemDirectoryA(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex)
{/* UINT GetSystemDirectory(   LPTSTR lpBuffer,   UINT uSize ); */
	uint32_t eip_save = popd();
	uint32_t p_buffer = popd();
	uint32_t size = popd();
	static char *sysdir = "c:\\WINDOWS\\system32";
	emu_memory_write_block(mem, p_buffer, sysdir, 20);
	set_ret(19);
	printf("%x\tGetSystemDirectoryA( c:\\windows\\system32\\ )\n",eip_save);
	emu_cpu_eip_set(cpu, eip_save);
	return 0;
}

