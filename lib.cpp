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

#include <stdint.h>
#include <stdio.h>
#include <conio.h>

#include "lib.h"

char *regm[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"};
uint32_t last_good_eip = 0;
uint32_t previous_eip  = 0;

void dumpRegisters(void){
	for(int i=0;i<9;i++){
		printf("%s=%-8x  ", regm[i], emu_reg32_read(uc,(emu_reg32)i) );
		if(i==3)printf("\n");
	}
	//dumpFlags(emu_cpu_get(e));
	printf("\n");
} 

uint32_t popd(void){
	uint32_t x=0;
	uint32_t r_esp = emu_reg32_read(uc, esp);
	if( emu_memory_read_dword(uc, r_esp, &x) == -1){
		printf("Failed to read stack memory at 0x%x", r_esp);
		exit(0);
	}
	emu_reg32_write(uc, esp, r_esp+4); 
	return x;
}

void set_ret(uint32_t val){
		emu_reg32_write(uc, eax, val); 
} 

bool isWapi(char*fxName){
	int x = strlen(fxName)-1;
	return fxName[x] == 'W' ? true : false;
}

struct emu_string* popstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_string(uc, addr, str, 1256);
	return str;
}

struct emu_string* popwstring(void){
	uint32_t addr = popd();
	struct emu_string *str = emu_string_new();
	emu_memory_read_wide_string(uc, addr, str, 1256);
	return str;
}

void nl(void){ printf("\n"); }

int fulllookupAddress(uint32_t eip, char* buf255){

	int numdlls=0;
	int i=0;
	strcpy(buf255," ");

	/*additional lookup for a couple addresses not in main tables..
	while(mm_points[i].address != 0){
		if(eip == mm_points[i].address){
			strcpy(buf255, mm_points[i].name);
			return 1;
		}
		i++;
	}*/

	while ( env->loaded_dlls[numdlls] != 0 )
	{
		if ( eip == env->loaded_dlls[numdlls]->baseaddr ){
			
			if(eip == 0x7C800000)
				strcpy(buf255, "Kernel32 Base Address");
			else
				sprintf(buf255, "%s Base Address", env->loaded_dlls[numdlls]->dllname );
			
			return 1;
		}
		else if ( eip > env->loaded_dlls[numdlls]->baseaddr && 
			      eip < env->loaded_dlls[numdlls]->baseaddr + 
				            env->loaded_dlls[numdlls]->imagesize )
		{
			struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls];
			void* ehi = (*dll->exports_by_fnptr)[eip - dll->baseaddr];

			if ( ehi == 0 )	return 0;

			struct emu_env_w32_dll_export *ex = (struct emu_env_w32_dll_export *)ehi;
			strncpy(buf255, ex->fnname, 254);
			return 1;

		}
		numdlls++;
	}

	return 0;
}

char* dllFromAddress(uint32_t addr){
	int numdlls=0;
	while ( env->loaded_dlls[numdlls] != 0 ){
		struct emu_env_w32_dll *dll = env->loaded_dlls[numdlls]; 
		if( addr >= dll->baseaddr && addr <= (dll->baseaddr + dll->imagesize) ){
			return dll->dllname;
		}
		numdlls++;
	}
	return strdup(""); //mem leak but no crash choose your fights
}
