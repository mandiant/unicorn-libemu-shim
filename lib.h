#ifndef lib_H
#define lib_H

#include <stdint.h>
#include <stdio.h>
#include <hash_map>
#include <string>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <conio.h>
#include <signal.h>
#include <io.h>
#include <algorithm>
#include <stdlib.h>

#include <Shlobj.h>
#include <time.h>
#include <ctype.h>
#include <winsock.h>
#include <wininet.h>
#include <Shlobj.h>
#include <TlHelp32.h>

//additional user include directories set in project properties..
#include <unicorn_dynload.h>
#include <emu_shim.h>
#include <emu_env_w32.h>
#include <emu_env_w32_dll.h>
#include <emu_env_w32_dll_export.h>
#include <emu_string.h>

struct run_time_options
{
	uint32_t cur_step;
	uint32_t steps;
	unsigned char *scode;
	uint32_t size;        //shellcode size
	uint32_t baseAddress; //where in memory shellcode is based at
};

extern run_time_options opts;
extern int r32_t[9];
extern char *regm[];
extern uint32_t previous_eip;

extern emu_env_w32* env;
extern uc_engine *uc;
extern uc_engine *mem;
extern emu_cpu *cpu;

void dumpRegisters(void);
uint32_t popd(void);
void nl(void);
void set_ret(uint32_t val);
bool isWapi(char*fxName);
struct emu_string* popstring(void);
struct emu_string* popwstring(void);
int fulllookupAddress(uint32_t eip, char* buf255);
char* dllFromAddress(uint32_t addr);

#endif