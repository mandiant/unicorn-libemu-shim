#ifndef emu_shim_H
#define emu_shim_H

/*
   libemu / Unicorn compatibility shim layer 
   Contributed by FireEye FLARE team
   Author: David Zimmer <david.zimmer@fireeye.com> <dzzie@yahoo.com>
   License: GPL
*/

//#include "./libdasm/libdasm.h"
#include <unicorn_dynload.h>
#include "emu_cpu.h"
#include <string.h>

enum emu_reg32 {
	eax = 0, ecx, edx, ebx, esp, ebp, esi, edi, eip
};

emu_cpu *emu_cpu_get(uc_engine *uc);
uc_engine *emu_memory_get(uc_engine *uc);

void emu_cpu_eip_set(uc_engine *uc, uint32_t value);
void emu_cpu_eip_set(emu_cpu *cpu, uint32_t value);
uint32_t emu_cpu_eip_get(uc_engine *uc);

int emu_memory_write_block(uc_engine *uc, uint32_t address, void* data, uint32_t size);
int emu_memory_write_dword(uc_engine *uc, uint32_t address, uint32_t value);
int32_t emu_memory_write_byte(uc_engine *uc, uint32_t addr, uint8_t byte);
int32_t emu_memory_write_word(uc_engine *uc, uint32_t addr, uint16_t *word);

uint32_t emu_reg32_read(uc_engine *uc, emu_reg32 regid);
void emu_reg32_write(uc_engine *uc, emu_reg32 regid, uint32_t value);

int32_t emu_memory_read_dword(uc_engine *uc, uint32_t addr, uint32_t *dword);
int32_t emu_memory_read_block(uc_engine *uc, uint32_t addr, void *dest, size_t len);
int32_t emu_memory_read_byte(uc_engine *uc, uint32_t addr, uint8_t *byte);


int32_t emu_memory_read_string(uc_engine *uc, uint32_t addr, struct emu_string *s, uint32_t maxsize);
int32_t emu_memory_read_wide_string(uc_engine *uc, uint32_t addr, struct emu_string *s, uint32_t maxsize);

void* bcopy (void* src, void* dest, unsigned int len);


#endif
