#include "emu_shim.h"
#include "emu_string.h"

/*
   libemu / Unicorn compatibility shim layer 
   Contributed by FireEye FLARE team
   Author: David Zimmer <david.zimmer@fireeye.com> <dzzie@yahoo.com>
   License: GPL
*/


int r32_t[9] = { UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, 
                 UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, 
                 UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP};

//the code in this file is so that we can port code from existing libemu projects
//over to unicorn without having to change all that much

//these next 3 classes are used to make the following work...(used to be access to a struct and direct access to register array)
//x = cpu->reg[eax];  cpu->reg[eax]= x;  
//x = cpu->eip ;      cpu->eip = x ;
void CAccessCheck::operator=(uint32_t v) 
{
    if(role==1){ //eip 
        emu_cpu_eip_set(this->uc,v);
    }
    else if(role==2){ //eflags
        uc_reg_write(this->uc,UC_X86_REG_EFLAGS,&v);
    }
    else if(role==32){ //32bit register access
        emu_reg32_write(this->uc,(emu_reg32)index,v);
    }

    //printf("SET index: %d   value: %d   role:%d\n",index,v,role);      
}

CAccessCheck::operator uint32_t const() 
{
    int ret;

    if(role==1){ //eip 
        ret = emu_cpu_eip_get(this->uc);
    }
    else if(role==2){ //eflags
        uc_reg_read(this->uc,UC_X86_REG_EFLAGS,&ret);
    }
    else if(role==32){ //32bit register access
        ret = emu_reg32_read(this->uc,(emu_reg32)index);
    }

    //printf("GET  index: %d   role:=%d\n", index, role); 
    return ret;
}   

emu_cpu::emu_cpu(uc_engine* engine){
    this->uc = engine;
    this->mem = engine;
    eip = CAccessCheck(1,engine);
    eflags = CAccessCheck(2,engine);
    reg = CRegAccess(32,engine);
    //reg16 = CRegAccess(16,engine);
    //reg8 = CRegAccess(8,engine);
}

emu_cpu *emu_cpu_get(uc_engine *uc){
    return new emu_cpu(uc);
}

uc_engine *emu_memory_get(uc_engine *uc){
    return uc;   
}

void* bcopy (void* src, void* dest, unsigned int len){
	return memcpy(dest, src, len);
}

int32_t emu_memory_write_word(uc_engine *uc, uint32_t addr, uint16_t *word){
    return emu_memory_write_block(uc, addr, &word,2);
}

int emu_memory_write_block(uc_engine *uc, uint32_t address, void* data, uint32_t size){
	uc_err x;
	uint32_t base = address;
    uint32_t sz = size;

	while(base % 0x1000 !=0){
		base--;
		if(base==0) break;
	}
	
	sz += address-base; //if data starts mid block, we need to alloc more than just size..
	while(sz % 0x1000 !=0){
		sz++;
	}

	x = uc_mem_map(uc, base, sz, UC_PROT_ALL); //let write determine final error..
	x = uc_mem_write(uc, address, (void*)data, size);

	return (x == UC_ERR_OK) ? 0 : -1; //map to expected libemu error codes
}

int emu_memory_write_dword(uc_engine *uc, uint32_t address, uint32_t value){
    return emu_memory_write_block(uc, address, &value,4);
}

uint32_t emu_cpu_eip_get(uc_engine *uc){
	uint32_t r_eip=0;
	uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
	return r_eip;
}

void emu_cpu_eip_set(emu_cpu *cpu, uint32_t value){
	//uc_reg_write(uc, UC_X86_REG_EIP, &value);
    cpu->eip = value;
}

void emu_cpu_eip_set(uc_engine *uc, uint32_t value){
	uc_reg_write(uc, UC_X86_REG_EIP, &value);
}

uint32_t emu_reg32_read(uc_engine *uc, emu_reg32 regid){
	uint32_t v=0;
	if(regid > 9) return -1;
	uc_reg_read(uc, r32_t[regid], &v);
	return v;
}

void emu_reg32_write(uc_engine *uc, emu_reg32 regid, uint32_t value){
	uint32_t v=0;
	if(regid > 9) return;
	uc_reg_write(uc, r32_t[regid], &value);
}

int32_t emu_memory_read_dword(uc_engine *uc, uint32_t addr, uint32_t *dword){
	return emu_memory_read_block(uc, addr, dword, 4);
}

int32_t emu_memory_read_byte(uc_engine *uc, uint32_t addr, uint8_t *byte){
	return emu_memory_read_block(uc, addr, byte, 1);
}

int32_t emu_memory_read_block(uc_engine *uc, uint32_t addr, void *dest, size_t len){
	uc_err e = uc_mem_read(uc, addr, dest, len);
	return e == UC_ERR_OK ? 0 : -1; //map to expected libemu error codes
}

//these next two were taken from scdbg
//------------------------------------------------------------
//modified so that even if it fails it still returns an empty string..makes logging easier.. -dzzie 3.10.11
//note reads to first null, size is set to strlen(), error size = 0\
//behavior changed again 6.7.11 -> read of partial strings ok.. not complete fail -dzzie
// + now allows for object reuse without memory leak
int32_t emu_memory_read_string(uc_engine *uc, uint32_t addr, struct emu_string *s, uint32_t maxsize)
{
	uint32_t i = 0;
	uint8_t b = 0;

	while( 1 )
	{
		if(emu_memory_read_byte(uc,addr+i,&b) != 0) break;
		if (i > maxsize - 1) break;
		if( b == '\0' ) break;
		i++;
	}

	s->emu_offset = addr;
	s->invalidAddress = 0;
	if( s->data != NULL ) free(s->data); //allow object reuse without memleak..

	if(addr == 0){
		s->data = (char*)malloc(4);
		strcpy((char*)s->data, "");
		s->size = 0;
		s->invalidAddress = 1;
		return 0;
	}else{
		s->data = (char*)malloc(i + 1);
		memset(s->data, 0, i + 1); //always null terminated..
		s->size = i;
		return emu_memory_read_block(uc, addr, s->data, i);
	}

}

int32_t emu_memory_read_wide_string(uc_engine *uc, uint32_t addr, struct emu_string *s, uint32_t maxsize)
{
	uint32_t i = 0;
	int outSize = 0;
	uint32_t read = 0;
	uint32_t j=0;

	s->emu_offset = addr;
	s->invalidAddress = 0;
	if( s->data != NULL ) free(s->data); //allow object reuse without memleak..
	
	char* tmp = (char*)malloc(maxsize);
	read = emu_memory_read_block(uc, addr, tmp, maxsize);

	if( read != -1){
		for(i=0; i < maxsize;i++){
			if(tmp[i]==0 && tmp[i+1]==0) break;
			if(tmp[i]!=0) outSize++;
		}
	}

	if( read == -1 || outSize==0){
		s->data = (char*)malloc(4);
		strcpy((char*)s->data, "");
		s->size = 0;
		s->invalidAddress = 1;
		free(tmp);
		return 0;
	}else{
		s->data = (char*)malloc(maxsize+2);
		memset(s->data, 0, maxsize+2); //always null terminated..
		s->size = outSize;
		for(i=0; i < maxsize;i++){
			if(tmp[i]==0 && tmp[i+1]==0) break;
			if(tmp[i]!=0) s->data[j++] = tmp[i];
		}
		return 1;
	}

}

int32_t emu_memory_write_byte(uc_engine *uc, uint32_t addr, uint8_t byte)
{
	return uc_mem_write(uc, addr,&byte,1) == UC_ERR_OK ? 0 : -1;
}
