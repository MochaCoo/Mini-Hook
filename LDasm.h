#ifndef _LDASM_
#define _LDASM_

#include <stdint.h>
#include <string.h>

#ifdef USE64
    #define is_x64 1
#else
    #define is_x64 0
#endif//USE64

#ifdef __cplusplus
extern "C"
{
#endif

#define F_INVALID       0x01
#define F_PREFIX        0x02 //指令前缀 rep lock
#define F_REX           0x04
#define F_MODRM         0x08
#define F_SIB           0x10
#define F_DISP          0x20 //mov eax,[eax+ecx*4+0x1234]
#define F_IMM           0x40 //mov eax,0x12345678
#define F_RELATIVE      0x80
/*
 Instruction format:
 
 (prefix | REX)(0-4byte) | opcode(1-2byte)(eg:mov) | modR/M(0-1byte) | SIB(0-1byte) | disp8/16/32(0,1,2,4byte) | imm8/16/32/64(0,1,2,4byte) |
*/

typedef struct _ldasm_data
{
    uint8_t  flags;
    uint8_t  rex;
    uint8_t  modrm;//modR/M
    uint8_t  sib;//SIB
    uint8_t  opcd_offset;//opcode
    uint8_t  opcd_size;
    uint8_t  disp_offset;//disp偏移
    uint8_t  disp_size;
    uint8_t  imm_offset;//imm立即数 
    uint8_t  imm_size;
} ldasm_data;

unsigned int __stdcall ldasm(void* code, ldasm_data* ld, uint32_t is64);
unsigned long __stdcall SizeOfProc(void* Proc);
void* __stdcall ResolveJmp(void* Proc);

#ifdef __cplusplus
}
#endif

#endif//_LDASM_