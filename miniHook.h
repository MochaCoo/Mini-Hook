#pragma once
#include <stdio.h>
#include <Windows.h>
#include "LDasm.h"
//待解决:大量HOOK相近地址时存在大量函数HOOK Bridge的空间浪费,但有时似乎又是微不足道的
//https://www.cnblogs.com/luconsole/p/14813573.html
//线程安全:启用和清除HOOK时,在附加hook的时候，暂停当前进程内 除当前线程外的其他所有线程，再继续执行附加hook的逻辑，附加hook完成之后，判断其他所有线程的eip，就是执行的代码地址，是否为目标函数的前几个覆盖的字节，如果是，需要把eip重新设置到跳板函数对应的位置。最后重新启动其他所有线程。

class miniHook
{
private:
	void* HookAddr;//被Hook地址,只修改首地址5字节
	unsigned int len;//被Hook字节数
	void* HookFunc;//用于Hook函数
	void* Bridge;//x86: 原函数原来的指令 + jmp  x64: Call原函数桥梁: [(原函数原来的指令 + jmp)] + [far jmp(HOOK 函数中转)]
#ifdef _WIN64
	void* AllocAt(void* Addr, size_t l);//在指定地址附近+-2GB处申请一块内存
#endif
public:
	~miniHook();
	miniHook();
	miniHook(void* Addr, void* NewFunc, BOOL Start = true);
	void* Set(void* Addr, void* NewFunc
		, BOOL Start = true//是否立即开始Hook
	);//返回新的函数地址
	BOOL Start();//Hook原函数前5字节
	BOOL Stop();//还原原函数前5字节
	void* GetBridge();
};