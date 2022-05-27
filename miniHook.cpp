#include "miniHook.h"
#ifdef _WIN64
#define IsX64 true
#else
#define IsX64 false
#endif

#ifdef _WIN64
void* miniHook::AllocAt(
	void* Addr,//Hook指令所在的地址
	size_t l)
{
	SYSTEM_INFO SystemInfo;
	MEMORY_BASIC_INFORMATION m;
	GetSystemInfo(&SystemInfo);

	if (VirtualQuery(Addr, &m, sizeof(m)) != sizeof(m))
		return NULL;

	for (ULONG_PTR i = (ULONG_PTR)m.AllocationBase + SystemInfo.dwAllocationGranularity; i < (ULONG_PTR)m.AllocationBase + 0x7fffffffu - SystemInfo.dwAllocationGranularity; i += SystemInfo.dwAllocationGranularity) {
		LPVOID r = VirtualAlloc((void*)i, l, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (r != NULL) {
			return r;
		}
	}
	for (ULONG_PTR i = (ULONG_PTR)m.AllocationBase - SystemInfo.dwAllocationGranularity; i > (ULONG_PTR)m.AllocationBase - 0x7fffffffu + SystemInfo.dwAllocationGranularity; i -= SystemInfo.dwAllocationGranularity) {
		LPVOID r = VirtualAlloc((void*)i, l, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (r != NULL) {
			return r;
		}
	}
	return NULL;
}
#endif

miniHook::~miniHook()
{
	this->Stop();
	if (this->Bridge != NULL)
		VirtualFree(this->Bridge, 0, MEM_RELEASE);
}

miniHook::miniHook()
{
	this->HookAddr = NULL;
	this->len = 0;
	this->NewFunc = NULL;
	this->Bridge = NULL;
}

miniHook::miniHook(void* Addr, void* NewFunc, BOOL Start)
{
	this->Set(Addr, NewFunc, Start);
}

void* miniHook::Set(void* Addr, void* NewFunc, BOOL Start)
{
	this->~miniHook();

	ldasm_data ld = { 0 };
	size_t l = 0;
	DWORD op;
	this->HookAddr = Addr;
	this->NewFunc = NewFunc;
	if (VirtualProtect(Addr, 16, PAGE_EXECUTE_READWRITE, &op) == FALSE)//hook内部函数时,设置内存属性可能会覆盖到正在执行的代码段,所以不能仅仅设置为PAGE_READWRITE
		return NULL;

	do {
		l += ldasm((void*)((ULONG_PTR)Addr + l), &ld, IsX64);
		if (ld.flags == F_INVALID)
			return NULL;
	} while (l < 5);
	this->len = l;

#ifdef _WIN64
	const char fj[] = { 0xff,0x25,0,0,0,0 };//far jmp
	this->Bridge = this->AllocAt(Addr, l + 5 + sizeof(fj) + sizeof(ULONG_PTR));
	//printf("\nBridge:%p\n", this->Bridge);
	if (this->Bridge == NULL)
		return NULL;

	memcpy((void*)this->Bridge, Addr, l);//拷贝因为HOOK被覆盖的指令

	ULONG_PTR offset5jmp = (ULONG_PTR)this->Bridge + l;
	*(char*)offset5jmp = 0xE9;//拷贝过来的指令后面添加jmp原函数(E9 +-2G偏移)
	*(DWORD*)(offset5jmp + 1) = ((ULONG_PTR)Addr + l) - ((offset5jmp) + 5);

	long long offset = ((ULONG_PTR)NewFunc) - ((ULONG_PTR)(Addr)+5);//计算New和HookAddr的偏移
	if ((signed int)0x80000000 <= offset && offset <= (signed int)0x7FFFFFFF) {
		if (Start) {
			*(char*)Addr = 0xE9;//+-2G范围内 直接E9 jmp
			*(DWORD*)((ULONG_PTR)Addr + 1) = offset;
		}
	}
	else {
		memcpy((void*)(offset5jmp + 5), fj, sizeof(fj));//原指令 + jmp原函数 + far jmp NewFunc
		*(ULONG_PTR*)(offset5jmp + 5 + sizeof(fj)) = (ULONG_PTR)NewFunc;
		if (Start) {
			*(char*)Addr = 0xE9;
			*(DWORD*)((ULONG_PTR)Addr + 1) = (offset5jmp + 5) - ((ULONG_PTR)(Addr)+5);
		}
	}

	DWORD op1;
	if (VirtualProtect(Addr, 16, op, &op1) == FALSE)
		return NULL;
	if (VirtualProtect(this->Bridge, l + 5 + sizeof(fj) + sizeof(ULONG_PTR), PAGE_EXECUTE_READ, &op1) == FALSE)
		return NULL;
#else
	this->Bridge = VirtualAlloc(NULL, l + 5, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (this->Bridge == NULL)
		return NULL;
	memcpy((void*)this->Bridge, Addr, l);//拷贝因为HOOK被覆盖的指令

	ULONG_PTR offset5jmp = (ULONG_PTR)this->Bridge + l;//拷贝过来的指令后面添加jmp原函数
	*(char*)offset5jmp = 0xE9;
	*(ULONG_PTR*)(offset5jmp + 1) = ((ULONG_PTR)Addr + l) - ((offset5jmp)+5);

	if (Start) {
		*(char*)Addr = 0xE9;
		*(PDWORD)((ULONG_PTR)Addr + 1) = (ULONG_PTR)NewFunc - ((ULONG_PTR)(Addr) + 5);
	}

	DWORD op1;
	if (VirtualProtect(Addr, 16, op, &op1) == FALSE)
		return NULL;
	if (VirtualProtect(this->Bridge, l + 5, PAGE_EXECUTE_READ, &op1) == FALSE)
		return NULL;
#endif
	return this->Bridge;
}

BOOL miniHook::Start()
{
	if (this->HookAddr == NULL || this->Bridge == NULL || this->NewFunc == NULL || this->len == 0)
		return false;

	DWORD op;
	if (VirtualProtect(this->HookAddr, 5, PAGE_EXECUTE_READWRITE, &op) == FALSE)
		return false;
	*(char*)this->HookAddr = 0xE9;
#ifdef _WIN64
	long long offset = ((ULONG_PTR)this->NewFunc) - (((ULONG_PTR)this->HookAddr) + 5);
	if ((signed int)0x80000000 <= offset && offset <= (signed int)0x7FFFFFFF)
		*(DWORD*)((ULONG_PTR)this->HookAddr + 1) = offset;
	else
		*(DWORD*)((ULONG_PTR)this->HookAddr + 1) = ((ULONG_PTR)this->Bridge + this->len + 5) - ((ULONG_PTR)(this->HookAddr) + 5);
#else
	* (DWORD*)((ULONG_PTR)this->HookAddr + 1) = ((ULONG_PTR)this->NewFunc) - ((ULONG_PTR)(this->HookAddr) + 5);
#endif
	DWORD op1;
	if (VirtualProtect(this->HookAddr, 5, op, &op1) == FALSE)
		return false;
	return true;
}

BOOL miniHook::Stop()
{
	if (this->HookAddr == NULL || this->Bridge == NULL)
		return false;

	DWORD op;
	if (VirtualProtect(this->HookAddr, 5, PAGE_EXECUTE_READWRITE, &op) == FALSE)
		return false;
	memcpy(this->HookAddr, this->Bridge, 5);//this->l

	DWORD op1;
	if (VirtualProtect(this->HookAddr, 5, op, &op1) == FALSE)
		return false;
	return true;
}

void* miniHook::GetBridge()
{
	return this->Bridge;
}