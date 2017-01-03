#include "MemoryInt.h"
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

#define MEM_WRITE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define MEM_EXEC_WRITE (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

UINT_PTR GetDMA(UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel)
{
	BaseAddress = Read<UINT_PTR>(BaseAddress);

	--PointerLevel;

	for (; PointerLevel && BaseAddress; --PointerLevel, ++Offsets)
		BaseAddress = Read<UINT_PTR>(BaseAddress + *Offsets);

	if (BaseAddress)
		return (BaseAddress + *Offsets);

	return 0;
}

UINT_PTR GetDMA_s(UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel)
{
	BaseAddress = Read_s<UINT_PTR>(BaseAddress);

	--PointerLevel;

	for (;PointerLevel && BaseAddress; --PointerLevel, ++Offsets)
		BaseAddress = Read_s<UINT_PTR>(BaseAddress + *Offsets);

	if (BaseAddress)
		return (BaseAddress + *Offsets);

	return 0;
}

bool IsValidWritePtr(void * Ptr)
{
	if (!Ptr)
		return false;

	MEMORY_BASIC_INFORMATION MBI{ 0 };
	if (!VirtualQuery(Ptr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
		return false;

	return (MBI.State == MEM_COMMIT && (MBI.Protect & MEM_WRITE) != 0);
}

bool IsValidReadPtr(void * Ptr)
{
	if (!Ptr)
		return false;

	MEMORY_BASIC_INFORMATION MBI{ 0 };
	if (!VirtualQuery(Ptr, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
		return false;

	if (MBI.State == MEM_COMMIT && !(MBI.Protect & PAGE_NOACCESS))
		return true;
	return false;
}

HANDLE CreateThreadAtAddress(PTHREAD_START_ROUTINE pFunc, void * pArg, BYTE * pAddress)
{
	if (!pFunc)
		return nullptr;

	bool Restore = false;
	if (pAddress)
		Restore = true;

	DWORD dwOld = 0;
	if (!pAddress)
		pAddress = reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	else if (!VirtualProtect(pAddress, 0x10, PAGE_EXECUTE_READWRITE, &dwOld))
		return nullptr;
	if (!pAddress)
		return nullptr;

	BYTE Buffer[0x10];
	if (Restore)
		memcpy(Buffer, pAddress, 0x10);

#ifdef _WIN64

	*pAddress = 0x48;
	*(pAddress + 1) = 0xB8;
	*reinterpret_cast<PTHREAD_START_ROUTINE*>(pAddress + 2) = pFunc;
	*(pAddress + 0xA) = 0xFF;
	*(pAddress + 0xB) = 0xE0;

#else

	*pAddress = 0xE9;
	*reinterpret_cast<DWORD*>(pAddress + 1) = (BYTE*)pFunc - pAddress - 5;

#endif

	HANDLE hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)pAddress, pArg, 0, nullptr);
	if (!hThread)
		VirtualFree(pAddress, 0x10, MEM_DECOMMIT);

	Sleep(100);
	if (Restore)
	{
		memcpy(pAddress, Buffer, 0x10);
		VirtualProtect(pAddress, 0x10, dwOld, &dwOld);
	}
	else
		VirtualFree(pAddress, 0x10, MEM_DECOMMIT);

	return hThread;
}