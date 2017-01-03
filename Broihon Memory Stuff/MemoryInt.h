#pragma once

#ifndef MEMORY_INT_H
#define MEMORY_INT_H

#include <Windows.h>

typedef unsigned __int64 QWORD;
#ifdef ReCa
#undef ReCa
#endif
#define ReCa reinterpret_cast

UINT_PTR GetDMA(UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel);
UINT_PTR GetDMA_s(UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel);
bool IsValidWritePtr(void * Ptr);
bool IsValidReadPtr(void * Ptr);
HANDLE CreateThreadAtAddress(PTHREAD_START_ROUTINE pFunc, void * pArg, BYTE * pAddress = nullptr);

template <class T>
T CreateFunctionTrp(T TargetFunc, BYTE * pLocation = nullptr)
{
#ifdef _WIN64

	BYTE Codecave[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x00 (+ 0x00)	-> db: pFunc
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x08			-> db: pOldRet
		0x48, 0x8B, 0x04, 0x24,							// + 0x10			-> mov rax, [rsp]
		0x48, 0x89, 0x05, 0xED, 0xFF, 0xFF, 0xFF,		// + 0x14			-> mov [ppOldRet], rax
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,		// + 0x1B (+ 0x1E)	-> mov [rsp], LO_DWORD(Codecave + 0x30)
		0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,	// + 0x22 (+ 0x26)	-> mov [rsp + 4], HI_DWORD(Codecave + 0x30)
		0xFF, 0x25, 0xD0, 0xFF, 0xFF, 0xFF,				// + 0x2A			-> jmp [ppFunc]
		0xFF, 0x25, 0xD2, 0xFF, 0xFF, 0xFF				// + 0x30			-> jmp [ppOldRet]
	};

#else

	BYTE Codecave[] =
	{
		0x00, 0x00, 0x00, 0x00,						// + 0x00			-> db: pOldRet
		0x8B, 0x04, 0x24,							// + 0x04			-> mov eax, [esp]
		0x89, 0x05, 0x00, 0x00, 0x00, 0x00,			// + 0x07 (+ 0x09)	-> mov [ppOldRet], eax
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x0D (+ 0x10)	-> mov [esp], Codecave + 0x19
		0xE9, 0x00, 0x00, 0x00, 0x00,				// + 0x14 (+ 0x15)	-> jmp Func
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00			// + 0x19 (+ 0x1B)	-> jmp [ppOldRet]
	};

#endif

	DWORD dwOld;
	if (!pLocation)
		pLocation = reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, sizeof(Codecave), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	else
		if (!VirtualProtect(pLocation, sizeof(Codecave), PAGE_EXECUTE_READWRITE, &dwOld))
			return (T)nullptr;

	if (!pLocation)
		return (T)nullptr;

#ifdef _WIN64

	DWORD dwLoFunc = (DWORD)(((UINT_PTR)pLocation + 0x30) & 0xFFFFFFFF);
	DWORD dwHiFunc = (DWORD)((((UINT_PTR)pLocation + 0x30) >> 0x20) & 0xFFFFFFFF);

	*reinterpret_cast<T*>(Codecave + 0x00) = TargetFunc;
	*reinterpret_cast<DWORD*>(Codecave + 0x1E) = dwLoFunc;
	*reinterpret_cast<DWORD*>(Codecave + 0x26) = dwHiFunc;

#else

	*reinterpret_cast<DWORD*>(Codecave + 0x09) = reinterpret_cast<DWORD>(pLocation);
	*reinterpret_cast<DWORD*>(Codecave + 0x10) = reinterpret_cast<DWORD>(pLocation) + 0x19;
	*reinterpret_cast<DWORD*>(Codecave + 0x15) = (DWORD)TargetFunc - reinterpret_cast<DWORD>(pLocation + 0x14) - 5;
	*reinterpret_cast<DWORD*>(Codecave + 0x1B) = reinterpret_cast<DWORD>(pLocation);

#endif

	memcpy(pLocation, Codecave, sizeof(Codecave));
	VirtualProtect(pLocation, sizeof(Codecave), dwOld, &dwOld);

#ifdef _WIN64
	return (T)(pLocation + 0x10);
#else
	return (T)(pLocation + 0x4);
#endif
}

#pragma region READ

template <class T>
T Read(UINT_PTR Address)
{
	if (Address)
		return *ReCa<T*>(Address);
	return 0;
}

template <class T>
T Read(UINT_PTR BaseAddress, UINT_PTR * Offset, UINT PointerLevel)
{
	return Read<T>(GetDMA(BaseAddress, Offset, PointerLevel));
}

template <class T>
T Read_s(UINT_PTR Address)
{
	if (IsValidReadPtr(ReCa<void*>(Address)))
		return *ReCa<T*>(Address);
	return 0;
}

template <class T>
T Read_s(UINT_PTR BaseAddress, UINT_PTR * Offset, UINT PointerLevel)
{
	return Read_s<T>(GetDMA(BaseAddress, Offset, PointerLevel));
}

#pragma endregion

#pragma region WRITE

template <class T>
bool Write(UINT_PTR Address, T Data)
{
	if (!Address)
		return false;

	*ReCa<T*>(Address) = Data;
	return true;
}

template <class T>
bool Write(UINT_PTR BaseAddress, UINT_PTR * Offset, UINT PointerLevel, T Data)
{
	return Write(GetDMA(BaseAddress, Offset, PointerLevel), Data);
}

template <class T>
bool Write_s(UINT_PTR Address, T Data)
{
	if (!IsValidWritePtr(ReCa<void*>(Address)))
		return false;

	*ReCa<T*>(Address) = Data;
	return true;
}

template <class T>
bool Write_s(UINT_PTR BaseAddress, UINT_PTR * Offset, UINT PointerLevel, T Data)
{
	return Write_s(GetDMA(BaseAddress, Offset, PointerLevel), Data);
}
#pragma endregion

#endif