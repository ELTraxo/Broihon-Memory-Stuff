#pragma once

#ifndef MEMORY_EXT_H
#define MEMORY_EXT_H

#include <Windows.h>
//#include "NT Func.h"

#define H_CURRENT_PROCESS (void*)-1

typedef unsigned __int64 QWORD;

UINT_PTR GetDMA(HANDLE hProc, UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel);

bool SetDebugPrivilege(bool Enable = true);

bool IsValidHandle(HANDLE hObject);

HANDLE GetProcessByNameA(const char		* szProcess, DWORD Access = PROCESS_ALL_ACCESS);

HANDLE GetProcessByNameW(const wchar_t	* szProcess, DWORD Access = PROCESS_ALL_ACCESS);

UINT_PTR GetModuleBaseA(const char		* szModule, DWORD ProcID);

UINT_PTR GetModuleBaseW(const wchar_t	* szModule, DWORD ProcID);

bool NopCode(HANDLE hProc, UINT_PTR Address, SIZE_T Size);

//ULONG_PTR GetThreadStartAddress(HANDLE hThread);

#ifdef UNICODE
#define GetProcessByName GetProcessByNameW
#define GetModuleBase GetModuleBaseW
#else
#define GetProcessByName GetProcessByNameA
#define GetModuleBase GetModuleBaseA
#endif

#pragma region READ

template <class T>
T ReadMemory(HANDLE hProc, UINT_PTR Address)
{
	T Ret;
	ReadProcessMemory(hProc, reinterpret_cast<void*>(Address), &Ret, sizeof(T), nullptr);
	return Ret;
}

template <class T>
BOOL ReadMemory(HANDLE hProc, UINT_PTR Address, T & Out)
{
	return ReadProcessMemory(hProc, reinterpret_cast<void*>(Address), Out, sizeof(T), nullptr);
}

template <class T>
BOOL ReadMemory(HANDLE hProc, UINT_PTR Address, T & Out, SIZE_T Count)
{
	return ReadProcessMemory(hProc, reinterpret_cast<void*>(Address), Out, sizeof(T) * Count, nullptr);
}

template <class T>
T ReadDMA(HANDLE hProc, UINT_PTR BaseAddress, DWORD * Offset, UINT PointerLevel)
{
	return ReadMemory<T>(hProc, GetDMA(hProc, BaseAddress, Offset, PointerLevel));
}

template <class T>
BOOL ReadDMA(HANDLE hProc, UINT_PTR BaseAddress, DWORD * Offset, UINT PointerLevel, T & Out)
{
	return ReadMemory<T>(hProc, GetDMA(hProc, BaseAddress, Offset, PointerLevel), Out);
}

template <class T>
BOOL ReadDMA(HANDLE hProc, UINT_PTR BaseAddress, DWORD * Offset, UINT PointerLevel, T & Out, SIZE_T Count)
{
	return ReadMemory<T>(hProc, GetDMA(hProc, BaseAddress, Offset, PointerLevel), Out, Count);
}

#define ReadByte	ReadMemory<BYTE>
#define ReadWord	ReadMemory<WORD>
#define ReadDword   ReadMemory<DWORD>
#define ReadQword   ReadMemory<QWORD>
#define ReadChar	ReadMemory<char>
#define ReadShort	ReadMemory<short>
#define ReadLong	ReadMemory<long>
#define ReadLLong	ReadMemory<long long>
#define ReadInt8	ReadMemory<__int8>
#define ReadInt16	ReadMemory<__int16>
#define ReadInt32	ReadMemory<__int32>
#define ReadInt64	ReadMemory<__int64>

#pragma endregion

#pragma region WRITE

template <class T>
BOOL WriteMemory(HANDLE hProc, UINT_PTR Address, const T & Data)
{
	return WriteProcessMemory(hProc, reinterpret_cast<void*>(Address), &Ret, sizeof(T), nullptr);
}

template <class T>
BOOL WriteMemory(HANDLE hProc, UINT_PTR Address, const T * Data, SIZE_T Count)
{
	return WriteProcessMemory(hProc, reinterpret_cast<void*>(Address), Data, sizeof(T) * Count, nullptr);
}

template <class T>
BOOL WriteDMA(HANDLE hProc, UINT_PTR BaseAddress, DWORD * Offset, UINT PointerLevel, const T & Data)
{
	return WriteMemory<T>(hProc, GetDMA(hProc, BaseAddress, Offset, PointerLevel), Data);
}

template <class T>
BOOL WriteDMA(HANDLE hProc, UINT_PTR BaseAddress, DWORD * Offset, UINT PointerLevel, const T & Data, SIZE_T Count)
{
	return WriteMemory<T>(hProc, GetDMA(hProc, BaseAddress, Offset, PointerLevel), Data, Count);
}

#define WriteByte	WriteMemory<BYTE>
#define WriteWord	WriteMemory<WORD>
#define WriteDword  WriteMemory<DWORD>
#define WriteQword  WriteMemory<QWORD>
#define WriteChar	WriteMemory<char>
#define WriteShort	WriteMemory<short>
#define WriteLong	WriteMemory<long>
#define WriteLLong	WriteMemory<long long>
#define WriteInt8	WriteMemory<__int8>
#define WriteInt16	WriteMemory<__int16>
#define WriteInt32	WriteMemory<__int32>
#define WriteInt64	WriteMemory<__int64>

#pragma endregion

#endif