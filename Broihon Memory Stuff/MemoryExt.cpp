#include "MemoryExt.h"
#include <TlHelp32.h>

#ifdef UNICODE //Thanks, Bill
#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

UINT_PTR GetDMA(HANDLE hProc, UINT_PTR BaseAddress, UINT_PTR * Offsets, UINT PointerLevel)
{
	if (!ReadProcessMemory(hProc, reinterpret_cast<void*>(BaseAddress), &BaseAddress, sizeof(BaseAddress), nullptr))
		return 0;

	--PointerLevel;

	for (; PointerLevel; --PointerLevel, ++Offsets)
		if (!ReadProcessMemory(hProc, reinterpret_cast<void*>(BaseAddress + *Offsets), &BaseAddress, sizeof(BaseAddress), nullptr) || !BaseAddress)
			return 0;

	return (BaseAddress + *Offsets);
}

bool SetDebugPrivilege(bool Enable)
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

	if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &TokenPrivileges.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	return true;
}

bool IsValidHandle(HANDLE hObject)
{
	if (!hObject)
		return false;

	DWORD dwFlags = 0;
	if (!GetHandleInformation(hObject, &dwFlags))
		return false;
	return true;
}

HANDLE GetProcessByNameA(const char * szProcess, DWORD Access)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 PE32 = { 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32);

	if (!szProcess || !hSnap)
		return nullptr;

	BOOL Ret = Process32First(hSnap, &PE32);
	while (Ret)
	{
		if (!strcmp(szProcess, PE32.szExeFile))
		{
			CloseHandle(hSnap);
			return OpenProcess(Access, FALSE, PE32.th32ProcessID);
		}
		Ret = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	return nullptr;
}

HANDLE GetProcessByNameW(const wchar_t * szProcess, DWORD Access)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W PE32 = { 0 };
	PE32.dwSize = sizeof(PROCESSENTRY32W);

	if (!szProcess || !hSnap)
		return nullptr;

	BOOL Ret = Process32FirstW(hSnap, &PE32);
	while (Ret)
	{
		if (!wcscmp(szProcess, PE32.szExeFile))
		{
			CloseHandle(hSnap);
			return OpenProcess(Access, FALSE, PE32.th32ProcessID);
		}
		Ret = Process32NextW(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	return nullptr;
}

UINT_PTR GetModuleBaseA(const char * szModule, DWORD ProcID)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcID);
	MODULEENTRY32 ME32 = { 0 };
	ME32.dwSize = sizeof(MODULEENTRY32);

	if (!szModule || !hSnap)
		return 0;

	BOOL Ret = Module32First(hSnap, &ME32);
	while (Ret)
	{
		if (ME32.th32ProcessID == ProcID && !strcmp(szModule, ME32.szModule))
		{
			CloseHandle(hSnap);
			return reinterpret_cast<UINT_PTR>(ME32.hModule);
		}
		Ret = Module32Next(hSnap, &ME32);
	}

	CloseHandle(hSnap);

	return 0;
}

UINT_PTR GetModuleBaseW(const wchar_t * szModule, DWORD ProcID)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcID);
	MODULEENTRY32W ME32 = { 0 };
	ME32.dwSize = sizeof(MODULEENTRY32W);

	if (!szModule || !hSnap)
		return 0;

	BOOL Ret = Module32FirstW(hSnap, &ME32);
	while (Ret)
	{
		if (ME32.th32ProcessID == ProcID && !wcscmp(szModule, ME32.szModule))
		{
			CloseHandle(hSnap);
			return reinterpret_cast<UINT_PTR>(ME32.hModule);
		}
		Ret = Module32NextW(hSnap, &ME32);
	}

	CloseHandle(hSnap);

	return 0;
}

bool NopCode(HANDLE hProc, UINT_PTR Address, SIZE_T Size)
{
	BYTE * Nops = new BYTE[Size];
	memset(Nops, 0x90, Size);
	BOOL ret = WriteProcessMemory(hProc, reinterpret_cast<void*>(Address), Nops, Size, nullptr);
	delete[] Nops;
	return (ret == 1);
}

//ULONG_PTR GetThreadStartAddress(HANDLE hThread)
//{
//	if (!NT::Load())
//		return 0;
//
//	ULONG_PTR ulStartAddress = 0;
//	NTSTATUS Ret = NT::NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ulStartAddress, sizeof(ULONG_PTR), nullptr);
//
//	if (Ret < 0)
//		return 0;
//
//	return ulStartAddress;
//}