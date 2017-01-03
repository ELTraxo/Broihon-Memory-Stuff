#include "Detour.h"

#ifdef _WIN64
#define DET_MIN_SIZE 0x0C
#else 
#define DET_MIN_SIZE 5
#endif

Detour::Detour()
{
	m_pTarget = nullptr;
	m_pHook = nullptr;
	m_pTrp = nullptr;
	m_Length = 0;
	m_State = false;
	m_Init = false;
}

Detour::~Detour()
{
	Remove();
}

void * Detour::CreateDetour(void * pTarget, void * pHook, UINT Length, bool Active)
{
	if (!pTarget || !pHook || Length < DET_MIN_SIZE)
		return nullptr;

	if (m_Init)
		Remove();

	m_pTrp = VirtualAlloc(nullptr, Length + DET_MIN_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!m_pTrp)
		return nullptr;

	m_pTarget = pTarget;
	m_pHook = pHook;
	m_Length = Length;

	memcpy(m_pTrp, m_pTarget, m_Length);

#ifdef _WIN64

	BYTE CodeCave[] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x00 (+ 0x02)	-> mov rax, pHook
		0xFF, 0xE0													// + 0x0A			-> jmp rax
	};
	*reinterpret_cast<UINT_PTR*>(CodeCave + 2) = reinterpret_cast<UINT_PTR>(m_pTarget) + Length;

#else

	BYTE CodeCave[] =
	{
		0xE9, 0x00, 0x00, 0x00, 0x00	// + 0x00 (+ 0x01)	-> jmp pHook
	};
	*reinterpret_cast<DWORD*>(CodeCave + 1) = reinterpret_cast<DWORD>(m_pTarget) - reinterpret_cast<DWORD>(m_pTrp) - 5;

#endif

	memcpy(reinterpret_cast<BYTE*>(m_pTrp) + Length, CodeCave, sizeof(CodeCave));

	m_Init = true;

	if (Active)
		Activate();

	return m_pTrp;
}

bool Detour::Activate()
{
	if (m_State)
		return true;

	if (!m_pTarget || !m_pHook || !m_Length || !m_Init)
		return false;

	if (!Hook())
		return false;

	m_State = true;

	return true;
}

bool Detour::Deactivate()
{
	if (!m_State)
		return true;

	if (!m_pTarget || !m_pHook || !m_Length || !m_Init)
		return false;

	DWORD dwOld;
	if (!VirtualProtect(m_pTarget, m_Length, PAGE_EXECUTE_READWRITE, &dwOld))
		return false;

	memcpy(m_pTarget, m_pTrp, m_Length);
	VirtualProtect(m_pTarget, m_Length, dwOld, &dwOld);

	m_State = false;

	return true;
}

bool Detour::Remove()
{
	if (Deactivate())
	{
		VirtualFree(m_pTrp, 0, MEM_RELEASE);
		m_pTarget = nullptr;
		m_pHook = nullptr;
		m_pTrp = nullptr;
		m_Length = 0;
		m_State = false;
		m_Init = false;

		return true;
	}
	return false;
}

bool Detour::Hook()
{
	if (!m_Init)
		return false;

#ifdef _WIN64

	BYTE CodeCave[] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x00 (+ 0x02)	-> mov rax, pHook
		0xFF, 0xE0													// + 0x0A			-> jmp rax
	};
	*reinterpret_cast<UINT_PTR*>(CodeCave + 2) = reinterpret_cast<UINT_PTR>(m_pHook);

#else

	BYTE CodeCave[] =
	{
		0xE9, 0x00, 0x00, 0x00, 0x00 // + 0x00 (+ 0x01)	-> jmp pHook
	};
	*reinterpret_cast<DWORD*>(CodeCave + 1) = reinterpret_cast<DWORD>(m_pHook) - reinterpret_cast<DWORD>(m_pTarget) - 5;

#endif

	DWORD dwOld = 0;
	if (!VirtualProtect(m_pTarget, sizeof(CodeCave), PAGE_EXECUTE_READWRITE, &dwOld))
		return false;

	memcpy(m_pTarget, CodeCave, sizeof(CodeCave));
	VirtualProtect(m_pTarget, sizeof(CodeCave), dwOld, &dwOld);

	return true;
}