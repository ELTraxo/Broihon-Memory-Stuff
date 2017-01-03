#pragma once

#ifndef DETOUR_H
#define DETOUR_H

#include <Windows.h>

class Detour
{
public:
	Detour();
	~Detour();

	void * CreateDetour(void * pTarget, void * pHook, UINT Length, bool Active);
	bool Activate();
	bool Deactivate();
	bool Remove();

private:
	void *	m_pTarget;
	void *	m_pHook;
	void *	m_pTrp;
	UINT	m_Length;
	bool	m_State;
	bool	m_Init;

	bool Hook();
};

#endif