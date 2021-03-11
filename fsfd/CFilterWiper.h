////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterWiper.h: interface for the CFilterWiper class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERWIPER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERWIPER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "CFilterRandomizer.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterWiper  
{

public:
	
	NTSTATUS				Init(CFilterRandomizer *random);
	void					Close();

	NTSTATUS				Prepare(ULONG flags, int *patterns = 0, int patternsCount = 0, HANDLE cancel = 0, HANDLE progress = 0);
	NTSTATUS				WipeFile(FILE_OBJECT *file);

private:
	
	bool					WipeStep(LARGE_INTEGER const* offset);	
	NTSTATUS				WipeData(FILE_OBJECT *file, DEVICE_OBJECT *lower);
	NTSTATUS				WipePost(FILE_OBJECT *file, DEVICE_OBJECT *lower);
							
							// DATA
	CFilterRandomizer*		m_random;
	KEVENT*					m_cancel;
	KSEMAPHORE*				m_progress;

	bool					m_rename;
	bool					m_truncate;
	bool					m_delete;

	char					m_patternsCount;
	int						m_patterns[50];
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterWiper::Init(CFilterRandomizer *random)
{
	ASSERT(random);

	RtlZeroMemory(this, sizeof(*this));

	m_random = random;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFILTERWIPER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
