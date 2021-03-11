///////////////////////////////////////////////////////////////////////////////
//
// CFilterProcess.h: definition of the CFilterProcess classes
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterProcess_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFilterProcess_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "CFilterFile.h"

///////////////////////////////////////////////////////////////////////////////

class CFilterProcess
{
	enum c_constants		{ c_incrementCount = 16 };

	struct CFilterProcessEntry
	{
		NTSTATUS	Init(ULONG pid, UNICODE_STRING const* image);
		void		Close();
		NTSTATUS    AddLink(ULONG pid,CFilterContextLink* link);
		bool    GetLink(CFilterContextLink* link);
	
		ULONG		m_pid;
		ULONG		m_state;

		LPWSTR		m_image;
		ULONG		m_imageLength;
		CFilterContextLink* m_link;//可信进程当前的 加密链
	};

public:

	NTSTATUS				Init();
	bool                    IsTrustProcess(IRP *irp);
	void					Close(bool destroy = false);

	void					Lock();
	void					Unlock();

	//bool                   s_bFilter;

	NTSTATUS				MarkForTermination(ULONG pid, bool enable);

	NTSTATUS				Add(ULONG pid, UNICODE_STRING const* image);
	NTSTATUS                AddFilterLink(ULONG pid,CFilterContextLink* link);
	bool                GetFilterLink(ULONG pid,CFilterContextLink* link);
	NTSTATUS				Remove(ULONG pid);
	LPCWSTR					Find(ULONG pid, ULONG *imageLength);
	bool					Match(IRP *irp, UNICODE_STRING *image);

	static CFilterProcess*	s_instance;
	static ULONG            s_ulParentPid;
	
private:

	bool					Search(ULONG pid, ULONG *pos = 0);

	static void NTAPI		Notify(HANDLE parent, HANDLE pid, BOOLEAN create);
	static void NTAPI		LoadImage(UNICODE_STRING *name, HANDLE pid, IMAGE_INFO *info);

							// DATA
	CFilterProcessEntry*	m_entries;		// sorted by PID
	ULONG					m_size;
	ULONG					m_capacity;

	ERESOURCE				m_lock;
};

///////////////////////////////////////////////////////////////////////////////

inline
void CFilterProcess::Lock()
{
	ExAcquireResourceSharedLite(&m_lock, true);
}

inline
void CFilterProcess::Unlock()
{
	ExReleaseResourceLite(&m_lock);
}

///////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFilterProcess_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_