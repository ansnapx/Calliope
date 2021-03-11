///////////////////////////////////////////////////////////////////////////////
//
// CFilterBlackList.h: interface for the CFilterBlackList class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterBlacklist__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
#define AFX_CFilterBlacklist__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////

class CFilterBlackList  
{
	enum c_constants			{ c_incrementCount = 4 };

public:

	NTSTATUS					Init(LUID const* luid = 0);
	void						Close();
	ULONG						Size() const;

	bool						Check(LUID const* luid) const;
	ULONG						Check(CFilterPath const* path, bool simple = false);
	
	NTSTATUS					Add(CFilterPath *path);
	NTSTATUS					Remove(CFilterPath const* path);

	CFilterPath const*			Entries() const;

private:

	CFilterPath*				m_entries;
	ULONG						m_size;
	ULONG						m_capacity;

	LUID						m_luid;
};

inline
NTSTATUS CFilterBlackList::Init(LUID const* luid)
{
	RtlZeroMemory(this, sizeof(*this));

	if(luid)
	{
		m_luid = *luid;
	}

	return STATUS_SUCCESS;
}

inline 
ULONG CFilterBlackList::Size() const
{
	return m_size;
}

inline
CFilterPath const* CFilterBlackList::Entries() const
{
	return m_entries;
}

inline
bool CFilterBlackList::Check(LUID const* luid) const
{
	ASSERT(luid);
	return *((ULONGLONG*) &m_luid) == *((ULONGLONG*) luid);
}

///////////////////////////////////////////////////////////////////////////////

class CFilterBlackListDisp
{
	enum c_constants			{ c_incrementCount = 4 };

public:

	NTSTATUS					Init();
	void						Close();
	void						Clear();

	bool						Check(CFilterPath const* path, LUID const* luid);
	NTSTATUS					Remove(LUID const* luid);

	NTSTATUS					Set(LPCWSTR buffer = 0, ULONG bufferSize = 0, ULONG flags = 0);	
	NTSTATUS					Get(LPWSTR buffer, ULONG *bufferSize);	

private:

	NTSTATUS					Manage(LPCWSTR path, ULONG length, ULONG flags);

								// DATA
	CFilterBlackList			m_generic;		// Generic Blacklist entries

	CFilterBlackList*			m_custom;		// Custom Blacklist entries, per LUID
	ULONG						m_size;
	ULONG						m_capacity;

	ERESOURCE					m_lock;
};

///////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterBlacklist__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
