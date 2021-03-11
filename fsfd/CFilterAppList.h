///////////////////////////////////////////////////////////////////////////////
//
// CFilterAppList.h: interface for the CFilterAppList class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterAppList_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFilterAppList_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////

enum FILFILE_APP_TYPES
{ 	
	FILFILE_APP_NULL		= 0x0, 
	FILFILE_APP_WHITE		= 0x1,		// Encrypt on file creation
	FILFILE_APP_BLACK		= 0x2,		// Bypass transparent crypto on read/write requests

	FILFILE_APP_INVALID		= 0x8, 
};

class CFilterAppListEntry
{	
	friend class CFilterAppList;

	enum c_constants		{ c_incrementCount = 4 };

public:

	NTSTATUS				Init(LPCWSTR image, ULONG imageLength, ULONG type, CFilterHeader *header = 0);
	bool					Close(LUID const* luid = 0);
	CFilterHeader*			GetHeader(LUID const* luid = 0);

private:

	LPWSTR					m_image;
	ULONG					m_imageLength;

	ULONG					m_type;

	CFilterHeader*			m_headers;		// In TS mode: one per LUID
	ULONG					m_size;
	ULONG					m_capacity;
};

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

class CFilterAppList
{
	enum c_constants		{ c_incrementCount = 4 };

public:

	NTSTATUS				Init();
	void					Close();
	ULONG					Size() const;

	NTSTATUS				Add(LPCWSTR image, ULONG imageLength, ULONG type, CFilterHeader *header = 0);
	NTSTATUS				Remove(LPCWSTR image, ULONG imageLength, LUID const* luid = 0);
	NTSTATUS				Remove(LUID const* luid = 0);

	ULONG					Check(IRP *irp, ULONG type, CFilterHeader *header = 0, LUID const* luid = 0);

private:

	ULONG					Search(LPCWSTR image, ULONG imageLength, ULONG type = 0);

							// DATA
	CFilterAppListEntry*	m_entries;
	ULONG					m_size;
	ULONG					m_capacity;

	ERESOURCE				m_lock;
};

inline
ULONG CFilterAppList::Size() const
{
	return m_size;
}

///////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFilterAppList_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_