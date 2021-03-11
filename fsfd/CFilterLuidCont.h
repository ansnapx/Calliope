///////////////////////////////////////////////////////////////////////////////
//
// CFilterLuidCont.h: definition of the CFilterLuidCont classes
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterLuidCont_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFilterLuidCont_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////

class CFilterLuidCont
{
	enum c_constants		{ c_incrementCount = 4 };

public:

	NTSTATUS				Init();
	void					Close();
	void					Clear();
	USHORT					Size() const;

	NTSTATUS				Add(LUID const* luid);
	NTSTATUS				Add(CFilterLuidCont const& other);
	NTSTATUS				Remove(LUID const* luid);
		
	ULONG					Check(LUID const* luid) const;

private:

	ULONGLONG*				m_luids;
	USHORT					m_size;
	USHORT					m_capacity;
};

///////////////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterLuidCont::Init()
{
	RtlZeroMemory(this, sizeof(*this));

	return STATUS_SUCCESS;
}

inline
USHORT CFilterLuidCont::Size() const
{
	return m_size;
}

inline
void CFilterLuidCont::Clear()
{
	m_luids	   = 0;
	m_size	   = 0;
	m_capacity = 0;
}

///////////////////////////////////////////////////////////////////////////////
#endif // AFX_CFilterLuidCont_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_