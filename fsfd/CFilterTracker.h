////////////////////////////////////////////////////////////////////////////////
//
// CFilterTracker.h: interface for the CFilterTracker class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterTracker_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFilterTracker_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////

enum FILFILE_TRACKER_STATE
{ 
	FILFILE_TRACKER_NULL	= 0x0, 
	FILFILE_TRACKER_IGNORE	= 0x1, 
	FILFILE_TRACKER_BYPASS	= 0x2,
};

class CFilterTracker
{
	enum c_constants		{ c_incrementCount = 8 };

	struct CFilterTrackerEntry
	{
		CFilterTrackerEntry(FILE_OBJECT *file, ULONG state) : m_file(file),
															  m_state(state)
		{ }

		FILE_OBJECT*	m_file;
		ULONG			m_state;
	};

public:

	NTSTATUS				Init();
	void					Close();

	NTSTATUS				Add(FILE_OBJECT *file, ULONG state);
	ULONG					Remove(FILE_OBJECT *file);
	ULONG					Check(FILE_OBJECT *file);

private:

	bool					Search(FILE_OBJECT *file, ULONG *pos) const;

							// DATA
	CFilterTrackerEntry*	m_entries;		// sorted by FO
	ULONG					m_size;
	ULONG					m_capacity;
	
	ERESOURCE				m_lock;
};

////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFilterTracker_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_