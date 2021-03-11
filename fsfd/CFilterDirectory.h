////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterDirectory.h: interface for the CFilterDirectory class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterDirectory_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFilterDirectory_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterDirectory  
{
public:

	FILE_OBJECT*			m_file;

	ULONG					m_entityIdentifier;		// identifies corresponding Entity
	ULONG					m_headerIdentifier;		// identifies corresponding Header

	ULONG					m_flags;
	ULONG					m_depth;				// directory depth

	ULONG					m_tid;					// thread id at last open
	ULONG					m_hash;					// hash of the name
	ULONG					m_tick;					// tick at last open
};

//////////////////////////////////////////////

class CFilterDirectoryCont
{
	enum c_constants		{	c_incrementCount = 8,
								c_timeout		 = 10,	// seconds
							};

public:

	NTSTATUS				Init();
	void					Close();

	CFilterDirectory*		Get(ULONG pos) const;
	ULONG					Size() const;

	bool					Search(FILE_OBJECT *file, ULONG *pos);
	bool					SearchSpecial(ULONG hash, ULONG *pos);

	NTSTATUS				Add(CFilterDirectory *directory);
	NTSTATUS				Remove(FILE_OBJECT *file, ULONG pos = ~0u);

private:
							// DATA
	CFilterDirectory*		m_directories;
	ULONG					m_size;
	ULONG					m_capacity;
	ULONG					m_timeout;		// ticks
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
CFilterDirectory* CFilterDirectoryCont::Get(ULONG pos) const
{
	ASSERT(pos < m_size);
	ASSERT(m_size <= m_capacity);
	ASSERT(m_directories);
	
	return m_directories + pos;
}

inline
ULONG CFilterDirectoryCont::Size() const
{
	ASSERT(m_size <= m_capacity);

	return m_size;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // !defined(AFX_CFilterDirectory_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)


