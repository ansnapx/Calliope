////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterFile.h: interface for the CFilterFile class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterFile_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFilterFile_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct CFilterContextLink 
{
	ULONG				m_entityIdentifier;		// identifies corresponding Entity
	ULONG				m_headerIdentifier;		// identifies corresponding Header
	ULONG				m_headerBlockSize;	 
	ULONG				m_flags;

	LARGE_INTEGER		m_nonce;
	CFilterKey			m_fileKey;
};

////////////////////////////////

class CFilterFile 
{
	enum c_constants			{ c_incrementCount = 4 };

public:

	NTSTATUS					Init();
	void						Close();

	NTSTATUS					OnCreate(FILE_OBJECT* file, ULONG hash);
	bool						OnClose(FILE_OBJECT* file);

	NTSTATUS					Update(CFilterFile const* other);
	NTSTATUS					Track(FILE_OBJECT *file);
	FILE_OBJECT*				Tracked();
	
								// DATA
	FSRTL_COMMON_FCB_HEADER*	m_fcb;

	FILE_OBJECT**				m_files;			// Array of user FOs
	ULONG						m_size;
	ULONG						m_capacity;

	ULONG						m_refCount;	
	ULONG						m_hash;				// hash of the file name

	HANDLE						m_threadId;			// thread id at last open
	ULONG						m_tick;				// tick at last open
    
	CFilterContextLink			m_link;
};

/////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterFile::Init()
{
	RtlZeroMemory(this, sizeof(*this));

	return STATUS_SUCCESS;
}

inline
void CFilterFile::Close()
{
	if(m_files)
	{
		ExFreePool(m_files);
		m_files = 0;
	}
}

inline
FILE_OBJECT* CFilterFile::Tracked()
{
	if(m_size)
	{
		ASSERT(m_files);
		ASSERT(m_files[0]);

		return m_files[0];
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterFileCont
{
	enum c_constants			{	c_incrementCount = 16,
									c_timeout		 = 30,	// seconds
								};
public:

	NTSTATUS					Init();
	void						Close();

	bool						Check(FILE_OBJECT *file, ULONG *pos = 0) const;
	bool						CheckIdentifier(ULONG identifier, ULONG *pos = 0) const;
	bool						CheckSpecial(FILE_OBJECT *file, ULONG *pos, ULONG hash) const;

	NTSTATUS					Add(CFilterFile *file, ULONG pos);
	NTSTATUS					Update(CFilterFile const* file, ULONG pos);
	NTSTATUS					Remove(ULONG pos);

	CFilterFile*				Get(ULONG pos) const;
	ULONG						Size() const;

private:

	CFilterFile*				m_files;
	ULONG						m_size;
	ULONG						m_capacity;
	ULONG						m_timeout;		// ticks
};

/////////////////////////////////////////////////////////////////////

inline
CFilterFile* CFilterFileCont::Get(ULONG pos) const
{
	ASSERT(m_files);
	ASSERT(m_capacity >= m_size);

	if(pos < m_size)
	{
		ASSERT(m_files[pos].m_fcb);

		return m_files + pos;
	}

	ASSERT(false);

	return 0;
}

inline
ULONG CFilterFileCont::Size() const
{
	ASSERT(m_capacity >= m_size);

	return m_size;
}

inline
NTSTATUS CFilterFileCont::Update(CFilterFile const* file, ULONG pos)
{
	ASSERT(file);
	ASSERT(pos < m_size);
	ASSERT(m_files);

	return m_files[pos].Update(file);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterFile_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)


