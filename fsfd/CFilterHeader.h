////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterHeader.h: interface for the CFilterHeader class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERHEADER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERHEADER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "CFilterLuidCont.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterHeader
{
	friend class CFilterHeaderCont;

public:

	enum c_constants
	{
		c_check	 = 0x200,		// bytes to read first in Header queries
		c_align	 = 0x1000,		// Header Alignment
	};
        
	NTSTATUS				Init(UCHAR* header, ULONG headerSize);
	void					Close();
	NTSTATUS				Copy(CFilterHeader *target) const;

	LONG					AddRef();
	LONG					Release();

	bool					Equal(CFilterHeader const *other) const;

private:
							// DATA
	LONG					m_refCount;		

public:

	ULONG					m_identifier;		// Unique identifier of this Header
	ULONG					m_blockSize;

	LARGE_INTEGER			m_nonce;

	UCHAR*					m_payload;			// Payload
	ULONG					m_payloadSize;		// Payload's size
	ULONG					m_payloadCrc;		// Payload's crc
	
	ULONG					m_deepness;

	CFilterKey				m_key;				// 1. If used in List  context   -> EntityKey
												// 2. If used in Track context   -> FileKey (encrypted)
												// 3. If used in AppList context -> EntityKey
	union
	{
		CFilterLuidCont		m_luids;			// LUID Container: stored already authenticated LUIDs
		LUID				m_luid;				// Single LUID: used by Application Black/White lists
	};
};

////////////////////////////////

inline
LONG CFilterHeader::AddRef()
{
	return ++m_refCount;
}

inline
LONG CFilterHeader::Release()
{
	ASSERT(m_refCount > 0);

	if(!--m_refCount)
	{
		Close();
	}

	return m_refCount;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterHeaderCont
{
	friend class CFilterContext;

public:

	enum c_constants			{	c_incrementCount = 8,
									c_identifierType = 0xfe000000,	// highest 8 bit of Header identifier
								};
	
	NTSTATUS					Init();
	void						Close();

	void						LockExclusive();
	void						LockShared();
	void						Unlock();
    
								// internal Header
	CFilterHeader*				Get(ULONG identifier);
	CFilterHeader*				Search(CFilterHeader const *header);
	ULONG						Size();
	ULONG						Match(CFilterHeader *header);
	
	NTSTATUS					Add(CFilterHeader *header, LUID const* luid = 0);
	NTSTATUS					Release(ULONG identifier);
	
	NTSTATUS					AddLuid(LUID const* luid, ULONG identifier);
	NTSTATUS					RemoveLuid(LUID const* luid, ULONG identifier = 0);
	NTSTATUS					CheckLuid(LUID const* luid, ULONG identifier);
	
private:
								// DATA
	CFilterHeader*				m_headers;
	ULONG						m_size;
	ULONG						m_capacity;
	ULONG						m_nextIdentifier;

	ERESOURCE					m_resource;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
ULONG CFilterHeaderCont::Size()
{
	return m_size;
}

inline
void CFilterHeaderCont::LockExclusive()
{
	ExAcquireResourceExclusiveLite(&m_resource, true);
}

inline
void CFilterHeaderCont::LockShared()
{
	ExAcquireResourceSharedLite(&m_resource, true);
}
	
inline
void CFilterHeaderCont::Unlock()
{
	ExReleaseResourceLite(&m_resource);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFILTERHEADER_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

