///////////////////////////////////////////////////////////////////////////////
//
// CFilterHeader.cpp: implementation of the CFilterHeader class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the IFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterHeader.h"

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeader::Init(UCHAR *header, ULONG headerSize)
{
	ASSERT(header);
	ASSERT(headerSize);

	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	m_payload = (UCHAR*) ExAllocatePool(PagedPool, headerSize);

	if(!m_payload)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(m_payload, header, headerSize);	

	m_payloadSize	= headerSize;
	m_payloadCrc	= CFilterBase::Crc32(m_payload, m_payloadSize);
	m_blockSize		= (sizeof(FILFILE_HEADER_BLOCK) + 
					  m_payloadSize + (CFilterHeader::c_align - 1)) & ~(CFilterHeader::c_align - 1);
        
	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeader::Close()
{
	PAGED_CODE();

	if(m_payload)
	{
		ExFreePool(m_payload);
	}

	// Operate in standard mode?
	if(m_identifier)
	{
		ASSERT((m_identifier & 0xff000000) == CFilterHeaderCont::c_identifierType);

		m_luids.Close();
	}

	RtlZeroMemory(this, sizeof(*this));
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeader::Copy(CFilterHeader *target) const
{
	ASSERT(target);

	PAGED_CODE();

	target->m_payload = (UCHAR*) ExAllocatePool(PagedPool, m_payloadSize);

	if(!target->m_payload)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(target->m_payload, m_payload, m_payloadSize);	

	target->m_payloadSize = m_payloadSize;
	target->m_payloadCrc  = m_payloadCrc;

	target->m_blockSize   = m_blockSize;

	target->m_key = m_key;

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterHeader::Equal(CFilterHeader const *header) const
{
	ASSERT(header);

	PAGED_CODE();

	ASSERT(header->m_payload);
	ASSERT(header->m_payloadSize);

	if(m_payloadCrc == header->m_payloadCrc)
	{
		if(m_payloadSize == header->m_payloadSize)
		{
			// valid payload ?
			if(m_payload && header->m_payload)
			{
				if(!RtlEqualMemory(m_payload, header->m_payload, m_payloadSize))
				{
					// crc collision, just want to know
					ASSERT(false);	

					return false;
				}
			}

			return true;
		}
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterHeaderCont::Init()
{
	PAGED_CODE();

	m_headers	= 0;
	m_size		= 0;
	m_capacity	= 0;

	m_nextIdentifier = c_identifierType;

	return ExInitializeResourceLite(&m_resource);
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeaderCont::Close()
{
	PAGED_CODE();

	if(m_headers)
	{
		ExAcquireResourceExclusiveLite(&m_resource, true);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_headers[pos].Close();
		}

		ExFreePool(m_headers);
		m_headers = 0;

		ExReleaseResourceLite(&m_resource);
	}
	
	m_size		= 0;
	m_capacity	= 0;

	ExDeleteResourceLite(&m_resource);
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

CFilterHeader* CFilterHeaderCont::Search(CFilterHeader const *header)
{
	ASSERT(header);

	PAGED_CODE();

	ASSERT(header->m_payloadSize);
	ASSERT(header->m_payloadCrc);

	ASSERT(m_size <= m_capacity);

	for(ULONG index = 0; index < m_size; ++index)
	{
		ASSERT(m_headers);

		if(m_headers[index].Equal(header))
		{
			// finish
			return m_headers + index;
		}
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

CFilterHeader* CFilterHeaderCont::Get(ULONG identifier)
{
	// ensure Header identifier type
	ASSERT((identifier & 0xff000000) == c_identifierType);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	ULONG pos = identifier & 0x00ffffff;

	// 1. try direct index
	if(pos < m_size)
	{
		ASSERT(m_headers);

		if(m_headers[pos].m_identifier == identifier)
		{
			return m_headers + pos;
		}
	}

	// 2. search in array
	for(pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_headers);
		ASSERT(m_headers[pos].m_payload);
		ASSERT((m_headers[pos].m_identifier & 0xff000000) == c_identifierType);

		if(m_headers[pos].m_identifier == identifier)
		{
			return m_headers + pos;
		}
	}	

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCont::Add(CFilterHeader *header, LUID const* luid)
{
	ASSERT(header);

	PAGED_CODE();

	ASSERT(header->m_blockSize);
	ASSERT(header->m_payload);
	ASSERT(header->m_payloadSize);
	ASSERT(header->m_payloadCrc);

	// already here ?
	CFilterHeader *const found = Search(header);

	if(found)
	{
		// just add RefCount
		LONG const refCount = found->AddRef();

		DBGPRINT(("HeaderCont::Add() new RefCount[%d]\n", refCount));

		if(luid)
		{
			ASSERT(found->m_identifier);

			found->m_luids.Add(luid);
		}

		header->m_identifier = found->m_identifier;

		return STATUS_ALERTED;
	}

	// advance buffer ?
	if(m_size == m_capacity)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterHeader* headers = (CFilterHeader*) ExAllocatePool(NonPagedPool, 
																 capacity * sizeof(CFilterHeader));

		if(!headers)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(headers, capacity * sizeof(CFilterHeader));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_headers);
				
			RtlCopyMemory(headers, m_headers, m_size * sizeof(CFilterHeader));
			RtlZeroMemory(m_headers, m_size * sizeof(CFilterHeader));

			ExFreePool(m_headers);
		}

		m_headers = headers;
	}

	ASSERT(m_size < m_capacity);

	// generate next Header identifier
	header->m_identifier = m_nextIdentifier++;

	// overflow ?
	if((m_nextIdentifier & 0x00ffffff) == 0x00ffffff)
	{
		//
		// TODO: search for unused Header identifiers
		//

		ASSERT(false);
	}

	NTSTATUS status = STATUS_SUCCESS;

	header->m_refCount = 1;

	// transfer buffer ownership to list member
	m_headers[m_size] = *header;

	if(luid)
	{
		status = m_headers[m_size].m_luids.Add(luid);
	}

	if(NT_SUCCESS(status))
	{
		// Clear only Header Payload
		header->m_payload		= 0;
		header->m_payloadSize	= 0;
		header->m_payloadCrc	= 0;

		m_size++;

		DBGPRINT(("HeaderCont::Add() new sizes[%d,%d]\n", m_size, 
														  m_capacity));
	}
	else
	{
		RtlZeroMemory(m_headers + m_size, sizeof(CFilterHeader));
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCont::Release(ULONG identifier)
{
	ASSERT((identifier & 0xff000000) == c_identifierType);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);
	
	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_resource, true);

	CFilterHeader *released = 0;

	ULONG pos = identifier & 0x00ffffff;

	// 1. try direct index
	if(pos < m_size)
	{
		if(m_headers[pos].m_identifier == identifier)
		{
			released = m_headers + pos;
		}
	}

	if(!released)
	{
		// 2. search in array
		for(pos = 0; pos < m_size; ++pos)
		{
			ASSERT(m_headers);
			ASSERT(m_headers[pos].m_payload);
			
			if(m_headers[pos].m_identifier == identifier)
			{
				released = m_headers + pos;
				break;
			}
		}
	}

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(released)
	{
		ASSERT(pos < m_size);

		status = STATUS_SUCCESS;

		// destroys Header implicitly
		LONG const refCount = released->Release();

		ASSERT(refCount >= 0);

		if(!refCount)
		{
			m_size--;

			// Close gap, if any
			if(pos < m_size)
			{
				RtlMoveMemory(m_headers + pos,
							  m_headers + pos + 1,
							  (m_size - pos) * sizeof(CFilterHeader));
			}

			RtlZeroMemory(m_headers + m_size, sizeof(CFilterHeader));

			DBGPRINT(("HeaderCont::Release() pos[%d], new sizes[%d,%d]\n", pos, 
																		   m_size, 
																		   m_capacity));
		}
		else
		{
			DBGPRINT(("HeaderCont::Release() new RefCount[%d]\n", refCount));
		}
	}

	ExReleaseResourceLite(&m_resource);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterHeaderCont::Match(CFilterHeader *header)
{
	ASSERT(header);

	PAGED_CODE();

	ASSERT(header->m_payload);
	ASSERT(header->m_payloadSize);
	ASSERT(header->m_payloadCrc);

	// Search list and get Identifier, if exists
	ULONG matchedIdentifier = 0;

	CFilterHeader *found = Search(header);

	if(found)
	{
		matchedIdentifier = found->m_identifier;
	}

	return matchedIdentifier;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCont::AddLuid(LUID const* luid, ULONG identifier)
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);
	ASSERT((identifier & 0xff000000) == c_identifierType);

	PAGED_CODE();

	CFilterHeader *found = Get(identifier);

	if(found)
	{
		return found->m_luids.Add(luid);
	}

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCont::RemoveLuid(LUID const* luid, ULONG identifier)
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	// Remove LUID from particular Header?
	if(identifier)
	{
		ASSERT((identifier & 0xff000000) == c_identifierType);

		CFilterHeader *found = Get(identifier);

		if(!found)
		{
			return STATUS_OBJECT_NAME_NOT_FOUND;	
		}

		return found->m_luids.Remove(luid);
	}

	// Remove given LUID from each Header
	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_headers);

		m_headers[pos].m_luids.Remove(luid);
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCont::CheckLuid(LUID const* luid, ULONG identifier)
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);
	ASSERT((identifier & 0xff000000) == c_identifierType);

	PAGED_CODE();

	CFilterHeader *found = Get(identifier);

	if(!found)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ULONG const pos = found->m_luids.Check(luid);

	if(pos == ~0u)
	{
		return STATUS_ACCESS_DENIED;	
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

