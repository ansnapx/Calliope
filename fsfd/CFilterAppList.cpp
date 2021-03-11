///////////////////////////////////////////////////////////////////////////////
//
// CFilterAppList.cpp: implementation of the CFilterAppList class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CFilterProcess.h"

#include "CFilterAppList.h"

///////////////////////////////////////////////////////////////////////////////
#pragma PAGEDCODE

NTSTATUS CFilterAppListEntry::Init(LPCWSTR		  image, 
								   ULONG		  imageLength,
								   ULONG		  type,
								   CFilterHeader *header)
{
	ASSERT(image);
	ASSERT(imageLength);
	ASSERT(type);

	PAGED_CODE();

	// Whitelist entries need Header
	ASSERT( !(type & FILFILE_APP_WHITE) || header);

	bool const terminal = CFilterControl::IsTerminalServices();

	// Already initialized?
	if(FILFILE_APP_WHITE == m_type)
	{
		ASSERT(header);

		if(!terminal)
		{
			return STATUS_OBJECT_NAME_COLLISION;
		}

		ASSERT(header->m_luid.LowPart || header->m_luid.HighPart);
		ASSERT(m_size <= m_capacity);

		// Check if LUID already exists
		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			ASSERT(m_headers[pos].m_luid.LowPart || m_headers[pos].m_luid.HighPart);

			if(*((ULONGLONG*) &m_headers[pos].m_luid) == *((ULONGLONG*) &header->m_luid))
			{
				return STATUS_OBJECT_NAME_COLLISION;
			}
		}
	}
	else if(m_type & FILFILE_APP_BLACK)
	{
		return STATUS_OBJECT_NAME_COLLISION;
	}
	else
	{
		// Fresh init:
		ASSERT(!m_image);
			
		m_image = (LPWSTR) ExAllocatePool(PagedPool, imageLength + sizeof(WCHAR));

		if(!m_image)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory(m_image, image, imageLength);

		m_imageLength = imageLength;

		m_image[imageLength / sizeof(WCHAR)] = UNICODE_NULL;

		m_type = type;
	}

	if(FILFILE_APP_WHITE == m_type)
	{
		ASSERT(header);

		if(m_capacity == m_size)
		{
			ULONG const capacity = m_capacity + ((terminal) ? 1 : c_incrementCount);

			CFilterHeader *headers = (CFilterHeader*) ExAllocatePool(NonPagedPool, 
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

		ASSERT(m_headers);

		// Take ownership of header's members
		m_headers[m_size] = *header;

		m_size++;
	
		RtlZeroMemory(header, sizeof(CFilterHeader));
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterAppListEntry::Close(LUID const* luid)
{
	PAGED_CODE();

	// Operate in TS mode?
	if(luid)
	{
		ASSERT(luid->LowPart || luid->HighPart);

		if(FILFILE_APP_WHITE == m_type)
		{
			bool found = false;

			// Remove caller's header with given LUID.
			for(ULONG pos = 0; pos < m_size; ++pos)
			{
				if(*((ULONGLONG*) &m_headers[pos].m_luid) == *((ULONGLONG*) luid))
				{
					m_headers[pos].Close();

					m_size--;

					if(pos < m_size)
					{
						RtlMoveMemory(m_headers + pos, 
									  m_headers + pos + 1, 
									  (m_size - pos) * sizeof(CFilterHeader));
					}

					RtlZeroMemory(m_headers + m_size, sizeof(CFilterHeader));

					found = true;

					break;
				}
			}

			// Remaining references?
			if(m_size)
			{
				return found;
			}
		}
	}

	if(m_image)
	{
		ExFreePool(m_image);
	}

	if(m_headers)
	{
		ASSERT(m_size <= m_capacity);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_headers[pos].Close();
		}

		ExFreePool(m_headers);
	}

	RtlZeroMemory(this, sizeof(*this));

	return true;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

CFilterHeader* CFilterAppListEntry::GetHeader(LUID const* luid)
{
	PAGED_CODE();

	ASSERT(FILFILE_APP_WHITE == m_type);

	// Operate not in TS mode?
	if(!luid)
	{
		ASSERT(1 == m_size);

		// Just return first Header only
		return m_headers;
	}

	ASSERT(m_size <= m_capacity);
		
	// Search for right Header with given LUID
	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		if(*((ULONGLONG*) &m_headers[pos].m_luid) == *((ULONGLONG*) luid))
		{
			return m_headers + pos;
		}
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterAppList::Init()
{
	RtlZeroMemory(this, sizeof(*this));
	
	return ExInitializeResourceLite(&m_lock);
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterAppList::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();

	if(m_entries)
	{
		ExAcquireResourceExclusiveLite(&m_lock, true);

		ASSERT(m_size <= m_capacity);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_entries[pos].Close();
		}

		ExFreePool(m_entries);
		m_entries	= 0;

		m_size		= 0;
		m_capacity  = 0;

		ExReleaseResourceLite(&m_lock);
	}	

	ExDeleteResourceLite(&m_lock);
	FsRtlExitFileSystem();
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterAppList::Search(LPCWSTR image, ULONG imageLength, ULONG type)
{
	ASSERT(image);
	ASSERT(imageLength);

	// Lock must be held

	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		CFilterAppListEntry *entry = m_entries + pos;

		// Skip incompatible types
		if(type)
		{
			if( !(entry->m_type & type))
			{
				continue;
			}
		}

		// Compare image names
		if(entry->m_imageLength == imageLength)
		{
			if(!_wcsnicmp(entry->m_image, image, imageLength / sizeof(WCHAR)))
			{
				return pos;
			}
		}
	}
	
	return ~0u;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterAppList::Add(LPCWSTR		image, 
							 ULONG			imageLength, 
							 ULONG			type, 
							 CFilterHeader *header)
{
	ASSERT(image);
	ASSERT(imageLength);
	ASSERT(type);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	ASSERT(m_size <= m_capacity);

	NTSTATUS status = STATUS_SUCCESS;

	// Search if an entry with given image already exists
	ULONG const pos = Search(image, imageLength);

	if(~0u != pos)
	{
		ASSERT(pos < m_size);
		ASSERT(m_entries);

		status = m_entries[pos].Init(image, imageLength, type, header);

		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();

		return status;
	}

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterAppListEntry *entries = (CFilterAppListEntry*) ExAllocatePool(PagedPool, 
																			 capacity * sizeof(CFilterAppListEntry));
		if(!entries)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(entries, capacity * sizeof(CFilterAppListEntry));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_entries);
				
			RtlCopyMemory(entries, m_entries, m_size * sizeof(CFilterAppListEntry));
			RtlZeroMemory(m_entries, m_size * sizeof(CFilterAppListEntry));

			ExFreePool(m_entries);
		}

		m_entries = entries;
	}

	ASSERT(m_entries);

	status = m_entries[m_size].Init(image, imageLength, type, header);

	if(NT_SUCCESS(status))
	{
		m_size++;
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterAppList::Remove(LPCWSTR image, ULONG imageLength, LUID const* luid)
{
	ASSERT(image);
	ASSERT(imageLength);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	ULONG status = STATUS_OBJECT_NAME_NOT_FOUND;

	ULONG const pos = Search(image, imageLength);

	if(pos != ~0u)
	{
		ASSERT(pos < m_size);
		ASSERT(m_entries);

		// Found LUID?
		if(m_entries[pos].Close(luid))
		{
			// Last LUID removed?
			if(!m_entries[pos].m_size)
			{
				m_size--;

				if(pos < m_size)
				{
					RtlMoveMemory(m_entries + pos, 
								  m_entries + pos + 1, 
								  (m_size - pos) * sizeof(CFilterAppListEntry));
				}

				RtlZeroMemory(m_entries + m_size, sizeof(CFilterAppListEntry));
			}

			status = STATUS_SUCCESS;
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterAppList::Remove(LUID const* luid)
{
	PAGED_CODE();

	if(m_size)
	{
		ExAcquireResourceExclusiveLite(&m_lock, true);

		for(LONG pos = m_size - 1; pos >= 0; --pos)
		{
			m_entries[pos].Close(luid);

			// Last LUID removed?
			if(!m_entries[pos].m_size)
			{
				m_size--;

				if((ULONG) pos < m_size)
				{
					RtlMoveMemory(m_entries + pos, 
								  m_entries + pos + 1, 
								  (m_size - pos) * sizeof(CFilterAppListEntry));
				}

				RtlZeroMemory(m_entries + m_size, sizeof(CFilterAppListEntry));
			}
		}

		ExReleaseResourceLite(&m_lock);
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterAppList::Check(IRP *irp, ULONG type, CFilterHeader *header, LUID const* luid)
{
	ASSERT(irp);
	ASSERT(type);

	PAGED_CODE();

	if(luid)
	{
		ASSERT(luid->LowPart || luid->HighPart);
	}

	if(!m_size)
	{
		// Empty
		return FILFILE_APP_NULL;
	}

	ULONG const pid = IoGetRequestorProcessId(irp);

	if(!pid)
	{
		// Ignore system process
		return FILFILE_APP_NULL;
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	ULONG pos;

	// Search if we have at least one entry of given type
	for(pos = 0; pos < m_size; ++pos)
	{
		if(m_entries[pos].m_type & type)
		{
			break;
		}
	}

	// No entry of given type?
	if(pos >= m_size)
	{
		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();

		return FILFILE_APP_NULL;
	}

	pos = ~0u;

	ASSERT(CFilterControl::Extension());
	CFilterProcess *const process = &CFilterControl::Extension()->Process;
	ASSERT(process);

	process->Lock();

	// Get image name for PID
	ULONG imageLength = 0;
	LPCWSTR image	  = process->Find(pid, &imageLength);

	if(image)
	{
		ASSERT(imageLength);
		
		// Search for image name with right type
		pos = Search(image, imageLength, type);
	}

	process->Unlock();

	ULONG found = FILFILE_APP_NULL;

	if(~0u != pos)
	{
		ASSERT(pos < m_size);

		found = m_entries[pos].m_type & (FILFILE_APP_WHITE | FILFILE_APP_BLACK);

		if((found & FILFILE_APP_WHITE) && header)
		{
			NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

			CFilterHeader const* source = m_entries[pos].GetHeader(luid);

			if(source)
			{
				// Copy Payload and key
				status = source->Copy(header);
			}
			
			if(NT_ERROR(status))
			{
				found &= ~FILFILE_APP_WHITE;
			}
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return found;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////