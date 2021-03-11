///////////////////////////////////////////////////////////////////////////////
//
// CFilterBlackList.cpp: implementation of the CFilterBlackList class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CFilterPath.h"

#include "CFilterBlackList.h"

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterBlackList::Close()
{
	PAGED_CODE();

	if(m_entries)
	{
		ASSERT(m_size <= m_capacity);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_entries[pos].Close();		
		}

		ExFreePool(m_entries);
	}

	RtlZeroMemory(this, sizeof(*this));
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterBlackList::Check(CFilterPath const* path, bool simple)
{
	ASSERT(path);

	PAGED_CODE();

	bool found = false;

	ASSERT(m_size <= m_capacity);

	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_entries);

		if(simple)
		{
			// Simple string compare
			if(m_entries[pos].Match(path, true))
			{
				return pos;
			}
		}
		else
		{
			// Semantically correct path compare
			if(m_entries[pos].MatchSpecial(path))
			{
				return pos;
			}
		}
	}
	
	return ~0u;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackList::Add(CFilterPath *path)
{
	ASSERT(path);

	PAGED_CODE();

	// Does entry already exist?
	if(Check(path, true) != ~0u)
	{
		return STATUS_OBJECT_NAME_COLLISION;
	}

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterPath *entries = (CFilterPath*) ExAllocatePool(PagedPool, 
															 capacity * sizeof(CFilterPath));
		if(!entries)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(entries, capacity * sizeof(CFilterPath));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_entries);
				
			RtlCopyMemory(entries, m_entries, m_size * sizeof(CFilterPath));
			ExFreePool(m_entries);
		}

		m_entries = entries;
	}

	ASSERT(m_entries);

	// Take ownership
	m_entries[m_size] = *path;

	m_size++;

	// Invalidate given object
	RtlZeroMemory(path, sizeof(CFilterPath));

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackList::Remove(CFilterPath const* path)
{
	ASSERT(path);

	PAGED_CODE();

	ULONG const pos = Check(path, true);

	if(~0u == pos)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ASSERT(pos < m_size);
	ASSERT(m_entries);

	m_entries[pos].Close();

	m_size--;

	if(pos < m_size)
	{
		RtlMoveMemory(m_entries + pos, 
					  m_entries + pos + 1, 
					  (m_size - pos) * sizeof(CFilterPath));
	}

	RtlZeroMemory(m_entries + m_size, sizeof(CFilterPath));

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterBlackListDisp::Init()
{
	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	NTSTATUS status = m_generic.Init();

	if(NT_SUCCESS(status))
	{
		status = ExInitializeResourceLite(&m_lock);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterBlackListDisp::Clear()
{
	PAGED_CODE();

	// Free generic Blacklist
	m_generic.Close();
	
	if(m_custom)
	{
		ASSERT(m_size <= m_capacity);

		// Free custom Blacklist
		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_custom[pos].Close();
		}

		ExFreePool(m_custom);
		m_custom = 0;

		m_size	   = 0;
		m_capacity = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterBlackListDisp::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	Clear();

	ExReleaseResourceLite(&m_lock);

	ExDeleteResourceLite(&m_lock);
	FsRtlExitFileSystem();
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterBlackListDisp::Check(CFilterPath const* path, LUID const* luid)
{
	ASSERT(path);
	
	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireSharedStarveExclusive(&m_lock, true);

	// First, check path against generic Blacklist
	bool found = m_generic.Check(path) != ~0u;
	
	if(!found && CFilterControl::IsTerminalServices())
	{
		ASSERT(luid);
		ASSERT(luid->LowPart || luid->HighPart);

		// In TS mode, search for list with current LUID
		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			if(m_custom[pos].Check(luid))
			{
				// Check path against custom Blacklist
				if(m_custom[pos].Check(path) != ~0u)
				{
					found = true;
				}

				break;
			}
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return found;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackListDisp::Manage(LPCWSTR path, ULONG length, ULONG flags)
{
	ASSERT(path);
	ASSERT(length);

	PAGED_CODE();

	CFilterPath entry;

	NTSTATUS status = entry.InitClient(path, length, CFilterPath::PATH_DEEPNESS);

	if(NT_ERROR(status))
	{
		return status;
	}

	#if DBG
	{
		DBGPRINT(("Blacklist: Manage entry ["));
		entry.Print(CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE | CFilterPath::PATH_DEEPNESS);
		DbgPrint("]\n");
	}
	#endif

	// Wildcards are only allowed with files
	if(!entry.m_volume && !entry.m_directory && entry.m_file)
	{
		UNICODE_STRING ustr = {0,0,0};
		entry.UnicodeString(&ustr);

		// Wildcard in name?
		if(FsRtlDoesNameContainWildCards(&ustr))
		{
			entry.m_flags |= TRACK_WILDCARD;
		}
	}

	// Defaults to generic
	CFilterBlackList *black = &m_generic;

	// Targeted not generic list and in TS mode?
	if( !(flags & FILFILE_CONTROL_SHARED) && CFilterControl::IsTerminalServices())
	{
		black = 0;

		LUID luid = {0,0};
		status = CFilterBase::GetLuid(&luid);

		if(NT_SUCCESS(status))
		{
			ASSERT(luid.HighPart || luid.LowPart);

			// See if LUID already exists
			for(ULONG pos = 0; pos < m_size; ++pos)
			{
				if(m_custom[pos].Check(&luid))
				{
					black = m_custom + pos;

					break;
				}
			}

			// Not found?
			if(!black)
			{
				// Create new list object for this LUID
				if(m_capacity == m_size)
				{
					ULONG const capacity = m_capacity + c_incrementCount;

					CFilterBlackList *custom = (CFilterBlackList*) ExAllocatePool(PagedPool, 
																				  capacity * sizeof(CFilterBlackList));
					if(!custom)
					{
						entry.Close();

						return STATUS_INSUFFICIENT_RESOURCES;
					}

					RtlZeroMemory(custom, capacity * sizeof(CFilterBlackList));

					m_capacity = capacity;

					if(m_size)
					{
						ASSERT(m_custom);
							
						RtlCopyMemory(custom, m_custom, m_size * sizeof(CFilterBlackList));
						ExFreePool(m_custom);
					}

					m_custom = custom;
				}

				ASSERT(m_custom);

				black = m_custom + m_size;

				black->Init(&luid);

				m_size++;
			}
		}
	}

	// Valid entry?
	if(black)
	{
		if(flags & FILFILE_CONTROL_ADD)
		{
			status = black->Add(&entry);
		}
		else
		{
			ASSERT(flags & FILFILE_CONTROL_REM);

			status = black->Remove(&entry);
		}
	}

	entry.Close();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackListDisp::Remove(LUID const* luid)
{
	ASSERT(luid);

	PAGED_CODE();

	ExAcquireResourceExclusiveLite(&m_lock, true);

	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		// In TS mode, search for list with LUID
		if(!luid || m_custom[pos].Check(luid))
		{
			m_custom[pos].Close();

			m_size--;

			if(pos < m_size)
			{
				RtlMoveMemory(m_custom + pos, 
							  m_custom + pos + 1, 
							  (m_size - pos) * sizeof(CFilterBlackList));
			}

			RtlZeroMemory(m_custom + m_size, sizeof(CFilterBlackList));

			break;
		}
	}

	ExReleaseResourceLite(&m_lock);

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackListDisp::Get(LPWSTR buffer, ULONG *bufferSize)
{
	ASSERT(buffer);
	ASSERT(bufferSize);

	PAGED_CODE();

	ULONG const flags = CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE | CFilterPath::PATH_DEEPNESS;
	ULONG const end   = *bufferSize / sizeof(WCHAR);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG curr		= 0;

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	__try
	{
		// Generic Blacklist:
		CFilterPath const* entries = m_generic.Entries();

		for(ULONG pos = 0; pos < m_generic.Size(); ++pos)
		{
			ULONG const written = entries[pos].Write(buffer + curr, 
													 end - curr, 
													 flags);
			if(!written)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			curr += written / sizeof(WCHAR);
		}

		if(NT_SUCCESS(status) && CFilterControl::IsTerminalServices())
		{
			// Custom Blacklist:

			LUID luid = {0,0};
			status = CFilterBase::GetLuid(&luid);

			if(NT_SUCCESS(status))
			{
				ASSERT(luid.HighPart || luid.LowPart);

				CFilterBlackList const* black = 0;		
		
				for(ULONG pos = 0; pos < m_size; ++pos)
				{
					if(m_custom[pos].Check(&luid))
					{
						black = m_custom + pos;

						break;
					}
				}

				// Found Blacklist for LUID?
				if(black)
				{
					entries = black->Entries();

					for(ULONG pos = 0; pos < black->Size(); ++pos)
					{
						ULONG const written = entries[pos].Write(buffer + curr, 
																 end - curr, 
																 flags);
						if(!written)
						{
							status = STATUS_BUFFER_TOO_SMALL;
							break;
						}

						curr += written / sizeof(WCHAR);
					}
				}
			}
		}

		if(NT_SUCCESS(status))
		{
			// Set final size of buffer
			*bufferSize = curr * sizeof(WCHAR);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = STATUS_INVALID_USER_BUFFER;
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBlackListDisp::Set(LPCWSTR buffer, ULONG bufferSize, ULONG flags)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	// New Blacklist buffer?
	if(buffer && bufferSize)
	{
		__try
		{
			// Change to char count
			ULONG const end = bufferSize / sizeof(WCHAR);

			ULONG curr = 0;

			while(curr < end)
			{
				LPCWSTR const wstr = buffer + curr;
				ULONG   const len  = (ULONG) wcslen(wstr);

				if(!len)
				{
					break;
				}

				ASSERT(curr + len < end);

				status = Manage(wstr, len * sizeof(WCHAR), flags);

				if(STATUS_OBJECT_NAME_COLLISION == status)
				{
					status = STATUS_SUCCESS;
				}

				if(NT_ERROR(status))
				{
					break;
				}

				curr += 1 + len;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_INVALID_USER_BUFFER;
		}
	}
	else
	{
		// Clear all lists
		Clear();
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
