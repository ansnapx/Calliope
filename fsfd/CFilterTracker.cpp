////////////////////////////////////////////////////////////////////////////////
//
// CFilterTracker.cpp: implementation of the CFilterTracker class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterTracker.h"

////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterTracker::Init()
{
	RtlZeroMemory(this, sizeof(*this));

	return ExInitializeResourceLite(&m_lock);
}

////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterTracker::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();

	if(m_entries)
	{
		ExAcquireResourceExclusiveLite(&m_lock, true);

		ExFreePool(m_entries);
		m_entries  = 0;

		m_size	   = 0;
		m_capacity = 0;

		ExReleaseResourceLite(&m_lock);
	}

	ExDeleteResourceLite(&m_lock);
	FsRtlExitFileSystem();
}

////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterTracker::Add(FILE_OBJECT *file, ULONG state)
{
	ASSERT(file);
	ASSERT(state);

	PAGED_CODE();

	// Do not track stack-based FOs because there will no Close for it
	if(CFilterBase::IsStackBased(file))
	{
		return STATUS_SUCCESS;
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	ASSERT(m_size <= m_capacity);

	ULONG pos = ~0u;

	if(Search(file, &pos))
	{
		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();

		// We should never come here
		ASSERT(false);

		return STATUS_OBJECT_NAME_COLLISION;
	}

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;	

		CFilterTrackerEntry *const entries = (CFilterTrackerEntry*) ExAllocatePool(NonPagedPool,capacity * sizeof(CFilterTrackerEntry));
		if(!entries)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(entries, capacity * sizeof(CFilterTrackerEntry));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_entries);

			RtlCopyMemory(entries, m_entries, m_size * sizeof(CFilterTrackerEntry));

			ExFreePool(m_entries);
		}

		m_entries = entries;
	}

	ASSERT(pos < m_capacity);
	ASSERT(m_entries);

	if(pos < m_size)
	{
		RtlMoveMemory(m_entries + pos + 1, 
					  m_entries + pos, 
					  (m_size - pos) * sizeof(CFilterTrackerEntry));
	}
	
	m_entries[pos].CFilterTrackerEntry::CFilterTrackerEntry(file, state);

	m_size++;

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterTracker::Remove(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	if(!m_size)
	{
		return FILFILE_TRACKER_NULL;
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	ASSERT(m_size <= m_capacity);

	ULONG state = FILFILE_TRACKER_NULL;
	ULONG pos	= ~0u;
	
	if(Search(file, &pos))
	{
		ASSERT(pos < m_size);
		ASSERT(m_entries);
		ASSERT(m_entries[pos].m_file == file);

		state = m_entries[pos].m_state;

		m_size--;

		if(pos < m_size)
		{
			RtlMoveMemory(m_entries + pos, 
						  m_entries + pos + 1, 
						  (m_size - pos) * sizeof(CFilterTrackerEntry));
		}

		RtlZeroMemory(m_entries + m_size, sizeof(CFilterTrackerEntry));
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return state;
}

////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterTracker::Check(FILE_OBJECT *file)
{
	ASSERT(file);

	ULONG state = FILFILE_TRACKER_NULL;

	if(m_size)
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_lock, true);

		ASSERT(m_size <= m_capacity);
		ASSERT(m_entries);

		ULONG pos = ~0u;

		if(Search(file, &pos))
		{
			ASSERT(pos < m_size);
			ASSERT(m_entries[pos].m_file == file);

			state = m_entries[pos].m_state;
		}

		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();
	}

	return state;
}

////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

bool CFilterTracker::Search(FILE_OBJECT *file, ULONG *pos) const
{
	ASSERT(file);
	ASSERT(pos);

	#if DBG
	{
		// Verify binary search property
		for(ULONG pos = 0; pos + 1 < m_size; ++pos)
		{
			if(m_entries[pos].m_file >= m_entries[pos + 1].m_file)
			{
				ASSERT(false);
			}
		}
	}
	#endif

	ULONG left  = 0;
	ULONG right = m_size;

	// binary search
	while(left < right)
	{
		ULONG const middle = left + (right - left) / 2;

		if(file == m_entries[middle].m_file)
		{
			*pos = middle;

			return true;
		}

		if(file > m_entries[middle].m_file)
		{
			// search right side
			left = middle + 1;
		}
		else
		{
			// search left side
			right = middle;
		}
	}

	*pos = left;

	return false;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

