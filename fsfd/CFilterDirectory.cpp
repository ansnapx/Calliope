////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterDirectory.cpp: implementation of the CFilterDirectory class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterDirectory.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterDirectoryCont::Init()
{
	PAGED_CODE();

	m_directories	= 0;
	m_size			= 0;
	m_capacity		= 0;

	// translate seconds to ticks
	m_timeout = CFilterBase::GetTicksFromSeconds(c_timeout);

	DBGPRINT(("DirectoryCont: timeout in ticks[0x%x]\n", m_timeout));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterDirectoryCont::Close()
{
	PAGED_CODE();

	if(m_directories)
	{
		ExFreePool(m_directories);
		m_directories = 0;
	}

	m_size	   = 0;
	m_capacity = 0;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterDirectoryCont::Search(FILE_OBJECT *file, ULONG *pos)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	#if DBG
	{
		// Verify binary search property
		for(ULONG index = 0; index + 1 < m_size; ++index)
		{
			if(m_directories[index].m_file >= m_directories[index + 1].m_file)
			{
				ASSERT(false);
			}
		}
	}
	#endif

	ULONG left  = 0;
	ULONG right = m_size;

	// Binary Search
	while(left < right)
	{
		ASSERT(m_directories);

		ULONG const middle = left + (right - left) / 2;

		if(m_directories[middle].m_file == file)
		{
			if(pos)
			{
				*pos = middle;
			}

			return true;
		}

		if(file > m_directories[middle].m_file)
		{
			// Search in right side
			left = middle + 1;
		}
		else
		{
			// Search in left side
			right = middle;
		}
	}

	if(pos)
	{
		*pos = left;
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterDirectoryCont::Add(CFilterDirectory *directory)
{
	ASSERT(directory);

	PAGED_CODE();

	ASSERT(directory->m_file);

	ULONG pos = ~0u;

	if(Search(directory->m_file, &pos))
	{
		// We should never come here
		ASSERT(false);

		return STATUS_OBJECT_NAME_COLLISION;
	}

	ASSERT(pos != ~0u);

	if(m_size == m_capacity)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterDirectory* directories = (CFilterDirectory*) ExAllocatePool(NonPagedPool, capacity * sizeof(CFilterDirectory));

		if(!directories)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(directories, capacity * sizeof(CFilterDirectory));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_directories);

			RtlCopyMemory(directories, m_directories, m_size * sizeof(CFilterDirectory));

			ExFreePool(m_directories);
		}

		m_directories = directories;
	}

	ASSERT(m_size < m_capacity);
	ASSERT(pos <= m_size);
	ASSERT(m_directories);

	if(pos < m_size)
	{
		RtlMoveMemory(m_directories + pos + 1, 
					  m_directories + pos, 
					  (m_size - pos) * sizeof(CFilterDirectory));
	}
	
	m_directories[pos] = *directory;

	m_size++;

	DBGPRINT(("DirectoryCont::Add: new sizes[%d,%d]\n", m_size, m_capacity));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterDirectoryCont::Remove(FILE_OBJECT *file, ULONG pos)
{
	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	// Exact position given?
	if(~0u == pos)
	{
		ASSERT(file);

		// Search for file
		if(!Search(file, &pos))
		{
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}

	ASSERT(pos < m_size);
	
	m_size--;

	if(pos < m_size)
	{
		RtlMoveMemory(m_directories + pos, 
					  m_directories + pos + 1, 
					  (m_size - pos) * sizeof(CFilterDirectory));
	}

	RtlZeroMemory(m_directories + m_size, sizeof(CFilterDirectory));

	if(m_capacity - m_size >= c_incrementCount * 2)
	{
		ULONG const capacity = m_capacity - c_incrementCount;

		CFilterDirectory* directories = (CFilterDirectory*) ExAllocatePool(NonPagedPool, capacity * sizeof(CFilterDirectory));

		if(directories)
		{
			RtlZeroMemory(directories, capacity * sizeof(CFilterDirectory));

			m_capacity = capacity;

			if(m_size)
			{
				ASSERT(m_directories);

				RtlCopyMemory(directories, m_directories, m_size * sizeof(CFilterDirectory));
			}

			ExFreePool(m_directories);

			m_directories = directories;
		}
	}

	DBGPRINT(("DirectoryCont::Remove: pos[%d] new sizes[%d,%d]\n", pos, m_size, m_capacity));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterDirectoryCont::SearchSpecial(ULONG hash, ULONG *pos)
{
	ASSERT(pos);

	PAGED_CODE();

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	ULONG const tid = (ULONG)(ULONG_PTR) PsGetCurrentThreadId(); 

	for(ULONG index = 0; index < m_size; ++index)
	{
		if(m_directories[index].m_hash == hash)
		{
			if(m_directories[index].m_tid == tid)
			{
				// valid entry ?
				if(m_directories[index].m_tick)
				{
					LONG delta = tick.LowPart - m_directories[index].m_tick;

					if(delta < 0)
					{
						delta = -delta;
					}

					// not outdated ?
					if((ULONG) delta < m_timeout)
					{
						*pos = index;

						return true;
					}

					DBGPRINT(("DirectoryCont::CheckSpecial -INFO: timed out by [0x%x]\n", delta));

					// invalidate entry
					m_directories[index].m_tick = 0;
				}

				break;
			}
		}
	}
     
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

