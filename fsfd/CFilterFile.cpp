////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterFile.cpp: implementation of the CFilterFile class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterFile.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterFile::Track(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	// Check if FO is already there
	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_files);

		if(m_files[pos] == file)
		{
			return STATUS_SUCCESS;
		}
	}

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;	

		FILE_OBJECT **files = (FILE_OBJECT**) ExAllocatePool(NonPagedPool, 
														     capacity * sizeof(FILE_OBJECT*));
		if(!files)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(files, capacity * sizeof(FILE_OBJECT*));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_files);

			RtlCopyMemory(files, m_files, m_size * sizeof(FILE_OBJECT*));

			ExFreePool(m_files);
		}

		m_files = files;
	}

	ASSERT(m_files);

	m_files[m_size] = file;

	m_size++;

	return STATUS_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterFile::Update(CFilterFile const* other)
{
	ASSERT(other);

	PAGED_CODE();

	// Merge tracked FOs
	for(ULONG index = 0; index < other->m_size; ++index)
	{
		ASSERT(other->m_files);

		NTSTATUS status = Track(other->m_files[index]);

		if(NT_ERROR(status))
		{
			return status;
		}
	}

	// Sum up RefCounts
	m_refCount += other->m_refCount;

	// Just overwrite remaining values
	m_hash		 = other->m_hash;
	m_threadId	 = other->m_threadId;
	m_tick		 = other->m_tick;
	m_link		 = other->m_link;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterFile::OnCreate(FILE_OBJECT* file, ULONG hash)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT( !CFilterBase::IsStackBased(file));

	// Very first FO?
	if(!m_fcb)
	{
		m_fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
	}
	else
	{
		ASSERT(m_fcb == file->FsContext);
	}

	ASSERT(m_size <= m_capacity);

	#if DBG
	{
		// FO should not already be tracked
		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			ASSERT(m_files);
			ASSERT(m_files[pos]);
			ASSERT(m_files[pos] != file);
		}
	}
	#endif

	// Add FO to tracked list for this data stream
	NTSTATUS status = Track(file);

	if(NT_ERROR(status))
	{
		return status;
	}

	if( !(file->Flags & FO_STREAM_FILE))
	{
		m_refCount++;
	}

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	m_tick		= tick.LowPart;
	m_hash		= hash;
	m_threadId	= PsGetCurrentThreadId();

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterFile::OnClose(FILE_OBJECT* file)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_files);

		if(m_files[pos] == file)
		{
			m_size--;

			if(pos < m_size)
			{
				RtlMoveMemory(m_files + pos,
							  m_files + pos + 1,
							  (m_size - pos) * sizeof(FILE_OBJECT*));
			}

			m_files[m_size] = 0;

			break;
		}
	}

	if( !(file->Flags & FO_STREAM_FILE))
	{	
		if(m_refCount)
		{
			m_refCount--;
		}
		else
		{
			// just want to know ...
			DBGPRINT(("CFilterFile::OnClose -WARN: m_refCount == 0\n"));
		}
	}
	else
	{
		DBGPRINT(("CFilterFile::OnClose: FO[0x%p] is FO_STREAM_FILE\n", file));
	}
	
	// no more outstanding references ?
	if(!m_refCount)
	{
		if(!file->SectionObjectPointer || (!file->SectionObjectPointer->DataSectionObject && !file->SectionObjectPointer->ImageSectionObject))
		{	
			m_fcb = 0;

			return true;
		}

		DBGPRINT(("CFilterFile::OnClose: FO[0x%p] new RefCount[0], DataSOP[0x%p], ImageSOP[0x%p]\n", file, file->SectionObjectPointer->DataSectionObject, file->SectionObjectPointer->ImageSectionObject));
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterFileCont::Init()
{
	PAGED_CODE();

	m_files	   = 0;
	m_size	   = 0;
	m_capacity = 0;

	// translate seconds to ticks
	m_timeout = CFilterBase::GetTicksFromSeconds(c_timeout);

	DBGPRINT(("FileCont: timeout in ticks[0x%x]\n", m_timeout));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterFileCont::Close()
{
	PAGED_CODE();

	ASSERT(m_capacity >= m_size);

	if(m_files)
	{
		ASSERT(m_capacity);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_files[pos].Close();
		}

		RtlZeroMemory(m_files, m_capacity * sizeof(CFilterFile));

		ExFreePool(m_files);
		m_files = 0;
	}

	m_size	   = 0;
	m_capacity = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterFileCont::Add(CFilterFile *filterFile, ULONG pos)
{
	ASSERT(filterFile);

	PAGED_CODE();

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;	

		CFilterFile *const files = (CFilterFile*) ExAllocatePool(NonPagedPool, 
																 capacity * sizeof(CFilterFile));
		if(!files)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(files, capacity * sizeof(CFilterFile));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_files);

			RtlCopyMemory(files, m_files, m_size * sizeof(CFilterFile));
			RtlZeroMemory(m_files, m_size * sizeof(CFilterFile));

			ExFreePool(m_files);
		}

		m_files = files;
	}

	if(pos < m_size)
	{
		RtlMoveMemory(m_files + pos + 1, 
					  m_files + pos, 
					  (m_size - pos) * sizeof(CFilterFile));
	}
	
	m_files[pos] = *filterFile;

	m_size++;

	// We took ownership
	filterFile->m_files		= 0;
	filterFile->m_size		= 0;
	filterFile->m_capacity  = 0;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterFileCont::Remove(ULONG pos)
{
	PAGED_CODE();

	ASSERT(m_size);
	ASSERT(m_size <= m_capacity);
	ASSERT(pos < m_size);

	m_files[pos].Close();

	m_size--;

	if(pos < m_size)
	{
		RtlMoveMemory(m_files + pos, 
					  m_files + pos + 1, 
					  (m_size - pos) * sizeof(CFilterFile));
	}

	RtlZeroMemory(m_files + m_size, sizeof(CFilterFile));

	// Exceeded threshold of unused space?
	if((m_capacity - m_size) > (c_incrementCount * 4))
	{
		ULONG const capacity = m_capacity - c_incrementCount;

		CFilterFile *const files = (CFilterFile*) ExAllocatePool(NonPagedPool, capacity * sizeof(CFilterFile));

		if(files)
		{
			RtlZeroMemory(files, capacity * sizeof(CFilterFile));

			m_capacity = capacity;

			if(m_size)
			{
				ASSERT(m_files);

				RtlCopyMemory(files, m_files, m_size * sizeof(CFilterFile));
			}

			ExFreePool(m_files);

			m_files = files;
		}
		else
		{
			// Well, just ignore it
		}
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterFileCont::CheckIdentifier(ULONG identifier, ULONG *pos) const
{
	ASSERT(identifier && (identifier != ~0u));

	PAGED_CODE();

	for(ULONG index = 0; index < m_size; ++index)
	{
		if(m_files[index].m_link.m_entityIdentifier == identifier)
		{
			if(pos)
			{
				*pos = index;
			}

			return true;
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterFileCont::CheckSpecial(FILE_OBJECT *file, ULONG *pos, ULONG hash) const
{
	ASSERT(file);
	ASSERT(pos);

	PAGED_CODE();

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	HANDLE const threadId = PsGetCurrentThreadId(); 

	for(ULONG index = 0; index < m_size; ++index)
	{
		if(m_files[index].m_hash == hash)
		{
			if(m_files[index].m_threadId == threadId)
			{
				// valid entry ?
				if(m_files[index].m_tick)
				{
					LONG delta = tick.LowPart - m_files[index].m_tick;

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

					DBGPRINT(("FilesCont::CheckSpecial() -INFO: timed out by [0x%x]\n", delta));

					// invalidate entry
					m_files[index].m_tick = 0;
				}

				break;
			}
		}
	}
     
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

bool CFilterFileCont::Check(FILE_OBJECT *file, ULONG *pos) const
{
	ASSERT(file);
	ASSERT(file->FsContext);

	#if DBG
	{
		// verify binary search property
		for(ULONG index = 0; index + 1 < m_size; ++index)
		{
			if(m_files[index].m_fcb >= m_files[index + 1].m_fcb)
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

		if(file->FsContext == m_files[middle].m_fcb)
		{
			if(pos)
			{
				*pos = middle;
			}

			return true;
		}

		if(file->FsContext > m_files[middle].m_fcb)
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

	if(pos)
	{
		*pos = left;
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

