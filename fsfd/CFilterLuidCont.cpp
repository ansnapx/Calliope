///////////////////////////////////////////////////////////////////////////////
//
// CFilterLuidCont.cpp: implementation of the CFilterLuidCont class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterLuidCont.h"

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterLuidCont::Close()
{
	PAGED_CODE();

	if(m_luids)
	{
		ExFreePool(m_luids);
		m_luids = 0;
	}

	m_size	   = 0;
	m_capacity = 0;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterLuidCont::Add(CFilterLuidCont const& other)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	for(USHORT pos = 0; pos < other.Size(); ++pos)
	{
		status = Add((LUID*) &other.m_luids[pos]);

		if(NT_ERROR(status))
		{
			break;
		}
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterLuidCont::Add(LUID const* luid)
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	ULONG const pos = Check(luid);

	if(pos != ~0u)
	{
		return STATUS_SUCCESS;
	}

	if(m_capacity == m_size)
	{
		USHORT const capacity = m_capacity + c_incrementCount;

		ULONGLONG *luids = (ULONGLONG*) ExAllocatePool(PagedPool, 
													   capacity * sizeof(ULONGLONG));

		if(!luids)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(luids, capacity * sizeof(ULONGLONG));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_luids);
				
			RtlCopyMemory(luids, m_luids, m_size * sizeof(ULONGLONG));
			ExFreePool(m_luids);
		}

		m_luids = luids;
	}

	ASSERT(m_luids);

	m_luids[m_size] = *((ULONGLONG*) luid);

	m_size++;

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterLuidCont::Remove(LUID const* luid)
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	ULONG const pos = Check(luid);

	if(pos == ~0u)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ASSERT(m_size);
	ASSERT(pos < m_size);
	ASSERT(m_luids);

	m_size--;

	if(pos < m_size)
	{
		RtlMoveMemory(m_luids + pos, 
					  m_luids + pos + 1, 
					  (m_size - pos) * sizeof(ULONGLONG));
	}

	m_luids[m_size] = 0;

	// Inform caller when last LUID was removed
	return (m_size) ? STATUS_SUCCESS : STATUS_ALERTED;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterLuidCont::Check(LUID const* luid) const
{
	ASSERT(luid);
	ASSERT(luid->HighPart || luid->LowPart);

	PAGED_CODE();

	ASSERT(m_size <= m_capacity);

	for(ULONG pos = 0; pos < m_size; ++pos)
	{
		ASSERT(m_luids);

		if(m_luids[pos] == *((ULONGLONG*) luid))
		{
			return pos;
		}
	}

	return ~0u;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
