////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterEntity.cpp: implementation of the CFilterEntity class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CFilterEntity.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterEntityCont::Close()
{
	PAGED_CODE();

	if(m_size || m_capacity)
	{
		ASSERT(m_entities);

		DBGPRINT(("EntityCont::Close() current sizes[%d,%d]\n", m_size, m_capacity));
	}

	for(ULONG index = 0; index < m_size; ++index)
	{
		m_entities[index].Close();
	}

	m_size = 0;

	if(m_entities)
	{
		ExFreePool(m_entities);
		m_entities = 0;
	}
	
	m_capacity = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

CFilterEntity* CFilterEntityCont::GetFromIdentifier(ULONG identifier, ULONG *pos) const
{
	ASSERT(identifier);
	ASSERT(identifier != ~0u);

	PAGED_CODE();

	// Lock must be held
	ASSERT(!m_size || m_entities);
	
	for(ULONG index = 0; index < m_size; ++index)
	{	
		// should always belong to same Volume
		ASSERT((m_entities[index].m_identifier & 0xff000000) == (identifier & 0xff000000));

		if(m_entities[index].m_identifier == identifier)
		{
			if(pos)
			{
				*pos = index;
			}

			return m_entities + index;
		}
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterEntityCont::CopyInfo(ULONG pos, CFilterEntity *target) const
{
	ASSERT(target);
	ASSERT(m_capacity >= m_size);
	
	if(pos < m_size)
	{
		ASSERT(m_entities);

		CFilterEntity const*const entity = m_entities + pos;

		ASSERT(entity->m_identifier);
		ASSERT(entity->m_headerIdentifier);

		// copy Entity Info
		target->m_flags			  |= entity->m_flags & (TRACK_AUTO_CONFIG | TRACK_MATCH_EXACT);
		target->m_identifier	   = entity->m_identifier;
		target->m_headerIdentifier = entity->m_headerIdentifier;
		target->m_headerBlocksize  = entity->m_headerBlocksize;
	}
	else
	{
		ASSERT(false);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterEntityCont::Arrange()
{
	PAGED_CODE();

	// Arrange Entities according following priority:
	//
	// 1. File entries before Directory ones
	// 2. Directory entries with higher depth before lower ones
	// 3. Newer entries before older ones

	if(m_size > 1)
	{
		ULONG const current = m_size - 1;
		ULONG target = 0;

		// directory type ?
		if(!m_entities[current].m_file)
		{
			ASSERT(m_entities[current].m_directory);

			USHORT const currentDepth = m_entities[current].m_directoryDepth; 
			
			// search first entry with lower or equal depth
			while(target < current)
			{
				ASSERT(target < m_size);

				if(!m_entities[target].m_file)
				{
					if(m_entities[target].m_directoryDepth <= currentDepth)
					{
						break;
					}
				}

				target++;
			}
		}

		if(target < current)
		{
			ASSERT(target  < m_size);
			ASSERT(current < m_size);

			// move remaining entries to free up target pos
			CFilterEntity temp = m_entities[current];

			RtlMoveMemory(m_entities + target + 1, 
						  m_entities + target, 
						  (current - target) * sizeof(CFilterEntity));

			m_entities[target] = temp;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterEntityCont::Check(CFilterPath const* path, bool exact) const
{
	ASSERT(path);

	PAGED_CODE();

	ASSERT(!m_size || m_entities);

	for(ULONG index = 0; index < m_size; ++index)
	{
		if(m_entities[index].Match(path, exact))
		{
			DBGPRINT(("Entities::Check: matched at[%d]\n", index));

			return index;
		}
	}

	return ~0u;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEntityCont::AddRaw(CFilterEntity *entity)
{
	ASSERT(entity);

	PAGED_CODE();

	#if DBG
	{
		// In TS mode, all Entities must contain at least one LUID
		if(CFilterControl::IsTerminalServices())
		{
			ASSERT(entity->m_luids.Size());
		}

		// Regular?
		if(entity->m_identifier)
		{
			// Regular Entities must have valid values for these:
			ASSERT(entity->m_headerIdentifier);
			ASSERT(entity->m_headerBlocksize);
		}
	}
	#endif

	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterEntity* entities = (CFilterEntity*) ExAllocatePool(NonPagedPool, capacity * sizeof(CFilterEntity));

		if(!entities)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(entities, capacity * sizeof(CFilterEntity));

		m_capacity = capacity;

		if(m_size)
		{
			ASSERT(m_entities);
				
			RtlCopyMemory(entities, m_entities, m_size * sizeof(CFilterEntity));
			ExFreePool(m_entities);
		}

		m_entities = entities;
	}

	CFilterEntity *const added = m_entities + m_size;

	// Copy Path
	NTSTATUS status = added->CopyFrom(entity);

	if(NT_SUCCESS(status))
	{
		// Ensure directory Entities have a trailing backslash
		if(!added->m_file && (added->m_directoryLength > sizeof(WCHAR)))
		{
			USHORT const len = added->m_directoryLength / sizeof(WCHAR);

			if(added->m_directory[len] != L'\\')
			{
				added->m_directory[len]     = L'\\';
				added->m_directory[len + 1] = UNICODE_NULL;
			}
		}

		// Copy Entity attribs
		added->m_identifier = entity->m_identifier;

		// Regular?
		if(entity->m_identifier)
		{
			added->m_headerIdentifier = entity->m_headerIdentifier;
			added->m_headerBlocksize  = entity->m_headerBlocksize;
		}

		// Take ownership of LUID list, if any
		added->m_luids = entity->m_luids;
		entity->m_luids.Clear();

		m_size++;

		Arrange();

		DBGPRINT(("EntityCont::AddRaw() new sizes[%d,%d]\n", m_size, m_capacity));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEntityCont::Remove(CFilterEntity const* entity)
{
	ASSERT(entity);

	PAGED_CODE();

	// Only remove exact matches
	ULONG const pos = Check(entity, true);
				
	if(pos != ~0u)
	{	
		// Remove it
		RemoveRaw(pos, true);

		return STATUS_SUCCESS;
	}

	DBGPRINT(("EntityCont::Remove() Entity[0x%p] not found\n", entity));

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEntityCont::Add(CFilterEntity *entity, bool exact)
{
	ASSERT(entity);

	PAGED_CODE();

	ULONG const pos = Check(entity, exact);
	
	if(pos == ~0u)
	{
		// Just add at end
		return AddRaw(entity);
	}

	DBGPRINT(("EntityCont::Add() Entity[0x%p] already exists\n", entity));

	return STATUS_OBJECT_NAME_COLLISION;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEntityCont::RemoveRaw(ULONG pos, bool release)
{
	ASSERT(pos < m_size);

	PAGED_CODE();

	ASSERT(m_entities);
	ASSERT(m_size <= m_capacity);

	if(release)
	{
		// references to Header should already be teared down
		ASSERT(!m_entities[pos].m_headerIdentifier);

		// release resources
		m_entities[pos].Close();
	}
		
	m_size--;

	// Close gap, if any
	if(pos < m_size)
	{
		RtlMoveMemory(m_entities + pos,
					  m_entities + pos + 1,
					  (m_size - pos) * sizeof(CFilterEntity));
	}

	RtlZeroMemory(m_entities + m_size, sizeof(CFilterEntity));

	// Reduce our memory footprint 
	if((m_capacity - m_size) >= (c_incrementCount * 2))
	{
		ULONG const capacity = m_capacity - c_incrementCount;

		CFilterEntity *const entities = (CFilterEntity*) ExAllocatePool(NonPagedPool, capacity * sizeof(CFilterEntity));

		if(entities)
		{
			RtlZeroMemory(entities, capacity * sizeof(CFilterEntity));

			m_capacity = capacity;

			if(m_size)
			{
				RtlCopyMemory(entities, m_entities, m_size * sizeof(CFilterEntity));
			}

			ExFreePool(m_entities);

			m_entities = entities;
		}
	}

	DBGPRINT(("EntityCont::RemoveRaw() pos[%d] new sizes[%d,%d]\n", pos, m_size, m_capacity));

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
