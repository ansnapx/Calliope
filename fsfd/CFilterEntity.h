////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterEntity.h: definition of the CFilterEntity,CFilterEntityCont classes
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERENTITY_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERENTITY_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CFilterPath.h"
#include "CFilterLuidCont.h"

/////////////////////////////

struct CFilterEntity : public CFilterPath
{
	void				Close();

	ULONG				m_identifier;			// identifier of this Entity
	ULONG				m_headerIdentifier;		// identifies corresponding Header
	ULONG				m_headerBlocksize;

	CFilterLuidCont		m_luids;
};

inline
void CFilterEntity::Close()
{
	m_luids.Close();
	CFilterPath::Close();
}
  
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterEntityCont
{
	enum c_constants		{ c_incrementCount = 8 };

public:

	NTSTATUS				Init();
	void					Close();
	ULONG					Size() const;

	NTSTATUS				Add(CFilterEntity *entity, bool exact = false);
	NTSTATUS				AddRaw(CFilterEntity *entity);

	NTSTATUS				Remove(CFilterEntity const* entity);
	NTSTATUS				RemoveRaw(ULONG pos, bool release);
	
	ULONG					Check(CFilterPath const* path, bool exact = false) const;
	void					CopyInfo(ULONG pos, CFilterEntity *target) const;

	CFilterEntity*			GetFromPosition(ULONG pos) const;
	CFilterEntity*			GetFromIdentifier(ULONG identifier, ULONG *pos = 0) const;

private:
	void					Arrange();

							// DATA
	CFilterEntity*			m_entities;
	ULONG					m_size;
	ULONG					m_capacity;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterEntityCont::Init()
{
	m_entities  = 0;
	m_size		= 0;
	m_capacity  = 0;

	return STATUS_SUCCESS;
}

inline
ULONG CFilterEntityCont::Size() const
{
	return m_size;
}

inline
CFilterEntity* CFilterEntityCont::GetFromPosition(ULONG pos) const
{
	ASSERT(pos < m_size);
	ASSERT(m_capacity >= m_size);
	ASSERT(m_entities);

	return m_entities + pos;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // AFX_CFILTERENTITY_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_