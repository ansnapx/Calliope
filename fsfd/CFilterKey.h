//
// CFilterKey.h: interface for the CFilterKey class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterKey__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
#define AFX_CFilterKey__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "CFilterBase.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterKey
{
public:

	void		Init(ULONG cipher, UCHAR const *key, ULONG keySize);
	void		Init(CFilterKey const* other);
	void		Clear(); 
	bool		Equal(CFilterKey const* other) const;

	ULONG		m_cipher;	// Cipher algo (0-15), Cipher mode (16-31) as defined in CFilterBase
	ULONG		m_size;
	UCHAR		m_key[32];
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
void CFilterKey::Init(ULONG cipher, UCHAR const* key, ULONG keySize)
{
	ASSERT(cipher);
	ASSERT(key);
	ASSERT(keySize);
	ASSERT(sizeof(m_key) >= keySize);

	m_cipher = cipher;
	m_size   = keySize;

	RtlZeroMemory(m_key, sizeof(m_key));
	RtlCopyMemory(m_key, key, keySize);
}

inline
void CFilterKey::Init(CFilterKey const* other)
{
	ASSERT(other);
	ASSERT(other->m_cipher);
	ASSERT(other->m_size);

	*this = *other;
}

inline
void CFilterKey::Clear()
{
	RtlZeroMemory(this, sizeof(*this));
}

inline
bool CFilterKey::Equal(CFilterKey const* other) const
{
	ASSERT(other);
	return RtlEqualMemory(m_key, other->m_key, sizeof(m_key)) != 0;
}
    
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFilterKey__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_