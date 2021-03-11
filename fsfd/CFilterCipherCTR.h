////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherCTR.h: interface for the CFilterCipherCTR class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterCipherCTR_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
#define AFX_CFilterCipherCTR_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "RijndaelCoder.h"

class CFilterCipherCTR  
{

public:

	enum c_constants { c_blockSize = 16 }; // in bytes

	explicit CFilterCipherCTR(FILFILE_CRYPT_CONTEXT const* crypt)
	{ Init(crypt); }
	~CFilterCipherCTR()
	{ Close(); }

	NTSTATUS			Init(FILFILE_CRYPT_CONTEXT const* crypt);
	void				Close();
	void				SetOffset(LARGE_INTEGER *offset);

	NTSTATUS			Encode(UCHAR *buffer, ULONG size);
	NTSTATUS			Decode(UCHAR *buffer, ULONG size);

private:

	template<typename AES>
	NTSTATUS			Code(UCHAR *buffer, ULONG size, AES &aes);
	void				Xor(UCHAR *buffer, UCHAR const *xor, ULONG size);

						// DATA
	UCHAR const*		m_key;
	ULONG				m_keySize;

	LONGLONG			m_nonce;
	LONGLONG			m_offset;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterCipherCTR::Init(FILFILE_CRYPT_CONTEXT const* crypt)
{ 
	ASSERT(crypt);

	m_key	  = crypt->Key.m_key;
	m_keySize = crypt->Key.m_size;

	m_nonce   = crypt->Nonce.QuadPart;
	m_offset  = crypt->Offset.QuadPart;

	return STATUS_SUCCESS;
}

inline
void CFilterCipherCTR::Close()
{
	RtlZeroMemory(this, sizeof(*this));
}

inline
void CFilterCipherCTR::SetOffset(LARGE_INTEGER *offset)
{
	ASSERT(offset);
	ASSERT(0 == (offset->QuadPart % c_blockSize));

	m_offset = offset->QuadPart;
}

inline
NTSTATUS CFilterCipherCTR::Decode(UCHAR *buffer, ULONG size)
{
	return Encode(buffer, size);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // !defined(AFX_CFilterCipherCTR_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
