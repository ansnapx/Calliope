////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherCFB.h: interface for the CFilterCipherCFB class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterCipherCFB_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
#define AFX_CFilterCipherCFB_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "RijndaelCoder.h"

class CFilterCipherCFB  
{

public:

	enum c_constants { c_blockSize = 16 }; // in bytes

	explicit CFilterCipherCFB(FILFILE_CRYPT_CONTEXT const* crypt)	
	{ Init(crypt); }
	~CFilterCipherCFB()	
	{ Close(); }

	NTSTATUS			Init(FILFILE_CRYPT_CONTEXT const* crypt);
	void				Close();

	NTSTATUS			Encode(UCHAR *buffer, ULONG size);
	NTSTATUS			Decode(UCHAR *buffer, ULONG size);

	void				SetOffset(LARGE_INTEGER *offset);

	static ULONG		ComputePadding(ULONG size);
	static ULONG		GetPadding(UCHAR const* source, ULONG size);
	static ULONG		AddPadding(UCHAR *target, ULONG size);

private:

	template<typename AES>
	NTSTATUS			Encode(UCHAR *buffer, ULONG size, AES &aes);
	template<typename AES>
	NTSTATUS			Decode(UCHAR *buffer, ULONG size, AES &aes);

   						// DATA
	UCHAR const*		m_key;
	ULONG				m_keySize;

	LONGLONG			m_nonce;
	LONGLONG			m_offset;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
NTSTATUS CFilterCipherCFB::Init(FILFILE_CRYPT_CONTEXT const* crypt)
{ 
	ASSERT(crypt);

	m_key	  = crypt->Key.m_key;
	m_keySize = crypt->Key.m_size;

	m_nonce   = crypt->Nonce.QuadPart;
	m_offset  = crypt->Offset.QuadPart;

	return STATUS_SUCCESS;
}

inline
void CFilterCipherCFB::Close()
{
	RtlZeroMemory(this, sizeof(*this));
}

inline 
ULONG CFilterCipherCFB::ComputePadding(ULONG size)
{
    return c_blockSize - (size & (c_blockSize - 1));
}

inline
void CFilterCipherCFB::SetOffset(LARGE_INTEGER *offset)
{
	ASSERT(offset);
	ASSERT(0 == (offset->QuadPart % c_blockSize));

	m_offset = offset->QuadPart;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // !defined(AFX_CFilterCipherCFB_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
