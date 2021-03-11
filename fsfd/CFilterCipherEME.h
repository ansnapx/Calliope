////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherEME.h: interface for the CFilterCipherEME class.
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterCipherEME_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
#define AFX_CFilterCipherEME_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" 
{
	// suppress warnings on #define offsetof in ddk
	#ifdef offsetof
	#undef offsetof
	#endif

	#include "pgpErrors.h"
	#include "pgpMemoryMgr.h"
	#include "pgpSymmetricCipher.h"
	#include "pgpEME.h"
	#include "pgpEME2.h"
}

class CFilterCipherEME  
{
public:

	enum c_constants
	{
		c_blockSize		= 512,				// bytes

		#ifdef _AMD64_						// This is for miniSDK's Fibonacci memory allocator
		 c_memoryNeeded	= 1597 + 12 + 12,	// 17th Fibonacci number plus 12 byte header and
		#else								// additonal 12 bytes for x64 systems
		 c_memoryNeeded	= 1597 + 12,
		#endif
	};

	CFilterCipherEME()	
	{ }
	~CFilterCipherEME()	
	{ Close(); }

	NTSTATUS						Init(FILFILE_CRYPT_CONTEXT const* crypt);
	void							Close();

	NTSTATUS						Encode(UCHAR *buffer, ULONG size);
	NTSTATUS						Decode(UCHAR *buffer, ULONG size);

	void							SetOffset(LARGE_INTEGER *offset);

	bool							UseEME2();

	static ULONG					ComputePadding(ULONG size);
	static ULONG					GetPadding(UCHAR const* source, ULONG size);
	static ULONG					AddPadding(UCHAR *target, ULONG size);

private:
   									// DATA
	LONGLONG						m_nonce;
	LONGLONG						m_offset;

	UCHAR const*					m_key;
	ULONG							m_keySize;	
	ULONG							m_cipher;	// Holds information which cipher is used

	PGPMemoryMgrRef					m_mgr;
	PGPSymmetricCipherContextRef	m_aes;
	PGPEMEContextRef				m_eme;
	PGPEME2ContextRef				m_eme2;

	UCHAR							m_memoryPool[c_memoryNeeded];
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
bool CFilterCipherEME::UseEME2()
{
	return (FILFILE_CIPHER_MODE_EME_2 == HIWORD(m_cipher));
}

inline 
ULONG CFilterCipherEME::ComputePadding(ULONG size)
{
    return (c_blockSize - (size & (c_blockSize - 1)));
}

inline
void CFilterCipherEME::SetOffset(LARGE_INTEGER *offset)
{
	ASSERT(offset);
	ASSERT(0 == (offset->QuadPart % c_blockSize));

	m_offset = offset->QuadPart / c_blockSize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // !defined(AFX_CFilterCipherEME_H__DD44F4C5_A189_494F_B0B9_2D48CEEA9591__INCLUDED_)
