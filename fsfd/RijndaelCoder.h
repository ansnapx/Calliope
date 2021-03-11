///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// RijndealCoder.h: interface for the RijndealCoder class
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef AFX_RijndealCoder_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED
#define AFX_RijndealCoder_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// define if decryption functions are needed
#define RIJNDAEL_USE_DECRYPTION

extern "C" 
{
	// suppress warnings on #define offsetof in ddk
	#ifdef offsetof
	#undef offsetof
	#endif

	#include "pgpErrors.h"
	#include "pgpMemoryMgr.h"
	#include "pgpSymmetricCipher.h"
}

struct AES_128
{
	enum c_constants
	{
		c_keyCount		= 4,		// longs

		#ifdef _AMD64_
		 c_memoryNeeded	= 624 + 10,	// 610+10 + 12 
		#else
		 c_memoryNeeded	= 624,		// 610+12, round up to mul of 8
		#endif
	};
};

struct AES_192
{
	enum c_constants
	{
		c_keyCount		= 6,		// longs

		#ifdef _AMD64_
		 c_memoryNeeded	= 624 + 10,	// 610+10 + 12
		#else
		 c_memoryNeeded	= 624,		// 610+12, round up to mul of 8
		#endif
	};
};

struct AES_256
{
	enum c_constants
	{
		c_keyCount		= 8,		// longs

		#ifdef _AMD64_
		 c_memoryNeeded	= 624 + 10,	// 610+10 + 12
		#else
		 c_memoryNeeded	= 624,		// 610+12, round up to mul of 8
		#endif
	};
};

////////////////////////////////////////

template<typename t_traits>
class RijndealCoder
{

public:

	enum c_contants
	{
		c_keySize       = t_traits::c_keyCount * 4,	// in bytes
		c_memoryNeeded  = t_traits::c_memoryNeeded,	// in bytes
		c_blockSize		= 16,						// in bytes
	};

	RijndealCoder() : m_mgr(0), m_aes(0)					
	{ }
	~RijndealCoder()				
	{ Close(); }

	bool							Init(unsigned char const *key, bool);
	void							Close();

	bool							EncodeBlock(unsigned char *block);	// works inplace
#ifdef RIJNDAEL_USE_DECRYPTION
	bool							DecodeBlock(unsigned char *block);	// works inplace
#endif

private:

	PGPMemoryMgrRef					m_mgr;
	PGPSymmetricCipherContextRef	m_aes;
	unsigned char					m_memoryPool[c_memoryNeeded];
};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template<typename t_traits>
inline
bool RijndealCoder<t_traits>::Init(unsigned char const *key, bool)
{
	ASSERT(key);

	// Allocate memory from c_memoryPool data area
	PGPError err = PGPNewFixedSizeMemoryMgr(m_memoryPool, c_memoryNeeded, &m_mgr);

	if(IsntPGPError(err))
	{
		PGPCipherAlgorithm const alg =	(c_keySize == 16) ? kPGPCipherAlgorithm_AES128 :
										(c_keySize == 24) ? kPGPCipherAlgorithm_AES192 :
															kPGPCipherAlgorithm_AES256;

		err = PGPNewSymmetricCipherContext(m_mgr, alg, &m_aes);

		if(IsntPGPError(err))
		{
			err = PGPInitSymmetricCipher(m_aes, key);

			if(IsntPGPError(err))
			{
				return true;
			}
		}
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template<typename t_traits>
inline
void RijndealCoder<t_traits>::Close()
{
	if(m_aes)
	{
		PGPFreeSymmetricCipherContext(m_aes);
	}

	if(m_mgr)
	{
		PGPFreeMemoryMgr(m_mgr);
	}

	RtlZeroMemory(this, sizeof(*this));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template<typename t_traits>
inline bool RijndealCoder<t_traits>::EncodeBlock(unsigned char *block)
{
	ASSERT(block);

	PGPError err = PGPSymmetricCipherEncrypt(m_aes, block, block);

	return (IsntPGPError(err)) ? true : false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef RIJNDAEL_USE_DECRYPTION

template<typename t_traits>
inline bool RijndealCoder<t_traits>::DecodeBlock(unsigned char *block)
{
	ASSERT(block);

	PGPError err = PGPSymmetricCipherDecrypt(m_aes, block, block);

	return (IsntPGPError(err)) ? true : false;
}

#endif
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_RijndealCoder_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED

