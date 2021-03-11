////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherCTR.cpp: implementation of the CFilterCipherCTR class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"

#ifdef FILFILE_USE_CTR
#include "CFilterCipherCTR.h"

// force template instances
#if DBG
 template class RijndealCoder<AES_128>;
 template class RijndealCoder<AES_192>;
 template class RijndealCoder<AES_256>;
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

void CFilterCipherCTR::Xor(UCHAR *buffer, UCHAR const* xor, ULONG size)
{
	ASSERT(buffer);
	ASSERT(xor);

	ASSERT(size <= c_blockSize);

	if(size == 16)
	{
		ULONG *b = (ULONG*) buffer;
		ULONG *x = (ULONG*) xor;

		// unrolled xor of 4x4 bytes
		*b++ ^= *x++;
		*b++ ^= *x++;
		*b++ ^= *x++;
		*b   ^= *x;
	}
	else
	{
		ULONG index = 0;

		while(index < size)
		{
			if((size - index) >= 4)
			{	
				*((ULONG*) (buffer + index)) ^= *((ULONG*) (xor + index));
			
				index += 4;
			}
			else
			{
				buffer[index] ^= xor[index];

				index++;
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

template<typename AES>
NTSTATUS CFilterCipherCTR::Code(UCHAR *buffer, ULONG size, AES &aes)
{
	ASSERT(buffer);
	ASSERT(size);

	ASSERT(m_key);
	ASSERT(m_keySize == aes.c_keySize);

	ULONG current = 0;
	UCHAR stream[c_blockSize];

	aes.Init(m_key, false);

	while(current < size)
	{
		// build CTR block (Nonce | Offset)
		*((LONGLONG*) stream)	  = m_nonce;
		*((LONGLONG*) stream + 1) = m_offset;

		// encrypt inplace
		aes.EncodeBlock(stream);

		ULONG remaining = size - current;

		if(remaining > c_blockSize)
		{
			remaining = c_blockSize;
		}
		
		// XOR plain and stream block
		Xor(buffer + current, stream, remaining);

		current	  += remaining;
		m_offset  += remaining;
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherCTR::Encode(UCHAR *buffer, ULONG size)
{
	ASSERT(buffer);
	ASSERT(size);

	if(m_keySize == 32)
	{
		return Code(buffer, size, RijndealCoder<AES_256>());
	}
	else if(m_keySize == 16)
	{
		return Code(buffer, size, RijndealCoder<AES_128>());
	}

	ASSERT(m_keySize == 24);

	return Code(buffer, size, RijndealCoder<AES_192>());
}

#endif //FILFILE_USE_CTR
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
