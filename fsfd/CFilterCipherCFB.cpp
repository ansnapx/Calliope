////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherCFB.cpp: implementation of the CFilterCipherCFB class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"

#ifdef FILFILE_USE_CFB

#include "CFilterCipherCFB.h"
// force template instances
#if DBG
 template class RijndealCoder<AES_128>;
 template class RijndealCoder<AES_192>;
 template class RijndealCoder<AES_256>;
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterCipherCFB::GetPadding(UCHAR const* source, ULONG size)
{
	ASSERT(source);
	ASSERT(size);
	ASSERT(0 == (size % c_blockSize));

	ULONG const padded = source[size - 1];

	if(!padded || (padded > c_blockSize) || (size < padded))
	{
		ASSERT(false);

		return 0;
	}

	source += size - padded;

	// verify padded values
	for(ULONG index = 0; index < padded; ++index)
	{
		if(source[index] != (UCHAR) padded)
		{
			ASSERT(false);

			return 0;
		}
	}
	
	return padded;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterCipherCFB::AddPadding(UCHAR *target, ULONG size)
{
	ASSERT(target);

	target += size;

	ULONG const padded = ComputePadding(size);

	if(padded < c_blockSize)
	{
		for(ULONG index = 0; index < padded; ++index)
		{
			target[index] = (UCHAR) padded;
		}

		return padded;
	}

	ASSERT(c_blockSize == 16);

	ULONG *t = (ULONG*) target;

	// pad whole block
	*t++ = 0x10101010;
	*t++ = 0x10101010;
	*t++ = 0x10101010;
	*t	 = 0x10101010;

	return c_blockSize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

template<typename AES>
NTSTATUS CFilterCipherCFB::Encode(UCHAR *buffer, ULONG size, AES &aes)
{
	ASSERT(buffer);
	ASSERT(size);

	ASSERT(0 == (size % c_blockSize));
	ASSERT(m_key);
	ASSERT(m_keySize == aes.c_keySize);

	aes.Init(m_key, false);

	ULONG current = 0;
	UCHAR output[c_blockSize];

	do
	{
		// init IV
		*((LONGLONG*) output)	  = m_nonce;
		*((LONGLONG*) output + 1) = m_offset;

		do
		{
			// encode inplace
			aes.EncodeBlock(output);

			ULONG *b = (ULONG*) (buffer + current);
			ULONG *o = (ULONG*) (output);

			// do the feedback stuff
			*o	  ^= *b;
			*b++   = *o++;

			*o	  ^= *b;
			*b++   = *o++;

			*o	  ^= *b;
			*b++   = *o++;

			*o	  ^= *b;
			*b     = *o;

			current += c_blockSize;

			// sector boundary crossed ?
			if( !(current & (CFilterBase::c_sectorSize - 1)))
			{
				break;
			}
		}
		while(current < size);

		m_offset += CFilterBase::c_sectorSize;
	}
	while(current < size);

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

template<typename AES>
NTSTATUS CFilterCipherCFB::Decode(UCHAR *buffer, ULONG size, AES &aes)
{
	ASSERT(buffer);
	ASSERT(size);

	ASSERT(0 == (size % c_blockSize));
	ASSERT(m_key);
    ASSERT(m_keySize == aes.c_keySize);

	aes.Init(m_key, false);

	ULONG current = 0;
	UCHAR output[c_blockSize];

	do
	{
		// init IV
		*((LONGLONG*) output)	  = m_nonce;
		*((LONGLONG*) output + 1) = m_offset;

		do
		{
			// encode inplace
			aes.EncodeBlock(output);
            			
			ULONG *o = (ULONG*) (output);
			ULONG *b = (ULONG*) (buffer + current);

			// do the feedback stuff
			ULONG c  = *b;
			*b++ = c ^ *o;
			*o++ = c;

			c    = *b;
			*b++ = c ^ *o;
			*o++ = c;

			c    = *b;
			*b++ = c ^ *o;
			*o++ = c;

			c    = *b;
			*b   = c ^ *o;
			*o   = c;

			current += c_blockSize;

			// sector boundary crossed ?
			if( !(current & (CFilterBase::c_sectorSize - 1)))
			{
				break;
			}
		}
		while(current < size);

		m_offset += CFilterBase::c_sectorSize;
	}
	while(current < size);

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherCFB::Encode(UCHAR *buffer, ULONG size)
{
	ASSERT(buffer);
	ASSERT(size);

	if(m_keySize == 32)
	{
		return Encode(buffer, size, RijndealCoder<AES_256>());
	}
	else if(m_keySize == 16)
	{
		return Encode(buffer, size, RijndealCoder<AES_128>());
	}

	ASSERT(m_keySize == 24);

	return Encode(buffer, size, RijndealCoder<AES_192>());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherCFB::Decode(UCHAR *buffer, ULONG size)
{
	ASSERT(buffer);
	ASSERT(size);

	if(m_keySize == 32)
	{
		return Decode(buffer, size, RijndealCoder<AES_256>());
	}
	else if(m_keySize == 16)
	{
		return Decode(buffer, size, RijndealCoder<AES_128>());
	}

	ASSERT(m_keySize == 24);

	return Decode(buffer, size, RijndealCoder<AES_192>());
}

#endif //FILFILE_USE_CFB
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
