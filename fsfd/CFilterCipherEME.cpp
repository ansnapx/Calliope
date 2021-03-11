////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherEME.cpp: implementation of the CFilterCipherEME class.
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"

#ifdef FILFILE_USE_EME
#include "CFilterCipherEME.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherEME::Init(FILFILE_CRYPT_CONTEXT const* crypt)
{ 
	ASSERT(crypt);
	ASSERT(crypt->Key.m_cipher);
	ASSERT(0 == (crypt->Offset.QuadPart % c_blockSize));

	// Clear everything
	m_mgr	  = 0;
	m_aes	  = 0;
	m_eme	  = 0;
	m_eme2 = 0;

	m_nonce   = crypt->Nonce.QuadPart;
	m_offset  = crypt->Offset.QuadPart / c_blockSize;

	m_key	  = crypt->Key.m_key;
	m_keySize = crypt->Key.m_size;

	m_cipher  = crypt->Key.m_cipher;

	// Allocate memory from c_memoryPool data area
	PGPError err = PGPNewFixedSizeMemoryMgr(m_memoryPool, c_memoryNeeded, &m_mgr);
    
	if(IsntPGPError(err))
	{
		// Here we could use the Cipher member of the given Crypt Context for the symmetric
		// algo and the key size used. Use LOWORD(crypt->Key.m_cipher) in this case
		PGPCipherAlgorithm const alg =  (m_keySize == 16) ? kPGPCipherAlgorithm_AES128
									  : (m_keySize == 24) ? kPGPCipherAlgorithm_AES192 
									  : kPGPCipherAlgorithm_AES256;

		err = PGPNewSymmetricCipherContext(m_mgr, alg, &m_aes);

		if(IsntPGPError(err))
		{
			err = kPGPError_FeatureNotAvailable;

			// Dispatch on cipher mode used for this key (FEK)
			if(FILFILE_CIPHER_MODE_EME_2 == HIWORD(m_cipher))
			{
				err = PGPNewEME2Context(m_aes, &m_eme2);

				if(IsntPGPError(err))
				{
					m_aes = 0;	// AES now belongs to EME*

					err = PGPInitEME2(m_eme2, m_key);
				}
			}
			else
			{
				ASSERT(FILFILE_CIPHER_MODE_EME == HIWORD(m_cipher));

				// Caution: Will return OutOfMemory if provided size for FixedMgr is too small
				err = PGPNewEMEContext(m_aes, &m_eme);

				if(IsntPGPError(err))
				{
					m_aes = 0;	// AES now belongs to EME

					err = PGPInitEME(m_eme, m_key);
				}
			}

			if(IsntPGPError(err))
			{
				return STATUS_SUCCESS;
			}
		}
	}

	return STATUS_UNSUCCESSFUL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

void CFilterCipherEME::Close()
{
	if(m_aes)
	{
		PGPFreeSymmetricCipherContext(m_aes);
	}

	if(m_eme)
	{
		PGPFreeEMEContext(m_eme);
	}

	if(m_eme2)
	{
		PGPFreeEME2Context(m_eme2);
	}

	if(m_mgr)
	{
		PGPFreeMemoryMgr(m_mgr);
	}

	RtlZeroMemory(this, sizeof(*this));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

/*
 * Padding may be from 1 to 512 bytes.
 * Padding of 1 byte is encoded by putting a 255 in the last byte of the file.
 * Padding of 2-512 bytes is encoded in the last two bytes of the file, LSB first.
 * I.e. the last byte of the file holds the MSB of the padding, which should be 0-2.
 * Remaining bytes of the file repeat the LSB of the number of padding bytes.
 *
 * Return zero for malformed padding
 */
ULONG CFilterCipherEME::GetPadding(UCHAR const* source, ULONG size)
{
	ASSERT(source);
	ASSERT(size);
	ASSERT(0 == (size % c_blockSize));

	ULONG padded = source[size - 1];

	// Handle special case for 1 byte of padding
	if (padded == 0xff)
		return 1;

	// Get two-byte padding amount
	padded = (padded << 8) | source[size - 2];

	if(padded > c_blockSize || padded <= 1)
		return 0;		// Malformed padding

	ASSERT(size >= padded);

	source += size - padded;

	// verify padded values
	for(ULONG index = 0; index < padded - 2; index++)
	{
		if(source[index] != (UCHAR) padded)
		{
			/* Malformed padding */
			return 0;
		}
	}
	
	return padded;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterCipherEME::AddPadding(UCHAR *target, ULONG size)
{
	ASSERT(target);

	target += size;

	ULONG const padded = ComputePadding(size);

	DBGPRINT(("AddPadding(EME): add Padding[0x%x]\n", padded));

	if (padded == 1)
	{
		// Special case for 1 byte of padding
		target[0] = 0xff;
	}
	else
	{
		// Last byte gets MSB of padding
		target[padded - 1] = (UCHAR) (padded >> 8);

		// Replicate LSB of padding
		for(ULONG index = 0; index < padded - 1; ++index)
		{
			target[index] = (UCHAR) padded;
		}
	}

	return padded;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherEME::Encode(UCHAR *buffer, ULONG size)
{
	ASSERT(buffer);
	ASSERT(size);

	ASSERT(0 == (size % c_blockSize));

	PGPError err = kPGPError_NoErr;

	if(UseEME2())
	{
		ASSERT(m_eme2);
		err = PGPEME2Encrypt(m_eme2, buffer, size, buffer, m_offset, m_nonce);
	}
	else
	{
		ASSERT(m_eme);
		err = PGPEMEEncrypt(m_eme, buffer, size, buffer, m_offset, m_nonce);
	}

	return IsPGPError(err) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterCipherEME::Decode(UCHAR *buffer, ULONG size)
{
	ASSERT(buffer);
	ASSERT(size);

	ASSERT(0 == (size % c_blockSize));
	
	PGPError err = kPGPError_NoErr;

	if(UseEME2())
	{
		ASSERT(m_eme2);
		err = PGPEME2Decrypt(m_eme2, buffer, size, buffer, m_offset, m_nonce);
	}
	else
	{
		ASSERT(m_eme);
		err = PGPEMEDecrypt(m_eme, buffer, size, buffer, m_offset, m_nonce);
	}

	return IsPGPError(err) ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

#endif //FILFILE_USE_EME
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
