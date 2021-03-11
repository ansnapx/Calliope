/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	EME is the wide block cipher of http://www.siswg.org/docs
	Also see http://eprint.iacr.org/2003/147

	$Id: pEME.c 47199 2006-08-24 03:21:33Z ajivsov $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include <string.h>

#include "pgpSDKBuildFlags.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpEMEPriv.h"
//#include "pgpUtilitiesPriv.h"
#include "pgpPFLPriv.h"



#define PGPValidateEME( EME )	\
	PGPValidateParam( pgpEMEIsValid( EME ) );


#define XOR4(out,in1,in2)	\
		out[0] = in1[0] ^ in2[0]; \
		out[1] = in1[1] ^ in2[1]; \
		out[2] = in1[2] ^ in2[2]; \
		out[3] = in1[3] ^ in2[3];

#define XOR4E(out,in)	\
		out[0] ^= in[0]; \
		out[1] ^= in[1]; \
		out[2] ^= in[2]; \
		out[3] ^= in[3];

	
/*____________________________________________________________________________
	EME uses a cipher context (typically AES) and a block-size array.
____________________________________________________________________________*/
	
	
struct PGPEMEContext
{
#define kEMEMagic		0xBAAB0915
	PGPUInt32						magic;
	PGPMemoryMgrRef					memoryMgr;
	PGPBoolean						EMEInited;
	PGPSymmetricCipherContextRef	symmetricRef;
	PGPUInt32						L[PGP_EME_CIPHERBLOCKS][PGP_EME_CIPHER_BLOCKWORDS];
};

	static PGPBoolean
pgpEMEIsValid( const PGPEMEContext * ref)
{
	PGPBoolean	valid	= FALSE;
	
	valid	= IsntNull( ref ) && ref->magic	 == kEMEMagic;
	
	return( valid );
}



/*____________________________________________________________________________
	Internal forward references
____________________________________________________________________________*/

static void		pgpEMEInit( PGPEMEContext *	ref, void const * key );
					


/*____________________________________________________________________________
	Exported routines
____________________________________________________________________________*/
	PGPError 
PGPNewEMEContext(
	PGPSymmetricCipherContextRef	symmetricRef,
	PGPEMEContextRef *				outRef )
{
	PGPEMEContextRef				newRef	= NULL;
	PGPError						err	= kPGPError_NoErr;
	PGPMemoryMgrRef					memoryMgr	= NULL;
	PGPSize							blockSize;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidatePtr( symmetricRef );

	pgpEnterPGPErrorFunction();

	err = PGPGetSymmetricCipherSizes( symmetricRef, NULL, &blockSize );
	if( IsPGPError( err ) )
		return err;

	if( blockSize != PGP_EME_CIPHER_BLOCKSIZE )
		return kPGPError_BadParams;

	memoryMgr	= pgpGetSymmetricCipherMemoryMgr( symmetricRef );
	newRef	= (PGPEMEContextRef)
			PGPNewData( memoryMgr,
				sizeof( *newRef ), 0 | kPGPMemoryMgrFlags_Clear);
			
	if ( IsntNull( newRef ) )
	{
#if PGP_DEBUG
		/* make original invalid to enforce semantics */
		PGPSymmetricCipherContextRef	tempRef;
		err	= PGPCopySymmetricCipherContext( symmetricRef, &tempRef );
		if ( IsntPGPError( err ) )
		{
			PGPFreeSymmetricCipherContext( symmetricRef );
			symmetricRef	= tempRef;
		}
		err	= kPGPError_NoErr;
#endif

		newRef->magic			= kEMEMagic;
		newRef->EMEInited		= FALSE;
		newRef->symmetricRef	= symmetricRef;
		newRef->memoryMgr		= memoryMgr;
	}
	else
	{
		/* we own it, so dispose it */
		PGPFreeSymmetricCipherContext( symmetricRef );
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= newRef;
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPFreeEMEContext( PGPEMEContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
	PGPValidateEME( ref );
	pgpEnterPGPErrorFunction();

	PGPFreeSymmetricCipherContext( ref->symmetricRef );
	
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPCopyEMEContext(
	PGPEMEContextRef	inRef,
	PGPEMEContextRef *	outRef )
{
	PGPError			err	= kPGPError_NoErr;
	PGPEMEContextRef	newRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateEME( inRef );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPEMEContextRef)
		PGPNewData( inRef->memoryMgr,
		sizeof( *newRef ), 0);

	if ( IsntNull( newRef ) )
	{
		*newRef		= *inRef;
		
		/* clear symmetric cipher in case later allocation fails */
		newRef->symmetricRef = NULL;
		
		/* copy symmetric cipher */
		err	= PGPCopySymmetricCipherContext(
				inRef->symmetricRef, &newRef->symmetricRef );
		
		if ( IsPGPError( err ) )
		{
			PGPFreeEMEContext( newRef );
			newRef	= NULL;
		}
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= newRef;
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPInitEME(
	PGPEMEContextRef	ref,
	const void *		key )
{
	PGPError			err	= kPGPError_NoErr;
	
	PGPValidateEME( ref );
	PGPValidateParam( IsntNull( key ) );
		
	pgpEnterPGPErrorFunction();

	pgpEMEInit( ref, key );
	
	return( err );
}


/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEMEEncrypt(
	PGPEMEContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	PGPError			err = kPGPError_NoErr;

	PGPValidatePtr( out );
	PGPValidateEME( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();
#if PGP_ENCRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	if ( ref->EMEInited )
	{
		err = pgpEMEEncryptInternal( ref, in, bytesIn, out, offset, nonce );
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
#endif
	
	return err;
}

					
/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEMEDecrypt(
	PGPEMEContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	PGPError			err = kPGPError_NoErr;

	PGPValidatePtr( out );
	PGPValidateEME( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();

#if PGP_DECRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	if ( ref->EMEInited )
	{
		err = pgpEMEDecryptInternal( ref, in, bytesIn, out, offset, nonce );
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
#endif
	
	return err;
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEMEGetSymmetricCipher(
	PGPEMEContextRef				ref,
	PGPSymmetricCipherContextRef *	outRef )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSymmetricCipherContextRef	symmetricRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateEME( ref );

	pgpEnterPGPErrorFunction();

	symmetricRef	= ref->symmetricRef;
	
	*outRef	= symmetricRef;
	return( err );
}




/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEMEGetSizes(
	PGPEMEContextRef				ref,
	PGPSize							*pKeySize,
	PGPSize							*pBlockSize )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSize							keySize;
	PGPSize							blockSize;
	
	if( IsntNull( pKeySize ) )
		PGPValidatePtr( pKeySize );
	if( IsntNull( pBlockSize ) )
		PGPValidatePtr( pBlockSize );
	if( IsntNull( pKeySize ) )
		*pKeySize = 0;
	if( IsntNull( pKeySize ) )
		*pBlockSize = 0;
	PGPValidateEME( ref );

	pgpEnterPGPErrorFunction();

	PGPGetSymmetricCipherSizes( ref->symmetricRef, &keySize, NULL );
	blockSize = PGP_EME_BLOCKSIZE;

	if( IsntNull( pKeySize ) )
		*pKeySize = keySize;

	if( IsntNull( pBlockSize ) )
		*pBlockSize = blockSize;

	return( err );
}





#ifdef PRAGMA_MARK_SUPPORTED
#pragma mark --- Internal Routines ---
#endif







/*____________________________________________________________________________
	Do a finite field multiplication by 2 per the EME spec
	obuf may be same as ibuf
____________________________________________________________________________*/


/*
* Temporarily disabled this for Windows builds. This allows us to use the same project
* file to target Win32 or Win64. We need to verify if this code can be re-written using
* intrinsic functions from MSDN's section "Intrinsics Available on All Architectures"
* [http://msdn2.microsoft.com/en-us/library/5704bbxw.aspx]. If so, it will be essentially 
* the same but portable.
*/

#if 0 // PGP_WIN32
static void
mul2 (PGPUInt32 *obufw, PGPUInt32 *ibufw)
{
__asm	{
	; ebx is input, edx is output pointers
	mov	esi, ibufw

	mov	eax, 0[esi]
	mov	ebx, 4[esi]
	mov	ecx, 8[esi]
	mov	edx, 12[esi]

	mov	esi, obufw
	clc

	rcl	eax, 1
	rcl	ebx, 1
	rcl	ecx, 1
	rcl	edx, 1

	mov	4[esi], ebx
	mov	8[esi], ecx

	; Carry is now set if MSBit is true, if so xor in to LSByte
#if 1
	/* non-branch way of conditional xor */
	setc bl				/* 1 if carry, 0 if not */
	xor bl, 1			/* 0 if carry, 1 if not */
	sub bl, 1			/* -1 if carry, 0 if not */
	and bl, 087h		/* 0x87 if carry, 0 if not */
	xor al, bl
#else
	jnc	skipxor
	xor	al, 087h
skipxor:
#endif

	mov	0[esi], eax
	mov	12[esi], edx


	}
}

#elif PGP_WORDSBIGENDIAN

#define LOAD4(i,b,o)  i = ((b[o+3]<<24) | (b[o+2]<<16) | (b[o+1]<<8) | b[o+0])
#define STORE4(b,o,i) b[o+3] = i>>24; b[o+2] = i>>16; b[o+1] = i>>8; b[o+0] = i


/* Attempt at faster general purpose one */
static void
mul2 (PGPUInt32 *obufw, PGPUInt32 *ibufw)
{
	PGPByte *ibuf = (PGPByte *)ibufw;
	PGPByte *obuf = (PGPByte *)obufw;
	PGPUInt32 ib0, ib1, ib2, ib3;
	PGPUInt32 ob0, ob1, ob2, ob3;
	PGPUInt32 hibit;
	PGPUInt32 carry;

	LOAD4(ib0, ibuf, 0);
	LOAD4(ib1, ibuf, 4);
	LOAD4(ib2, ibuf, 8);
	LOAD4(ib3, ibuf, 12);

	hibit = ib3 & 0x80000000;
	carry = ib2 & 0x80000000;
	ob3 = (ib3 << 1) | (carry >> 31);
	carry = ib1 & 0x80000000;
	ob2 = (ib2 << 1) | (carry >> 31);
	carry = ib0 & 0x80000000;
	ob1 = (ib1 << 1) | (carry >> 31);
	ob0 = ib0 << 1;
	if (hibit)
		ob0 ^= 0x87;	/* finite field polynomial */

	STORE4(obuf, 0, ob0);
	STORE4(obuf, 4, ob1);
	STORE4(obuf, 8, ob2);
	STORE4(obuf, 12, ob3);
}

#else

/* This is a faster version only for little endian machines */
static void
mul2 (PGPUInt32 *obuf, PGPUInt32 *ibuf)
{
	PGPUInt32 hibit = ibuf[3] & 0x80000000;
	PGPUInt32 carry;

	carry = ibuf[2] & 0x80000000;
	obuf[3] = (ibuf[3] << 1) | (carry >> 31);
	carry = ibuf[1] & 0x80000000;
	obuf[2] = (ibuf[2] << 1) | (carry >> 31);
	carry = ibuf[0] & 0x80000000;
	obuf[1] = (ibuf[1] << 1) | (carry >> 31);
	obuf[0] = ibuf[0] << 1;
	if (hibit)
		obuf[0] ^= 0x87;	/* finite field polynomial */
}
#endif


/*____________________________________________________________________________
____________________________________________________________________________*/
/* Set up L array */
static void
emeInit (PGPUInt32 L[PGP_EME_CIPHERBLOCKS][PGP_EME_CIPHER_BLOCKWORDS], PGPSymmetricCipherContextRef aesref)
{
	PGPUInt32 block;

	/* Compute L[0] as 2*aes(0) */
	memset (L, 0, PGP_EME_BLOCKSIZE);
	PGPSymmetricCipherEncrypt (aesref, L[0], L[0]);
	mul2 (L[0], L[0]);
	for (block=0; block < PGP_EME_CIPHERBLOCKS-1; block++)
	{
		mul2 (L[block+1], L[block]);
	}
}


/*____________________________________________________________________________
	Encrypt one EME block.
____________________________________________________________________________*/


static PGPError
emeEncrypt (PGPSymmetricCipherContextRef aesref, PGPUInt32 L[PGP_EME_CIPHERBLOCKS][PGP_EME_CIPHER_BLOCKWORDS],
	PGPByte const *ibuf, PGPByte *obuf, PGPUInt64 tweakLo, PGPUInt64 tweakHi)
{
	PGPUInt32 *ibufwp;
	PGPUInt32 *obufwp;
	PGPUInt32 block;
	PGPUInt32 MP[PGP_EME_CIPHER_BLOCKWORDS];
	PGPUInt32 MC[PGP_EME_CIPHER_BLOCKWORDS];
	PGPUInt32 M[PGP_EME_CIPHER_BLOCKWORDS];
#if !PGP_WORDSLITTLEENDIAN
	PGPByte tweak[PGP_EME_CIPHER_BLOCKSIZE];
#endif

	/* Load MP with tweak in LSB form, which is nonce and big-block number */
#if PGP_WORDSLITTLEENDIAN
	MP[0] = (PGPUInt32)(tweakHi >>  0);
	MP[1] = (PGPUInt32)(tweakHi >> 32);
	MP[2] = (PGPUInt32)(tweakLo >>  0);
	MP[3] = (PGPUInt32)(tweakLo >> 32);
#else
	tweak[0]  = (PGPByte)(tweakHi >>  0);
	tweak[1]  = (PGPByte)(tweakHi >>  8);
	tweak[2]  = (PGPByte)(tweakHi >> 16);
	tweak[3]  = (PGPByte)(tweakHi >> 24);
	tweak[4]  = (PGPByte)(tweakHi >> 32);
	tweak[5]  = (PGPByte)(tweakHi >> 40);
	tweak[6]  = (PGPByte)(tweakHi >> 48);
	tweak[7]  = (PGPByte)(tweakHi >> 56);
	tweak[8]  = (PGPByte)(tweakLo >>  0);
	tweak[9]  = (PGPByte)(tweakLo >>  8);
	tweak[10] = (PGPByte)(tweakLo >> 16);
	tweak[11] = (PGPByte)(tweakLo >> 24);
	tweak[12] = (PGPByte)(tweakLo >> 32);
	tweak[13] = (PGPByte)(tweakLo >> 40);
	tweak[14] = (PGPByte)(tweakLo >> 48);
	tweak[15] = (PGPByte)(tweakLo >> 56);
	MP[0] = ((PGPUInt32 *)tweak)[0];
	MP[1] = ((PGPUInt32 *)tweak)[1];
	MP[2] = ((PGPUInt32 *)tweak)[2];
	MP[3] = ((PGPUInt32 *)tweak)[3];
#endif

	/* First pass: */
	/* XOR L into buf, encrypt buf, xor all blocks */
	ibufwp = (PGPUInt32 *)ibuf;
	obufwp = (PGPUInt32 *)obuf;
	for (block=0; block < PGP_EME_CIPHERBLOCKS; block++)
	{
		XOR4 (obufwp, ibufwp, L[block]);
		PGPSymmetricCipherEncrypt (aesref, obufwp, obufwp);
		XOR4E (MP, obufwp);
		ibufwp += PGP_EME_CIPHER_BLOCKWORDS;
		obufwp += PGP_EME_CIPHER_BLOCKWORDS;
	}

	/* Middle step, encrypt MP to MC, calculate M = MP ^ MC, xor T into MC */
	PGPSymmetricCipherEncrypt (aesref, MP, MC);
	XOR4 (M, MP, MC);
#if PGP_WORDSLITTLEENDIAN
	MC[0] ^= (PGPUInt32)(tweakHi >>  0);
	MC[1] ^= (PGPUInt32)(tweakHi >> 32);
	MC[2] ^= (PGPUInt32)(tweakLo >>  0);
	MC[3] ^= (PGPUInt32)(tweakLo >> 32);
#else
	MC[0] ^= ((PGPUInt32 *)tweak)[0];
	MC[1] ^= ((PGPUInt32 *)tweak)[1];
	MC[2] ^= ((PGPUInt32 *)tweak)[2];
	MC[3] ^= ((PGPUInt32 *)tweak)[3];
#endif

	/* Second pass, xor M, encrypt, xor L for all but 1st block */
	obufwp = (PGPUInt32 *)(obuf + PGP_EME_CIPHER_BLOCKSIZE);
	for (block=1; block < PGP_EME_CIPHERBLOCKS; block++)
	{
		mul2 (M, M);
		XOR4E (obufwp, M);
		XOR4E (MC, obufwp);
		PGPSymmetricCipherEncrypt (aesref, obufwp, obufwp);
		XOR4E (obufwp, L[block]);
		obufwp += PGP_EME_CIPHER_BLOCKWORDS;
	}

	/* Last step, do first block */
	obufwp = (PGPUInt32 *)obuf;
	PGPSymmetricCipherEncrypt (aesref, MC, obufwp);
	XOR4E (obufwp, L[0]);

	return kPGPError_NoErr;
}


/*____________________________________________________________________________
	Decrypt one EME block.
	Note that decryption code is IDENTICAL to encryption code except that
	all but the first Encrypt call becomes Decrypt
____________________________________________________________________________*/


static PGPError
emeDecrypt (PGPSymmetricCipherContextRef aesref, PGPUInt32 L[PGP_EME_CIPHERBLOCKS][PGP_EME_CIPHER_BLOCKWORDS],
	PGPByte const *ibuf, PGPByte *obuf, PGPUInt64 tweakLo, PGPUInt64 tweakHi)
{
	PGPUInt32 *ibufwp;
	PGPUInt32 *obufwp;
	PGPUInt32 block;
	PGPUInt32 MP[PGP_EME_CIPHER_BLOCKWORDS];
	PGPUInt32 MC[PGP_EME_CIPHER_BLOCKWORDS];
	PGPUInt32 M[PGP_EME_CIPHER_BLOCKWORDS];
#if !PGP_WORDSLITTLEENDIAN
	PGPByte tweak[PGP_EME_CIPHER_BLOCKSIZE];
#endif

	/* Load MP with tweak in LSB form, which is nonce and big-block number */
#if PGP_WORDSLITTLEENDIAN
	MP[0] = (PGPUInt32)(tweakHi >>  0);
	MP[1] = (PGPUInt32)(tweakHi >> 32);
	MP[2] = (PGPUInt32)(tweakLo >>  0);
	MP[3] = (PGPUInt32)(tweakLo >> 32);
#else
	tweak[0]  = (PGPByte)(tweakHi >>  0);
	tweak[1]  = (PGPByte)(tweakHi >>  8);
	tweak[2]  = (PGPByte)(tweakHi >> 16);
	tweak[3]  = (PGPByte)(tweakHi >> 24);
	tweak[4]  = (PGPByte)(tweakHi >> 32);
	tweak[5]  = (PGPByte)(tweakHi >> 40);
	tweak[6]  = (PGPByte)(tweakHi >> 48);
	tweak[7]  = (PGPByte)(tweakHi >> 56);
	tweak[8]  = (PGPByte)(tweakLo >>  0);
	tweak[9]  = (PGPByte)(tweakLo >>  8);
	tweak[10] = (PGPByte)(tweakLo >> 16);
	tweak[11] = (PGPByte)(tweakLo >> 24);
	tweak[12] = (PGPByte)(tweakLo >> 32);
	tweak[13] = (PGPByte)(tweakLo >> 40);
	tweak[14] = (PGPByte)(tweakLo >> 48);
	tweak[15] = (PGPByte)(tweakLo >> 56);
	MP[0] = ((PGPUInt32 *)tweak)[0];
	MP[1] = ((PGPUInt32 *)tweak)[1];
	MP[2] = ((PGPUInt32 *)tweak)[2];
	MP[3] = ((PGPUInt32 *)tweak)[3];
#endif

	/* First pass: */
	/* XOR L into buf, encrypt buf, xor all blocks */
	ibufwp = (PGPUInt32 *)ibuf;
	obufwp = (PGPUInt32 *)obuf;
	for (block=0; block < PGP_EME_CIPHERBLOCKS; block++)
	{
		XOR4 (obufwp, ibufwp, L[block]);
		PGPSymmetricCipherDecrypt (aesref, obufwp, obufwp);
		XOR4E (MP, obufwp);
		ibufwp += PGP_EME_CIPHER_BLOCKWORDS;
		obufwp += PGP_EME_CIPHER_BLOCKWORDS;
	}

	/* Middle step, encrypt MP to MC, calculate M = MP ^ MC, xor T into MC */
	PGPSymmetricCipherDecrypt (aesref, MP, MC);
	XOR4 (M, MP, MC);
#if PGP_WORDSLITTLEENDIAN
	MC[0] ^= (PGPUInt32)(tweakHi >>  0);
	MC[1] ^= (PGPUInt32)(tweakHi >> 32);
	MC[2] ^= (PGPUInt32)(tweakLo >>  0);
	MC[3] ^= (PGPUInt32)(tweakLo >> 32);
#else
	MC[0] ^= ((PGPUInt32 *)tweak)[0];
	MC[1] ^= ((PGPUInt32 *)tweak)[1];
	MC[2] ^= ((PGPUInt32 *)tweak)[2];
	MC[3] ^= ((PGPUInt32 *)tweak)[3];
#endif

	/* Second pass, xor M, encrypt, xor L for all but 1st block */
	obufwp = (PGPUInt32 *)(obuf + PGP_EME_CIPHER_BLOCKSIZE);
	for (block=1; block < PGP_EME_CIPHERBLOCKS; block++)
	{
		mul2 (M, M);
		XOR4E (obufwp, M);
		XOR4E (MC, obufwp);
		PGPSymmetricCipherDecrypt (aesref, obufwp, obufwp);
		XOR4E (obufwp, L[block]);
		if (block < PGP_EME_CIPHERBLOCKS-1)
		{
			obufwp += PGP_EME_CIPHER_BLOCKWORDS;
		}
	}

	/* Last step, do first block */
	obufwp = (PGPUInt32 *)obuf;
	PGPSymmetricCipherDecrypt (aesref, MC, obufwp);
	XOR4E (obufwp, L[0]);

	return kPGPError_NoErr;
}


/*____________________________________________________________________________
	Initialize contexts.
____________________________________________________________________________*/


	static void
pgpEMEInit(
	PGPEMEContext *		ref,
	void const *		key )
{
	PGPInitSymmetricCipher( ref->symmetricRef, key );
	emeInit( ref->L, ref->symmetricRef );

	ref->EMEInited		= TRUE;
}



/*____________________________________________________________________________
	Encrypt a buffer of data blocks, using a block cipher in EME mode.
____________________________________________________________________________*/
	PGPError
pgpEMEEncryptInternal(
	PGPEMEContext *		ref,
	void const *		srcParam,
	PGPSize				len,
	void *				destParam,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	/* Length must be a multiple of blocksize */
	if( len % PGP_EME_BLOCKSIZE != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		emeEncrypt(ref->symmetricRef, ref->L, src, dest, offset, nonce);

		/* Loop until we have exhausted the data */
		src += PGP_EME_BLOCKSIZE;
		dest += PGP_EME_BLOCKSIZE;
		len -= PGP_EME_BLOCKSIZE;
		++offset;
	}

	return kPGPError_NoErr;
}


/*____________________________________________________________________________
	Decrypt a buffer of data blocks, using a block cipher in EME mode.
____________________________________________________________________________*/
	PGPError
pgpEMEDecryptInternal(
	PGPEMEContext *	ref,
	void const *	srcParam,
	PGPSize			len,
	void *			destParam,
	PGPUInt64		offset,
	PGPUInt64		nonce )
{
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	/* Length must be a multiple of blocksize */
	if( len % PGP_EME_BLOCKSIZE != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		emeDecrypt(ref->symmetricRef, ref->L, src, dest, offset, nonce);

		/* Loop until we have exhausted the data */
		src += PGP_EME_BLOCKSIZE;
		dest += PGP_EME_BLOCKSIZE;
		len -= PGP_EME_BLOCKSIZE;
		++offset;
	}

	return kPGPError_NoErr;
}




/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
