/*____________________________________________________________________________
	Copyright (C) 2007 PGP Corporation
	All rights reserved.

	EME2 is the wide block cipher of the IEEE P1619 Working Group,
	http://www.siswg.org/.  It is a modification of EME to improve
	generality and simplify the security proof.

	The full EME2 requires special handling for large-block sizes
	greater than 2048 bytes.  Since we hard-code our block sizes to
	512 bytes we do not support that option at present.
	EME2 also allows a tweak size other than 16 bytes, but we do not
	currently make use of that generality.

	See http://eprint.iacr.org/2004/125 for the normative reference.

	$Id: pEME2.c 59758 2008-01-10 20:29:11Z vinnie $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include <string.h>

#include "pgpSDKBuildFlags.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpEME2Priv.h"
//#include "pgpUtilitiesPriv.h"
#include "pgpPFLPriv.h"



#define PGPValidateEME2( EME2 )	\
	PGPValidateParam( pgpEME2IsValid( EME2 ) );


#define COPY4(out,in)	\
		out[0] = in[0]; \
		out[1] = in[1]; \
		out[2] = in[2]; \
		out[3] = in[3];

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
	EME2 uses a cipher context (typically AES) and a block-size array.
____________________________________________________________________________*/
	
	
struct PGPEME2Context
{
#define kEME2Magic		0xBAAB0916
	PGPUInt32						magic;
	PGPMemoryMgrRef					memoryMgr;
	PGPBoolean						EME2Inited;
	PGPSymmetricCipherContextRef	symmetricRef;
	PGPUInt32						L[PGP_EME2_CIPHERBLOCKS][PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32						R2[PGP_EME2_CIPHER_BLOCKWORDS];
};

	static PGPBoolean
pgpEME2IsValid( const PGPEME2Context * ref)
{
	PGPBoolean	valid	= FALSE;
	
	valid	= IsntNull( ref ) && ref->magic	 == kEME2Magic;
	
	return( valid );
}



/*____________________________________________________________________________
	Internal forward references
____________________________________________________________________________*/

static void		pgpEME2Init( PGPEME2Context *	ref, void const * key );
					


/*____________________________________________________________________________
	Exported routines
____________________________________________________________________________*/
	PGPError 
PGPNewEME2Context(
	PGPSymmetricCipherContextRef	symmetricRef,
	PGPEME2ContextRef *				outRef )
{
	PGPEME2ContextRef				newRef	= NULL;
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

	if( blockSize != PGP_EME2_CIPHER_BLOCKSIZE )
		return kPGPError_BadParams;

	memoryMgr	= pgpGetSymmetricCipherMemoryMgr( symmetricRef );
	newRef	= (PGPEME2ContextRef)
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

		newRef->magic			= kEME2Magic;
		newRef->EME2Inited		= FALSE;
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
PGPFreeEME2Context( PGPEME2ContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
	PGPValidateEME2( ref );
	pgpEnterPGPErrorFunction();

	PGPFreeSymmetricCipherContext( ref->symmetricRef );
	
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPCopyEME2Context(
	PGPEME2ContextRef	inRef,
	PGPEME2ContextRef *	outRef )
{
	PGPError			err	= kPGPError_NoErr;
	PGPEME2ContextRef	newRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateEME2( inRef );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPEME2ContextRef)
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
			PGPFreeEME2Context( newRef );
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
PGPInitEME2(
	PGPEME2ContextRef	ref,
	const void *		key )
{
	PGPError			err	= kPGPError_NoErr;
	
	PGPValidateEME2( ref );
	PGPValidateParam( IsntNull( key ) );
		
	pgpEnterPGPErrorFunction();

	pgpEME2Init( ref, key );
	
	return( err );
}


/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEME2Encrypt(
	PGPEME2ContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	PGPError			err = kPGPError_NoErr;

	PGPValidatePtr( out );
	PGPValidateEME2( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();
#if PGP_ENCRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	if ( ref->EME2Inited )
	{
		err = pgpEME2EncryptInternal( ref, in, bytesIn, out, offset, nonce );
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
PGPEME2Decrypt(
	PGPEME2ContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	PGPError			err = kPGPError_NoErr;

	PGPValidatePtr( out );
	PGPValidateEME2( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();

#if PGP_DECRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	if ( ref->EME2Inited )
	{
		err = pgpEME2DecryptInternal( ref, in, bytesIn, out, offset, nonce );
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
PGPEME2GetSymmetricCipher(
	PGPEME2ContextRef				ref,
	PGPSymmetricCipherContextRef *	outRef )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSymmetricCipherContextRef	symmetricRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateEME2( ref );

	pgpEnterPGPErrorFunction();

	symmetricRef	= ref->symmetricRef;
	
	*outRef	= symmetricRef;
	return( err );
}




/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
PGPEME2GetSizes(
	PGPEME2ContextRef				ref,
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
	PGPValidateEME2( ref );

	pgpEnterPGPErrorFunction();

	PGPGetSymmetricCipherSizes( ref->symmetricRef, &keySize, NULL );
	blockSize = PGP_EME2_BLOCKSIZE;

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
	Do a finite field multiplication by 2 per the EME2 spec
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
/* Set up L, R2 arrays */
static void
emeInit (PGPUInt32 L[PGP_EME2_CIPHERBLOCKS][PGP_EME2_CIPHER_BLOCKWORDS],
	PGPUInt32 R2[PGP_EME2_CIPHER_BLOCKWORDS],
	PGPSymmetricCipherContextRef aesref)
{
	PGPUInt32 block;
	PGPUInt32 aeszero[PGP_EME2_CIPHER_BLOCKWORDS];

	/* Compute L[0] as 2*aes(0) */
	memset (aeszero, 0, PGP_EME2_CIPHER_BLOCKSIZE);
	PGPSymmetricCipherEncrypt (aesref, aeszero, aeszero);
	mul2 (L[0], aeszero);
	/* Compute R as 3*aes(0), R2 as 2*R */
	XOR4 (R2, L[0], aeszero);
	mul2 (R2, R2);
	/* Pre-compute additional multiples of L */
	for (block=0; block < PGP_EME2_CIPHERBLOCKS-1; block++)
	{
		mul2 (L[block+1], L[block]);
	}
	memset (aeszero, 0, PGP_EME2_CIPHER_BLOCKSIZE);
}


/*____________________________________________________________________________
	Encrypt one EME2 block.
____________________________________________________________________________*/


static PGPError
emeEncrypt (PGPSymmetricCipherContextRef aesref,
	PGPUInt32 L[PGP_EME2_CIPHERBLOCKS][PGP_EME2_CIPHER_BLOCKWORDS],
	PGPUInt32 R2[PGP_EME2_CIPHER_BLOCKWORDS],
	PGPByte const *ibuf, PGPByte *obuf, PGPUInt64 tweakLo, PGPUInt64 tweakHi)
{
	PGPUInt32 *ibufwp;
	PGPUInt32 *obufwp;
	PGPUInt32 block;
	PGPUInt32 MP[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 MC[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 M[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 TTT[PGP_EME2_CIPHER_BLOCKWORDS];
#if PGP_EME2_CIPHERBLOCKS > PGP_EME2_RESETBLOCKS
	PGPUInt32 M1[PGP_EME2_CIPHER_BLOCKWORDS];
#endif

	/* Load TTT with tweak in LSB form, which is nonce and big-block number */
#if PGP_WORDSLITTLEENDIAN
	TTT[0] = (PGPUInt32)(tweakHi >>  0);
	TTT[1] = (PGPUInt32)(tweakHi >> 32);
	TTT[2] = (PGPUInt32)(tweakLo >>  0);
	TTT[3] = (PGPUInt32)(tweakLo >> 32);
#else
	((PGPByte *)TTT)[0]  = (PGPByte)(tweakHi >>  0);
	((PGPByte *)TTT)[1]  = (PGPByte)(tweakHi >>  8);
	((PGPByte *)TTT)[2]  = (PGPByte)(tweakHi >> 16);
	((PGPByte *)TTT)[3]  = (PGPByte)(tweakHi >> 24);
	((PGPByte *)TTT)[4]  = (PGPByte)(tweakHi >> 32);
	((PGPByte *)TTT)[5]  = (PGPByte)(tweakHi >> 40);
	((PGPByte *)TTT)[6]  = (PGPByte)(tweakHi >> 48);
	((PGPByte *)TTT)[7]  = (PGPByte)(tweakHi >> 56);
	((PGPByte *)TTT)[8]  = (PGPByte)(tweakLo >>  0);
	((PGPByte *)TTT)[9]  = (PGPByte)(tweakLo >>  8);
	((PGPByte *)TTT)[10] = (PGPByte)(tweakLo >> 16);
	((PGPByte *)TTT)[11] = (PGPByte)(tweakLo >> 24);
	((PGPByte *)TTT)[12] = (PGPByte)(tweakLo >> 32);
	((PGPByte *)TTT)[13] = (PGPByte)(tweakLo >> 40);
	((PGPByte *)TTT)[14] = (PGPByte)(tweakLo >> 48);
	((PGPByte *)TTT)[15] = (PGPByte)(tweakLo >> 56);
#endif

	/* Pre-encrypt the tweak and copy into MP */
	XOR4E (TTT, R2);
	PGPSymmetricCipherEncrypt (aesref, TTT, TTT);
	XOR4E (TTT, R2);
	COPY4 (MP, TTT);

	/* First pass: */
	/* XOR L into buf, encrypt buf, xor all blocks */
	ibufwp = (PGPUInt32 *)ibuf;
	obufwp = (PGPUInt32 *)obuf;
	for (block=0; block < PGP_EME2_CIPHERBLOCKS; block++)
	{
		XOR4 (obufwp, ibufwp, L[block]);
		PGPSymmetricCipherEncrypt (aesref, obufwp, obufwp);
		XOR4E (MP, obufwp);
		ibufwp += PGP_EME2_CIPHER_BLOCKWORDS;
		obufwp += PGP_EME2_CIPHER_BLOCKWORDS;
	}

	/* Middle step, encrypt MP to MC, calculate M = MP ^ MC, xor TTT into MC */
	PGPSymmetricCipherEncrypt (aesref, MP, MC);
	XOR4 (M, MP, MC);
	XOR4E (MC, TTT);

	/* Second pass, xor M, encrypt, xor L for all but 1st block */
	obufwp = (PGPUInt32 *)(obuf + PGP_EME2_CIPHER_BLOCKSIZE);
	for (block=1; block < PGP_EME2_CIPHERBLOCKS; block++)
	{
#if PGP_EME2_CIPHERBLOCKS > PGP_EME2_RESETBLOCKS
		/* Every 128 blocks we recalculate M */
		if ((block % PGP_EME2_RESETBLOCKS) == 0)
		{
			if ((block / PGP_EME2_RESETBLOCKS) == 1)
			{
				COPY4 (M1, M);
			}
			XOR4 (M, M1, obufwp);
			PGPSymmetricCipherEncrypt (aesref, M, obufwp);
			XOR4E (M, obufwp);
			XOR4E (obufwp, M1);
		} else {
			mul2 (M, M);
			XOR4E (obufwp, M);
		}
#else
		mul2 (M, M);
		XOR4E (obufwp, M);
#endif
		XOR4E (MC, obufwp);
		PGPSymmetricCipherEncrypt (aesref, obufwp, obufwp);
		XOR4E (obufwp, L[block]);
		obufwp += PGP_EME2_CIPHER_BLOCKWORDS;
	}

	/* Last step, do first block */
	obufwp = (PGPUInt32 *)obuf;
	PGPSymmetricCipherEncrypt (aesref, MC, obufwp);
	XOR4E (obufwp, L[0]);

	return kPGPError_NoErr;
}


/*____________________________________________________________________________
	Decrypt one EME2 block.
	Note that decryption code is IDENTICAL to encryption code except that
	all but the first Encrypt call becomes Decrypt
____________________________________________________________________________*/


static PGPError
emeDecrypt (PGPSymmetricCipherContextRef aesref,
	PGPUInt32 L[PGP_EME2_CIPHERBLOCKS][PGP_EME2_CIPHER_BLOCKWORDS],
	PGPUInt32 R2[PGP_EME2_CIPHER_BLOCKWORDS],
	PGPByte const *ibuf, PGPByte *obuf, PGPUInt64 tweakLo, PGPUInt64 tweakHi)
{
	PGPUInt32 *ibufwp;
	PGPUInt32 *obufwp;
	PGPUInt32 block;
	PGPUInt32 MP[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 MC[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 M[PGP_EME2_CIPHER_BLOCKWORDS];
	PGPUInt32 TTT[PGP_EME2_CIPHER_BLOCKWORDS];
#if PGP_EME2_CIPHERBLOCKS > PGP_EME2_RESETBLOCKS
	PGPUInt32 M1[PGP_EME2_CIPHER_BLOCKWORDS];
#endif

	/* Load TTT with tweak in LSB form, which is nonce and big-block number */
#if PGP_WORDSLITTLEENDIAN
	TTT[0] = (PGPUInt32)(tweakHi >>  0);
	TTT[1] = (PGPUInt32)(tweakHi >> 32);
	TTT[2] = (PGPUInt32)(tweakLo >>  0);
	TTT[3] = (PGPUInt32)(tweakLo >> 32);
#else
	((PGPByte *)TTT)[0]  = (PGPByte)(tweakHi >>  0);
	((PGPByte *)TTT)[1]  = (PGPByte)(tweakHi >>  8);
	((PGPByte *)TTT)[2]  = (PGPByte)(tweakHi >> 16);
	((PGPByte *)TTT)[3]  = (PGPByte)(tweakHi >> 24);
	((PGPByte *)TTT)[4]  = (PGPByte)(tweakHi >> 32);
	((PGPByte *)TTT)[5]  = (PGPByte)(tweakHi >> 40);
	((PGPByte *)TTT)[6]  = (PGPByte)(tweakHi >> 48);
	((PGPByte *)TTT)[7]  = (PGPByte)(tweakHi >> 56);
	((PGPByte *)TTT)[8]  = (PGPByte)(tweakLo >>  0);
	((PGPByte *)TTT)[9]  = (PGPByte)(tweakLo >>  8);
	((PGPByte *)TTT)[10] = (PGPByte)(tweakLo >> 16);
	((PGPByte *)TTT)[11] = (PGPByte)(tweakLo >> 24);
	((PGPByte *)TTT)[12] = (PGPByte)(tweakLo >> 32);
	((PGPByte *)TTT)[13] = (PGPByte)(tweakLo >> 40);
	((PGPByte *)TTT)[14] = (PGPByte)(tweakLo >> 48);
	((PGPByte *)TTT)[15] = (PGPByte)(tweakLo >> 56);
#endif

	/* Pre-encrypt the tweak and copy into MP */
	XOR4E (TTT, R2);
	PGPSymmetricCipherEncrypt (aesref, TTT, TTT);
	XOR4E (TTT, R2);
	COPY4 (MP, TTT);

	/* First pass: */
	/* XOR L into buf, encrypt buf, xor all blocks */
	ibufwp = (PGPUInt32 *)ibuf;
	obufwp = (PGPUInt32 *)obuf;
	for (block=0; block < PGP_EME2_CIPHERBLOCKS; block++)
	{
		XOR4 (obufwp, ibufwp, L[block]);
		PGPSymmetricCipherDecrypt (aesref, obufwp, obufwp);
		XOR4E (MP, obufwp);
		ibufwp += PGP_EME2_CIPHER_BLOCKWORDS;
		obufwp += PGP_EME2_CIPHER_BLOCKWORDS;
	}

	/* Middle step, encrypt MP to MC, calculate M = MP ^ MC, xor TTT into MC */
	PGPSymmetricCipherDecrypt (aesref, MP, MC);
	XOR4 (M, MP, MC);
	XOR4E (MC, TTT);

	/* Second pass, xor M, encrypt, xor L for all but 1st block */
	obufwp = (PGPUInt32 *)(obuf + PGP_EME2_CIPHER_BLOCKSIZE);
	for (block=1; block < PGP_EME2_CIPHERBLOCKS; block++)
	{
#if PGP_EME2_CIPHERBLOCKS > PGP_EME2_RESETBLOCKS
		/* Every 128 blocks we recalculate M */
		if ((block % PGP_EME2_RESETBLOCKS) == 0)
		{
			if ((block / PGP_EME2_RESETBLOCKS) == 1)
			{
				COPY4 (M1, M);
			}
			XOR4 (M, M1, obufwp);
			PGPSymmetricCipherDecrypt (aesref, M, obufwp);
			XOR4E (M, obufwp);
			XOR4E (obufwp, M1);
		} else {
			mul2 (M, M);
			XOR4E (obufwp, M);
		}
#else
		mul2 (M, M);
		XOR4E (obufwp, M);
#endif
		XOR4E (MC, obufwp);
		PGPSymmetricCipherDecrypt (aesref, obufwp, obufwp);
		XOR4E (obufwp, L[block]);
		if (block < PGP_EME2_CIPHERBLOCKS-1)
		{
			obufwp += PGP_EME2_CIPHER_BLOCKWORDS;
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
pgpEME2Init(
	PGPEME2Context *		ref,
	void const *		key )
{
	PGPInitSymmetricCipher( ref->symmetricRef, key );
	emeInit( ref->L, ref->R2, ref->symmetricRef );

	ref->EME2Inited		= TRUE;
}



/*____________________________________________________________________________
	Encrypt a buffer of data blocks, using a block cipher in EME2 mode.
____________________________________________________________________________*/
	PGPError
pgpEME2EncryptInternal(
	PGPEME2Context *		ref,
	void const *		srcParam,
	PGPSize				len,
	void *				destParam,
	PGPUInt64			offset,
	PGPUInt64			nonce )
{
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	/* Length must be a multiple of blocksize */
	if( len % PGP_EME2_BLOCKSIZE != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		emeEncrypt(ref->symmetricRef, ref->L, ref->R2, src, dest, offset, nonce);

		/* Loop until we have exhausted the data */
		src += PGP_EME2_BLOCKSIZE;
		dest += PGP_EME2_BLOCKSIZE;
		len -= PGP_EME2_BLOCKSIZE;
		++offset;
	}

	return kPGPError_NoErr;
}

/*____________________________________________________________________________
	Decrypt a buffer of data blocks, using a block cipher in EME2 mode.
____________________________________________________________________________*/
PGPError pgpEME2DecryptInternal(PGPEME2Context*	ref,void const*	srcParam,PGPSize	len,void* destParam,PGPUInt64 offset,PGPUInt64 nonce )
{
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	/* Length must be a multiple of blocksize */
	if( len % PGP_EME2_BLOCKSIZE != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		emeDecrypt(ref->symmetricRef, ref->L, ref->R2, src, dest, offset, nonce);

		/* Loop until we have exhausted the data */
		src += PGP_EME2_BLOCKSIZE;
		dest += PGP_EME2_BLOCKSIZE;
		len -= PGP_EME2_BLOCKSIZE;
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
