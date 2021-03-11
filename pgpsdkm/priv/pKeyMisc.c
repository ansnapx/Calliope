/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pKeyMisc.c 49613 2006-11-29 09:01:48Z hal $
____________________________________________________________________________*/
/*
 * pgpKeyMisc.c -- Miscellaneous helper functions for public key modules.
 * Including packing and unpacking for PKCS compatibility.
 */
#include "pgpSDKBuildFlags.h"
#include "pgpConfig.h"
#include <string.h>
#include <stdio.h>

#include <stdarg.h>

#include "pgpDebug.h"
#include "pgpCFBPriv.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpHashPriv.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpUsuals.h"
#include "pgpUtilities.h"


/* perform PKCS#1 OAEP encoding/decoding with Mask Generation Function MGF1
 * for message m to produce 'bytes' bytes of output
 *
 * Original input message is first formed as 
 *
 * [hash(p)] [000...0] [1] [...m...] 
 *
 * for the exact size of bytes-1. plen must be no greater then the blocksize for hashAlg.
 *
 * We assume MGF1 as Mask Generation Function. MGF1 is defined as follow:
 *
 * start with T empty
 * for( counter=0; counter<round_up(l/hLen); counter++ )
 *    T = T || hash(seed || C)
 *
 * MGF is used twice: with l=mlen-hLen and l=hLen. In the second case we don't bother 
 * to make the loop - the MGF1 is just a hash of seed and 4 zeroes.
 * First MGF is applied to  padded input message. Second MGF is applied to the seed 
 * of the first MGF with its seed coming from the result of first MGF.
 *
 * 512 bit key will occupy 64 + 1 + 2*20 = 105 bytes for SHA1
 *
 */

static PGPError
pgpPKCS1oaepMGF1Pack( PGPMemoryMgrRef memMgr, 
		PGPByte const *m, unsigned mlen, 	/* original message */
		PGPByte const *p, unsigned plen, 	/* parameters */
		PGPHashAlgorithm hashAlg, 
		const PGPByte *seed,				/* random bytes of size hLen */
		PGPByte *out, unsigned bytes )		/* output */
{
	PGPHashVTBL const *hvtbl;
	PGPHashContextRef hash;
	unsigned  hLen;
	const PGPByte *pHash;
	unsigned l;
	PGPUInt32 counter=0;
	PGPByte counter_bytes[4];
	unsigned i, j;
	
	hvtbl = pgpHashByNumber( hashAlg );
	if( hvtbl==NULL )
		return kPGPError_BadHashNumber;
	
	hash = pgpHashCreate( memMgr, hvtbl );
	if( hash==NULL )
		return kPGPError_OutOfMemory;

	hLen = hvtbl->hashsize;

	if( plen > hvtbl->blocksize || mlen > bytes-2*hLen-1 )  {
		PGPFreeHashContext( hash );
		return kPGPError_BufferTooSmall;
	}

	PGPContinueHash( hash, p, plen );	/* hash parameters */
	pHash = pgpHashFinal( hash );

	/* form a padded right aligned input message of size bytes-hLen */
	
	pgpCopyMemoryNO( m, out + bytes-1-mlen, mlen );	/* message */

	out[ bytes-1-mlen-1 ] = 1;		/* 01 */

	l = bytes-1 - hLen - 1 - mlen;
	if( l )
		memset( out + hLen, 0, l );	/* zero padding */

	pgpCopyMemoryNO( pHash, out + hLen, hLen );	/* hash(p) */
						/* first hLen bytes are ignored */

	/* apply a mask from Mask Generation Function */

	pgpCopyMemoryNO( seed, out, hLen );	/* temporarily put seed in out */
	
	/* we assume this when we iterate over words in the following loop 
	 * (otherwize it must be bytes-1)*/
	pgpAssert( bytes % sizeof(PGPUInt32) == 0 );	

	/* mask all hLen-size blocks except the first block with the seed */
	for( counter=1; counter<(bytes+hLen-1)/hLen; counter++ )  {
		PGPUInt32 t = counter-1;
		counter_bytes[3] = (PGPByte)t;
		counter_bytes[2] = (PGPByte)(t>>8);
		counter_bytes[1] = (PGPByte)(t>>16);
		counter_bytes[0] = (PGPByte)(t>>24);

		PGPResetHash( hash );
		PGPContinueHash( hash, out, hLen );
		PGPContinueHash( hash, counter_bytes, 4 );	
		pHash = pgpHashFinal( hash );	/* hash(seed || countner) */
	
		l = hLen / sizeof(PGPUInt32);	/* words in hLen */
		for( j=0; j<l && counter*l+j < bytes/sizeof(PGPUInt32); j++ )
			((PGPUInt32*)out)[counter*l+j] ^= ((PGPUInt32*)pHash)[j];
	}
	
	/* finally mask the original seed */
	PGPResetHash( hash );
	
	PGPContinueHash( hash, out+hLen, bytes-1-hLen );
	*(PGPUInt32*)counter_bytes = 0;
	PGPContinueHash( hash, counter_bytes, 4 );
	pHash = pgpHashFinal( hash );		/* MGF result is hash( masked_msg 00 00 00 00 ) */

	l = hLen/sizeof(PGPUInt32);
	for(i=0; i<l; i++ )
		((PGPUInt32*)out)[i] ^= ((PGPUInt32*)pHash)[i];

	/* because of alignment issues it is most likely faster to move result */
	memmove( out+1, out, bytes-1 ); 
	out[0] = 0;
	
	PGPFreeHashContext( hash );

	return kPGPError_NoErr;
}

static PGPError
pgpPKCS1oaepMGF1Unpack( PGPMemoryMgrRef memMgr,
		const PGPByte *in, unsigned bytes,	/* PKCS1 padded input */
		PGPByte const *p, unsigned plen, 	/* parameters used to encode */
		PGPHashAlgorithm hashAlg, 
		PGPByte *mout, unsigned *mlen )		/* output, mout must be at least bytes long */
{
	PGPHashVTBL const *hvtbl;
	PGPHashContextRef hash;
	unsigned  hLen;
	const PGPByte *pHash;
	unsigned l;
	PGPUInt32 counter=0;
	PGPByte counter_bytes[4];
	unsigned i, j;

	*mlen = 0;
	
	hvtbl = pgpHashByNumber( hashAlg );
	if( hvtbl==NULL )
		return kPGPError_BadHashNumber;
	
	hash = pgpHashCreate( memMgr, hvtbl );
	if( hash==NULL )
		return kPGPError_OutOfMemory;
	
	hLen = hvtbl->hashsize;

	if( plen > hvtbl->blocksize || bytes < 2*hLen+1 )  {
		PGPFreeHashContext( hash );
		return kPGPError_CantHash;
	}

#if PGP_DEBUG
	{
		const PGPByte *out_test = memmove( mout, in+1, bytes-1 );	/* remove leading zero, align */
		if( out_test==NULL )
			PGPSDK_TRACE1("memmove for [%d] failed", bytes-1);
	}
#else
	memmove( mout, in+1, bytes-1 );	/* remove leading zero, align */
#endif

	/* get original seed */
	
	PGPContinueHash( hash, in+1+hLen, bytes-1-hLen );
	*(PGPUInt32*)counter_bytes = 0;
	PGPContinueHash( hash, counter_bytes, 4 );
	pHash = pgpHashFinal( hash );		/* MGF result is hash( masked_msg 00 00 00 00 ) */

	l = hLen/sizeof(PGPUInt32);
	for(i=0; i<l; i++ )
		((PGPUInt32*)mout)[i] ^= ((PGPUInt32*)pHash)[i];

	/* unmask original message */

	/* we assume this when we iterate over words in the follwing loop 
	 * (otherwize it must be bytes-1)*/
	pgpAssert( bytes % sizeof(PGPUInt32) == 0 );	

	i = hLen/sizeof(PGPUInt32);
	while( i < bytes/sizeof(PGPUInt32) )  {
		
		PGPResetHash( hash );
		
		PGPContinueHash( hash, mout, hLen );	/* hash(seed) */
		
		counter_bytes[3] = (PGPByte)counter;
		counter_bytes[2] = (PGPByte)(counter>>8);
		counter_bytes[1] = (PGPByte)(counter>>16);
		counter_bytes[0] = (PGPByte)(counter>>24);

		counter++;

		PGPContinueHash( hash, counter_bytes, 4 );	
		pHash = pgpHashFinal( hash );	/* hash(seed || coutner) */

		l = hLen / sizeof(PGPUInt32);
		for( j=0; j<l && i+j<bytes/sizeof(PGPUInt32); j++ )
			((PGPUInt32*)mout)[i+j] ^= ((PGPUInt32*)pHash)[j];
		i += l;
	}

	/* move message */

	/* determine the size of original message. 
	 * We have seed || hash(p) || 0...0 || 01 || M */	
	for( i=2*hLen; i<bytes-1; i++ )  {
		if( mout[i] )
			break;
	}

	if( i==bytes-1 || mout[i] != 1 )  {
		PGPFreeHashContext( hash );
		PGPSDK_TRACE("Corrupt data: could not find 0...00 01 sequence");
		return kPGPError_CorruptData;
	}
	
	PGPResetHash( hash );
	PGPContinueHash( hash, p, plen );	/* hash parameters */
	pHash = pgpHashFinal( hash );

	/* check parameters hash */
	if( memcmp( pHash, mout+hLen, hLen )!=0 )  {
		PGPSDK_TRACE1("Corrupt data: hash doesn't match: [%d]", hLen);
		PGPFreeHashContext( hash );
		return kPGPError_CorruptData;
	}

	memmove( mout, mout+i+1, bytes-1-i );
	*mlen = bytes-1-i-1;
	PGPSDK_TRACE1("Removed PKCS1 OAEP padding OK, return [%d] bytes of data", *mlen);

	PGPFreeHashContext( hash );

	return kPGPError_NoErr;
}

PGPError PGPSDKM_PUBLIC_API
PGPPKCS1Pack(PGPMemoryMgrRef memMgr, 
			PGPByte const *in, PGPSize len, 
			const PGPByte seed[20], /*size SHA1*/
			PGPByte *out, PGPSize out_bytes)
{
	PGPError err;

	/* OAEP padding follows: default OAEP with empty P */
	err = pgpPKCS1oaepMGF1Pack( memMgr, in, len, (PGPByte *) "", 0, 
		kPGPHashAlgorithm_SHA, seed, out, out_bytes );

	return err;
}

	PGPError PGPSDKM_PUBLIC_API
PGPPKCS1Unpack(PGPMemoryMgrRef memMgr, 
			  const PGPByte *in, PGPSize len, 
			  PGPByte *out /* size len */, PGPSize *out_bytes )
{
	PGPError err;
	
	/* OAEP padding follows */
	err = pgpPKCS1oaepMGF1Unpack( memMgr, in, len, (PGPByte *) "", 0, 
		kPGPHashAlgorithm_SHA, out, (unsigned *) out_bytes );

	return err;
}
