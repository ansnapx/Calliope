/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

        $Id: pHMAC.c 20640 2004-02-10 01:53:41Z ajivsov $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include "pgpErrors.h"
#include "pgpMem.h"
#include "pgpPFLPriv.h"

#include "pgpHMAC.h"
#include "pgpHash.h"
#include "pgpHashPriv.h"
//#include "pgpUtilitiesPriv.h"

#define kPGPHMAC_ipad			0x36
#define kPGPHMAC_opad			0x5C
#define kPGPHMAC_MaxHashBlock	128		/* maximum reached for SHA-384 and SHA-512 */


struct PGPHMACContext
{
#define kHMACContextMagic		0xEBBADBBA
	PGPUInt32			magic;
	PGPMemoryMgrRef		memoryMgr;
	PGPHashContextRef	hash;
	PGPByte *			secret;
	PGPSize				secretLen;
};

	static PGPBoolean
pgpHMACContextIsValid( PGPHMACContextRef ref)
{
	return( IsntNull( ref ) &&
			IsntNull( ref->hash ) &&
			ref->magic == kHMACContextMagic  );
}


#define pgpValidateHMAC( ref )		\
	PGPValidateParam( pgpHMACContextIsValid( ref ) )
/* FIPS140 statetrans SP.PGPNewHMACContext.1 */
	PGPError 
pgpNewHMACContext(
	PGPMemoryMgrRef		memoryMgr,
	PGPHashAlgorithm	algorithm,
	PGPByte *			secret,
	PGPSize				secretLen,
	PGPHMACContextRef *	outRef )
{
	PGPError			err			= kPGPError_NoErr;
	PGPHMACContextRef	ref 		= NULL;
	PGPSize				hashMsgBlockSize = 0;	
	
/* FIPS140 statetrans PGPNewHMACContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	
	err = PGPValidateMemoryMgr( memoryMgr );
	if( IsntPGPError( err ) )
	{
/* FIPS140 statetrans PGPNewHMACContext.3 */
		ref	= (PGPHMACContextRef) PGPNewData( memoryMgr, sizeof( *ref ),
												kPGPMemoryMgrFlags_Clear );
		if ( IsntNull( ref ) )
		{
			ref->magic = kHMACContextMagic;
			ref->memoryMgr	= memoryMgr;
			err = pgpNewHashContext( memoryMgr, algorithm, &ref->hash );
			if ( IsPGPError( err ) )
				goto done;

			err = pgpGetHashMessageSize( ref->hash, &hashMsgBlockSize );
			if ( IsPGPError( err ) )
				goto done;

			pgpAssert( hashMsgBlockSize != 0 && hashMsgBlockSize <= kPGPHMAC_MaxHashBlock );
			
			if( secretLen > hashMsgBlockSize )
			{
				/* revert it down to the hash size */
				err = PGPGetHashSize( ref->hash, &ref->secretLen );
				if( IsPGPError( err ) )
					goto done;
				ref->secret	= (PGPByte *) PGPNewSecureData( memoryMgr,
														ref->secretLen, 0 );
				if ( IsNull( ref->secret ) )
				{
					err	= kPGPError_OutOfMemory;
					goto done;
				}
				err = PGPContinueHash( ref->hash, secret, secretLen );
				if( IsPGPError( err ) )
					goto done;
				err = PGPFinalizeHash( ref->hash, ref->secret );
				if( IsPGPError( err ) )
					goto done;
			}
			else
			{
				ref->secretLen = secretLen;
				ref->secret	=  (PGPByte *) PGPNewSecureData( memoryMgr,
																secretLen, 0 );
				if ( IsNull( ref->secret ) )
				{
					err	= kPGPError_OutOfMemory;
					goto done;
				}
				pgpCopyMemory( secret, ref->secret, secretLen );
			}
			pgpAssert( hashMsgBlockSize > 0 && ref->secretLen <= hashMsgBlockSize );
			err = PGPResetHMAC( ref );
		}
		else
		{
			err	= kPGPError_OutOfMemory;
		}
	}
	
done:
	if( IsPGPError( err ) )
	{
		if( PGPHMACContextRefIsValid( ref ) )
		{
			if( PGPHashContextRefIsValid( ref->hash ) )
				PGPFreeHashContext( ref->hash );
			if( IsntNull( ref->secret ) )
				PGPFreeData( ref->secret );
			PGPFreeData( ref );
			ref = NULL;
		}
	}
	*outRef	= ref;
	return( err );
}

/* FIPS140 statetrans SP.PGPFreeHMACContext.1 */
	PGPError 
PGPFreeHMACContext( PGPHMACContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPFreeHMACContext.1 */
	pgpValidateHMAC( ref );
	
	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans PGPFreeHMACContext.3 */
	PGPFreeData( ref->secret );
	PGPFreeHashContext( ref->hash );
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}

/* FIPS140 statetrans SP.PGPResetHMAC.1 */
	PGPError 
PGPResetHMAC( PGPHMACContextRef ref )
{
	PGPError	err	= kPGPError_NoErr;
	PGPSize		hashMsgBlockSize; 
	
/* FIPS140 statetrans PGPResetHMAC.1 */
	pgpValidateHMAC( ref );
	
	pgpEnterPGPErrorFunction();

	err = pgpGetHashMessageSize( ref->hash, &hashMsgBlockSize );

/* FIPS140 statetrans SP.PGPResetHMAC.3 */
	if( IsntPGPError( err ) )
		err = PGPResetHash( ref->hash );

	if( IsntPGPError( err ) )
	{
		PGPByte		bstr[kPGPHMAC_MaxHashBlock];
		PGPUInt32	bindex;
		
		pgpCopyMemory( ref->secret, bstr, ref->secretLen );
		pgpClearMemory( bstr + ref->secretLen, hashMsgBlockSize-ref->secretLen );
		for( bindex = 0; bindex < hashMsgBlockSize; bindex++ )
			bstr[bindex] ^= kPGPHMAC_ipad;
		err = PGPContinueHash( ref->hash, bstr, hashMsgBlockSize );
	}
	
	return( err );
}

/* FIPS140 statetrans SP.PGPContinueHMAC.1 */
	PGPError 
PGPContinueHMAC(
	PGPHMACContextRef	ref,
	const void *		in,
	PGPSize				numBytes )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPContinueHMAC.1 */
	pgpValidateHMAC( ref );
	PGPValidatePtr( in );

	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans PGPContinueHMAC.3 */
	if ( numBytes != 0 )
		err = PGPContinueHash( ref->hash, in, numBytes );
	
	return( err );
}

/* FIPS140 statetrans SP.PGPFinalizeHMAC.1 */
	PGPError 
PGPFinalizeHMAC(
	PGPHMACContextRef	ref,
	void *				hmacOut )
{
	PGPError			err	= kPGPError_NoErr;
	PGPSize				hashSize;
	PGPSize				hashMsgBlockSize;
	PGPByte				bstr[kPGPHMAC_MaxHashBlock];
	PGPUInt32			bindex;
	
/* FIPS140 statetrans PGPFinalizeHMAC.1 */
	pgpValidateHMAC( ref );
	PGPValidatePtr( hmacOut );
	
	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans PGPFinalizeHMAC.3 */
	(void)PGPGetHashSize( ref->hash, &hashSize);
	err = pgpGetHashMessageSize( ref->hash, &hashMsgBlockSize );
	if( IsPGPError( err ) )
		goto done;
	err = PGPFinalizeHash( ref->hash, hmacOut );
	if( IsPGPError( err ) )
		goto done;
	err = PGPResetHash( ref->hash );
	if( IsPGPError( err ) )
		goto done;
	pgpCopyMemory( ref->secret, bstr, ref->secretLen );
	pgpClearMemory( bstr + ref->secretLen, hashMsgBlockSize-ref->secretLen );
	for( bindex = 0; bindex < hashMsgBlockSize; bindex++ )
		bstr[bindex] ^= kPGPHMAC_opad;
	err = PGPContinueHash( ref->hash, bstr, hashMsgBlockSize );
	if( IsPGPError( err ) )
		goto done;
	err = PGPContinueHash( ref->hash, hmacOut, hashSize );
	if( IsPGPError( err ) )
		goto done;
	err = PGPFinalizeHash( ref->hash, hmacOut );
	if( IsPGPError( err ) )
		goto done;
done:
	return( err );
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
