/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

        $Id: pCFB.c 47723 2006-09-14 01:40:51Z hal $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include <string.h>

#include "pgpSDKBuildFlags.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpMemoryMgr.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpCFBPriv.h"
//#include "pgpUtilitiesPriv.h"
#include "pgpPFLPriv.h"


#define PGPValidateCFB( cfb )	\
	PGPValidateParam( pgpCFBIsValid( cfb ) );
	
/*____________________________________________________________________________
	Some stuff does double duty for CFB encryption/decryption,
	and for X9.17 random number generation.
	
	For random number generate, it is illegal to attempt to use
	an interleaved CFB.

	When used for CFB, iv[] is used as a circular buffer.  bufLeft is
	the number of bytes at the end which have to be filled in before we
	crank the block cipher again.  We do the block cipher operation
	lazily: bufLeft may be 0.  When we need one more byte, we
	crank the block cipher and set bufLeft to 7.

	prev[] holds the previous 8 bytes of ciphertext, for use
	by ideaCFBSync() and Phil's, ahem, unique (not insecure, just
	unusual) way of doing CFB encryption.

	When used for X9.17 random number generation, iv[] holds the V initial
	vector, and prev[] holds the R random output.  bufLeft indicates how
	much of R is still available before the generator has to be cranked again.
____________________________________________________________________________*/


/*____________________________________________________________________________
	Each interleaved CFB has its own data.
____________________________________________________________________________*/
typedef struct
{
	PGPSymmetricCipherContextRef	symmetricRef;
	PGPByte							prev[ PGP_CFB_MAXBLOCKSIZE ];
	PGPByte							iv[ PGP_CFB_MAXBLOCKSIZE ];
	/* note bufLeft could actually be in the main structure,
	but it's more convenient here */
	PGPSize							bufLeft;
} CFBInterleaveStruct;
#define kCFBSize		sizeof( CFBInterleaveStruct )


struct PGPCFBContext
{
#define kCFBMagic		0xBAABBAAB
	PGPUInt32						magic;
	PGPMemoryMgrRef					memoryMgr;
	PGPUInt16						interleave;
	PGPUInt16						curCFBIndex;
	PGPSize							bytesInCur;
	PGPBoolean						cfbInited;
	CFBInterleaveStruct				cfbData[ 1 ];	/* variable */
};
#define IndCFB( ref, x )	(ref)->cfbData[ x ]

	static PGPSize
CalcContextSize( PGPUInt16	numInterleaves )
{
	/* one CFBInterleaveStruct is already declared in main struct */
	return( sizeof( PGPCFBContext ) +
		( numInterleaves - 1 ) * kCFBSize );
}


	static PGPBoolean
pgpCFBIsValid( const PGPCFBContext * ref)
{
	PGPBoolean	valid	= FALSE;
	
	valid	= IsntNull( ref ) && ref->magic	 == kCFBMagic;
	
	return( valid );
}



static void		pgpCFBSync(CFBInterleaveStruct *cfb);

static PGPError	pgpCFBRandCycle(PGPCFBContext *ref,
					void const *salt);
					
static void		pgpCFBRandWash(PGPCFBContext *ref,
					void const *buf, PGPSize len);
					
static void		pgpCFBInit( PGPCFBContext *	ref,
					void const * key, void const * iv);
					
static void		pgpCFBEncrypt( CFBInterleaveStruct *ref,
					void const * src, PGPSize len, void * dest );
					
static void		pgpCFBDecrypt( CFBInterleaveStruct *ref,
					void const * src, PGPSize len, void * dest );


/* Returns as many bytes as are available before more salt is needed */
static PGPSize 	pgpCFBRandBytes(PGPCFBContext *ref,
						PGPSize len, void *dest );


/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPNewCFBContext.1 */
	PGPError 
PGPNewCFBContext(
	PGPSymmetricCipherContextRef	symmetricRef,
	PGPUInt16						interleave,
	PGPCFBContextRef *	outRef )
{
	PGPCFBContextRef		newRef	= NULL;
	PGPError						err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans PGPNewCFBContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidatePtr( symmetricRef );
	PGPValidateParam( interleave != 0 );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPCFBContextRef)
			PGPNewData( pgpGetSymmetricCipherMemoryMgr( symmetricRef ),
				CalcContextSize( interleave ),
				0 | kPGPMemoryMgrFlags_Clear);
			
	if ( IsntNull( newRef ) )
	{
		PGPUInt32	cfbIndex;
		
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

        /* FIPS140 statetrans PGPNewCFBContext.3 */
		newRef->magic						= kCFBMagic;
		newRef->interleave					= interleave;	
		newRef->cfbInited					= FALSE;
		IndCFB( newRef, 0 ).symmetricRef	= symmetricRef;
		
		newRef->memoryMgr = pgpGetSymmetricCipherMemoryMgr( symmetricRef );
		
		/* create a separate symmetric cipher for each cfb */
		for ( cfbIndex = 1; cfbIndex < interleave; ++ cfbIndex )
		{
			err	= PGPCopySymmetricCipherContext( symmetricRef,
						&IndCFB( newRef, cfbIndex ).symmetricRef );
			if ( IsPGPError( err ) )
			{
				break;
			}
		}
		
		/* make sure we clean up */
		if ( IsPGPError( err ) )
		{
			PGPFreeCFBContext( newRef );
			newRef	= NULL;
		}
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
/* FIPS140 statetrans SP.PGPFreeCFBContext.1 */
	PGPError 
PGPFreeCFBContext( PGPCFBContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	PGPUInt32		cfbIndex;
	
/* FIPS140 statetrans PGPFreeCFBContext.1 */
	PGPValidateCFB( ref );
	
	pgpEnterPGPErrorFunction();

   /* FIPS140 statetrans PGPFreeCFBContext.3 */
	for( cfbIndex = 0; cfbIndex < ref->interleave; ++cfbIndex )
	{
		if ( IsntNull( IndCFB( ref, cfbIndex ).symmetricRef ) )
		{
			PGPFreeSymmetricCipherContext(
				IndCFB( ref, cfbIndex ).symmetricRef );
			IndCFB( ref, cfbIndex ).symmetricRef	= NULL;
		}
	}
	
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCopyCFBContext.1 */
	PGPError 
PGPCopyCFBContext(
	PGPCFBContextRef	inRef,
	PGPCFBContextRef *	outRef )
{
	PGPError					err	= kPGPError_NoErr;
	PGPCFBContextRef	newRef	= NULL;
	
    /* FIPS140 statetrans PGPCopyCFBContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateCFB( inRef );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPCFBContextRef)
		PGPNewData( inRef->memoryMgr,
		CalcContextSize( inRef->interleave ), 0);
	if ( IsntNull( newRef ) )
	{
        /* FIPS140 statetrans PGPCopyCFBContext.3 */
		PGPUInt32	cfbIndex;
		
		*newRef		= *inRef;
		
		/* clear each symmetric cipher in case later allocation fails */
		for ( cfbIndex = 0; cfbIndex < inRef->interleave; ++cfbIndex )
		{
			IndCFB( newRef, cfbIndex ).symmetricRef	= NULL;
		}
		
		/* copy each symmetric cipher */
		for ( cfbIndex = 0; cfbIndex < inRef->interleave; ++cfbIndex )
		{
			err	= PGPCopySymmetricCipherContext(
					IndCFB( inRef, cfbIndex ).symmetricRef,
					&IndCFB( newRef, cfbIndex ).symmetricRef );
			if ( IsPGPError( err ) )
			{
				break;
			}
		}
		
		if ( IsPGPError( err ) )
		{
			PGPFreeCFBContext( newRef );
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
/* FIPS140 statetrans SP.PGPInitCFB.1 */
	PGPError 
PGPInitCFB(
	PGPCFBContextRef	ref,
	const void *		key,
	const void *		initializationVector )
{
	PGPError	err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans PGPInitCFB.1 */
	PGPValidateCFB( ref );
	/* at least one param must be non-nil */
	PGPValidateParam( IsntNull( key ) || IsntNull( initializationVector ) );
		
	pgpEnterPGPErrorFunction();

    /* FIPS140 statetrans PGPInitCFB.3 */
	pgpCFBInit( ref, key, initializationVector);
	
	return( err );
}




/* FIPS140 state CFB encrypt data interleaved */
/* FIPS140 state CFB decrypt data interleaved */
	static void
pgpEncryptDecryptInterleaved(
	PGPBoolean			encrypt,
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
	PGPSize			blockSize	= pgpCFBGetBlockSize( ref );
	PGPUInt16		cfbIndex;
	PGPSize			remaining;
	const PGPByte *	curIn	= (const PGPByte *) in;
	PGPByte *		curOut	= (PGPByte *) out;
	
	cfbIndex	= ref->curCFBIndex;
	remaining	= bytesIn;
	while ( remaining != 0 )
	{
		CFBInterleaveStruct *	cfb	= NULL;
		PGPSize				bytesAvail;
		
		bytesAvail	= blockSize - ref->bytesInCur;
		if ( bytesAvail > remaining )
			bytesAvail	= remaining;
		
		cfb	= &IndCFB( ref, cfbIndex );
		if ( encrypt )
			pgpCFBEncrypt( cfb, curIn, bytesAvail, curOut);
		else
			pgpCFBDecrypt( cfb, curIn, bytesAvail, curOut);
		
		ref->bytesInCur	+= bytesAvail;
		curIn			+= bytesAvail;
		curOut			+= bytesAvail;
		remaining		-= bytesAvail;
		
		/* do we need to go onto the next CFB? */
		pgpAssert( ref->bytesInCur <= blockSize );
		if ( ref->bytesInCur == blockSize )
		{
			++cfbIndex;
			/* wrap around to first CFB if necessary */
			if ( cfbIndex == ref->interleave )
			{
				cfbIndex	= 0;
			}
			ref->bytesInCur	= 0;
		}
	}
	
	ref->curCFBIndex	= cfbIndex;
	
	(void)encrypt;
	(void)ref;
	(void)in;
	(void)bytesIn;
	(void)out;
}

	PGPError 
pgpCFBEncryptInternal(
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
	PGPError	err	= kPGPError_NoErr;
	
	if ( ref->cfbInited )
	{
		if ( ref->interleave == 1 )
		{
			/* keep it most efficient for common case */
			CFBInterleaveStruct *cfb	= &IndCFB( ref, 0);
			
			/* FIPS140 statetrans PGPCFBEncrypt.3 */
			pgpCFBEncrypt( cfb, in, bytesIn, out);
		}
		else
		{
/* FIPS140 statetrans PGPCFBEncrypt.5 */
			pgpEncryptDecryptInterleaved( TRUE, ref, in, bytesIn, out );
		}
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	return( err );
}

	PGPError 
/* FIPS140 statetrans SP.PGPCFBEncrypt.1 */
PGPCFBEncrypt(
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
/* FIPS140 statetrans PGPCFBEncrypt.1 */
	PGPValidatePtr( out );
	PGPValidateCFB( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();

#if PGP_ENCRYPT_DISABLE
	return( kPGPError_FeatureNotAvailable );
#else
	return( pgpCFBEncryptInternal( ref, in, bytesIn, out ) );
#endif
}

					
	PGPError 
pgpCFBDecryptInternal(
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
	PGPError	err	= kPGPError_NoErr;
	
	if ( ref->cfbInited )
	{
		if ( ref->interleave == 1 )
		{
			/* keep it most efficient for common case */
			CFBInterleaveStruct *cfb	= &IndCFB( ref, 0);
			
/* FIPS140 statetrans PGPCFBDecrypt.3 */
			pgpCFBDecrypt( cfb, in, bytesIn, out);
		}
		else
		{
/* FIPS140 statetrans PGPCFBDecrypt.5 */
			pgpEncryptDecryptInterleaved( FALSE, ref, in, bytesIn, out );
		}
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	return( err );
}

/* FIPS140 statetrans SP.PGPCFBDecrypt.1 */
	PGPError 
PGPCFBDecrypt(
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
/* FIPS140 statetrans PGPCFBDecrypt.1 */
	PGPValidatePtr( out );
	PGPValidateCFB( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();

#if PGP_DECRYPT_DISABLE
	return( kPGPError_FeatureNotAvailable );
#else
	return( pgpCFBDecryptInternal( ref, in, bytesIn, out ) );
#endif
}



/* FIPS140 statetrans SP.PGPCFBGetSymmetricCipher.1 */
	PGPError 
PGPCFBGetSymmetricCipher(
	PGPCFBContextRef		ref,
	PGPSymmetricCipherContextRef *	outRef )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSymmetricCipherContextRef	symmetricRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateCFB( ref );

	pgpEnterPGPErrorFunction();

	symmetricRef	= IndCFB( ref, 0).symmetricRef;
	
	*outRef	= symmetricRef;
	return( err );
}




/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCFBSync.1 */
	PGPError 
PGPCFBSync( PGPCFBContextRef ref )
{
	PGPError			err	= kPGPError_NoErr;
	
/* FIPS140 statetrans SP.PGPCFBSync.1 */
	PGPValidateCFB( ref );
	
	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans SP.PGPCFBSync.3 */
	pgpCFBSync( &IndCFB( ref, ref->curCFBIndex ) );
	
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCFBGetRandom.1 */
	PGPError 
PGPCFBGetRandom(
	PGPCFBContextRef	ref,
	PGPSize				requestCount,
	void *				outBytes,
	PGPSize *			outCount )
{
	PGPError	err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans PGPCFBGetRandom.1 */
	PGPValidatePtr( outCount );
	*outCount	= 0;
	PGPValidateCFB( ref );
	PGPValidatePtr( outBytes );
	PGPValidateParam( ref->interleave == 1 );
		
	pgpEnterPGPErrorFunction();

    /* FIPS140 statetrans PGPCFBGetRandom.3 */
	*outCount	= pgpCFBRandBytes( ref, requestCount, outBytes);
	
	return( err );
}

					
					
/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCFBRandomCycle.1 */
	PGPError 
PGPCFBRandomCycle(
	PGPCFBContextRef	ref,
	const void *		salt)
{
	PGPError	err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans PGPCFBRandomCycle.1 */
	PGPValidateCFB( ref );
	PGPValidatePtr( salt );
	PGPValidateParam( ref->interleave == 1 );
	
	pgpEnterPGPErrorFunction();

  /* FIPS140 statetrans PGPCFBRandomCycle.3 */
	err = pgpCFBRandCycle( ref, salt);
	
	return( err );
}

					
					
/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCFBRandomWash.1 */
	PGPError 
PGPCFBRandomWash(
	PGPCFBContextRef	ref,
	const void *		in,
	PGPSize				bytesIn )
{
	PGPError	err	= kPGPError_NoErr;
	
   /* FIPS140 statetrans PGPCFBRandomWash.1 */
	PGPValidateCFB( ref );
	PGPValidatePtr( in );
	PGPValidateParam( ref->interleave == 1 );
	
	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPCFBRandomWash.3 */
	pgpCFBRandWash( ref, in, bytesIn );
	
	return( err );
}







#ifdef PRAGMA_MARK_SUPPORTED
#pragma mark --- Internal Routines ---
#endif









	PGPCFBContextRef
pgpCFBCreate(
	PGPMemoryMgrRef			memoryMgr,
	PGPCipherVTBL const *	vtbl)
{
	PGPError						err				= kPGPError_NoErr;
	PGPCFBContextRef		newRef			= NULL;
	PGPSymmetricCipherContextRef	symmetricRef	= NULL;
	
	pgpAssert( vtbl->blocksize <= PGP_CFB_MAXBLOCKSIZE );
	pgpAssert( IsntPGPError( PGPValidateMemoryMgr( memoryMgr ) ) );
		
	err	= pgpNewSymmetricCipherContextInternal( memoryMgr,
		vtbl->algorithm, &symmetricRef );
	if ( IsntPGPError( err ) )
	{
		err	= PGPNewCFBContext( symmetricRef, 1, &newRef );
		if ( IsPGPError( err ) )
		{
			PGPFreeSymmetricCipherContext( symmetricRef );
			symmetricRef	= NULL;
			pgpAssert( IsNull( newRef ) );
		}
	}
	
	return newRef;
}


/*____________________________________________________________________________
	Initialize contexts.
	If key is NULL, the current key is not changed.
	if iv is NULL, the IV is set to all zero.
____________________________________________________________________________*/
/* FIPS140 state Initialize CFB Context */
	static void
pgpCFBInit(
	PGPCFBContext *	ref,
	void const *	key,
	void const *	iv)
{
	PGPSize			blockSize;
	PGPUInt32		cfbIndex;
	PGPByte const *	curIV	= (const PGPByte *) iv;
	
	PGPGetSymmetricCipherSizes( IndCFB( ref, 0 ).symmetricRef,
		NULL, &blockSize );
	
	for ( cfbIndex = 0; cfbIndex < ref->interleave; ++cfbIndex )
	{
		CFBInterleaveStruct *	cfb;
		
		cfb	= &IndCFB( ref, cfbIndex);
		
		if ( IsntNull( key ) )
		{
			PGPInitSymmetricCipher( cfb->symmetricRef, key );
		}
		
		pgpClearMemory( cfb->prev, sizeof( cfb->prev )  );
		pgpClearMemory( cfb->iv, sizeof( cfb->iv )  );
		if ( IsntNull( iv ) )
		{
			pgpCopyMemory( curIV, &cfb->iv, blockSize );
			curIV	+= blockSize;
		}
		
		cfb->bufLeft	= 0;
	}
	
	ref->curCFBIndex	= 0;
	ref->bytesInCur		= 0;
	/* rely on the symmetric cipher to know whether it has been inited */
	/* also, iv of NULL is OK, since semantics say that means zeroes */
	ref->cfbInited		= TRUE;
}



	PGPSize
pgpCFBGetKeySize( PGPCFBContextRef ref )
{
	PGPSize	keySize;
	
	pgpAssert( pgpCFBIsValid( ref ) );
	
	PGPGetSymmetricCipherSizes( IndCFB( ref, 0).symmetricRef, &keySize, NULL );
	return( keySize );
}

	PGPSize
pgpCFBGetBlockSize( PGPCFBContextRef ref )
{
	PGPSize	blockSize;
	
	pgpAssert( pgpCFBIsValid( ref ) );
	
	PGPGetSymmetricCipherSizes( IndCFB( ref, 0).symmetricRef,
		NULL, &blockSize );
	return( blockSize );
}



	void
pgpCFBWipe( PGPCFBContextRef	ref)
{
	PGPUInt32	cfbIndex;
	
	ref->cfbInited			= FALSE;
		
	pgpAssert( pgpCFBIsValid( ref ) );
	
	for ( cfbIndex = 0; cfbIndex < ref->interleave; ++cfbIndex )
	{
		CFBInterleaveStruct *	cfb;
		
		cfb	= &IndCFB( ref, cfbIndex);
		
		PGPWipeSymmetricCipher( cfb->symmetricRef );
		
		pgpClearMemory( cfb->prev, sizeof( cfb->prev )  );
		pgpClearMemory( cfb->iv, sizeof( cfb->iv )  );
		
		cfb->bufLeft = 0;
	}
	
	ref->curCFBIndex	= 0;
}



/*____________________________________________________________________________
	Encrypt a buffer of data, using a block cipher in CFB mode.
	here are more compact ways of writing this, but this is
	written for speed.
____________________________________________________________________________*/
/* FIPS140 state CFB Encrypt data */
	static void
pgpCFBEncrypt(
	CFBInterleaveStruct *	cfb,
	void const *			srcParam,
	PGPSize					len,
	void *					destParam )
{
	PGPSize			blockSize;
	PGPSize			bufLeft		= cfb->bufLeft;
	PGPByte *		bufptr;
	const PGPByte *	src;
	PGPByte *		dest;
	
	PGPGetSymmetricCipherSizes( cfb->symmetricRef, NULL, &blockSize );
	
	bufptr	= cfb->iv + blockSize - bufLeft;
	src		= (const PGPByte *) srcParam;
	dest	= (PGPByte *) destParam;
	
	/*
	 * If there are no more bytes to encrypt that there are bytes
	 * in the buffer, XOR them in and return.
	 */
	if (len <= bufLeft)
	{
		cfb->bufLeft = bufLeft - len;
		while (len--)
		{
			*dest++ = *bufptr++ ^= *src++;
		}
		return;
	}
	len -= bufLeft;
	/* Encrypt the first bufLeft (0 to 7) bytes of the input by XOR
	 * with the last bufLeft bytes in the iv buffer.
	 */
	while (bufLeft--)
	{
		*dest++ = (*bufptr++ ^= *src++);
	}
	/* Encrypt middle blocks of the input by cranking the cipher,
	 * XORing blockSize-byte blocks, and repeating until the len
	 * is blockSize or less.
	 */
	while (len > blockSize)
	{
		bufptr = cfb->iv;
		pgpCopyMemory( bufptr, cfb->prev, blockSize);
		pgpSymmetricCipherEncryptInternal(cfb->symmetricRef, bufptr, bufptr);
		bufLeft = blockSize;
		len -= blockSize;
		do
		{
			*dest++ = (*bufptr++ ^= *src++);
		} while (--bufLeft);
	}
	/* Do the last 1 to blockSize bytes */
	bufptr = cfb->iv;
	pgpCopyMemory( bufptr, cfb->prev, blockSize);
	pgpSymmetricCipherEncryptInternal(cfb->symmetricRef, bufptr, bufptr);
	cfb->bufLeft = blockSize-len;
	do 
	{
		*dest++ = (*bufptr++ ^= *src++);
	} while (--len);
}


/*____________________________________________________________________________
	Decrypt a buffer of data, using a cipher in CFB mode.
	There are more compact ways of writing this, but this is
	written for speed.
____________________________________________________________________________*/
/* FIPS140 state CFB Decrypt data */
	static void
pgpCFBDecrypt(
	CFBInterleaveStruct *	cfb,
	void const *			srcParam,
	PGPSize					len,
	void *					destParam )
{
	PGPSize			blockSize;
	PGPSize			bufLeft = cfb->bufLeft;
	PGPByte *		bufptr	= NULL;
	PGPByte			t;
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	PGPGetSymmetricCipherSizes( cfb->symmetricRef, NULL, &blockSize );

	bufptr = cfb->iv + (blockSize-bufLeft);
	if (len <= bufLeft)
	{
		cfb->bufLeft = bufLeft - len;
		while (len--)
		{
			t = *bufptr;
			*dest++ = t ^ (*bufptr++ = *src++);
		}
		return;
	}
	len -= bufLeft;
	while (bufLeft--)
	{
		t = *bufptr;
		*dest++ = t ^ (*bufptr++ = *src++);
	}
	while (len > blockSize)
	{
		bufptr = cfb->iv;
		pgpCopyMemory( bufptr, cfb->prev, 8);
		pgpSymmetricCipherEncryptInternal(cfb->symmetricRef, bufptr, bufptr);
		bufLeft = blockSize;
		len -= blockSize;
		do
		{
			t = *bufptr;
			*dest++ = t ^ (*bufptr++ = *src++);
		} while (--bufLeft);
	}
	bufptr = cfb->iv;
	pgpCopyMemory( bufptr, cfb->prev, blockSize);
	pgpSymmetricCipherEncryptInternal(cfb->symmetricRef, bufptr, bufptr);
	cfb->bufLeft = blockSize-len;
	do
	{
		t = *bufptr;
		*dest++ = t ^ (*bufptr++ = *src++);
	} while (--len);
}

/*____________________________________________________________________________
	Okay, explanation time:
	Phil invented a unique way of doing CFB that's sensitive to semantic
	boundaries within the data being encrypted.  One way to phrase
	CFB en/decryption on an 8-byte block cipher is to say that you XOR
	the current 8 bytes with CRYPT(previous 8 bytes of ciphertext).
	Normally, you repeat this at 8-byte intervals, but Phil decided to
	resync things on the boundaries between elements in the stream being
	encrypted.

	That is, the last 4 bytes of a 12-byte field are en/decrypted using
	the first 4 bytes of CRYPT(previous 8 bytes of ciphertext), but then
	the last 4 bytes of that CRYPT computation are thrown away, and the
	first 8 bytes of the next field are en/decrypted using
	CRYPT(last 8 bytes of ciphertext).  This is equivalent to using a
	shorter feedback length (if you're familiar with the general CFB
	technique) briefly, and doesn't weaken the cipher any (using shorter
	CFB lengths makes it stronger, actually), it just makes it a bit unusual.

	Anyway, to accomodate this behaviour, every time we do an
	encryption of 8 bytes of ciphertext to get 8 bytes of XOR mask,
	we remember the ciphertext.  Then if we have to resync things
	after having processed, say, 2 bytes, we refill the iv buffer
	with the last 6 bytes of the old ciphertext followed by the
	2 bytes of new ciphertext stored in the front of the iv buffer.
____________________________________________________________________________*/
/* FIPS140 state Sync the CFB context */
	static void
pgpCFBSync(CFBInterleaveStruct *cfb)
{
	PGPSize	blockSize;
	PGPSize	bufLeft		= cfb->bufLeft;

	(void)PGPGetSymmetricCipherSizes( cfb->symmetricRef, NULL, &blockSize );
	
	if (bufLeft)
	{
		pgpCopyMemory( cfb->iv, cfb->iv + bufLeft, blockSize - bufLeft);
		pgpCopyMemory( cfb->prev + blockSize - bufLeft, cfb->iv, bufLeft);
		cfb->bufLeft	= 0;
	}
}

/*____________________________________________________________________________
	Cryptographically strong pseudo-random-number generator.
	The design is from Appendix C of ANSI X9.17, "Financial
	Institution Key Management (Wholesale)", with IDEA
	substituted for triple-DES.
 
	This generates one block (64 bits) of random number R, based on a
	key K, an initial vector V, and a time-dependent salt I.  I need not
	be truly random, but should differ for each block of output R, and
	contain as much entropy as possible.  In X9.17, I is encrypt(K,time()),
	where time() is the most accurate time available.  This has I supplied
	(from the true random number pool, which is based on similar information)
	to the ideaRandCycle function.

	The operation of ideaRandCycle is straight from X9.17::
	R = encrypt(K, V^I)
	V = encrypt(K, R^I)

	One thing worth noting is that, given fixed values of K and V,
	there is an isomorphism between values of I and values of R.
	Thus, R always contains at least as much entropy as is in I;
	if I is truly completely random, it does not matter if K and/or V
	are known.  Thus, if the supplied I (from the true random number pool)
	are good, the output of this is good.


	Fills in the supplied buffer with up to "count" pseudo-random bytes.
	Returns the number of bytes filled in.  If less than "count",
	pgpCFBRandCycle will need to be called with a new random salt value
	before more bytes are available.  pgpCFBRandBytes will return 0 until
	that is done.

	For FIPS compliance, we assume that we have to stick to the letter
	of the law.  X9.17 actually says that we are to do the following:

	*K is a secret 3DES key,
	ede is a 3DES operation,
	V is a secret seed value
	DT is a date/time vector which is updated every key generation
	I is an intermediate value,
	
	R is generated as follows:

	I = ede*K(DT)
	R = ede*K(I+V)

	and a new V is generated to seed the next generation

	V = ede*K(R+I)

	so we need to to the following:
	replace CAST with 3DES -
	check that 'I' is computed correctly - don't
	use the random pool


____________________________________________________________________________*/
/* FIPS140 state Return CFB random bytes */
	static PGPSize
pgpCFBRandBytes(
	PGPCFBContextRef	ref,
	PGPSize				count,
	void *				dest )
{
	PGPSize					bufLeft;
	CFBInterleaveStruct *	cfb;

	pgpAssert( ref->interleave == 1 );
	
	cfb	= &IndCFB( ref, 0 );
	
	bufLeft = cfb->bufLeft;
	
	if (count > bufLeft)
		count = bufLeft;
		
	cfb->bufLeft = bufLeft - count;
	pgpCopyMemory( cfb->prev + pgpCFBGetBlockSize( ref ) - bufLeft,
		dest, count);
		
	return count;
}


/*____________________________________________________________________________
	Make more random bytes available from ideaRandBytes using the X9.17
	algorithm and the supplied random salt.  Expects "ref->cipher->blockSize"
	bytes of salt.
____________________________________________________________________________*/
/* FIPS140 state Create random data in CFB */

PGPByte		sLastCFBCycle[ PGP_CFB_MAXBLOCKSIZE ] = {0,};

	static PGPError
pgpCFBRandCycle(
	PGPCFBContext *	ref,
	void const *	saltParam)
{
	PGPSize					i;
	PGPSize					blockSize = pgpCFBGetBlockSize( ref );
	CFBInterleaveStruct *	cfb;
	const PGPByte *			salt = (const PGPByte *) saltParam;
	PGPError				err = kPGPError_NoErr;
	
	pgpAssert( ref->interleave == 1 );
	
	cfb	= &IndCFB( ref, 0 );

	pgpAssert( ref->interleave == 1 );
	
	for (i = 0; i < blockSize; i++)
	{
		cfb->iv[i] ^= salt[i];
	}
	
	pgpSymmetricCipherEncryptInternal( cfb->symmetricRef, cfb->iv, cfb->prev);
	
	if( pgpFIPSModeEnabled() )
	{
		/*
		** For FIPS compliance, we compare the random bytes for each cycle to
		** the result of the previous cycle to make sure they are different
		*/
		
		if( pgpMemoryEqual( cfb->prev, sLastCFBCycle, blockSize ) )
		{
			err = kPGPError_SelfTestFailed;
			
			pgpSetSDKErrorState( err );
		}
		else
		{
			/* Remember results for next cycle */
			pgpCopyMemory( cfb->prev, sLastCFBCycle, blockSize );
		}
	}

	for (i = 0; i < blockSize; i++)
	{
		cfb->iv[i] = cfb->prev[i] ^ salt[i];
	}
	
	pgpSymmetricCipherEncryptInternal( cfb->symmetricRef, cfb->iv, cfb->iv);
	cfb->bufLeft = blockSize;
	
	return err;
}


/*____________________________________________________________________________
	"Wash" the random number state using an irreversible transformation
	based on the input buffer and the previous state.
____________________________________________________________________________*/
/* FIPS140 state Wash CFB random bytes */
	static void
pgpCFBRandWash(
	PGPCFBContextRef	ref,
	void const *		bufParam,
	PGPSize				len)
{
	PGPSize							blockSize = pgpCFBGetBlockSize( ref );
	PGPSize 						i, j;
	CFBInterleaveStruct *			cfb	= NULL;
	PGPSymmetricCipherContextRef	symmetricRef;
	const PGPByte *					buf = (const PGPByte *) bufParam;
	
	pgpAssert( ref->interleave == 1 );
	
	cfb	= &IndCFB( ref, 0 );
	symmetricRef	= cfb->symmetricRef;

	/* Wash the key (if supported) */
	PGPWashSymmetricCipher( symmetricRef, buf, len);

	/*
	 * Wash the IV - a bit ad-hoc, but it works.   It's
	 * basically a CBC-MAC.
	 */
	for (i = j = 0; i < len; i++)
	{
		cfb->iv[j] ^= buf[i];
		if (++j == blockSize)
		{
			pgpSymmetricCipherEncryptInternal(symmetricRef, cfb->iv, cfb->iv);
			j = 0;
		}
	}
	/* Pad with typical CBC padding indicating the length */
	while (j < blockSize)
	{
		cfb->iv[j++] ^= (PGPByte)len;
	}
	
	pgpSymmetricCipherEncryptInternal( symmetricRef, cfb->iv, cfb->iv);

	/* Set to empty */
	cfb->bufLeft = 0;
}
















/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
