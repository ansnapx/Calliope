/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pCBC.c 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include <string.h>

#include "pgpSDKBuildFlags.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpSymmetricCipherPriv.h"
#include "pgpCBCPriv.h"
//#include "pgpUtilitiesPriv.h"
#include "pgpPFLPriv.h"



#define PGPValidateCBC( CBC )	\
	PGPValidateParam( pgpCBCIsValid( CBC ) );
	
/*____________________________________________________________________________
	In CBC, iv[] is the previous block's ciphertext, or the Initial
	Vector before the first block is processed.  As we read plaintext
	bytes during encryption, they are xored into iv[] until it is
	full, then the symmetric cipher is run.  For decryption, iv[] is
	loaded with the previous ciphertext after we finish decrypting the
	current block.
____________________________________________________________________________*/
	
	

struct PGPCBCContext
{
#define kCBCMagic		0xBAAB0957
	PGPUInt32						magic;
	PGPMemoryMgrRef					memoryMgr;
	PGPBoolean						CBCInited;
	PGPSymmetricCipherContextRef	symmetricRef;
	PGPByte							iv1[ PGP_CBC_MAXBLOCKSIZE ];
	PGPByte							iv2[ PGP_CBC_MAXBLOCKSIZE ];
	PGPByte *						iv;
};

	static PGPBoolean
pgpCBCIsValid( const PGPCBCContext * ref)
{
	PGPBoolean	valid	= FALSE;
	
	valid	= IsntNull( ref ) && ref->magic	 == kCBCMagic
				&& (ref->iv == ref->iv1  ||  ref->iv == ref->iv2);
	
	return( valid );
}



/*____________________________________________________________________________
	Internal forward references
____________________________________________________________________________*/

static void		pgpCBCInit( PGPCBCContext *	ref,
					void const * key, void const * iv);
					
static PGPError	pgpCBCEncrypt( PGPCBCContext *ref,
					void const * src, PGPSize len, void * dest );
					
static PGPError	pgpCBCDecrypt( PGPCBCContext *ref,
					void const * src, PGPSize len, void * dest );



/*____________________________________________________________________________
	Exported routines
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPNewCBCContext.1 */
	PGPError 
PGPNewCBCContext(
	PGPSymmetricCipherContextRef	symmetricRef,
	PGPCBCContextRef *				outRef )
{
	PGPCBCContextRef				newRef	= NULL;
	PGPError						err	= kPGPError_NoErr;
	PGPMemoryMgrRef					memoryMgr	= NULL;
	
    /* FIPS140 statetrans PGPNewCBCContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidatePtr( symmetricRef );

	pgpEnterPGPErrorFunction();

	memoryMgr	= pgpGetSymmetricCipherMemoryMgr( symmetricRef );
	newRef	= (PGPCBCContextRef)
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

        /* FIPS140 statetrans PGPNewCBCContext.3 */
		newRef->magic			= kCBCMagic;
		newRef->CBCInited		= FALSE;
		newRef->symmetricRef	= symmetricRef;
		newRef->iv				= newRef->iv1;
		newRef->memoryMgr		= memoryMgr;
		
		/* make sure we clean up */
		if ( IsPGPError( err ) )
		{
			PGPFreeCBCContext( newRef );
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
/* FIPS140 statetrans SP.PGPFreeCBCContext.1 */
	PGPError 
PGPFreeCBCContext( PGPCBCContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPFreeCBCContext.1 */
	PGPValidateCBC( ref );
	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPFreeCBCContext.3 */
	PGPFreeSymmetricCipherContext( ref->symmetricRef );
	
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}



/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCopyCBCContext.1 */
	PGPError 
PGPCopyCBCContext(
	PGPCBCContextRef	inRef,
	PGPCBCContextRef *	outRef )
{
	PGPError			err	= kPGPError_NoErr;
	PGPCBCContextRef	newRef	= NULL;
	
    /* FIPS140 statetrans PGPCopyCBCContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateCBC( inRef );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPCBCContextRef)
		PGPNewData( inRef->memoryMgr,
		sizeof( *newRef ), 0);

	if ( IsntNull( newRef ) )
	{
        /* FIPS140 statetrans PGPCopyCBCContext.3 */
		*newRef		= *inRef;
		newRef->iv	= (inRef->iv==inRef->iv1) ? newRef->iv1 : newRef->iv2;
		
		/* clear symmetric cipher in case later allocation fails */
		newRef->symmetricRef = NULL;
		
		/* copy symmetric cipher */
		err	= PGPCopySymmetricCipherContext(
				inRef->symmetricRef, &newRef->symmetricRef );
		
		if ( IsPGPError( err ) )
		{
			PGPFreeCBCContext( newRef );
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
/* FIPS140 statetrans SP.PGPInitCBC.1 */
	PGPError PGPSDKM_PUBLIC_API
PGPInitCBC(
	PGPCBCContextRef	ref,
	const void *		key,
	const void *		initializationVector )
{
	PGPError			err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans PGPInitCBC.1 */
	PGPValidateCBC( ref );
	/* at least one param must be non-nil */
	PGPValidateParam( IsntNull( key ) || IsntNull( initializationVector ) );
		
	pgpEnterPGPErrorFunction();

    /* FIPS140 statetrans PGPInitCBC.3 */
	pgpCBCInit( ref, key, initializationVector);
	
	return( err );
}


/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
pgpCBCEncryptInternal(
	PGPCBCContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
	PGPError	err;
	
	if ( ref->CBCInited )
	{
/* FIPS140 statetrans PGPCBCEncrypt.3 */
		err = pgpCBCEncrypt( ref, in, bytesIn, out);
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	return( err );
}

/*____________________________________________________________________________
____________________________________________________________________________*/
   /* FIPS140 statetrans SP.PGPCBCEncrypt.1 */
	PGPError 
PGPCBCEncrypt(
	PGPCBCContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
   /* FIPS140 statetrans PGPCBCEncrypt.1 */
	PGPValidatePtr( out );
	PGPValidateCBC( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();
#if PGP_ENCRYPT_DISABLE
	return( kPGPError_FeatureNotAvailable );
#else
	return( pgpCBCEncryptInternal( ref, in, bytesIn, out ) );
#endif
}

					
/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPError 
pgpCBCDecryptInternal(
	PGPCBCContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
	PGPError	err;
	
	if ( ref->CBCInited )
	{
		err = pgpCBCDecrypt( ref, in, bytesIn, out);
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	return( err );
}

/*____________________________________________________________________________
____________________________________________________________________________*/
   /* FIPS140 statetrans SP.PGPCBCDecrypt */
	PGPError 
PGPCBCDecrypt(
	PGPCBCContextRef	ref,
	const void *		in,
	PGPSize				bytesIn,
	void *				out )
{
  /* FIPS140 statetrans PGPCBCDecrypt.1 */
	PGPValidatePtr( out );
	PGPValidateCBC( ref );
	PGPValidatePtr( in );
	PGPValidateParam( bytesIn != 0 );

	pgpEnterPGPErrorFunction();

#if PGP_DECRYPT_DISABLE
	return( kPGPError_FeatureNotAvailable );
#else
  /* FIPS140 statetrans PGPCBCDecrypt.3 */
	return( pgpCBCDecryptInternal( ref, in, bytesIn, out ) );
#endif
}



/*____________________________________________________________________________
____________________________________________________________________________*/
/* FIPS140 statetrans SP.PGPCBCGetSymmetricCipher.1 */	
	PGPError 
PGPCBCGetSymmetricCipher(
	PGPCBCContextRef				ref,
	PGPSymmetricCipherContextRef *	outRef )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSymmetricCipherContextRef	symmetricRef	= NULL;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateCBC( ref );

	pgpEnterPGPErrorFunction();

	symmetricRef	= ref->symmetricRef;
	
	*outRef	= symmetricRef;
	return( err );
}





#ifdef PRAGMA_MARK_SUPPORTED
#pragma mark --- Internal Routines ---
#endif








/*____________________________________________________________________________
	Initialize contexts.
	If key is NULL, the current key is not changed.
	if iv is NULL, the IV is set to all zero.
____________________________________________________________________________*/
/* FIPS140 state Initialize CBC context */
	static void
pgpCBCInit(
	PGPCBCContext *		ref,
	void const *		key,
	void const *		iv)
{
	PGPSize			blockSize;
	void const *	curIV	= iv;
	
	PGPGetSymmetricCipherSizes( ref->symmetricRef, NULL, &blockSize );
	
	if ( IsntNull( key ) )
	{
		PGPInitSymmetricCipher( ref->symmetricRef, key );
	}

	pgpClearMemory( ref->iv1, sizeof( ref->iv1 )  );
	pgpClearMemory( ref->iv2, sizeof( ref->iv2 )  );
	ref->iv = ref->iv1;

	if ( IsntNull( iv ) )
	{
		pgpCopyMemory( curIV, ref->iv, blockSize );
	}

	/* rely on the symmetric cipher to know whether it has been inited */
	/* also, iv of NULL is OK, since semantics say that means zeroes */
	ref->CBCInited		= TRUE;
}



/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPSize
pgpCBCGetKeySize( PGPCBCContextRef ref )
{
	PGPSize	keySize;
	
	pgpAssert( pgpCBCIsValid( ref ) );
	
	PGPGetSymmetricCipherSizes( ref->symmetricRef, &keySize, NULL );
	return( keySize );
}


/*____________________________________________________________________________
____________________________________________________________________________*/
	PGPSize
pgpCBCGetBlockSize( PGPCBCContextRef ref )
{
	PGPSize	blockSize;
	
	pgpAssert( pgpCBCIsValid( ref ) );
	
	PGPGetSymmetricCipherSizes( ref->symmetricRef, NULL, &blockSize );
	return( blockSize );
}




/*____________________________________________________________________________
	Encrypt a buffer of data blocks, using a block cipher in CBC mode.
____________________________________________________________________________*/
	static PGPError
pgpCBCEncrypt(
	PGPCBCContext *		ref,
	void const *		srcParam,
	PGPSize				len,
	void *				destParam )
{
	PGPSize			blockSize;
	PGPSize			bufcnt;
	PGPByte *		bufptr;
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	PGPGetSymmetricCipherSizes( ref->symmetricRef, NULL, &blockSize );
	
	/* Length must be a multiple of blocksize */
	if( len % blockSize != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		bufptr		= ref->iv;
		bufcnt		= blockSize;

		/* XOR new data into iv buffer */
		while( bufcnt-- )
		{
			*bufptr++ ^= *src++;
		}

		/* Encrypt IV buffer to itself to form ciphertext */
		bufptr = ref->iv;
		pgpSymmetricCipherEncryptInternal(ref->symmetricRef, bufptr, bufptr);

		/* Copy ciphertext to destination buffer */
		bufcnt = blockSize;
		while( bufcnt-- )
		{
			*dest++ = *bufptr++;
		}

		/* Loop until we have exhausted the data */
		len -= blockSize;
	}

	return kPGPError_NoErr;
}


/*____________________________________________________________________________
	Decrypt a buffer of data blocks, using a block cipher in CBC mode.
____________________________________________________________________________*/
	static PGPError
pgpCBCDecrypt(
	PGPCBCContext *	ref,
	void const *	srcParam,
	PGPSize			len,
	void *			destParam )
{
	PGPSize			blockSize;
	PGPSize			bufcnt;
	PGPByte *		bufptr;
	const PGPByte *	src = (const PGPByte *) srcParam;
	PGPByte *		dest = (PGPByte *) destParam;
	
	PGPGetSymmetricCipherSizes( ref->symmetricRef, NULL, &blockSize );
	
	/* Length must be a multiple of blocksize */
	if( len % blockSize != 0 )
	{
		return kPGPError_BadParams;
	}

	while( len != 0 )
	{
		PGPByte *	altiv;

		/* Copy input ciphertext into alternate iv buffer */
		altiv		= (ref->iv == ref->iv1) ? ref->iv2 : ref->iv1;
		bufcnt		= blockSize;
		bufptr		= altiv;
		while( bufcnt-- )
		{
			*bufptr++ = *src++;
		}

		/* Decrypt ciphertext into destination */
		pgpSymmetricCipherDecryptInternal(ref->symmetricRef, altiv, dest);

		/* XOR iv into output data to form plaintext */
		bufcnt		= blockSize;
		bufptr		= ref->iv;
		while( bufcnt-- )
		{
			*dest++ ^= *bufptr++;
		}

		/* Toggle the IV buffers each iteration */
		ref->iv = altiv;
		
		/* Loop until we have exhausted the data */
		len -= blockSize;
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
