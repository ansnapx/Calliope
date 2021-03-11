/*____________________________________________________________________________
	Copyright (C) 2003 PGP Corporation
	All rights reserved.

	$Id: pSym.c 47369 2006-08-31 23:32:55Z hal $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"

#include "pgpSymmetricCipherPriv.h"
#include "pgpMem.h"
#include "pgpPFLPriv.h"
#include "pgpErrors.h"
//#include "pgpUtilitiesPriv.h"

#include "pgpOpaqueStructs.h"
#include "pgpSDKBuildFlags.h"
#include "pgpDES3.h"
#include "pgpAES.h"

#include "pgpSymmetricCipher.h"
#include "pgpSymmetricCipherPriv.h"

#if PGP_ENCRYPT_DISABLE && PGP_DECRYPT_DISABLE
	#define PGP_HAVE_SYMMETRIC_CIPHERS	0
#else
	#define PGP_HAVE_SYMMETRIC_CIPHERS	1
#endif

struct PGPSymmetricCipherContext
{
#define kSymmetricContextMagic		0xABBADABA
	PGPUInt32				magic;
	PGPMemoryMgrRef			memoryMgr;
	PGPCipherVTBL const *	vtbl;
	void *					cipherData;
	PGPBoolean				keyInited;
} ;

/* Macros to access the member functions */
#define CallInitKey(cc, k)       ((cc)->vtbl->initKey((cc)->cipherData, k))
#define CallEncrypt(cc, in, out) ((cc)->vtbl->encrypt((cc)->cipherData, in, out))
#define CallDecrypt(cc, in, out) ((cc)->vtbl->decrypt((cc)->cipherData, in, out))
#define CallWash(cc, buf, len) 	 ((cc)->vtbl->wash((cc)->cipherData, buf, len))
#define CallRollback(cc, len) 	 ((cc)->vtbl->rollback((cc)->cipherData, len))

PGPBoolean pgpSymmetricCipherIsValid( const PGPSymmetricCipherContext * ref)
{
	PGPBoolean	valid	= FALSE;
	
	valid	= IsntNull( ref ) && ref->magic	 == kSymmetricContextMagic;
	
	return( valid );
}
#define pgpValidateSymmetricCipher( s )		\
	PGPValidateParam( pgpSymmetricCipherIsValid( s ) )

#if PGP_DEBUG
#define AssertSymmetricContextValid( ref )	\
	pgpAssert( pgpSymmetricCipherIsValid( ref ) )
#else
#define AssertSymmetricContextValid( ref )
#endif

static PGPBoolean IsValidAlgorithm(PGPCipherAlgorithm algorithm)
{
	PGPBoolean				valid	= FALSE;
	PGPCipherVTBL const *	vtbl	= NULL;
	
	vtbl = pgpCipherGetVTBL( algorithm );
	if ( IsntNull( vtbl ) )
	{
		valid = TRUE;
	}
	
	return( valid );
}

/* FIPS140 state Setup symmetric context */
static PGPError sSymmetricCipherCreate(PGPMemoryMgrRef	memoryMgr,PGPCipherAlgorithm algorithm,PGPSymmetricCipherContextRef* outRef )
{
	PGPSymmetricCipherContextRef	ref	= NULL;
	PGPError						err	= kPGPError_OutOfMemory;
	
	ref	= (PGPSymmetricCipherContextRef)
		PGPNewData( memoryMgr, sizeof( *ref ),
				0 | kPGPMemoryMgrFlags_Clear );
	
	if ( IsntNull( ref ) )
	{
		PGPCipherVTBL const *	vtbl	= pgpCipherGetVTBL( algorithm );
		void *					cipherData;
		
		ref->vtbl	= vtbl;
			
		cipherData	= PGPNewData(memoryMgr,vtbl->context_size,0 | kPGPMemoryMgrFlags_Clear);
			
		if ( IsntNull( cipherData ) )
		{
			ref->cipherData	= cipherData;	
			ref->magic		= kSymmetricContextMagic;
			ref->memoryMgr	= memoryMgr;
			ref->keyInited	= FALSE;
			err	= kPGPError_NoErr;
		}
		else
		{
			PGPFreeData( ref );
			ref	= NULL;
			err	= kPGPError_OutOfMemory;
		}
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= ref;
	return( err );
}

PGPError PGPSDKM_PUBLIC_API PGPNewSymmetricCipherContext(PGPMemoryMgrRef	memoryMgr,PGPCipherAlgorithm	algorithm,PGPSymmetricCipherContextRef* outRef )
{
	pgpEnterPGPErrorFunction();
	return pgpNewSymmetricCipherContextInternal(memoryMgr, algorithm, outRef );
}

PGPError pgpNewSymmetricCipherContextInternal(PGPMemoryMgrRef	memoryMgr,PGPCipherAlgorithm	algorithm,PGPSymmetricCipherContextRef* outRef )
{
	PGPError		err	= kPGPError_NoErr;
	
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	PGPValidateMemoryMgr( memoryMgr );
	PGPValidateParam( IsValidAlgorithm( algorithm ) );
	
	err	= sSymmetricCipherCreate( memoryMgr, algorithm, outRef );
	
	pgpAssertErrWithPtr( err, *outRef );
	return( err );
}

/* FIPS140 statetrans  SP.PGPFreeSymmetricCipherContext.1 */
PGPError PGPSDKM_PUBLIC_API PGPFreeSymmetricCipherContext(PGPSymmetricCipherContextRef ref)
{
	PGPError		err	= kPGPError_NoErr;
	PGPMemoryMgrRef	memoryMgr;
	
	/* FIPS140 statetrans  PGPFreeSymmetricCipherContext.1 */
	pgpValidateSymmetricCipher( ref );
	
	pgpEnterPGPErrorFunction();

	memoryMgr = ref->memoryMgr;
	
	/* FIPS140 statetrans  PGPFreeSymmetricCipherContext.3 */
	PGPWipeSymmetricCipher( ref );
	PGPFreeData( ref->cipherData );
	
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}

/* FIPS140 statetrans  SP.PGPCopySymmetricCipherContext.1 */
PGPError PGPCopySymmetricCipherContext(PGPSymmetricCipherContextRef ref,PGPSymmetricCipherContextRef* outRef )
{
	PGPError						err	= kPGPError_NoErr;
	PGPSymmetricCipherContextRef	newRef	= NULL;
	
	/* FIPS140 statetrans  PGPCopySymmetricCipherContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	pgpValidateSymmetricCipher( ref );
	
	pgpEnterPGPErrorFunction();

	newRef	= (PGPSymmetricCipherContextRef)PGPNewData( ref->memoryMgr,sizeof( *newRef ), 0 );
	if ( IsntNull( newRef ) )
	{
		/* FIPS140 statetrans  PGPCopySymmetricCipherContext.3 */
		void *		newData;
		PGPSize		dataSize	= ref->vtbl->context_size;
		
		*newRef	= *ref;
		
		newData	= PGPNewData( ref->memoryMgr,dataSize, 0 );
		if ( IsntNull( newData ) )
		{
			pgpCopyMemory( ref->cipherData, newData, dataSize );
			newRef->cipherData	= newData;
		}
		else
		{
			PGPFreeData( newRef );
			err	= kPGPError_OutOfMemory;
		}
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= newRef;
	pgpAssertErrWithPtr( err, *outRef );
	return( err );
}

/* FIPS140 statetrans SP.PGPInitSymmetricCipher.1 */
PGPError PGPInitSymmetricCipher(PGPSymmetricCipherContextRef ref,const void*	key )
{
	PGPError	err	= kPGPError_NoErr;
	
	/* FIPS140 statetrans PGPInitSymmetricCipher.1 */
	pgpValidateSymmetricCipher( ref );
	PGPValidatePtr( key );
	
	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPInitSymmetricCipher.3 */
	CallInitKey( ref, key );
	ref->keyInited	= TRUE;
	
	return( err );
}

/* FIPS140 statetrans SP.PGPWipeSymmetricCipher.1 */
PGPError  PGPWipeSymmetricCipher( PGPSymmetricCipherContextRef ref )
{
	PGPError	err	= kPGPError_NoErr;
	
	/* FIPS140 statetrans PGPWipeSymmetricCipher.1 */
	pgpValidateSymmetricCipher( ref );
	
	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPWipeSymmetricCipher.3 */
	pgpClearMemory( ref->cipherData, ref->vtbl->context_size);
	ref->keyInited	= FALSE;
	
	return( err );
}

/* FIPS140 statetrans SP.PGPWashSymmetricCipher.1 */
PGPError PGPWashSymmetricCipher(PGPSymmetricCipherContextRef ref,void const* buf,PGPSize len)
{
	PGPError	err	= kPGPError_NoErr;
	
	/* FIPS140 statetrans PGPWashSymmetricCipher.1 */
	pgpValidateSymmetricCipher( ref );
	PGPValidatePtr( buf );
	
	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPWashSymmetricCipher.3 */
	CallWash( ref, buf, len );
	ref->keyInited = TRUE;
	
	return( err );
}

PGPError pgpSymmetricCipherEncryptInternal(PGPSymmetricCipherContextRef ref,const void* in,void* out )
{
	PGPError	err	= kPGPError_NoErr;
	
	if ( ref->keyInited )
	{
/* FIPS140 statetrans PGPSymmetricCipherEncrypt.3 */
		CallEncrypt( ref, in, out );
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	
	return( err );
}

/* FIPS140 statetrans SP.PGPSymmetricCipherEncrypt.1 */
PGPError PGPSymmetricCipherEncrypt(PGPSymmetricCipherContextRef ref,const void*	in,void* out )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPSymmetricCipherEncrypt.1 */
	pgpValidateSymmetricCipher( ref );
	PGPValidatePtr( in );
	PGPValidatePtr( out );

	pgpEnterPGPErrorFunction();

#if PGP_ENCRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	err = pgpSymmetricCipherEncryptInternal( ref, in, out );
#endif
	
	return( err );
}
					
PGPError pgpSymmetricCipherDecryptInternal(PGPSymmetricCipherContextRef ref,const void*	in,void* out )
{
	PGPError	err	= kPGPError_NoErr;
	
	if ( ref->keyInited )
	{
/* FIPS140 statetrans PGPSymmetricCipherDecrypt.3 */
		CallDecrypt( ref, in, out );
	}
	else
	{
		err	= kPGPError_ImproperInitialization;
	}
	
	return( err );
}

/* FIPS140 statetrans SP.PGPSymmetricCipherDecrypt.1 */
PGPError PGPSymmetricCipherDecrypt(PGPSymmetricCipherContextRef ref,const void*	in,void* out )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPSymmetricCipherDecrypt.1 */
	pgpValidateSymmetricCipher( ref );
	PGPValidatePtr( in );
	PGPValidatePtr( out );

	pgpEnterPGPErrorFunction();

#if PGP_DECRYPT_DISABLE
	err = kPGPError_FeatureNotAvailable;
#else
	err = pgpSymmetricCipherDecryptInternal( ref, in, out );
#endif
	
	return( err );
}

/* FIPS140 statetrans SP.PGPGetSymmetricCipherSizes.1 */
PGPError PGPSDKM_PUBLIC_API PGPGetSymmetricCipherSizes(PGPSymmetricCipherContextRef ref,PGPSize* keySizePtr,PGPSize* blockSizePtr )
{
	PGPError	err	= kPGPError_NoErr;
	PGPSize		blockSize	= 0;
	PGPSize		keySize		= 0;
	
	if ( IsntNull( keySizePtr ) )
		*keySizePtr	= 0;
	if ( IsntNull( blockSizePtr ) )
		*blockSizePtr	= 0;
		
	/* FIPS140 statetrans PGPGetSymmetricCipherSizes.1 */
	pgpValidateSymmetricCipher( ref );
	PGPValidateParam( IsntNull( blockSizePtr ) || IsntNull( keySizePtr ) );

	pgpEnterPGPErrorFunction();

	/* FIPS140 statetrans PGPGetSymmetricCipherSizes.3 */
	blockSize	= ref->vtbl->blocksize;
	keySize		= ref->vtbl->keysize;
		
	if ( IsntNull( blockSizePtr ) )
	{
		pgpAssertAddrValid( blockSizePtr, PGPUInt32 );
		*blockSizePtr	= blockSize;
	}
	
	if ( IsntNull( keySizePtr ) )
	{
		pgpAssertAddrValid( keySizePtr, PGPUInt32 );
		*keySizePtr	= keySize;
	}
	
	return( err );
}

PGPError PGPSymmetricCipherRollback(PGPSymmetricCipherContextRef ref,PGPSize lastBlockSize )
{
	pgpValidateSymmetricCipher( ref );

	pgpEnterPGPErrorFunction();

	/* Defined only for stream ciphers */
	if( ref->vtbl->algorithm != kPGPCipherAlgorithm_Arc4_128 ) 
			return kPGPError_BadCipherNumber;

//	if( lastBlockSize!=0xffffffff && lastBlockSize > ref->vtbl->blocksize )
//		return kPGPError_BadParams;

	/* Commit routine is normally undefined, so check it here */
	pgpAssert( ref->vtbl->rollback != NULL );

	CallRollback( ref, lastBlockSize );

	return kPGPError_NoErr;
}

PGPMemoryMgrRef pgpGetSymmetricCipherMemoryMgr(PGPSymmetricCipherContextRef	ref)
{
	AssertSymmetricContextValid( ref );
	
	return( ref->memoryMgr );
}

extern PGPCipherVTBL const cipherTwofish256, cipherBadTwofish256;

static PGPCipherVTBL const * const sCipherList[] =
{
	&cipher3DES,
#if PGP_AES
	&cipherAES128,
	&cipherAES192,
	&cipherAES256,
#endif
};
#define kNumCiphers	 ( sizeof( sCipherList ) / sizeof( sCipherList[ 0 ] ) )

#if PGP_PLUGGABLECIPHERS
static PGPCipherVTBL * sPluggableCipherList;
static PGPUInt32 sNumPluggableCiphers;
#endif


PGPUInt32 pgpCountSymmetricCiphers( void )
{
	PGPUInt32 numCiphers = kNumCiphers;
#if PGP_PLUGGABLECIPHERS
	numCiphers += sNumPluggableCiphers;
#endif
	return( numCiphers );
}


PGPCipherVTBL const *pgpCipherGetVTBL (PGPCipherAlgorithm	algorithm)
{
	const PGPCipherVTBL *	vtbl	= NULL;
	PGPUInt32				algIndex;
	
	for( algIndex = 0; algIndex < kNumCiphers; ++algIndex )
	{
		if ( sCipherList[ algIndex ]->algorithm == algorithm )
		{
			vtbl	= sCipherList[ algIndex ];
			break;
		}
	}

#if PGP_PLUGGABLECIPHERS
	if( IsNull( vtbl ) )
	{
		for( algIndex = 0; algIndex < sNumPluggableCiphers; ++algIndex )
		{
			if ( sPluggableCipherList[ algIndex ].algorithm == algorithm )
			{
				vtbl	= sPluggableCipherList + algIndex;
				break;
			}
		}
	}
#endif
	
	return vtbl;
}
/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
