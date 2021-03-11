/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pHash.c 68697 2008-10-27 22:11:03Z ajivsov $
____________________________________________________________________________*/
#include "pgpConfig.h"
#include "pgpSDKPriv.h"
#include "pgpErrors.h"
#include "pgpMem.h"
#include "pgpPFLPriv.h"

#include "pgpSHA.h"
#include "pgpSHA2.h"

#include "pgpHash.h"
#include "pgpHashPriv.h"
#include "pgpSHA.h"
#include "pgpMemoryMgr.h"


struct PGPHashContext
{
#define kHashContextMagic		0xABBADABA
	PGPUInt32			magic;
	PGPHashVTBL const *	vtbl;
	PGPMemoryMgrRef		memoryMgr;
	void *				hashData;
};

struct PGPHashList
{
	PGPUInt32		numHashes;
	PGPMemoryMgrRef	memoryMgr;
	PGPHashContext	hashes[ 1 ];	/* open ended */
};

static void	sDisposeHashData( PGPHashContextRef	ref );


#define CallInit(hc)	(hc)->vtbl->init((hc)->hashData)
#define CallUpdate(hc, buf, len) (hc)->vtbl->update((hc)->hashData, buf, len)
#define CallFinal(hc) (hc)->vtbl->final((hc)->hashData)


	static PGPBoolean
pgpHashContextIsValid( const PGPHashContext * ref)
{
	return( IsntNull( ref ) &&
			IsntNull( ref->hashData ) &&
			ref->magic == kHashContextMagic  );
}


#define pgpValidateHash( ref )		\
	PGPValidateParam( pgpHashContextIsValid( ref ) )
	
#define IsValidAlgorithm( alg )		\
	IsntNull( pgpHashByNumber( alg ) )


/* FIPS140 state Initialize hash context */
	static PGPError
sHashInit(
	PGPHashContextRef		ref,
	PGPMemoryMgrRef			memoryMgr,
	PGPHashVTBL const *		hashEntry )
{
	PGPError				err	= kPGPError_NoErr;
	
    /* FIPS140 statetrans InitHashContext.1 */
	pgpClearMemory( ref, sizeof( *ref ) );
	ref->magic		= kHashContextMagic;
	ref->memoryMgr	= memoryMgr;
    /* FIPS140 statetrans InitHashContext.3 */
	ref->vtbl		= hashEntry;
	pgpAssert( IsntNull( hashEntry ) );
	
    /* FIPS140 statetrans InitHashContext.5 */
	ref->hashData	= PGPNewData( memoryMgr,
		hashEntry->context_size, 0);
	if ( IsntNull( ref->hashData ) )
	{
       /* FIPS140 statetrans InitHashContext.7 */
		CallInit( ref );
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	return( err );
}

static PGPError sHashCreate(PGPMemoryMgrRef	memoryMgr,const PGPHashVTBL* hashEntry,PGPHashContextRef* outRef )
{
	PGPHashContextRef		ref	= NULL;
	PGPError				err	= kPGPError_NoErr;
	
	*outRef	= NULL;
	
	ref	= (PGPHashContextRef)
		PGPNewData( memoryMgr, sizeof( *ref ),
			0 | kPGPMemoryMgrFlags_Clear );
	
	if ( IsntNull( ref ) )
	{
        /* FIPS140 statetrans PGPNewHashContext.3 */
        /* FIPS140 statetrans PGPCopyHashContext.3 */
		err	= sHashInit( ref, memoryMgr, hashEntry );
		
		if ( IsPGPError( err ) )
		{
			PGPFreeData( ref );
			ref	= NULL;
		}
	}
	else
	{
		err	= kPGPError_OutOfMemory;
	}
	
	*outRef	= ref;
	return( err );
}


PGPError pgpNewHashContext(PGPMemoryMgrRef	memoryMgr,PGPHashAlgorithm algorithm,PGPHashContextRef* outRef )
{
	PGPError		err			= kPGPError_NoErr;
	
   /* FIPS140 statetrans PGPNewHashContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	
	PGPValidateParam( IsValidAlgorithm( algorithm ) );	
	pgpEnterPGPErrorFunction();

	err = PGPValidateMemoryMgr( memoryMgr );
	if( IsntPGPError( err ) )
	{
		const PGPHashVTBL *hashEntry = pgpHashByNumber( algorithm );
		if( hashEntry==NULL )
			return kPGPError_BadHashNumber;

		err	= sHashCreate( memoryMgr, hashEntry, outRef );
	}
	
	return( err );
}



/* FIPS140 statetrans SP.PGPFreeHashContext.1 */
PGPError PGPFreeHashContext( PGPHashContextRef ref )
{
	PGPError		err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPFreeHashContext.1 */
	pgpValidateHash( ref );
	
	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans PGPFreeHashContext.3 */
	sDisposeHashData(ref);
/* FIPS140 statetrans PGPFreeHashContext.5 */
	pgpClearMemory( ref, sizeof( *ref ) );
	PGPFreeData( ref );
	
	return( err );
}


/* FIPS140 statetrans SP.PGPCopyHashContext.1 */
	PGPError 
PGPCopyHashContext(
	PGPHashContextRef	ref,
	PGPHashContextRef *	outRef)
{
	PGPError			err	= kPGPError_NoErr;
	PGPHashContextRef	newRef	= NULL;
	
/* FIPS140 statetrans SP.PGPCopyHashContext.1 */
	PGPValidatePtr( outRef );
	*outRef	= NULL;
	pgpValidateHash( ref );
	
	pgpEnterPGPErrorFunction();

	err	= sHashCreate( ref->memoryMgr, ref->vtbl, &newRef );
	if ( IsntPGPError( err ) )
	{
      /* FIPS140 statetrans PGPCopyHashContext.5 */
		pgpCopyMemory( ref->hashData,
			newRef->hashData, ref->vtbl->context_size );
		
	}
	
	*outRef	= newRef;
	return( err );
}



/* FIPS140 statetrans SP.PGPResetHash.1 */
	PGPError 
PGPResetHash( PGPHashContextRef ref )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPResetHash.1 */
	pgpValidateHash( ref );
	
	pgpEnterPGPErrorFunction();

/* FIPS140 statetrans PGPResetHash.3 */
	CallInit( ref );
	
	return( err );
}


/* FIPS140 statetrans SP.PGPContinueHash.1 */
	PGPError 
PGPContinueHash(
	PGPHashContextRef	ref,
	const void *		in,
	PGPSize			numBytes )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPContinueHash.1 */
	pgpValidateHash( ref );
	PGPValidatePtr( in );

	pgpEnterPGPErrorFunction();

	if ( numBytes != 0 )
	{
/* FIPS140 statetrans PGPContinueHash.3 */
		CallUpdate( ref, in, numBytes );
	}
	
	return( err );
}


/* FIPS140 statetrans SP.PGPFinalizeHash.1 */
	PGPError 
PGPFinalizeHash(
	PGPHashContextRef	ref,
	void *				hashOut )
{
	PGPError		err	= kPGPError_NoErr;
	const void *	result;
	PGPSize			hashSize;
	
/* FIPS140 statetrans PGPFinalizeHash.1 */
	pgpValidateHash( ref );
	PGPValidatePtr( hashOut );
	
	(void)PGPGetHashSize( ref, &hashSize);
	
/* FIPS140 statetrans PGPFinalizeHash.3 */
	result	= CallFinal( ref );
	pgpCopyMemory( result, hashOut, hashSize );
	
	return( err );
}


/* FIPS140 statetrans SP.PGPGetHashSize.1 */
	PGPError 
PGPGetHashSize(
	PGPHashContextRef	ref,
	PGPSize *			hashSize )
{
	PGPError	err	= kPGPError_NoErr;
	
/* FIPS140 statetrans PGPGetHashSize.1 */
	PGPValidatePtr( hashSize );
	*hashSize	= 0;

	pgpEnterPGPErrorFunction();

	pgpValidateHash( ref );
	
/* FIPS140 statetrans PGPGetHashSize.3 */
	*hashSize	= ref->vtbl->hashsize;
	
	return( err );
}

	
	PGPHashContextRef
pgpHashCreate(
	PGPMemoryMgrRef		memoryMgr,
	PGPHashVTBL const *	vtbl)
{
	PGPError			err	= kPGPError_NoErr;
	PGPHashContextRef	newRef;
	
	pgpAssert( PGPMemoryMgrIsValid( memoryMgr ) );

	if( vtbl==NULL )
		return NULL;
	
	err	= sHashCreate( memoryMgr, vtbl, &newRef );

	pgpAssert( ( IsntPGPError( err ) && IsntNull( newRef ) ) ||
		( IsPGPError( err ) && IsNull( newRef ) ) );
	
	return( newRef );
}




	static void
sDisposeHashData (PGPHashContextRef	ref)
{
	if ( pgpHashContextIsValid( ref ) )
	{
		pgpClearMemory (ref->hashData, ref->vtbl->context_size);
		PGPFreeData( ref->hashData );
		ref->hashData	= NULL;
	}
}


	void const *
pgpHashFinal( PGPHashContextRef ref )
{
	pgpAssert( pgpHashContextIsValid( ref ) );
	
	return( CallFinal( ref ) );
}


	PGPHashContextRef
pgpHashCopy(const PGPHashContext *ref)
{
	PGPHashContextRef	newRef;

	pgpAssert( pgpHashContextIsValid( ref ) );
	
	(void)PGPCopyHashContext( (PGPHashContextRef)ref, &newRef );
	
	return newRef;
}

	void
pgpHashCopyData(
	PGPHashContext  *	src,
	PGPHashContext *	dest )
{
	pgpAssert( pgpHashContextIsValid( src ) );
	pgpAssert(dest->vtbl == src->vtbl);
	
	pgpCopyMemory( src->hashData, dest->hashData, src->vtbl->context_size);
}

	PGPError 
pgpGetHashMessageSize(
	PGPHashContextRef	ref,
	PGPSize *			msgBlockSize )
{
	PGPError err	= kPGPError_NoErr;
	
	PGPValidatePtr( msgBlockSize );
	*msgBlockSize = 0;

	pgpValidateHash( ref );
	
	*msgBlockSize = ref->vtbl->blocksize;
	
	return( err );
}

	static void
shaInit(void *priv)
{
	pgpSHAInit( priv );
}

	static void
shaUpdate(void *priv, void const *buf, PGPSize len)
{
	pgpSHAUpdate( priv, buf, len );
}

	static const void *
shaFinal(void *priv)
{
	return( pgpSHAFinalize( priv ) );
}

PGPHashVTBL const HashSHA = {
	PGPTXT_MACHINE("SHA1"), kPGPHashAlgorithm_SHA,
	SHADERprefix, sizeof(SHADERprefix),
	PGP_SHA_HASHBYTES,
	PGP_SHA_BLOCKBYTES, 
	sizeof(PGPSHAContext),
	sizeof(struct{char _a; PGPSHAContext _b;}) -
		sizeof(PGPSHAContext),
	shaInit, shaUpdate, shaFinal
};

/* Access to all known hashes */
/* The order of the entries in this table is not significant */
static PGPHashVTBL const * const sHashList[]  =
{
	&HashSHA,
	&HashSHA256,
	&HashSHA384,
	&HashSHA512,
};
#define kNumHashes	 ( sizeof( sHashList ) / sizeof( sHashList[ 0 ] ) )

/*
 * Returns the hash that is allowed for the given mask 
 */
	PGPHashVTBL const *
pgpHashByNumberWithMask (PGPHashAlgorithm algorithm, PGPUInt32 algorithmMask)
{
	const PGPHashVTBL *	vtbl	= NULL;
	PGPUInt32			algIndex;
	PGPHashAlgorithm 	currAlg;
	
	for( algIndex = 0; algIndex < kNumHashes; ++algIndex )
	{
		currAlg = sHashList[ algIndex ]->algorithm;
		if ( (currAlg == algorithm) && ((PGPHashAlgorithm)(currAlg & algorithmMask) == currAlg) )
		{
			vtbl	= sHashList[ algIndex ];
			break;
		}
	}
	
	return vtbl;
}

/*
 * Return the hash that is allowed outside of SDK
 */
	PGPHashVTBL const *
pgpHashByNumber (PGPHashAlgorithm algorithm)
{
	return pgpHashByNumberWithMask( algorithm, 0xff );
}

/*
 * Given a hash name, return the corresponding hash that is allowed for the given mask
 */
	PGPHashVTBL const *
pgpHashByNameWithMask (char const *name, size_t namelen, PGPUInt32 algorithmMask)
{
	PGPUInt32	algIndex;

	for( algIndex = 0; algIndex < kNumHashes; ++algIndex )
	{
		PGPHashVTBL const *vtbl;
	
		vtbl = sHashList[ algIndex ];

		if( (PGPHashAlgorithm)(vtbl->algorithm & algorithmMask) != vtbl->algorithm )
			continue;
		
		if ( pgpMemoryEqual (name, vtbl->name, namelen*sizeof(PGPChar)) && 
		    vtbl->name[ namelen ] == '\0')
		{
			return vtbl;
		}
	}
	return NULL;	/* Not found */
}

/*
 * Given a hash name, return the corresponding hash that is allowed outside of SDK
 */
	PGPHashVTBL const *
pgpHashByName (char const *name, size_t namelen)  {
	return pgpHashByNameWithMask( name, namelen, 0xff );
}


	PGPHashVTBL const  *
pgpHashGetVTBL( const PGPHashContext *ref )
{
	pgpAssert( pgpHashContextIsValid( ref ) );
	
	return( ref->vtbl );
}

/*____________________________________________________________________________
	Given a list of hash identifiers, create a list of hash contexts.
	Ignores unknown algorithms.  Returns the number of PgpHashContexts
	created and stored in the "hashes" buffer, or an Error (and none created)
	on error.
	
	Note that the formal data type returned is an opaque 'PGPHashListRef',
	although the actual format of the list is just an array of PGPHashContext.
	The formal data type is used to preserve opacity of the PGPHashContext.
____________________________________________________________________________*/
	PGPError
pgpHashListCreate (
	PGPMemoryMgrRef		memoryMgr,
	void const *		bufParam,
	PGPHashListRef *	hashListPtr,
	PGPUInt32			numHashes )
{
	PGPInt32				numHashesCreated;
	PGPHashListRef			hashList;
	PGPError				err	= kPGPError_NoErr;
	PGPSize				listSize;
	const PGPByte *			buf;
	
	PGPValidatePtr( hashListPtr );
	*hashListPtr = NULL;
	PGPValidatePtr( bufParam );
	PGPValidateParam( numHashes != 0 );
	PGPValidateMemoryMgr( memoryMgr );

	buf 		= (const PGPByte *) bufParam;
	listSize	= sizeof( *hashList ) +
		( (PGPSize)numHashes -1 )  * sizeof( hashList->hashes[ 0 ] );
		
	hashList	= (PGPHashListRef)
		PGPNewData( memoryMgr, listSize,
		0 | kPGPMemoryMgrFlags_Clear );
	
	if ( IsNull( hashList ) )
		return( kPGPError_OutOfMemory );
		
	pgpClearMemory( hashList, listSize );
	hashList->numHashes	= 0;
	hashList->memoryMgr	= memoryMgr;

	numHashesCreated = 0;
	while (numHashes--)
	{
		PGPHashAlgorithm		algorithm;
		PGPHashVTBL const *		vtbl;
		
		algorithm	= (PGPHashAlgorithm) ( *buf++ );
		
		vtbl	= pgpHashByNumber ( algorithm );
		if ( IsntNull( vtbl ) )
		{
			PGPHashContext *	curHash;
			
			curHash	= &hashList->hashes[ numHashesCreated ];
			
			err	= sHashInit( curHash, memoryMgr, vtbl );
			if ( IsPGPError( err ) )
			{
				while ( numHashesCreated-- )
				{
					sDisposeHashData( curHash );
				}
				
				PGPFreeData( hashList );
				*hashListPtr = NULL;
				return kPGPError_OutOfMemory;
			}
			numHashesCreated++;
		}
	}

	hashList->numHashes	= numHashesCreated;
	
	*hashListPtr = hashList;
	
	return err;
}


	void
pgpHashListDestroy ( PGPHashListRef	hashList )
{
	PGPUInt32		hashIndex;
	
	pgpAssertAddrValid( hashList, PGPHashList );
	
	hashIndex	= hashList->numHashes;
	if ( hashIndex != 0 )
	{
		while ( hashIndex--)
		{
			sDisposeHashData( &hashList->hashes[ hashIndex ] );
		}
		
		PGPFreeData( hashList );
	}
}


	PGPUInt32
pgpHashListGetSize( PGPHashListRef	list  )
{
	pgpAssertAddrValid( list, PGPHashList );
	return( list->numHashes );
}

/*____________________________________________________________________________
	pgpHashListGetIndHash() is made necessary by incestuous code that wants
	to be able to index over a struct.  Since we want to keep the structure
	of a PGPHashContext opaque, we need to provide this accessor.
____________________________________________________________________________*/

	PGPHashContext *
pgpHashListGetIndHash(
	PGPHashListRef	list,
	PGPUInt32		algIndex )
{
	pgpAssertAddrValid( list, PGPHashList );
	pgpAssert( algIndex < list->numHashes );
	
	if ( algIndex < list->numHashes )
		return( &list->hashes[ algIndex ] );
		
	return( NULL );
}


	PGPHashContext *
pgpHashListFind (
	PGPHashListRef		hashList,
	PGPHashVTBL const *	vtbl)
{
	PGPHashContext *	cur;
	PGPUInt32			remaining;
	
	pgpAssertAddrValid( hashList, PGPHashList );
	
	cur	= &hashList->hashes[ 0 ];
	remaining	= hashList->numHashes;
	while (remaining--)
	{
		if ( cur->vtbl == vtbl )
			return cur;
		cur++;
	}
	return NULL;
}






















/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
