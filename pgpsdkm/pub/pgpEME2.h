/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpEME2.h 59758 2008-01-10 20:29:11Z vinnie $
____________________________________________________________________________*/

#ifndef Included_pgpEME2_h	/* [ */
#define Included_pgpEME2_h

#include "pgpSymmetricCipher.h"


PGP_BEGIN_C_DECLARATIONS

/*____________________________________________________________________________
	An EME2 context requires use of a symmetric cipher which has
	been created (but whose key has not been set).  The symmetric
	cipher must have a block size of 16 bytes.  An error will
	be returned if this condition does not hold.

	After the call, the EME2ContextRef "owns" the symmetric ref
	and will dispose of it properly (even if an error occurs).
	The caller should no longer reference it.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPNewEME2Context( PGPSymmetricCipherContextRef ref,
					PGPEME2ContextRef *outRef );

/*____________________________________________________________________________
	Disposal clears all data in memory before releasing it.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPFreeEME2Context( PGPEME2ContextRef ref );

/*____________________________________________________________________________
	Make an exact copy, including current state.  Original is not changed.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPCopyEME2Context( PGPEME2ContextRef ref, PGPEME2ContextRef *outRef );

/*____________________________________________________________________________
	Key the EME2 context.  Key size is that of underlying symmetric cipher.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPInitEME2( PGPEME2ContextRef ref, const void *key );

/*____________________________________________________________________________
	Call repeatedly to process arbitrary amounts of data.  Each call must
	have bytesIn be a multiple of the cipher block size.  offset is the
	offset in 512-byte blocks from the front of the file.  nonce is a per-file
	constant which should be unique among all files that are encrypted with
	the samem key.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPEME2Encrypt( PGPEME2ContextRef ref, const void *in,
					PGPSize bytesIn, void *out, PGPUInt64 offset,
					PGPUInt64 nonce );
					
PGPError 	PGPSDKM_PUBLIC_API PGPEME2Decrypt( PGPEME2ContextRef ref, const void *in,
					PGPSize bytesIn, void *out, PGPUInt64 offset,
					PGPUInt64 nonce );

/*____________________________________________________________________________
	Determine key and block size for EME2 mode.  Block size is fixed and
	is independent of cipher block size.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPEME2GetSizes( PGPEME2ContextRef ref,
					PGPSize *keySize, PGPSize *blockSize );

/*____________________________________________________________________________
	Get the symmetric cipher being used for this EME2 context.
____________________________________________________________________________*/

PGPError 	PGPSDKM_PUBLIC_API PGPEME2GetSymmetricCipher( PGPEME2ContextRef ref,
					PGPSymmetricCipherContextRef *outRef );

PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpEME2_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
