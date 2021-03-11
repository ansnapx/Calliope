/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

        $Id: pgpEMEPriv.h 38419 2005-09-21 22:03:47Z hal $
____________________________________________________________________________*/

#ifndef Included_pgpEMEPriv_h	/* [ */
#define Included_pgpEMEPriv_h

#include "pgpOpaqueStructs.h"
#include "pgpSymmetricCipher.h"
#include "pgpEME.h"


PGP_BEGIN_C_DECLARATIONS


#define PGP_EME_BLOCKSIZE		512
#define PGP_EME_CIPHER_BLOCKSIZE 16

#define PGP_EME_BLOCKWORDS  (PGP_EME_BLOCKSIZE/sizeof(PGPUInt32))
#define PGP_EME_CIPHER_BLOCKWORDS (PGP_EME_CIPHER_BLOCKSIZE/sizeof(PGPUInt32))

#define PGP_EME_CIPHERBLOCKS	(PGP_EME_BLOCKSIZE/PGP_EME_CIPHER_BLOCKSIZE)



/*____________________________________________________________________________
	internal glue routine follow; use is discouraged
____________________________________________________________________________*/

PGPError 	pgpEMEDecryptInternal(PGPEMEContextRef ref, const void *in,
					PGPSize bytesIn, void *	out, PGPUInt64 offset,
					PGPUInt64 nonce );
PGPError 	pgpEMEEncryptInternal(PGPEMEContextRef ref, const void *in,
					PGPSize bytesIn, void *	out, PGPUInt64 offset,
					PGPUInt64 nonce );

PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpEMEPriv_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
