/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

        $Id: pgpEME2Priv.h 59758 2008-01-10 20:29:11Z vinnie $
____________________________________________________________________________*/

#ifndef Included_pgpEME2Priv_h	/* [ */
#define Included_pgpEME2Priv_h

#include "pgpOpaqueStructs.h"
#include "pgpSymmetricCipher.h"
#include "pgpEME2.h"


PGP_BEGIN_C_DECLARATIONS


#define PGP_EME2_BLOCKSIZE		512
#define PGP_EME2_CIPHER_BLOCKSIZE 16
#define PGP_EME2_RESETBLOCKS		128

#define PGP_EME2_BLOCKWORDS  (PGP_EME2_BLOCKSIZE/sizeof(PGPUInt32))
#define PGP_EME2_CIPHER_BLOCKWORDS (PGP_EME2_CIPHER_BLOCKSIZE/sizeof(PGPUInt32))

#define PGP_EME2_CIPHERBLOCKS	(PGP_EME2_BLOCKSIZE/PGP_EME2_CIPHER_BLOCKSIZE)



/*____________________________________________________________________________
	internal glue routine follow; use is discouraged
____________________________________________________________________________*/

PGPError 	pgpEME2DecryptInternal(PGPEME2ContextRef ref, const void *in,
					PGPSize bytesIn, void *	out, PGPUInt64 offset,
					PGPUInt64 nonce );
PGPError 	pgpEME2EncryptInternal(PGPEME2ContextRef ref, const void *in,
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
