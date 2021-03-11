/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

        $Id: pgpCFBPriv.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpCFBPriv_h	/* [ */
#define Included_pgpCFBPriv_h

#include "pgpOpaqueStructs.h"
#include "pgpSymmetricCipher.h"
#include "pgpCFB.h"
#include "pgpMemoryMgr.h"


PGP_BEGIN_C_DECLARATIONS


#define PGP_CFB_MAXBLOCKSIZE 20



/* Clear a PGPCFBContext of its sensitive data */
void 		pgpCFBWipe( PGPCFBContextRef ref );

PGPError 	pgpCFBDecryptInternal(PGPCFBContextRef ref, const void *in,
					PGPSize bytesIn, void *out);
PGPError 	pgpCFBEncryptInternal(PGPCFBContextRef ref, const void *in,
					PGPSize bytesIn, void *out);

/*____________________________________________________________________________
	internal glue routine follow; use is discouraged
____________________________________________________________________________*/

PGPSize		pgpCFBGetKeySize( PGPCFBContextRef ref );
PGPSize		pgpCFBGetBlockSize( PGPCFBContextRef ref );

/* Allocate a new PGPCFBContext structure */
PGPCFBContextRef		pgpCFBCreate( PGPMemoryMgrRef memoryMgr,
									PGPCipherVTBL const *c );



PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpCFBPriv_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
