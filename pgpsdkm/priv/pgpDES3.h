/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

	headers for TripleDES
	
		By Richard Outerbridge
	
	 This is a PRIVATE header file, for use only within the PGP Library.
	 You should not be using these functions in an application.
	
        $Id: pgpDES3.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpDES3_h
#define Included_pgpDES3_h

#include "pgpSymmetricCipherPriv.h"

PGP_BEGIN_C_DECLARATIONS

/* This is the definition of the 3DES cipher, for use with the PGP
 * Generic Cipher code.
 */
extern PGPCipherVTBL const cipher3DES;

PGP_END_C_DECLARATIONS

#endif /* Included_pgpDES3_h */
