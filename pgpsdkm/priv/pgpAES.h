/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

	header file for pgpAES.c
	
	 This is a PRIVATE header file, for use only within the PGP Library.
	 You should not be using these functions in an application.
	
        $Id: pgpAES.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/
#ifndef Included_pgpAES_h
#define Included_pgpAES_h


#include "pgpSDKBuildFlags.h"

#ifndef PGP_AES
#error you must define PGP_AES one way or the other
#endif


#if PGP_AES	/* [ */


#include "pgpSymmetricCipherPriv.h"		/* for Cipher */

PGP_BEGIN_C_DECLARATIONS

/*
 * This is the definition of the AES cipher, for use with the
 * PGP Generic Cipher code.
 */
extern PGPCipherVTBL const cipherAES128;
extern PGPCipherVTBL const cipherAES192;
extern PGPCipherVTBL const cipherAES256;

PGP_END_C_DECLARATIONS

#endif /* ] PGP_AES */

#endif /* !Included_pgpAES_h */
