/*____________________________________________________________________________
        Copyright (C) 2002 PGP Corporation
        All rights reserved.

	The SHA-256 Message Digest.
	
	 This is a PRIVATE header file, for use only within the PGP Library.
	 You should not be using these functions in an application.
	
        $Id: pgpSHA2.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpSHA256_h
#define Included_pgpSHA256_h

#include "pgpHashPriv.h"
#include "pgpMem.h"

PGP_BEGIN_C_DECLARATIONS

extern PGPHashVTBL const HashSHA256;
extern PGPHashVTBL const HashSHA384;
extern PGPHashVTBL const HashSHA512;

/* Set of big endian platforms */
#if PGP_WORDSBIGENDIAN
#define SHA256_BIG_ENDIAN 1
#define SHA512_BIG_ENDIAN 1
#endif

PGP_END_C_DECLARATIONS

#endif /* !Included_pgpSHA256_h */
