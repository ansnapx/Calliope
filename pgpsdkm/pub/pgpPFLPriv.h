/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpPFLPriv.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpPFLPriv_h	/* [ */
#define Included_pgpPFLPriv_h

#include "pgpConfig.h"

#include "pgpDebug.h"
#include "pgpPFLErrors.h"

#define PGPValidateParam( expr )	\
	if ( ! (expr ) )	\
	{\
		pgpAssert( expr );\
		return( kPGPError_BadParams );\
	}

#define PGPValidatePtr( ptr )	\
			PGPValidateParam( (ptr) != NULL )




#endif /* ] Included_pgpPFLPriv_h */
