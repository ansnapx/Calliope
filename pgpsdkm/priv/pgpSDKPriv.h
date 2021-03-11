/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpSDKPriv.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpSDKPriv_h	/* [ */
#define Included_pgpSDKPriv_h

#include "pgpSDKBuildFlags.h"
#include "pgpPubTypes.h"

// few FIPS redefinitions
#define pgpFIPSModeEnabled() 0
#define pgpSetSDKErrorState( err ) 


/*____________________________________________________________________________
	Dependencies
____________________________________________________________________________*/

#if !( defined(PGP_MACINTOSH) || defined(PGP_UNIX) || defined(PGP_WIN32) )
#error one of {PGP_MACINTOSH, PGP_UNIX, PGP_WIN32} must be defined
#endif

#if PGP_RSA	/* [ */

	#if ! PGP_IDEA
	#error PGP_RSA requires PGP_IDEA
	#endif

	#if (PGP_USECAPIFORRSA + PGP_USEBSAFEFORRSA + PGP_USERSAREF + \
			PGP_USEPGPFORRSA) != 1
	#error Must enable exactly one RSA implementation option
	#endif

	#if PGP_USECAPIFORRSA && (PGP_MACINTOSH || PGP_UNIX)
	#error Cannot enable CAPI RSA implementation on this platform
	#endif
	
#else	/* ] PGP_RSA [ */

	#if PGP_RSA_KEYGEN
	#error Cannot enable PGP_RSA_KEYGEN without PGP_RSA
	#endif

	#if (PGP_USECAPIFORRSA + PGP_USEBSAFEFORRSA + PGP_USERSAREF + \
			PGP_USEPGPFORRSA) != 0
	#error Cannot enable any RSA implementation options without PGP_RSA
	#endif

#endif	/* ] PGP_RSA */

#if PGP_USECAPIFORMD2 && ! PGP_USECAPIFORRSA
#error Cannot use CAPI MD2 without CAPI RSA
#endif

#ifndef PGPSDK_FRONTEND
#define PGPSDK_FRONTEND		1
#define PGPSDK_BACKEND		0
#endif

/*____________________________________________________________________________
	Function profiling (needed for FIPS)
____________________________________________________________________________*/

#define kProfileArgs	__FILE__, (PGPUInt32) __LINE__

PGPError pgpEnterFunction(const char *fileName, PGPUInt32 lineNumber);

#define pgpEnterPGPErrorFunction()

#define pgpEnterZeroFunction()

#define pgpEnterVoidFunction()

#define pgpEnterBooleanFunction(result)

#define pgpEnterOptionListFunction()

#endif /* ] Included_pgpSDKPriv_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
