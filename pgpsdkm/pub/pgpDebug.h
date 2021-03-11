/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpDebug.h 59461 2007-12-21 00:43:52Z dmurphy $
____________________________________________________________________________*/

#ifndef Included_pgpDebug_h	/* [ */
#define Included_pgpDebug_h

#if ! PGP_UNIX_DARWIN
#include <stdlib.h>
#endif
#include <stdarg.h>
#include <string.h>

#ifndef PGP_WIN32
#define PGP_WIN32 0
#endif

#if PGP_WIN32 && !defined(PGP_EFI)
#if _MSC_VER > 1200
#include <crtdbg.h>
#else 
#include <windows.h>
#endif
#endif

#if ! PGP_UNIX_DARWIN
#include <assert.h>
#endif

#include "pgpTypes.h"

PGP_BEGIN_C_DECLARATIONS

#if PGP_DEBUG==1  
#if PGP_WIN32==1 && (_MSC_VER > 1200)/* ] [ */

#define pgpDebugMsg(message)										\
		{															\
			if (_CrtDbgReport(_CRT_ASSERT, NULL, 0, NULL,			\
										PGPTXT_DEBUG8("\r\n%s"),	\
											(message))==1)			\
				_CrtDbgBreak();										\
    	}

#else	/* ] [ */
#define pgpDebugMsg(s)  printf(s)
#endif
#else
#define pgpDebugMsg(s)
#endif

/*
 * Convenient short-hands follow
 */

#if 0 && PGP_DEBUG /* Have to disable this since there is no printf in driver, need cross platform printf call later */
	int printf(const char *format, ...);
	#define pgpAssert(condition) if (!(condition)) { printf("%s(%d): %s is not true in MiniSDK\n", \
		__FILE__, __LINE__, #condition ); }
#else
	#define pgpAssert(condition)
#endif

#define pgpAssertAddrValid(ptr, type)	pgpAssert( ptr != NULL )	/* not a full SDK version */

#define pgpAssertErrWithPtr(err, ptr) \
		pgpAssert( ( IsntPGPError( err ) && (ptr) != NULL ) || \
		( IsPGPError( err ) && (ptr) == NULL ) )
		

PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpDebug_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
