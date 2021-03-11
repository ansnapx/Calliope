/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpTypes.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpTypes_h	/* [ */
#define Included_pgpTypes_h

#include <sys/types.h>

#include "pgpBase.h"

/* Lookie here!  An ANSI-compliant alignment finder! */
#ifndef	alignof

#ifdef __cplusplus
#define	alignof(type) (1)
#else
#define	alignof(type) (sizeof(struct{type _x; PGPByte _y;}) - sizeof(type))
#endif

#if PGP_WIN32==1
#ifndef __MWERKS__
/* Causes "unnamed type definition in parentheses" warning" */
#pragma warning ( disable : 4116 )
#endif
#endif

#endif

#endif /* ] Included_pgpTypes_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
