/*____________________________________________________________________________
	Copyright (C) 2004 PGP Corporation
	All rights reserved.

	Mini SDK - specific functions
	
	$Id: pgpMiniUtil.h 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpMiniUtil_h	/* [ */
#define Included_pgpMiniUtil_h

#include "pgpPubTypes.h"
#include "pgpMemoryMgr.h"

#if !PGP_WIN32
#define __cdecl
#endif

PGP_BEGIN_C_DECLARATIONS

/* CRC32 doesn't comply with the above API because it is critical to maintain
   its efficiency; for example, we assume that its result fits into an integer. 
*/
#define WDE_CRC_INIT( crc ) (crc^=0xffffffff);
PGPUInt32	__cdecl pgpCRC32( PGPUInt32 crc32, const PGPByte *in, int size );
#define WDE_CRC_FINALIZE( crc ) (crc^=0xffffffff);
PGPUInt32	__cdecl pgpCRC32Buffer( const PGPByte *in, int size );

PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpMiniUtil_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
