/*____________________________________________________________________________
	Copyright (C) 2006 PGP Corporation
	All rights reserved.

	MiniSDK flat memory manager. Thread-safe.

	$Id: pMMFlat.c 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/

//#include "pgpPFLErrors.h"
#include "pgpErrors.h"
#include "pgpMem.h"
//#include "pgpPFLPriv.h"

#include "pgpMemoryMgr.h"
#include "pgpMallocFlat.h"

static void *malloc_p2(void *p1, size_t size, unsigned long flags)  {
	(void)flags;
	return malloc_flat( (struct mem_flat_region_descriptor const *)p1, size );
}

static void free_p2(void *p1, void *ptr, unsigned long flags)  {
	(void)flags;
	free_flat( (struct mem_flat_region_descriptor const *)p1, ptr );	
}

static void *realloc_p2(void *p1, void *ptr, size_t size, unsigned long flags) {
	(void)flags;
	return realloc_flat( (struct mem_flat_region_descriptor const *)p1, ptr, size );
}

	PGPError
PGPNewFixedSizeMemoryMgr( PGPByte *pool, PGPSize poolsize, PGPMemoryMgrRef *newMgr )
{
	struct mem_flat_region_descriptor * const descr = (struct mem_flat_region_descriptor *)pool;
	PGPError err;
	
	*newMgr = NULL;
	
	if( poolsize <= sizeof(struct mem_flat_region_descriptor) )
		return kPGPError_BufferTooSmall;
		
	if( malloc_flat_init( descr+1, poolsize-sizeof(*descr), descr ) != 0 )
		return kPGPError_BadIntegrity;
		
	err = PGPNewMemoryMgrExternal( malloc_p2, free_p2, realloc_p2, descr, 0, newMgr);

	return err;
}


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
