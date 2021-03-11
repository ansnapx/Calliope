/*____________________________________________________________________________
	Copyright (C) 2006 PGP Corporation
	All rights reserved.

	Thin manager wrapper that doesn't call explicitly any system memory call. 
	Instead it relies on passed function pointers to do the job. Most platforms 
	have runtime library with malloc/free type of functions.
	The manager allows these standard POSIX APIs and similiar defined 
	APIs with extra parameters.
	
	Complies with PGPSDK memory manager API.

	While PGPSDK has a mechanism for custom memory manager, here we
	redefine the top level API for simplicity.
	
	$Id: pgpMemoryMgr.c 56142 2007-08-29 19:26:07Z jroark $
____________________________________________________________________________*/

#include "pgpPFLErrors.h"
#include "pgpMem.h"
#include "pgpPFLPriv.h"

#define DEBUG_MEM 0

#if DEBUG_MEM
#include <stdio.h>
#endif

#include "pgpMemoryMgr.h"

enum pgpMiniSDKMMType  {
	PGP_MM_TYPE_UNKNOWN=0,
	PGP_MM_TYPE_FLAT,			// serves allocation from passed buffer: do we need to support it here?
	PGP_MM_TYPE_EXT_WITH_P2,	// like malloc, free, realloc but with 2 extra parameters
	PGP_MM_TYPE_POSIX				// malloc, free, realloc
};

struct pgpMiniSDKPoolInfo  {
	void *start;
	unsigned size;
};

typedef struct PGPMemoryMgr
{
#define kPGPFixedSizeMemoryMgrMagic	0x4D4D67	/* 'MMg' */
	PGPUInt32				magic;				/* Always kPGPMemoryMgrMagic */

	enum pgpMiniSDKMMType 	type;

	malloc_proc				f_malloc_posix;
	free_proc				f_free_posix;
	realloc_proc			f_realloc_posix;

	/* 2 parameters to allocation routines follow: */
	void *					param;
	unsigned long			flags;

	malloc_with_p2_proc		f_malloc_p2;
	free_with_p2_proc		f_free_p2;
	realloc_with_p2_proc	f_realloc_p2;

	// struct pgpMiniSDKPoolInfo fixed_info;

#if DEBUG_MEM
	unsigned				total_alloced;
	unsigned				total_freed;
	unsigned				total_realloced;
#endif
	
} PGPMemoryMgr;


// complies with malloc_with_p2_proc
static void *malloc_posix_wrapper_p2(void *param, size_t size, unsigned long flags)  {
	PGPMemoryMgr *c = (PGPMemoryMgr*)param;

	return ( IsPGPError(PGPValidateMemoryMgr( c )) ? NULL : c->f_malloc_posix(size) );
}

// complies with free_with_p2_proc
static void free_posix_wrapper_p2(void *param, void *ptr, unsigned long flags)  {
	PGPMemoryMgr *c = (PGPMemoryMgr*)param;
	
	if( IsntPGPError(PGPValidateMemoryMgr( c )) ) 
		c->f_free_posix(ptr);
}

// complies with realloc_with_p2_proc
static void *realloc_posix_wrapper_p2(void *param, void *ptr, size_t size, unsigned long flags)  {
	PGPMemoryMgr *c = (PGPMemoryMgr*)param;

	return ( IsPGPError(PGPValidateMemoryMgr( c )) ? NULL : c->f_realloc_posix(ptr, size) );
}

#if 0
// complies with malloc_with_param_proc
static void *malloc_flat_wrapper_p1(void *param, size_t size)  {
	struct pgpMiniSDKPoolInfo *i = (struct pgpMiniSDKPoolInfo)param;
	// malloc_flat();
}

// complies with free_with_param_proc
static void free_flat_wrapper_p1(void *param, void *ptr)  {
	struct pgpMiniSDKPoolInfo *i = (struct pgpMiniSDKPoolInfo)param;
	// free_flat();
}

// complies with realloc_with_param_proc
static void *realloc_flat_wrapper_p1(void *param, void *ptr, size_t size)  {
	struct pgpMiniSDKPoolInfo *i = (struct pgpMiniSDKPoolInfo)param;
	// realloc_flat();
}
#endif


	PGPError
PGPValidateMemoryMgrExternal( PGPMemoryMgrRef mgr )
{
	PGPError	err = kPGPError_NoErr;
	
	if( IsntNull( mgr ) )  {
		if( mgr->magic != kPGPFixedSizeMemoryMgrMagic || 
			mgr->f_malloc_p2==NULL || mgr->f_free_p2==NULL || mgr->f_realloc_p2==NULL )
		{
#if DEBUG_MEM
			printf("Bad memory manager: magic=%s!\n", mgr->magic == kPGPFixedSizeMemoryMgrMagic ? "OK" : "BAD");
			assert(0);
#endif
			err = kPGPError_BadParams;
		}
	}
	else  {
#if DEBUG_MEM
		printf("Bad memory manager: NULL!\n");
		assert(0);
#endif
		err = kPGPError_BadParams;
	}

	return( err );
}


PGPError PGPNewMemoryMgrPosix( malloc_proc f_malloc, free_proc f_free, realloc_proc f_realloc, PGPMemoryMgrRef *newMgr )  {
	PGPMemoryMgr *c;
	if( newMgr==NULL )
		return kPGPError_BadParams;
	*newMgr = NULL;
	if( f_malloc==NULL || f_free==NULL || f_realloc==NULL )
		return kPGPError_BadParams;
	c = (PGPMemoryMgr *)(*f_malloc)( sizeof(PGPMemoryMgr) );
	if( c==NULL )
		return kPGPError_OutOfMemory;
	
	memset( c, 0, sizeof(*c) );
	
	c->magic = kPGPFixedSizeMemoryMgrMagic;
	c->type = PGP_MM_TYPE_POSIX;

	c->f_malloc_posix = f_malloc;
	c->f_free_posix = f_free;
	c->f_realloc_posix = f_realloc;

	c->param = c;
	// c->flags = NULL;		/* ignored */
	c->f_malloc_p2 = malloc_posix_wrapper_p2;
	c->f_free_p2 = free_posix_wrapper_p2;
	c->f_realloc_p2 = realloc_posix_wrapper_p2;

	PGPValidateMemoryMgr( c );

	*newMgr = c;

	return kPGPError_NoErr;
}

PGPError PGPSDKM_PUBLIC_API PGPNewMemoryMgrExternal( malloc_with_p2_proc f_malloc, free_with_p2_proc f_free, realloc_with_p2_proc f_realloc, 
	void *param, unsigned long flags, PGPMemoryMgrRef *newMgr )  
{
	PGPMemoryMgr *c;
	if( newMgr==NULL )
		return kPGPError_BadParams;
	*newMgr = NULL;
	if( f_malloc==NULL || f_free==NULL || f_realloc==NULL )
		return kPGPError_BadParams;
	c = (PGPMemoryMgr *)(*f_malloc)( param, sizeof(PGPMemoryMgr), flags );
	if( c==NULL )
		return kPGPError_OutOfMemory;
	
	memset( c, 0, sizeof(*c) );

	c->magic = kPGPFixedSizeMemoryMgrMagic;
	c->type = PGP_MM_TYPE_EXT_WITH_P2;

	c->param = param;
	c->flags = flags;
	c->f_malloc_p2 = f_malloc;
	c->f_free_p2 = f_free;
	c->f_realloc_p2 = f_realloc;

	*newMgr = c;

	return kPGPError_NoErr;
}

/*____________________________________________________________________________
	Delete an existing PFLContext and all resources associated with it.
____________________________________________________________________________*/
PGPError PGPFreeMemoryMgrExternal(PGPMemoryMgrRef mgr)
{
	PGPError err = PGPValidateMemoryMgr(mgr);
	PGPMemoryMgr *c = (PGPMemoryMgr *)mgr;

	if( IsPGPError(err) )
		return err;

	if( c==NULL || c->magic != kPGPFixedSizeMemoryMgrMagic )  {
		pgpAssert(0);
		return kPGPError_BadParams;
	}

#if DEBUG_MEM
	printf("Freeing data manager: total alloced=%d, realloced=%d, freed=%d\n",
		c->total_alloced, c->total_realloced, c->total_freed );
#endif
		
	if( c->type != PGP_MM_TYPE_FLAT )
		c->f_free_p2( c->param, c, c->flags );

	return kPGPError_NoErr;
}

// 4-8 bytes
#define EXTRA_ALLOC_SIZE sizeof(PGPMemoryMgr*)

/*____________________________________________________________________________
	Allocate a block of memory using the allocator stored in a PFLContext.
____________________________________________________________________________*/

static void * pgpNewData( PGPMemoryMgrRef mgr, PGPSize requestSize, PGPMemoryMgrFlags flags )  {
	void *p;
	PGPMemoryMgr *c = (PGPMemoryMgr*)mgr;
	PGPError err = PGPValidateMemoryMgr(mgr);

	if( IsPGPError(err) )
		return NULL;

	p = c->f_malloc_p2( c->param, requestSize + EXTRA_ALLOC_SIZE, c->flags );
	if( p )  {
		if( ( flags & kPGPMemoryMgrFlags_Clear ) )
			memset( p, 0, requestSize + EXTRA_ALLOC_SIZE );
		*(PGPMemoryMgr**)p = c;	
#if DEBUG_MEM
		c->total_alloced++;
#endif
	} else {
		return NULL;
	}
	return (PGPMemoryMgr**)p + 1;
}

void * PGPSDKM_PUBLIC_API PGPNewDataExternal(PGPMemoryMgrRef mgr,PGPSize requestSize,PGPMemoryMgrFlags flags)
{
	return pgpNewData( mgr, requestSize, flags );
}

void *PGPNewSecureDataExternal(PGPMemoryMgrRef mgr,PGPSize requestSize,PGPMemoryMgrFlags flags)
{
	return pgpNewData( mgr, requestSize, flags );
}

/*____________________________________________________________________________
	Allocate a block of memory (secure or non-secure).
____________________________________________________________________________*/
	PGPError
PGPReallocDataExternal(
	PGPMemoryMgrRef 	mgr,
	void **				userPtr,
	PGPSize 			requestSize,
	PGPMemoryMgrFlags	flags)
{
	PGPMemoryMgr *c = (PGPMemoryMgr*)mgr;
	void *p;
	PGPError err;

	if( userPtr==NULL )
		return kPGPError_BadParams;

	err = PGPValidateMemoryMgr( mgr );
	if( IsPGPError(err) )
		return err;

	p = c->f_realloc_p2( c->param, (PGPMemoryMgr **)*userPtr - 1, requestSize + EXTRA_ALLOC_SIZE, c->flags );
	if( p && ( flags & kPGPMemoryMgrFlags_Clear ) )
		memset( p, 0, requestSize + EXTRA_ALLOC_SIZE );

	if( p )  {
		*(PGPMemoryMgr**)p = c;
		*userPtr = (PGPMemoryMgr **)p + 1;
#if DEBUG_MEM
		c->total_realloced++;
#endif
	} else {
		return kPGPError_OutOfMemory;
	}
		
	return kPGPError_NoErr;
}



/*____________________________________________________________________________
	Free a block of memory, whether secure or not.
____________________________________________________________________________*/
	PGPError PGPSDKM_PUBLIC_API
PGPFreeDataExternal( void * allocation )
{
	PGPMemoryMgr *c, **buf;
	PGPError err;

	if( allocation==NULL )
		return kPGPError_BadParams;

	buf = (PGPMemoryMgr **)allocation - 1;
	c = *buf;

	err = PGPValidateMemoryMgr( c );
	if( IsPGPError(err) )
		return err;

	c->f_free_p2( c->param, buf, c->flags );

#if DEBUG_MEM
	c->total_freed++;
#endif

	return kPGPError_NoErr;
}

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
