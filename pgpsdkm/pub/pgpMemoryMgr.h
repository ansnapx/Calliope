/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	A PGPMemoryMgr is an object which implements memory management, including
	allocation, reallocation, deallocation, and secure versions of the same.

	$Id: pgpMemoryMgr.h 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpMemoryMgr_h	/* [ */
#define Included_pgpMemoryMgr_h

#include "pgpBase.h"

PGP_BEGIN_C_DECLARATIONS

/**
 * @defgroup MINISDK_MEM_PUB Mini-SDK public memory management API
 * @brief Describes important changes from main SDK
 * @par Purpose
 * Mini-SDK memory management routines allow SDK code to work on 
 * any platform we care about, from normal OS level, where POSIX memory allocations
 * can be used, to embedded systems with non-standard memory allocations. 
*/

/**
	@ingroup MINISDK_MEM_PUB 
	Buffer content management 
*/
enum 
{
	kPGPMemoryMgrFlags_None		=	0,	/**< do nothing with allocated memory: return new memory with undefined content */
	kPGPMemoryMgrFlags_Clear	=	1	/**< zero out allocated memory before returning it to application */
};

typedef PGPFlags	PGPMemoryMgrFlags;

typedef struct PGPMemoryMgr	*	PGPMemoryMgrRef;

#define	kInvalidPGPMemoryMgrRef			((PGPMemoryMgrRef) NULL)
#define PGPMemoryMgrRefIsValid(ref)		((ref) != kInvalidPGPMemoryMgrRef)

typedef	void	*(*PGPMemoryMgrAllocationProc)( PGPMemoryMgrRef mgr,
						PGPUserValue userValue,
						PGPSize requestSize, PGPMemoryMgrFlags flags );

/* realloc not be implemented using PGPNewData() */
typedef	PGPError (*PGPMemoryMgrReallocationProc)( PGPMemoryMgrRef mgr,
						PGPUserValue userValue,
						void **allocation, PGPSize newAllocationSize,
						PGPMemoryMgrFlags flags, PGPSize existingSize );

typedef	PGPError (*PGPMemoryMgrDeallocationProc)( PGPMemoryMgrRef mgr,
						PGPUserValue userValue,
						void *allocation, PGPSize allocationSize );


typedef	void	*(*PGPMemoryMgrSecureAllocationProc)( PGPMemoryMgrRef mgr,
						PGPUserValue userValue,
						PGPSize requestSize, PGPMemoryMgrFlags flags,
						PGPBoolean *isNonPageable );
						

/* deallocation proc need not clear the memory upon deallocation since
	PGPFreeData() does it automatically */
typedef	PGPError (*PGPMemoryMgrSecureDeallocationProc)( PGPMemoryMgrRef mgr,
						PGPUserValue userValue,
						void *allocation, PGPSize allocationSize,
						PGPBoolean	wasLocked );

typedef struct PGPNewMemoryMgrStruct
{
	/* sizeofStruct must be inited to sizeof( PGPNewMemoryMgrStruct ) */
	PGPUInt32		sizeofStruct;
	PGPFlags		reservedFlags;
	
	PGPMemoryMgrAllocationProc		allocProc;
	PGPMemoryMgrReallocationProc	reallocProc;
	PGPMemoryMgrDeallocationProc	deallocProc;
	
	PGPMemoryMgrSecureAllocationProc		secureAllocProc;
	void *									reserved;	/* MUST be zeroed */
	PGPMemoryMgrSecureDeallocationProc		secureDeallocProc;
	
	PGPUserValue					customValue;
	void *							pad[ 8 ];	/* MUST be zeroed */
} PGPNewMemoryMgrStruct;


/*____________________________________________________________________________
	Memory Mgr routines
____________________________________________________________________________*/

//PGPError	PGPNewMemoryMgr( PGPFlags reserved, PGPMemoryMgrRef *newMemoryMgr );

/**
	@ingroup MINISDK_MEM_PUB 
	Buffer content management 
	@note: deprecated
*/
PGPError	PGPSDKM_PUBLIC_API PGPNewFixedSizeMemoryMgr( PGPByte *pool, PGPSize size, PGPMemoryMgrRef *newMemoryMgr );

/**
	@addtogroup MINISDK_MEM_PUB 
	@{
*/
/** POSIX prototype */
typedef void *(*malloc_proc)(size_t size);
/** POSIX prototype */
typedef void (*free_proc)(void *ptr);
/** POSIX prototype */
typedef void *(*realloc_proc)(void *ptr, size_t size); 

/** advanced memory allocation prototype with two extra parameters */
typedef void *(*malloc_with_p2_proc)(void *p1, size_t size, unsigned long flags);
/** advanced memory allocation prototype with two extra parameters */
typedef void (*free_with_p2_proc)(void *p1, void *ptr, unsigned long flags);
/** advanced memory allocation prototype with two extra parameters */
typedef void *(*realloc_with_p2_proc)(void *p2, void *ptr, size_t size, unsigned long flags); 

/** Allocates POSIX-based memory manager.
* @param f_malloc caller-defined allocation function or POSIX libc malloc 
* @param f_free caller-defined deallocation function or POSIX libc free
* @param f_realloc caller-defined advanced reallocation or POSIX libc realloc
* @param newMgr output
* @code
* // in the simplest case:
* PGPNewMemoryMgrPosix( malloc, free, realloc, &myMemMgr );
* // then you can pass myMemMgr to SDK calls and they will call the malloc. 
* void *p = PGPNewDataExternal(myMemMgr, 10, kPGPMemoryMgrFlags_None);
* @endcode
*/
PGPError PGPNewMemoryMgrPosix( malloc_proc f_malloc, free_proc f_free, realloc_proc f_realloc, PGPMemoryMgrRef *newMgr );

/** Allocates advanced memory allocation manager 
* @param f_malloc caller-defined advanced allocation function that is called with @a param and @a flags passed to this function
* @param f_free caller-defined advanced deallocation function that is called with @a param and @a flags passed to this function
* @param f_realloc caller-defined advanced reallocation function that is called with @a param and @a flags passed to this function
* @param param first extra parameter passed to caller-defined allocation functions
* @param flags second extra parameter passed to caller-defined allocation functions. "Extra" is in reference to corresponding POSIX functions.
* @param newMgr output
*/
PGPError	PGPSDKM_PUBLIC_API PGPNewMemoryMgrExternal( malloc_with_p2_proc f_malloc, free_with_p2_proc f_free, realloc_with_p2_proc f_realloc, 
				void *param, unsigned long flags, PGPMemoryMgrRef *newMgr );
 
//PGPError	PGPNewMemoryMgrCustom( PGPNewMemoryMgrStruct const * custom,
//				PGPMemoryMgrRef *newMemoryMgr );

PGPError	PGPSDKM_PUBLIC_API PGPFreeMemoryMgrExternal( PGPMemoryMgrRef mgr );

//PGPError	PGPGetMemoryMgrCustomValue( PGPMemoryMgrRef mgr,
//					PGPUserValue *customValue );
//PGPError	PGPSetMemoryMgrCustomValue( PGPMemoryMgrRef mgr,
//				PGPUserValue customValue );

PGPError	PGPValidateMemoryMgrExternal( PGPMemoryMgrRef mgr );

/** allocate a block of the specified size */
void * PGPSDKM_PUBLIC_API PGPNewDataExternal( PGPMemoryMgrRef mgr,
				PGPSize requestSize, PGPMemoryMgrFlags flags );
				
/* In full SDK allocate a block of the specified size in non-pageable memory
*/
/** Identical to @ref PGPNewDataExternal. In mini-SDK caller controls memory allocation.
 * It is recommended to use PGPNewSecureDataExternal for style clarity. 
 */
void *  	PGPNewSecureDataExternal( PGPMemoryMgrRef mgr,
				PGPSize requestSize, PGPMemoryMgrFlags flags );

/** Properly reallocs memory blocks.
 * @note the block may move, even if its size is being reduced */
PGPError  	PGPSDKM_PUBLIC_API PGPReallocDataExternal( PGPMemoryMgrRef mgr,
					void **allocation, PGPSize newAllocationSize,
					PGPMemoryMgrFlags flags );
					
/** Frees previously allocatted memory blocks */
PGPError 	PGPSDKM_PUBLIC_API PGPFreeDataExternal( void *allocation );

/* we redefine memory routines to *External */
#ifndef PGPValidateMemoryMgr
#define PGPValidateMemoryMgr PGPValidateMemoryMgrExternal
#endif
#ifndef PGPNewData
#define PGPNewData PGPNewDataExternal
#endif
#ifndef PGPNewSecureData
#define PGPNewSecureData PGPNewSecureDataExternal
#endif
#ifndef PGPReallocData
#define PGPReallocData PGPReallocDataExternal
#endif
#ifndef PGPFreeData
#define PGPFreeData PGPFreeDataExternal
#endif
#ifndef PGPFreeMemoryMgr
#define PGPFreeMemoryMgr PGPFreeMemoryMgrExternal
#endif

/** @} */

#define PGPMemoryMgrIsValid( memoryMgr )    \
                ( IsntPGPError( PGPValidateMemoryMgr( memoryMgr ) ) )

#if 0
/*____________________________________________________________________________
	Block Info:
		kPGPMemoryMgrBlockInfo_Valid		it's a valid block
		kPGPMemoryMgrBlockInfo_Secure		block is a secure allocation
		kPGPMemoryMgrBlockInfo_NonPageable	block cannot be paged by VM
		
	Secure blocks are always wiped before being disposed,
	but may or may not be pageable, depending on the OS facilities.  Some
	OSs may not provide the ability to make blocks non-pageable.
	
	You should check these flags if the information matters to you.
____________________________________________________________________________*/
#define kPGPMemoryMgrBlockInfo_Valid		( ((PGPFlags)1) << 0 )
#define kPGPMemoryMgrBlockInfo_Secure		( ((PGPFlags)1) << 1 )
#define kPGPMemoryMgrBlockInfo_NonPageable	( ((PGPFlags)1) << 2 )
PGPFlags		PGPGetMemoryMgrDataInfo( void *allocation );


/*____________________________________________________________________________
	Default memory manager routines:
____________________________________________________________________________*/

PGPMemoryMgrRef	PGPGetDefaultMemoryMgr(void);
PGPError		PGPSetDefaultMemoryMgr(PGPMemoryMgrRef memoryMgr);
#endif

PGP_END_C_DECLARATIONS


#endif /* ] Included_pgpMemoryMgr_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
