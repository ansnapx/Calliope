/*____________________________________________________________________________
	pgpMem.h
	
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	Memory allocation routines with debugging support

	$Id: pgpMem.h 40455 2006-01-04 01:46:14Z ajivsov $
____________________________________________________________________________*/
#ifndef Included_pgpMem_h	/* [ */
#define Included_pgpMem_h

/* aCC barfs on <sys/time.h> if <sys/sigevent.h> is not included first */
#if defined(PGP_COMPILER_HPUX) && PGP_COMPILER_HPUX
#include <sys/sigevent.h>
#endif /* PGP_COMPILER_HPUX */

#if !defined(PGP_UNIX_DARWIN) || !PGP_UNIX_DARWIN
#include <stdlib.h>
#endif
#include <string.h>		/* for memset and memcmp */

#include "pgpTypes.h"
#include "pgpPFLErrors.h"
#include "pgpDebug.h"

#ifndef IsNull
#define IsntNull( p )	( (PGPBoolean) ( (p) != NULL ) )
#define IsNull( p )		( (PGPBoolean) ( (p) == NULL ) )
#endif

#if PGP_WIN32
#pragma intrinsic(memcmp)
#endif

PGP_BEGIN_C_DECLARATIONS
/*____________________________________________________________________________
 * There are five macros which control the debugging features of pgpmem.
 * Unless explicitly set, they default to the value of the PGP_DEBUG macro.
 *
 * NOTE: There's no need to set these explicitly for most purposes.
 *
 * DEBUG_FILL_MEM		If set, all allocated memory will be set to 0xDD
 *						before use, and all deallocated memory will be set
 *						to 0xDD before being freed.  This is also done when
 *						resizing blocks.
 * DEBUG_MEM_HEAD_MAGIC	If set, a ulong-byte magic number is placed immediately
 *						before each block, to detect buffer overruns.
 * DEBUG_MEM_TAIL_MAGIC	If set, magic numbers are placed after the end of each
 *						block to detect buffer overruns.  The value of the
 *						macro determines the number of bytes added.
 * PGP_DEBUG_FIND_LEAKS		If set, a list is kept of all allocated blocks 
 *						which is used to detect memory leaks on program exit.
 * DEBUG_ALWAYS_MOVE	If set, memory blocks are always moved when increasing
 *						the size of a block.
____________________________________________________________________________*/

#ifndef USE_PGP_LEAKS
#define USE_PGP_LEAKS 0
#endif

#ifndef PGP_DEBUG_FIND_LEAKS
#define PGP_DEBUG_FIND_LEAKS	USE_PGP_LEAKS	/* Find memory leaks */
#endif

#if PGP_DEBUG_FIND_LEAKS

#define PGPALLOC_CONTEXT_PARAMS			, PGPTXT_DEBUG(__FILE__), __LINE__
#define PGPALLOC_CONTEXT_PARAMS_DEF		, PGPChar const *fileName, long lineNumber
#define PGPALLOC_CONTEXT_PASS_PARAMS	, fileName, lineNumber
#define PGP_INTERNAL_ALLOC				pgpInternalContextAlloc
#define PGP_INTERNAL_MEMALLOC			pgpInternalContextMemAlloc
#define PGP_INTERNAL_MEMREALLOC			pgpInternalContextMemRealloc

#else

#define PGPALLOC_CONTEXT_PARAMS
#define PGPALLOC_CONTEXT_PARAMS_DEF
#define PGPALLOC_CONTEXT_PASS_PARAMS
#define PGP_INTERNAL_ALLOC				pgpInternalAlloc
#define PGP_INTERNAL_MEMALLOC			pgpInternalMemAlloc
#define PGP_INTERNAL_MEMREALLOC			pgpInternalMemRealloc

#endif

/*
 * These functions won't return NULL for 0-sized blocks,
 * and will fail assertions if NULL is passed in.
 * pgpRealloc also has a different, cleaner calling convention.
 */
#define 			pgpAlloc(size)											\
					PGP_INTERNAL_ALLOC(size  PGPALLOC_CONTEXT_PARAMS)
#define 			pgpNew(type)											\
					((type *)pgpAlloc(sizeof(type)))
PGPError 	pgpRealloc(void **userPtrRef, size_t newSize);
void 		pgpFree(void *userPtr);

/*
 * These functions WILL return NULL for 0-sized blocks, and
 * deal with NULL passed in as if it was a 0-sized block,
 * for backward compatibility.  They have the same semantics
 * as malloc/realloc/free.
 */
#define 			pgpMemAlloc(size) 										\
					PGP_INTERNAL_MEMALLOC(size  PGPALLOC_CONTEXT_PARAMS)
#define 			pgpMemNew(type)											\
					((type *)pgpMemAlloc(sizeof(type)))
#define 			pgpMemRealloc(userPtr, newSize) 						\
					PGP_INTERNAL_MEMREALLOC(userPtr, newSize				\
											PGPALLOC_CONTEXT_PARAMS)
void 				pgpMemFree(void *userPtr);


/* Memory copy routine optimized for large blocks, overlapping okay */
#ifndef pgpCopyMemory
	#define			pgpCopyMemory(src, dest, size) memmove((dest), (src), (size))
#endif
#ifndef pgpCopyMemoryNO
	#define			pgpCopyMemoryNO(src, dest, size) memcpy((dest), (src), (size))
#endif

#define				pgpMemoryEqual(b1, b2, length)							\
					(memcmp((void *)(b1), (void *)(b2), (length)) == 0)
#define				pgpFillMemory(buffer, length, fillChar)					\
					((void)memset((void *)(buffer), (fillChar), (length)))
#define 			pgpClearMemory(buffer, byteCount)						\
					pgpFillMemory((buffer), (byteCount), '\0')

void 	pgpCopyPattern(const void *pattern, size_t patternLength,
									void *buffer, size_t bufferLength);

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

/*
 * WARNING: These should only be used by the above macros
 */
void  *	PGP_INTERNAL_ALLOC(size_t size
										PGPALLOC_CONTEXT_PARAMS_DEF);
void  *	PGP_INTERNAL_MEMALLOC(size_t size
											PGPALLOC_CONTEXT_PARAMS_DEF);
void  *	PGP_INTERNAL_MEMREALLOC(void *userPtr, size_t newSize
											PGPALLOC_CONTEXT_PARAMS_DEF);


PGP_END_C_DECLARATIONS

#endif /* ] Included_pgpMem_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
