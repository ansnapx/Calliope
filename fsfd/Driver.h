///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Driver.h - generic header file
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef _DRIVER_H_
#define _DRIVER_H_

#ifndef DBG
//#define RELEASE_DBPRINT
#endif

#if _MSC_VER >= 1200
// disable VC 7+ runtime checks to avoid linker errors in checked builds
#pragma runtime_checks("[runtime_checks]", off)
#endif

// avoid linker errors on W2k
#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DRIVER_USE_NTIFS

#include <ntifs.h>

#else	//DRIVER_USE_NTIFS

#include <ntddk.h>
#include <ntdddisk.h>

#include "EXT_DDK.h"	// additional definitions for WinXP and needed functions from NTIFS.H

#endif //DRIVER_USE_NTIFS

#ifdef __cplusplus
}
#endif

#ifndef offsetof
#define offsetof(s,m)   ((size_t)&(((s *)0)->m))
#endif

#define FILF_POOL_TAG 'XDKX'

#ifdef POOL_TAGGING
#ifdef ExAllocatePool
#undef ExAllocatePool
#endif
#define ExAllocatePool(type, size) ExAllocatePoolWithTag((type), (size), FILF_POOL_TAG)
#endif // POOL_TAGGING

// MACROS ////////////////////////////////////////////////////////////////////////////////////////////////////

extern char* g_debugHeader;

#if DBG
#define DBGPRINT_N(format) DbgPrint format;

#define DBGPRINT(format)		\
	{							\
    	DbgPrint(g_debugHeader);\
		DbgPrint format;		\
	}
#else

#define DBGPRINT(x) 	// No debug stuff in free builds
#define DBGPRINT_N(x)

#endif  // DBG

// some usefull macros

#define MAKELONG(w1, w2) (((ULONG)(w1) << 16) | (ULONG)(w2))
#define HIWORD(ul) (((ULONG)(ul)) >> 16)
#define LOWORD(ul) (((ULONG)(ul)) & 0x0000ffff)

// segment management

#define PAGEDCODE	code_seg("PAGE")
#define LOCKEDCODE	code_seg()
#define INITCODE	code_seg("INIT")

// time management

#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //_DRIVER_H_