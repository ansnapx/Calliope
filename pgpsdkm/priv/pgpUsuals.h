/*
 * pgpUsuals.h - Typedefs and #defines used widely.
 *
 * $Id: pgpUsuals.h 47014 2006-08-16 02:24:28Z ajivsov $
 */
#ifndef Included_pgpUsuals_h
#define Included_pgpUsuals_h

#include "pgpBase.h"

#include "pgpOpaqueStructs.h"

PGP_BEGIN_C_DECLARATIONS


#if PGP_HAVE64
typedef PGPUInt64	bnword64;
#endif



/* A way to hold the PGP Version number */
typedef int PgpVersion;
#define PGPVERSION_2	2	/* 2.0 through 2.5 */
#define PGPVERSION_3	3	/* 2.6.x */
#define PGPVERSION_4    4       /* 3.0 */


/* The PGP Library Cipher maximum IV Length for symmetric encrypted blocks */
#define MAXIVLEN		16

/* Literal Message Types */
#define PGP_LITERAL_TEXT	'\164' /* Ascii 't' */
#define PGP_LITERAL_BINARY	'\142' /* Ascii 'b' */
/* Used only internally for now, when looks like PGP msg inside literal */
#define PGP_LITERAL_RECURSE	'\162' /* Ascii 'r' */

#if 0 && PGP_DEBUG
#define PGPSDK_TRACE( s ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__ )
#define PGPSDK_TRACE1( s, p1 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1)
#define PGPSDK_TRACE2( s, p1,p2 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1,p2)
#define PGPSDK_TRACE3( s, p1,p2,p3 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1,p2,p3)
#define PGPSDK_TRACE4( s, p1,p2,p3,p4 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1,p2,p3,p4)
#define PGPSDK_TRACE5( s, p1,p2,p3,p4,p5 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1,p2,p3,p4,p5)
#define PGPSDK_TRACE6( s, p1,p2,p3,p4,p5,p6 ) printf("sdkm %s(%d): " s "\n", __FILE__, __LINE__, p1,p2,p3,p4,p5,p6)
#else
#define PGPSDK_TRACE( s )
#define PGPSDK_TRACE1( s, p1 )
#define PGPSDK_TRACE2( s, p1,p2 )
#define PGPSDK_TRACE3( s, p1,p2,p3 )
#define PGPSDK_TRACE4( s, p1,p2,p3,p4 )
#define PGPSDK_TRACE5( s, p1,p2,p3,p4,p5 )
#define PGPSDK_TRACE6( s, p1,p2,p3,p4,p5,p6 )
#endif

#if 0
#if 0
#ifdef BOOTGUARD
	extern void boot_printf (const char *format,...);
	#define PGPSDK_TRACE( s, params... ) printf( "sdkm %s(%d) | %s: " s "\n", __FILE__, __LINE__, __FUNCTION__, ##params )
#else 
	#include <stdio.h>
	#define PGPSDK_TRACE( s, params... ) printf( "sdkm %s(%d) | %s: " s "\n", __FILE__, __LINE__, __FUNCTION__, ##params )
#endif
#else
#define PGPSDK_TRACE( s, params... ) 
#endif
#endif

PGP_END_C_DECLARATIONS

#endif /* Included_pgpUsuals_h */
