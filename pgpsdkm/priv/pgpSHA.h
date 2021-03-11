/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	$Id: pgpSHA.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpSHA_h
#define Included_pgpSHA_h

#ifndef PGPSDK_DRIVER
#define PGPSDK_DRIVER	0
#endif

#if ! PGPSDK_DRIVER
#include "pgpDebug.h"
#endif

#define PGP_SHA_BLOCKBYTES	64
#define PGP_SHA_BLOCKWORDS	16

#define PGP_SHA_HASHBYTES	20
#define PGP_SHA_HASHWORDS	5

typedef struct PGPSHAContext
{
	PGPUInt32 key[PGP_SHA_BLOCKWORDS];
	PGPUInt32 iv[PGP_SHA_HASHWORDS];
#if PGP_HAVE64
	PGPUInt64 bytes;
#else
	PGPUInt32 bytesHi, bytesLo;
#endif
} PGPSHAContext;



PGP_BEGIN_C_DECLARATIONS

extern PGPByte const SHADERprefix[15];

void		pgpSHAInit(PGPSHAContext *ctx);
void		pgpSHATransform(PGPUInt32 *block, PGPUInt32 *key);
void		pgpSHAUpdate(PGPSHAContext *ctx, void const *bufIn, PGPSize len);
const void *pgpSHAFinalize(PGPSHAContext *ctx);

PGP_END_C_DECLARATIONS

#endif /* !Included_pgpSHA_h */
