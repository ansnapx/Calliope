/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pStr2Key.c 59832 2008-01-14 20:49:40Z ajivsov $
____________________________________________________________________________*/
/*
 * pgpStr2Key.c -- A prototype string-to-key framework.
 */
#include "pgpConfig.h"

#include <string.h>
#if ! PGP_UNIX_DARWIN
#include <stddef.h>	/* For offsetof() */
#endif

#include "pgpDebug.h"
#include "pgpStr2Key.h"
#include "pgpHashPriv.h"
#include "pgpMem.h"
#include "pgpErrors.h"
#include "pgpMemoryMgr.h"
#include "pgpUtilities.h"

#define TAG ('S'<<8 | 2);

/* Number of chars (1<<SALT_LOG_CHARS_DEFAULT) to hash when creating default S2K */
#define SALT_LOG_CHARS_DEFAULT          16      /* this is 65536 */

/* It turns out that they all use the same private context structure */
typedef struct StringToKeyPriv {
	PGPMemoryMgrRef memMgr;
	PGPHashVTBL const *hash;
	PGPByte buf[1];	/* Variable-sized */
} StringToKeyPriv;

/* And it can be destroyed with a common routine */
static void
s2kDestroy(PGPStringToKey *s2k)
{
	StringToKeyPriv *priv;
	
	if( s2k==NULL )  {
		return;
	}
		
	priv = (StringToKeyPriv *)s2k->priv;
	
	pgpClearMemory( priv,  s2k->encodelen+offsetof(StringToKeyPriv, buf));

	PGPFreeData( priv );
	pgpClearMemory( s2k,  sizeof(*s2k));
	PGPFreeData( s2k );
}

static PGPStringToKey *
s2kAlloc16(PGPMemoryMgrRef memMgr, PGPHashVTBL const *h, unsigned size)
{
	StringToKeyPriv *priv;
	PGPStringToKey *s2k = NULL;

	priv = (StringToKeyPriv *)
		PGPNewData( memMgr,
			offsetof(StringToKeyPriv, buf) + size, kPGPMemoryMgrFlags_Clear);
//bgmodule_printf(100, "priv=%x\n", priv);
//getchar();
	if (priv) {
		s2k = (PGPStringToKey *)PGPNewData( memMgr,
			sizeof(*s2k), kPGPMemoryMgrFlags_Clear);
//bgmodule_printf(100, "s2k=%x\n", s2k);
//getchar();
		if ( IsntNull( s2k ) ) {
//			s2k->tag = TAG;
			s2k->priv = priv;
			s2k->encoding = priv->buf;
			s2k->encodelen = size;
			s2k->destroy = s2kDestroy;
//			priv->tag = TAG;
			priv->memMgr = memMgr;
			priv->hash = h;
			if (h)
				priv->buf[1] = (PGPByte)h->algorithm;
		}
		else
		{
			PGPFreeData( priv );
			priv	= NULL;
		}
	}
	return s2k;
}

/* Allocate an array of "num" hash private buffers, all sharing the same hash*/
static void **
multiHashCreate(
	PGPMemoryMgrRef	memMgr,
	PGPHashVTBL const *h, unsigned num)
{
	void **v;
	void *p;
	unsigned i, j;
	PGPByte const b = 0;

	v = (void **)PGPNewData( memMgr, num * sizeof(*v), kPGPMemoryMgrFlags_Clear);
	if (!v)
		return NULL;

	for (i = 0; i < num; i++) {
		p = PGPNewData( memMgr,
			h->context_size, kPGPMemoryMgrFlags_Clear);
		if (!p) {
			while (i) {
				pgpClearMemory(v[--i], h->context_size);
				PGPFreeData( v[i] );
			}
			PGPFreeData( v );
			return NULL;
		}
		h->init(p);
		/* Initialze the PGPHashContext with leading null bytes */
		for (j = 0; j < i; j++)
			h->update(p, &b, 1);
		v[i] = p;
	}
	return v;
}

/* Update an array of hash private buffers, all sharing the same hash */
static void
multiHashUpdate(PGPHashVTBL const *h, void * const *v, unsigned num,
	PGPByte const *string, size_t len)
{
	while (num--)
		h->update(*v++, string, len);
}

/*
 * Extract the final combined string from an array of hash private buffers,
 * then wipe and free them.
 */
static void
multiHashFinal(
	PGPMemoryMgrRef	memMgr,
	PGPHashVTBL const *h, void **v, PGPByte *key, size_t klen)
{
	void **v0 = v;
	size_t hsize = h->hashsize;

	while (klen > hsize) {
		pgpCopyMemoryNO(h->final(*v), key, hsize);
		key += hsize;
		klen -= hsize;
		pgpClearMemory(*v, h->context_size);
		PGPFreeData( *(v++) );
	}
	pgpCopyMemoryNO(h->final(*v), key, klen);
	pgpClearMemory(*v, h->context_size);
	PGPFreeData( *v );

	PGPFreeData( v0 );
}


/*
 * The count is stored as 4.4 bit normalized floating-point.  The high
 * 4 bits are the exponent (with a bias of 6), and the low 4 bits
 * are the mantissa.  0x12 corresponds to (16+0x2) << (0x1+6).
 * The minimum value is (16+0) << (0+6) = 0x400 = 1024.
 * The maximum is (16+0xf) << (0xf+6) = 0x3e00000 = 65011712.
 * These functions convert between the expanded count and a
 * floating-point approximation.
 */
#define EXPBIAS	6
static PGPUInt32
c_to_bytes(PGPByte c)
{
	return ((PGPUInt32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
}


/* SDK sets number of iterations as a power of 2 (2^k). So optimize the calculations.
We need to find c:
   c=n1*16+n0, so
   bytes=(16+n0)*2^(n1+6)
   log(bytes)=n1+6+log(16+n0)
   k=6+n1+log(16+n0)
Forcing n0=0:
   k=10+n1
*/
static PGPByte
log_bytes_to_c(unsigned log_bytes)
{
	pgpAssert( (unsigned)(1<<log_bytes) == c_to_bytes((log_bytes-10)<<4) );
	return (log_bytes-10)<<4;
}

static int
s2kIterSalt(PGPStringToKey const *s2k, PGPByte const *str,
	PGPSize slen, PGPByte *key, size_t klen)
{
	unsigned num;
	StringToKeyPriv const *priv;
	PGPHashVTBL const *h;
	PGPUInt32 bytes;
	void **v;
	PGPMemoryMgrRef		memMgr = NULL;

	pgpAssert(s2k->encodelen == 16+3);

	if (!klen)
		return 0;	/* Okay, I guess... */

	priv = (StringToKeyPriv *)s2k->priv;
	memMgr	= priv->memMgr;
	h = priv->hash;
	pgpAssert(h->algorithm == priv->buf[1]);
	num = (klen-1)/h->hashsize + 1;
	v = multiHashCreate( memMgr, h, num);
	if (!v)
		return kPGPError_OutOfMemory;
	/* Find the length of the material to hash */
	bytes = c_to_bytes(priv->buf[16+2]);
	/* Always hash a least the whole passphrase! */
	if (bytes < slen + 16)
		bytes = (PGPUInt32)(slen + 16);

	/* Hash len bytes of (salt, passphrase) repeated... */
	while (bytes > slen + 16) {
		multiHashUpdate (h, v, num, priv->buf+2, 16);
		multiHashUpdate (h, v, num, (PGPByte const *)str, slen);
		bytes -= slen + 16;
	}
	if (bytes <= 16) {
		multiHashUpdate (h, v, num, priv->buf+2, (size_t)bytes);
	} else {
		multiHashUpdate (h, v, num, priv->buf+2, 16);
		multiHashUpdate (h, v, num, (PGPByte const *)str, (size_t)bytes-16);
	}
	multiHashFinal( memMgr, h, v, key, klen);

	return 0;
}

/* Encoded as 100 + hash specifier + salt16 + (compressed) count */
static PGPStringToKey *
pgpS2Kiterintern16(PGPMemoryMgrRef memMgr, PGPHashVTBL const *h,
		 PGPByte const *salt16, PGPByte c)
{
	PGPStringToKey *s2k;
	PGPByte *buff;

	s2k = s2kAlloc16(memMgr, h, 16+3);
	if (s2k) {
		s2k->stringToKey = s2kIterSalt;
		buff = ((StringToKeyPriv *)s2k->priv)->buf;
		buff[0] = kPGPStringToKey_IteratedSalted_16;
		pgpCopyMemoryNO(salt16, buff+2, 16);
		buff[16+2] = c;
	}
	return s2k;
}

/* ------------------------------------------------------------ 
   Public funcitons
*/

	PGPError PGPSDKM_PUBLIC_API 
PGPNewS2KDefault( PGPMemoryMgrRef memMgr, const PGPByte salt[16], PGPStringToKeyRef *s2k )  {
	/* TODO: should use half of SHA256 with another half smartly re-added, perhaps
	 * xor at half-step instead of memcpy in multiHashFinal
	 *
	 * SHA256 reduces number of hashing steps that are needed to produce the key, while 
	 * we don't care here about performance
	 */
	PGPHashAlgorithm hashalg = kPGPHashAlgorithm_SHA;	

	/* use a salt */
	*s2k = (PGPStringToKeyRef)pgpS2Kiterintern16(memMgr, pgpHashByNumber(hashalg), salt, log_bytes_to_c(SALT_LOG_CHARS_DEFAULT));

	return ( *s2k==NULL ? kPGPError_OutOfMemory : kPGPError_NoErr);
}

	PGPError PGPSDKM_PUBLIC_API 
PGPNewS2K( PGPMemoryMgrRef memMgr, PGPUInt32 log2HashIterations, const PGPByte salt[16], PGPStringToKeyRef *s2k )  {

	/* TODO: should use half of SHA256 with another half smartly re-added, perhaps
	 * xor at half-step instead of memcpy in multiHashFinal
	 *
	 * SHA256 reduces number of hashing steps that are needed to produce the key, while 
	 * we don't care here about performance
	 */
	PGPHashAlgorithm hashalg = kPGPHashAlgorithm_SHA;

	pgpAssert( c_to_bytes( log_bytes_to_c(log2HashIterations) ) == (1<<log2HashIterations));	

	/* use a salt and passed log2(hashIterations) */
	*s2k = (PGPStringToKeyRef)pgpS2Kiterintern16(memMgr, pgpHashByNumber(hashalg), salt, log_bytes_to_c(log2HashIterations));

	return ( *s2k==NULL ? kPGPError_OutOfMemory : kPGPError_NoErr);
}

void PGPFreeS2K(PGPStringToKeyRef s2k)  {
	if( s2k==NULL )  {
		return;
	}

	s2kDestroy( (PGPStringToKey*)s2k );
}

PGPError PGPSDKM_PUBLIC_API PGPGetS2K( PGPStringToKeyRef s2k, PGPByte const *passphrase, PGPSize passphraseLen, 
	PGPByte *keyOut, size_t keyLenOut )  
{
	PGPError err;

	err = ((PGPStringToKey*)s2k)->stringToKey( (PGPStringToKey const *)s2k, 
		passphrase, passphraseLen, keyOut, keyLenOut);

	return err;
}

