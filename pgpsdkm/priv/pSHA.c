/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pSHA.c 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/
/*
 * pgpSHA.c - NIST Secure Hash Algorithm, FIPS PUB 180 and 180.1.
 *
 * Written 2 September 1992, Peter C. Gutmann.
 * This implementation placed in the public domain.
 *
 * Modified 1 June 1993, Colin Plumb.
 * Modified for the new SHS based on Peter Gutmann's work,
 * 18 July 1994, Colin Plumb.
 *
 * Renamed to SHA and comments updated a bit 1 November 1995, Colin Plumb.
 * These modifications placed in the public domain.
 * Hacked on some more for PGP 3, December 1995, Colin Plumb.
 * You probably don't *want* these modifications.
 *
 * Comments to pgut1@cs.aukuni.ac.nz
 */

#include "pgpConfig.h"
#include "pgpMem.h"
#include "pgpSHA.h"

/*
 * Define to 1 for FIPS 180.1 version (with extra rotate in prescheduling),
 * 0 for FIPS 180 version (with the mysterious "weakness" that the NSA
 * isn't talking about).
 */
#define SHA_VERSION 1


/*
 * Shuffle the bytes into big-endian order within words, as per the
 * SHA spec.
 */
	static void
shaByteSwap(PGPUInt32 *dest, PGPByte const *src, unsigned words)
{
	do {
		*dest++ = (PGPUInt32)((unsigned)src[0] << 8 | src[1]) << 16 |
		                  ((unsigned)src[2] << 8 | src[3]);
		src += 4;
	} while (--words);
}

/* Initialize the SHA values */

	void
pgpSHAInit(PGPSHAContext *ctx)
{
	/* Set the h-vars to their initial values */
	ctx->iv[0] = 0x67452301;
	ctx->iv[1] = 0xEFCDAB89;
	ctx->iv[2] = 0x98BADCFE;
	ctx->iv[3] = 0x10325476;
	ctx->iv[4] = 0xC3D2E1F0;

	/* Initialise bit count */
#if PGP_HAVE64 
	ctx->bytes = 0;
#else
	ctx->bytesHi = 0;
	ctx->bytesLo = 0;
#endif
}

/* shaLoadIV will allow the IV do be loaded with
   an alternate value, this is used by FIPS compliant
   parameter generation.

   This is done via a unsigned character buffer so that the
   output of a SHA operation can be used to initialize the
   IV as described in FIPS 186 appendix 3.3
*/

void shaLoadIV( void *priv, void *init);

	void
shaLoadIV( void *priv, void *init)
{
  PGPSHAContext *ctx = (PGPSHAContext *)priv;
  PGPByte *initp;
  int i,j;

  initp = (PGPByte *)init;
  
  /* pack the initialization string into the IV */
  for (i=0; i < PGP_SHA_HASHWORDS; i++) {
    ctx->iv[i] = 0;
    for (j=0; j<4; j++) {
      ctx->iv[i] <<= 8;
      ctx->iv[i] |= *(initp++);
    }
  }
}

#if 0
/* variant of SHA inititialization, used for
   FIPS compliant DSA parameter generation */
static void
shaInitDSA(void *priv)
{
	PGPSHAContext *ctx = (PGPSHAContext *)priv;

	/* Set the h-vars to their initial values */
	/* This is just rotated by 1 place, as described
	   in FIPS 186, Appendix 3.2 */

	ctx->iv[0] = 0xEFCDAB89;
	ctx->iv[1] = 0x98BADCFE;
	ctx->iv[2] = 0x10325476;
	ctx->iv[3] = 0xC3D2E1F0;
	ctx->iv[4] = 0x67452301;

	/* Initialise bit count */
#if PGP_HAVE64 
	ctx->bytes = 0;
#else
	ctx->bytesHi = 0;
	ctx->bytesLo = 0;
#endif
}
#endif

/*
 * The SHA f()-functions.  The f1 and f3 functions can be optimized to
 * save one boolean operation each - thanks to Rich Schroeppel,
 * rcs@cs.arizona.edu for discovering this.
 * The f3 function can be modified to use an addition to combine the
 * two halves rather than OR, allowing more opportunity for using
 * associativity in optimization.  (Colin Plumb)
 *
 * Note that it may be necessary to add parentheses to these macros
 * if they are to be called with expressions as arguments.
 */
/* f1 is a bit-select function.  If (x) then y else z */
/*#define f1(x,y,z)	( (x & y) | (~x & z) )		// Rounds  0-19 */
#define f1(x,y,z)	( z ^ (x & (y ^ z) ) )		/* Rounds  0-19 */
#define f2(x,y,z)	( x ^ y ^ z )			/* Rounds 20-39 */
/* f3 is a majority function */
/*#define f3(x,y,z)	( (x & y) | (y & z) | (z & x) )	// Rounds 40-59 */
/*#define f3(x,y,z)	( (x & y) | (z & (x | y) ) )	// Rounds 40-59 */
#define f3(x,y,z)	( (x & y) + (z & (x ^ y) ) )	/* Rounds 40-59 */
#define f4(x,y,z)	( x ^ y ^ z )			/* Rounds 60-79 */

/* The SHA Mysterious Constants. */
#define K2	0x5A827999L	/* Rounds  0-19 - floor(sqrt(2) * 2^30) */
#define K3	0x6ED9EBA1L	/* Rounds 20-39 - floor(sqrt(3) * 2^30) */
#define K5	0x8F1BBCDCL	/* Rounds 40-59 - floor(sqrt(5) * 2^30) */
#define K10	0xCA62C1D6L	/* Rounds 60-79 - floor(sqrt(10) * 2^30) */
/* I wonder why not use K7=0xA953FD4E, K11=0xD443949F or K13=0xE6C15A23 */

/* 32-bit rotate left - kludged with shifts */

#define ROTL(n,X)  ( (X << n) | (X >> (32-n)) )

/*
 * The initial expanding function
 *
 * The hash function is defined over an 80-word expanded input array W,
 * where the first 16 are copies of the input data, and the remaining 64
 * are defined by W[i] = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3].  This
 * implementation generates these values on the fly in a circular buffer.
 *
 * The new "corrected" FIPS 180.1 added a 1-bit left rotate to this
 * computation of W[i].
 *
 * The expandx() version doesn't write the result back, which can be
 * used for the last three rounds since those outputs are never used.
 */

#if SHA_VERSION	/* FIPS 180.1 */
#define expandx(W,i) (t = W[i&15] ^ W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15], \
                      ROTL(1, t))
#define expand(W,i) (W[i&15] = expandx(W,i))
#else	/* Old FIPS 180 */
#define expandx(W,i) (W[i&15] ^ W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15])
#define expand(W,i) (W[i&15] ^= W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15])
#endif

/*
 * The prototype SHA sub-round
 *
 * The fundamental sub-round is
 * a' = e + ROTL(5,a) + f(b, c, d) + k + data;
 * b' = a;
 * c' = ROTL(30,b);
 * d' = c;
 * e' = d;
 * ... but this is implemented by unrolling the loop 5 times and renaming
 * the variables (e,a,b,c,d) = (a',b',c',d',e') each iteration.
 */
#define subRound(a, b, c, d, e, f, k, data) \
	( e += ROTL(5,a) + f(b, c, d) + k + data, b = ROTL(30, b) )
/*
 * The above code is replicated 20 times for each of the 4 functions,
 * using the next 20 values from the W[] array for "data" each time.
 */

/*
 * Perform the SHA transformation.  Note that this code, like MD5, seems to
 * break some optimizing compilers due to the complexity of the expressions
 * and the size of the basic block.  It may be necessary to split it into
 * sections, e.g. based on the four subrounds
 *
 * Note that this corrupts the sha->key area.
 * NOTE This is not declared as static because pgpRndPool.c references it.
 * (Sorry for that modularity violation.)
 */

	void
pgpSHATransform(PGPUInt32 *block, PGPUInt32 *key)
{
	register PGPUInt32 A, B, C, D, E;
#if SHA_VERSION
	register PGPUInt32 t;
#endif

	/* Set up first buffer */
	A = block[0];
	B = block[1];
	C = block[2];
	D = block[3];
	E = block[4];

	/* Heavy mangling, in 4 sub-rounds of 20 interations each. */
	subRound( A, B, C, D, E, f1, K2, key[ 0] );
	subRound( E, A, B, C, D, f1, K2, key[ 1] );
	subRound( D, E, A, B, C, f1, K2, key[ 2] );
	subRound( C, D, E, A, B, f1, K2, key[ 3] );
	subRound( B, C, D, E, A, f1, K2, key[ 4] );
	subRound( A, B, C, D, E, f1, K2, key[ 5] );
	subRound( E, A, B, C, D, f1, K2, key[ 6] );
	subRound( D, E, A, B, C, f1, K2, key[ 7] );
	subRound( C, D, E, A, B, f1, K2, key[ 8] );
	subRound( B, C, D, E, A, f1, K2, key[ 9] );
	subRound( A, B, C, D, E, f1, K2, key[10] );
	subRound( E, A, B, C, D, f1, K2, key[11] );
	subRound( D, E, A, B, C, f1, K2, key[12] );
	subRound( C, D, E, A, B, f1, K2, key[13] );
	subRound( B, C, D, E, A, f1, K2, key[14] );
	subRound( A, B, C, D, E, f1, K2, key[15] );
	subRound( E, A, B, C, D, f1, K2, expand(key, 16) );
	subRound( D, E, A, B, C, f1, K2, expand(key, 17) );
	subRound( C, D, E, A, B, f1, K2, expand(key, 18) );
	subRound( B, C, D, E, A, f1, K2, expand(key, 19) );

	subRound( A, B, C, D, E, f2, K3, expand(key, 20) );
	subRound( E, A, B, C, D, f2, K3, expand(key, 21) );
	subRound( D, E, A, B, C, f2, K3, expand(key, 22) );
	subRound( C, D, E, A, B, f2, K3, expand(key, 23) );
	subRound( B, C, D, E, A, f2, K3, expand(key, 24) );
	subRound( A, B, C, D, E, f2, K3, expand(key, 25) );
	subRound( E, A, B, C, D, f2, K3, expand(key, 26) );
	subRound( D, E, A, B, C, f2, K3, expand(key, 27) );
	subRound( C, D, E, A, B, f2, K3, expand(key, 28) );
	subRound( B, C, D, E, A, f2, K3, expand(key, 29) );
	subRound( A, B, C, D, E, f2, K3, expand(key, 30) );
	subRound( E, A, B, C, D, f2, K3, expand(key, 31) );
	subRound( D, E, A, B, C, f2, K3, expand(key, 32) );
	subRound( C, D, E, A, B, f2, K3, expand(key, 33) );
	subRound( B, C, D, E, A, f2, K3, expand(key, 34) );
	subRound( A, B, C, D, E, f2, K3, expand(key, 35) );
	subRound( E, A, B, C, D, f2, K3, expand(key, 36) );
	subRound( D, E, A, B, C, f2, K3, expand(key, 37) );
	subRound( C, D, E, A, B, f2, K3, expand(key, 38) );
	subRound( B, C, D, E, A, f2, K3, expand(key, 39) );

	subRound( A, B, C, D, E, f3, K5, expand(key, 40) );
	subRound( E, A, B, C, D, f3, K5, expand(key, 41) );
	subRound( D, E, A, B, C, f3, K5, expand(key, 42) );
	subRound( C, D, E, A, B, f3, K5, expand(key, 43) );
	subRound( B, C, D, E, A, f3, K5, expand(key, 44) );
	subRound( A, B, C, D, E, f3, K5, expand(key, 45) );
	subRound( E, A, B, C, D, f3, K5, expand(key, 46) );
	subRound( D, E, A, B, C, f3, K5, expand(key, 47) );
	subRound( C, D, E, A, B, f3, K5, expand(key, 48) );
	subRound( B, C, D, E, A, f3, K5, expand(key, 49) );
	subRound( A, B, C, D, E, f3, K5, expand(key, 50) );
	subRound( E, A, B, C, D, f3, K5, expand(key, 51) );
	subRound( D, E, A, B, C, f3, K5, expand(key, 52) );
	subRound( C, D, E, A, B, f3, K5, expand(key, 53) );
	subRound( B, C, D, E, A, f3, K5, expand(key, 54) );
	subRound( A, B, C, D, E, f3, K5, expand(key, 55) );
	subRound( E, A, B, C, D, f3, K5, expand(key, 56) );
	subRound( D, E, A, B, C, f3, K5, expand(key, 57) );
	subRound( C, D, E, A, B, f3, K5, expand(key, 58) );
	subRound( B, C, D, E, A, f3, K5, expand(key, 59) );

	subRound( A, B, C, D, E, f4, K10, expand(key, 60) );
	subRound( E, A, B, C, D, f4, K10, expand(key, 61) );
	subRound( D, E, A, B, C, f4, K10, expand(key, 62) );
	subRound( C, D, E, A, B, f4, K10, expand(key, 63) );
	subRound( B, C, D, E, A, f4, K10, expand(key, 64) );
	subRound( A, B, C, D, E, f4, K10, expand(key, 65) );
	subRound( E, A, B, C, D, f4, K10, expand(key, 66) );
	subRound( D, E, A, B, C, f4, K10, expand(key, 67) );
	subRound( C, D, E, A, B, f4, K10, expand(key, 68) );
	subRound( B, C, D, E, A, f4, K10, expand(key, 69) );
	subRound( A, B, C, D, E, f4, K10, expand(key, 70) );
	subRound( E, A, B, C, D, f4, K10, expand(key, 71) );
	subRound( D, E, A, B, C, f4, K10, expand(key, 72) );
	subRound( C, D, E, A, B, f4, K10, expand(key, 73) );
	subRound( B, C, D, E, A, f4, K10, expand(key, 74) );
	subRound( A, B, C, D, E, f4, K10, expand(key, 75) );
	subRound( E, A, B, C, D, f4, K10, expand(key, 76) );
	subRound( D, E, A, B, C, f4, K10, expandx(key, 77) );
	subRound( C, D, E, A, B, f4, K10, expandx(key, 78) );
	subRound( B, C, D, E, A, f4, K10, expandx(key, 79) );

	/* Build message digest */
	block[0] += A;
	block[1] += B;
	block[2] += C;
	block[3] += D;
	block[4] += E;
}

/* Update SHA for a block of data. */

	void
pgpSHAUpdate(PGPSHAContext *ctx, void const *bufIn, PGPSize len)
{
	PGPByte *buf = (PGPByte *) bufIn;
	unsigned i;

	/* Update bitcount */

#if PGP_HAVE64 
	i = (unsigned)ctx->bytes % PGP_SHA_BLOCKBYTES;
	ctx->bytes += len;
#else
	PGPUInt32 t = ctx->bytesLo;
	if ( ( ctx->bytesLo = t + len ) < t )
		ctx->bytesHi++;	/* Carry from low to high */

	i = (unsigned)t % PGP_SHA_BLOCKBYTES; /* Bytes already in ctx->key */
#endif

	/* i is always less than PGP_SHA_BLOCKBYTES. */
	if (PGP_SHA_BLOCKBYTES-i > len) {
		pgpCopyMemory(buf, (PGPByte *)ctx->key + i, len);
		return;
	}

	if (i) {	/* First chunk is an odd size */
		pgpCopyMemoryNO( buf, (PGPByte *)ctx->key + i, PGP_SHA_BLOCKBYTES - i );
		shaByteSwap(ctx->key, (PGPByte *)ctx->key, PGP_SHA_BLOCKWORDS);
		pgpSHATransform(ctx->iv, ctx->key);
		buf += PGP_SHA_BLOCKBYTES-i;
		len -= PGP_SHA_BLOCKBYTES-i;
	}

	/* Process data in 64-byte chunks */
	while (len >= PGP_SHA_BLOCKBYTES) {
		shaByteSwap(ctx->key, buf, PGP_SHA_BLOCKWORDS);
		pgpSHATransform(ctx->iv, ctx->key);
		buf += PGP_SHA_BLOCKBYTES;
		len -= PGP_SHA_BLOCKBYTES;
	}

	/* Handle any remaining bytes of data. */
	if (len)
		pgpCopyMemory(buf, ctx->key, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
	void const *
pgpSHAFinalize(PGPSHAContext *ctx)
{
	PGPByte *digest;
#if PGP_HAVE64 
	unsigned i = (unsigned)ctx->bytes % PGP_SHA_BLOCKBYTES;
#else
	unsigned i = (unsigned)ctx->bytesLo % PGP_SHA_BLOCKBYTES;
#endif
	PGPByte *p = (PGPByte *)ctx->key + i;	/* First unused byte */
	PGPUInt32 t;

	/* Set the first char of padding to 0x80.  There is always room. */
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes (0..63) */
	i = PGP_SHA_BLOCKBYTES - 1 - i;

	if (i < 8) {	/* Padding forces an extra block */
		pgpClearMemory( p,  i);
		shaByteSwap(ctx->key, (PGPByte *)ctx->key, 16);
		pgpSHATransform(ctx->iv, ctx->key);
		p = (PGPByte *)ctx->key;
		i = 64;
	}
	pgpClearMemory( p,  i-8);
	shaByteSwap(ctx->key, (PGPByte *)ctx->key, 14);

	/* Append length in bits and transform */
#if PGP_HAVE64 
	ctx->key[14] = (PGPUInt32)(ctx->bytes >> 29);
	ctx->key[15] = (PGPUInt32)ctx->bytes << 3;
#else
	ctx->key[14] = ctx->bytesHi << 3 | ctx->bytesLo >> 29;
	ctx->key[15] = ctx->bytesLo << 3;
#endif
	pgpSHATransform(ctx->iv, ctx->key);

	digest = (PGPByte *)ctx->iv;
	for (i = 0; i < PGP_SHA_HASHWORDS; i++) {
		t = ctx->iv[i];
		digest[0] = (PGPByte)(t >> 24);
		digest[1] = (PGPByte)(t >> 16);
		digest[2] = (PGPByte)(t >> 8);
		digest[3] = (PGPByte)t;
		digest += 4;
	}
	/* In case it's sensitive */
/* XXX	pgpClearMemory( ctx,  sizeof(ctx)); */
	return (PGPByte const *)ctx->iv;
}

/* 
   the following function is used for the 'G' function in DSA random
   generation - it does not pad with a 1 or include the byte length.
*/

#if 0
/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first) */
/* FIPS140 state Finalize SHA1 hash */
static void const *
shaDSAFinal(void *priv)
{
	PGPSHAContext *ctx = (PGPSHAContext *)priv;
	PGPByte *digest;
#if PGP_HAVE64 
	unsigned i = (unsigned)ctx->bytes % PGP_SHA_BLOCKBYTES;
#else
	unsigned i = (unsigned)ctx->bytesLo % PGP_SHA_BLOCKBYTES;
#endif
	PGPByte *p = (PGPByte *)ctx->key + i;	/* First unused byte */
	PGPUInt32 t;

#if !PGP_FIPS140
	/* this code is what we leave out for FIPS
	   'G' function definition.  */
	/* here is the code to remove for DSA randomization */
	/* Set the first char of padding to 0x80.  There is always room. */
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes (0..63) */
	i = PGP_SHA_BLOCKBYTES - 1 - i;

	if (i < 8) {	/* Padding forces an extra block */
		pgpClearMemory( p,  i);
		shaByteSwap(ctx->key, (PGPByte *)ctx->key, 16);
		pgpSHATransform(ctx->iv, ctx->key);
		p = (PGPByte *)ctx->key;
		i = 64;
	}
	pgpClearMemory( p,  i-8);
	shaByteSwap(ctx->key, (PGPByte *)ctx->key, 14);

	/* Append length in bits and transform */
#if PGP_HAVE64 
	ctx->key[14] = (PGPUInt32)(ctx->bytes >> 29);
	ctx->key[15] = (PGPUInt32)ctx->bytes << 3;
#else
	ctx->key[14] = ctx->bytesHi << 3 | ctx->bytesLo >> 29;
	ctx->key[15] = ctx->bytesLo << 3;
#endif
	pgpSHATransform(ctx->iv, ctx->key);

#endif
	digest = (PGPByte *)ctx->iv;
	for (i = 0; i < PGP_SHA_HASHWORDS; i++) {
		t = ctx->iv[i];
		digest[0] = (PGPByte)(t >> 24);
		digest[1] = (PGPByte)(t >> 16);
		digest[2] = (PGPByte)(t >> 8);
		digest[3] = (PGPByte)t;
		digest += 4;
	}
	/* In case it's sensitive */
/* XXX	pgpClearMemory( ctx,  sizeof(ctx)); */
	return (PGPByte const *)ctx->iv;
}

/* TODO - need to make sure that all of the
   following is correct... */
/* special variant of SHA used by FIPS compliant
   DSA during parameter generation */
const PGPHashVTBL  HashDSASHA = {
	PGPTXT_MACHINE("DSASHA1"), kPGPHashAlgorithm_SHA,
	SHADERprefix, sizeof(SHADERprefix),
	PGP_SHA_HASHBYTES,
	sizeof(PGPSHAContext),
	sizeof(struct{char _a; PGPSHAContext _b;}) -
		sizeof(PGPSHAContext),
	shaInitDSA, shaUpdate, shaDSAFinal
};

#endif

/*
 * SHA.1 has an OID of 1.3.14.3.2.26
 * (From the 1994 Open Systems Environment Implementor's Workshop (OIW))
 * The rest of the format is stolen from MD5.  Do we need the @#$@$
 * NULL in there?
 */
PGPByte const SHADERprefix[] = {
	0x30, /* Universal, Constructed, Sequence */
	0x21, /* Length 33 (bytes following) */
		0x30, /* Universal, Constructed, Sequence */
		0x09, /* Length 9 */
			0x06, /* Universal, Primitive, object-identifier */
			0x05, /* Length 8 */
				43, /* 43 = ISO(1)*40 + 3 */
				14,
				3,
				2,
				26,
			0x05, /* Universal, Primitive, NULL */
			0x00, /* Length 0 */
		0x04, /* Universal, Primitive, Octet string */
		0x14 /* Length 20 */
			/* 20 SHA.1 digest bytes go here */
};

#ifdef TESTMAIN

/* ----------------------------- SHA Test code --------------------------- */
#include <stdio.h>
#include <stdlib.h>	/* For exit() */
#include <time.h>

/* Size of buffer for SHA speed test data */

#define TEST_BLOCK_SIZE	( SHA_HASHBYTES * 100 )

/* Number of bytes of test data to process */

#define TEST_BYTES	10000000L
#define TEST_BLOCKS	( TEST_BYTES / TEST_BLOCK_SIZE )

#if SHA_VERSION
static char const *shaTestResults[] = {
	PGPTXT_PROGRAMMER8("A9993E364706816ABA3E25717850C26C9CD0D89D"),
	PGPTXT_PROGRAMMER8("84983E441C3BD26EBAAE4AA1F95129E5E54670F1"),
	PGPTXT_PROGRAMMER8("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"),
	PGPTXT_PROGRAMMER8("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"),
	PGPTXT_PROGRAMMER8("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F") };
#else
static char const *shaTestResults[] = {
	PGPTXT_PROGRAMMER8("0164B8A914CD2A5E74C4F7FF082C4D97F1EDF880"),
	PGPTXT_PROGRAMMER8("D2516EE1ACFA5BAF33DFC1C471E438449EF134C8"),
	PGPTXT_PROGRAMMER8("3232AFFA48628A26653B5AAA44541FD90D690603"),
	PGPTXT_PROGRAMMER8("3232AFFA48628A26653B5AAA44541FD90D690603"),
	PGPTXT_PROGRAMMER8("3232AFFA48628A26653B5AAA44541FD90D690603") };
#endif

static int
compareSHAresults(PGPByte const *hash, int level)
{
	char buf[41];
	int i;

	for (i = 0; i < SHA_HASHBYTES; i++)
		sprintf(buf+2*i, PGPTXT_PROGRAMMER8("%02X"), hash[i]);

	if (strcmp(buf, shaTestResults[level-1]) == 0) {
		printf(PGPTXT_PROGRAMMER8("Test %d passed, result = %s\n"), level, buf);
		return 0;
	} else {
		printf(PGPTXT_PROGRAMMER8(
				"Error in SHA implementation: Test %d failed\n"), level);
		printf(PGPTXT_PROGRAMMER8("  Result = %s\n"), buf);
		printf(PGPTXT_PROGRAMMER8("Expected = %s\n"), shaTestResults[level-1]);
		return -1;
	}
}


int
main(void)
{
	PGPSHAContext sha;
	PGPByte data[TEST_BLOCK_SIZE];
	byte const *	hash;
	clock_t ticks;
	long i;

	/*
	 * Test output data (these are the only test data given in the
	 * Secure Hash Standard document, but chances are if it works
	 * for this it'll work for anything)
	 */
	shaInit(&sha);
	shaUpdate(&sha, (PGPByte *)"abc", 3);
	hash	= shaFinal(&sha);
	if (compareSHAresults(hash, 1) < 0)
		exit (-1);

	shaInit(&sha);
	shaUpdate(&sha, (PGPByte *)"abcdbcdecdefdefgefghfghighijhijki\
jkljklmklmnlmnomnopnopq", 56);
	hash	= shaFinal(&sha);
	if (compareSHAresults(hash, 2) < 0)
		exit (-1);

	/* 1,000,000 bytes of ASCII 'a' (0x61), by 64's */
	shaInit(&sha);
	for (i = 0; i < 15625; i++)
		shaUpdate(&sha, (PGPByte *)"aaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64);
	hash	= shaFinal(&sha);
	if (compareSHAresults(hash, 3) < 0)
		exit (-1);

	/* 1,000,000 bytes of ASCII 'a' (0x61), by 25's */
	shaInit(&sha);
	for (i = 0; i < 40000; i++)
		shaUpdate(&sha, (PGPByte *)"aaaaaaaaaaaaaaaaaaaaaaaaa", 25);
	shaFinal(&sha, hash);
	if (compareSHAresults(hash, 4) < 0)
		exit (-1);

	/* 1,000,000 bytes of ASCII 'a' (0x61), by 125's */
	shaInit(&sha);
	for (i = 0; i < 8000; i++)
		shaUpdate(&sha, (PGPByte *)"aaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 125);
	, hashshaFinal(&sha);
	if (compareSHAresults(hash, 5) < 0)
		exit (-1);

	/* Now perform time trial, generating MD for 10MB of data.  First,
	   initialize the test data */
	pgpClearMemory( data,  TEST_BLOCK_SIZE);

	/* Get start time */
	printf(PGPTXT_PROGRAMMER8(
			"SHA time trial.  Processing %ld characters...\n"), TEST_BYTES);
	ticks = clock();

	/* Calculate SHA message digest in TEST_BLOCK_SIZE byte blocks */
	shaInit(&sha);
	for (i = TEST_BLOCKS; i > 0; i--)
		shaUpdate(&sha, data, TEST_BLOCK_SIZE);
	hash	= shaFinal(&sha);

	/* Get finish time and print difference */
	ticks = clock() - ticks;
	printf(PGPTXT_PROGRAMMER8("Ticks to process test input: %lu\n"), 
			(unsigned long)ticks);

	return 0;
}
#endif /* Test driver */
