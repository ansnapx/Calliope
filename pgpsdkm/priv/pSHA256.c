/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pSHA256.c 20640 2004-02-10 01:53:41Z ajivsov $
____________________________________________________________________________*/

#include "pgpConfig.h"
#include <string.h>

#include "pgpHash.h"
#include "pgpSHA2.h"
#include "pgpDebug.h"

typedef PGPUInt32 sha256_word;
#define SHA256_BITS_IN_WORD 32

#ifdef SHA256_BIG_ENDIAN
#define swap_sha256_word(x) x
#else
#define swap_sha256_word(x)	\
	(sha256_word)(	\
		(( ((PGPByte*)&(x))[0] << 8 | ((PGPByte*)&(x))[1] ) << 16 ) |	\
		   ((PGPByte*)&(x))[2] << 8 | ((PGPByte*)&(x))[3] )
#endif

/* right rotation of x by n bits */
#define S(x,n) ( ((x)>>(n)) | ((x)<<(SHA256_BITS_IN_WORD-(n))) )

typedef sha256_word sha256_message[16];

/* SHA 256 constants */
static const sha256_word K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5, 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3, 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc, 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7, 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13, 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3, 0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5, 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208, 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* 256 bit SHA register set */
typedef struct SHA256_REGS_  
{
	sha256_word a;
	sha256_word b;
	sha256_word c;
	sha256_word d;
	sha256_word e;
	sha256_word f;
	sha256_word g;
	sha256_word h;
} SHA256_REGS;

/* 64 bit message length */
typedef struct SHA256_LENGTH_  
{
	PGPUInt32 low;
	PGPUInt32 high;
} SHA256_LENGTH;
typedef SHA256_LENGTH sha256_length;	
/* sha256_length type can be made native 64 bit type for >64 bit platforms */

#ifdef SHA256_TEST
static void
sha256_print(SHA256_REGS *H)  
{
	printf( PGPTXT_DEBUG8("%08x %08x %08x %08x  %08x %08x %08x %08x\n"),  
		H->a, H->b, H->c, H->d,  H->e, H->f, H->g, H->h
	);
}
#define SHA256_PRINT(H) sha256_print(H)
#else
#define SHA256_PRINT(H) 
#endif


static void sha256WordSwapInPlace(sha256_word * const s, unsigned words)
{
	while(words--) 
		s[words] = swap_sha256_word(s[words]);
}

#if 0
static void sha256WordSwap(sha256_word * const dest, 
						   const sha256_word * const src, unsigned words)
{
	while(words--) 
		dest[words] = swap_sha256_word(src[words]);
}
#endif


static void sha256Add( sha256_length *l, unsigned u )  
{
	PGPUInt32 t;

	t = l->low;
	if ( ( l->low = t + u ) < t )
		l->high++;	/* Carry from low to high */
}

static void sha256Mul8( sha256_length *l )  
{
	l->high = (l->high << 3) | (l->low >> (SHA256_BITS_IN_WORD-3));
	l->low <<= 3;
}

static void sha256_init( SHA256_REGS * const H )  
{
	/* initialise SHA registers */
	H->a = 0x6a09e667;
	H->b = 0xbb67ae85;
	H->c = 0x3c6ef372;
	H->d = 0xa54ff53a;
	H->e = 0x510e527f;
	H->f = 0x9b05688c;
	H->g = 0x1f83d9ab;
	H->h = 0x5be0cd19;
}

/* Processes 512 bit message block M. 
  
	Words in M are big endian, so this function performs word swap. Placing 
	swap here saves one memcpy.

   No partial blocks here (padding is not performed in this function) */
static void sha256_process( SHA256_REGS * const H, const sha256_message M[] )  
{
	int t;				/* counter */

	sha256_word T1, T2;	/* temporary variable */
	sha256_word W[64];	/* 64*32=2748 bit message schedule */

	SHA256_REGS r = *H;			

	/* fill message schedule W[i], i=[0..15], swapping words */
	W[0] = swap_sha256_word( ((sha256_word*)M)[0] );
	W[1] = swap_sha256_word( ((sha256_word*)M)[1] );
	W[2] = swap_sha256_word( ((sha256_word*)M)[2] );
	W[3] = swap_sha256_word( ((sha256_word*)M)[3] );
	W[4] = swap_sha256_word( ((sha256_word*)M)[4] );
	W[5] = swap_sha256_word( ((sha256_word*)M)[5] );
	W[6] = swap_sha256_word( ((sha256_word*)M)[6] );
	W[7] = swap_sha256_word( ((sha256_word*)M)[7] );
	W[8] = swap_sha256_word( ((sha256_word*)M)[8] );
	W[9] = swap_sha256_word( ((sha256_word*)M)[9] );
	W[10] = swap_sha256_word( ((sha256_word*)M)[10] );
	W[11] = swap_sha256_word( ((sha256_word*)M)[11] );
	W[12] = swap_sha256_word( ((sha256_word*)M)[12] );
	W[13] = swap_sha256_word( ((sha256_word*)M)[13] );
	W[14] = swap_sha256_word( ((sha256_word*)M)[14] );
	W[15] = swap_sha256_word( ((sha256_word*)M)[15] );

	/* fill message schedule W[i], i=[16..63] */
	for( t=16; t<64; t++ )  {
		T1 = W[t-2];
		W[t] = ( S(T1,17) ^ S(T1,19) ^ (T1>>10) )	/* sigma1( W[t-1] ) */ +
			W[t-7] + W[t-16];

		T1 = W[t-15];
		W[t] += S(T1,7) ^ S(T1,18) ^ (T1 >> 3);		/* sigma0( W[t-15] ) */
	}

	/* hash */
	for( t=0; t<64; t++ )  {
		T1 = r.h +
			( S(r.e,6) ^ S(r.e,11) ^ S(r.e,25) )		/* Sum1(e) */ +
			( (r.e & r.f) ^ ((~r.e) & r.g)) +			/* Ch(e,f,g) */
			K[t] + W[t];

		T2 = ( S(r.a,2) ^ S(r.a,13) ^ S(r.a,22) )		/* Sum0(a) */ +
			( (r.a & r.b) ^ (r.a & r.c) ^ (r.b & r.c) );/* Maj(a,b,c) */

		r.h = r.g;
		r.g = r.f;
		r.f = r.e;
		r.e = r.d + T1;
		r.d = r.c;
		r.c = r.b;
		r.b = r.a;
		r.a = T1 + T2;
/*
#ifdef SHA256_TEST
		printf( PGPTXT_DEBUG8("[%02d] "), t );
		SHA256_PRINT(&r);
#endif
*/
	}

	/* finally, add new registers to old; result becomes new hash */

	/* unroll this loop */
	H->a += r.a;
	H->b += r.b;
	H->c += r.c;
	H->d += r.d;
	H->e += r.e;
	H->f += r.f;
	H->g += r.g;
	H->h += r.h;

/*	SHA256_PRINT(H); */
}

/* processes up to 512 bit message block M, output is a 256 bit hash in H. 
   Words in M are big endian. 
   Exact length of M in bytes is in 'length'. 
   Total hashed length is in total_length, also in bytes. 
   Length is expected to always be even to 8 bit (because we work with bytes) 
*/
static void sha256_finalize( SHA256_REGS * const H, 
					 const sha256_message M[] /* points to double size buffer */, 
					 unsigned length, sha256_length * const total_length )  
{
	int padding_length;
	unsigned two=0;

	pgpAssert( length < 512 );

	((PGPByte *)M)[length] = 0x80;

	/* padding_length = block size - length(M) - length(10000000b) - length(total_length) */
	padding_length = 512/8 - length - 1 - 64/8;

	if( padding_length < 0 ) { 	/* extra block */
		padding_length += 512/8;
		two = 1;
	}

	memset( (PGPByte *)M+length+1, 0, padding_length );

	sha256Mul8( total_length );	/* total_length *= 8 */

	( (sha256_word *)((PGPByte *)M+length+1+padding_length) )[0] = swap_sha256_word( total_length->high );
	( (sha256_word *)((PGPByte *)M+length+1+padding_length) )[1] = swap_sha256_word( total_length->low );

	sha256_process( H, M );
	if( two )
		sha256_process( H, M+1 );

	sha256WordSwapInPlace( (sha256_word*)H, sizeof(*H)/sizeof(sha256_word) );
}


/* *************************** Inteface with PGPsdk ************************ */

typedef struct PGPSHA256Context_
{
	sha256_message M[2];/* partial message block */
	SHA256_REGS H;		/* SHA-256 registers */
	sha256_length l;	/* 64 bit length */
} PGPSHA256Context;

/* Initialize the SHA values */
static void
pgpSHA256Init(void *priv)
{
	PGPSHA256Context *ctx = (PGPSHA256Context *)priv;
#if PGP_DEBUG
	memset( ctx, 0xcd, sizeof(ctx) );
#endif
	ctx->l.low = ctx->l.high = 0;
	sha256_init( &(ctx->H) );
}


/* Update SHA for a block of data. */
static void
pgpSHA256Update( void *priv, void const *bufIn, PGPSize len)
{
	PGPSHA256Context *ctx = (PGPSHA256Context *)priv;
	unsigned const old_tail=(unsigned)(ctx->l.low & (512/8 - 1));

	unsigned blocks;
	unsigned tail;
	unsigned i;

	const PGPByte *buf = bufIn;

	sha256Add( &(ctx->l), len );		/* first, update number of processed bytes */

	i = sizeof(sha256_message)-old_tail;	/* bytes to add to the message block */

	if( i>len )  {	/* still have no complete block */
		pgpCopyMemoryNO( buf, ((PGPByte*)ctx->M) + old_tail, len );
		return;
	}

	if( old_tail ) {
		pgpCopyMemoryNO( buf, ((PGPByte*)ctx->M) + old_tail, i );
		buf += i;
		len -= i;

		sha256_process( &(ctx->H), (const sha256_message*)ctx->M );
	}
	
	blocks =  len / (512/8);
	tail = len & (512/8 - 1);

	for( i=0; i<blocks; i++ )  
		sha256_process( &(ctx->H), ((const sha256_message*)buf)+i );

	if( tail )
		pgpCopyMemoryNO( ((const sha256_message*)buf)+blocks, ctx->M, tail );
}

#ifdef SHA256_TEST
/* prints SHA-256 result after pgpSHA256Finalize was called, or 
   prints intermediate SHA-256 registers */
static void pgpSHA256Print( PGPSHA256Context *ctx )  {
	sha256_print( &(ctx->H) );
}
#endif

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void const *
pgpSHA256Finalize(void *priv)
{
	PGPSHA256Context *ctx = (PGPSHA256Context *)priv;
	sha256_finalize( &(ctx->H), (const sha256_message *)ctx->M, (unsigned)(ctx->l.low & (512/8 - 1)), &(ctx->l) );
	return &(ctx->H);
}

/*
 * SHA256 has an OID of 2.16.840.1.101.3.4.2.1. 
 * From draft-ietf-openpgp-rfc2440bis-03.txt
 */
static PGPByte const SHA256DERprefix[] = {
	0x30, /* Universal, Constructed, Sequence */
	0x31, /* Length 49 (bytes following) */
		0x30, /* Universal, Constructed, Sequence */
		0x0d, /* Length 13 */
			0x06, /* Universal, Primitive, object-identifier */
			0x09, /* Length 9 */
				96, /* 96 = ISO(2)*40 + 16 */
				0x86, 0x48,
				1,
				101,
				3,
				4,
				2,
				1,
			0x05, /* Universal, Primitive, NULL */
			0x00, /* Length 0 */
		0x04,	/* Universal, Primitive, Octet string */
		0x20	/* Length 32 */
				/* 32 SHA256 digest bytes go here */
};

PGPHashVTBL const HashSHA256 = {
	PGPTXT_MACHINE("SHA256"), kPGPHashAlgorithm_SHA256,
	SHA256DERprefix, sizeof(SHA256DERprefix),
	256/8,
	512/8, 
	sizeof(PGPSHA256Context),
	sizeof(struct{char _a; PGPSHA256Context _b;}) -
		sizeof(PGPSHA256Context),
	pgpSHA256Init, pgpSHA256Update, pgpSHA256Finalize
};

#ifdef SHA256_TEST
void main()  
{
	unsigned i;

	PGPByte test1[] = PGPTXT_DEBUG8("abc");
	PGPByte test2[] = PGPTXT_DEBUG8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	PGPByte test3[sizeof(sha256_message)];

	PGPSHA256Context ctx;

	printf(PGPTXT_DEBUG8("Beginning SHA 256 test\n"));

	pgpSHA256Init( &ctx );
	pgpSHA256Update( &ctx, test1, sizeof(test1)-1 );
	pgpSHA256Finalize( &ctx );
	pgpSHA256Print( &ctx );

	pgpSHA256Init( &ctx );
	pgpSHA256Update( &ctx, test2, sizeof(test2)-1 );
	pgpSHA256Finalize( &ctx );
	pgpSHA256Print( &ctx );

	memset(test3, 'a', sizeof(test3));
	pgpSHA256Init( &ctx );
	for( i=1000000; i>=sizeof(test3); i-=sizeof(test3) )
		pgpSHA256Update( &ctx, test3, sizeof(test3) );
	pgpSHA256Update( &ctx, test3, i );
	pgpSHA256Finalize( &ctx );
	pgpSHA256Print( &ctx );

	getchar();
}
#endif
