/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

  Implementation of SHA 384 and SHA 512 for platforms which have 64 bit type. 
  64 bit hardware platform is not required for this module to work correctly, 
  only existence of the compiler-supported uint64 type. 

  Use file sha384_512.c on all other platforms. 

	$Id: pSHA5122.c 20640 2004-02-10 01:53:41Z ajivsov $
____________________________________________________________________________*/

#include "pgpConfig.h"
#include <string.h>

#include "pgpHash.h"
#include "pgpSHA2.h"

#include "pgpDebug.h"

#if PGP_HAVE64 /* [ */

typedef PGPUInt64 sha512_word;
#define SHA512_BITS_IN_WORD 64

#ifdef SHA512_BIG_ENDIAN
#define swap_sha512_word(d,s) *(d)=*(s)
#else
static void swap_sha512_word(const sha512_word *d, sha512_word *s) {
	((PGPByte*)d)[0] = ((PGPByte*)s)[7];
	((PGPByte*)d)[1] = ((PGPByte*)s)[6];
	((PGPByte*)d)[2] = ((PGPByte*)s)[5];
	((PGPByte*)d)[3] = ((PGPByte*)s)[4];
	((PGPByte*)d)[4] = ((PGPByte*)s)[3];
	((PGPByte*)d)[5] = ((PGPByte*)s)[2];
	((PGPByte*)d)[6] = ((PGPByte*)s)[1];
	((PGPByte*)d)[7] = ((PGPByte*)s)[0];
}
#endif

/* LC is used to define 64 bit constant */
#if PGP_WIN32
#define LC( c ) c
#else
/* fixes gcc warning */
#define LC( c ) c##L
#endif

/* right rotation of x by n bits */
#define S(x,n) ( ((x)>>(n)) | ((x)<<(SHA512_BITS_IN_WORD-(n))) )

typedef sha512_word sha512_message[16];	/* 1024 bit message */

/* constant words for SHA 384 and SHA 512 */
static const sha512_word K[80] = {
	LC(0x428a2f98d728ae22UL),LC(0x7137449123ef65cdUL),LC(0xb5c0fbcfec4d3b2fUL),LC(0xe9b5dba58189dbbcUL),
	LC(0x3956c25bf348b538UL),LC(0x59f111f1b605d019UL),LC(0x923f82a4af194f9bUL),LC(0xab1c5ed5da6d8118UL),
	LC(0xd807aa98a3030242UL),LC(0x12835b0145706fbeUL),LC(0x243185be4ee4b28cUL),LC(0x550c7dc3d5ffb4e2UL),
	LC(0x72be5d74f27b896fUL),LC(0x80deb1fe3b1696b1UL),LC(0x9bdc06a725c71235UL),LC(0xc19bf174cf692694UL),
	LC(0xe49b69c19ef14ad2UL),LC(0xefbe4786384f25e3UL),LC(0x0fc19dc68b8cd5b5UL),LC(0x240ca1cc77ac9c65UL),
	LC(0x2de92c6f592b0275UL),LC(0x4a7484aa6ea6e483UL),LC(0x5cb0a9dcbd41fbd4UL),LC(0x76f988da831153b5UL),
	LC(0x983e5152ee66dfabUL),LC(0xa831c66d2db43210UL),LC(0xb00327c898fb213fUL),LC(0xbf597fc7beef0ee4UL),
	LC(0xc6e00bf33da88fc2UL),LC(0xd5a79147930aa725UL),LC(0x06ca6351e003826fUL),LC(0x142929670a0e6e70UL),
	LC(0x27b70a8546d22ffcUL),LC(0x2e1b21385c26c926UL),LC(0x4d2c6dfc5ac42aedUL),LC(0x53380d139d95b3dfUL),
	LC(0x650a73548baf63deUL),LC(0x766a0abb3c77b2a8UL),LC(0x81c2c92e47edaee6UL),LC(0x92722c851482353bUL),
	LC(0xa2bfe8a14cf10364UL),LC(0xa81a664bbc423001UL),LC(0xc24b8b70d0f89791UL),LC(0xc76c51a30654be30UL),
	LC(0xd192e819d6ef5218UL),LC(0xd69906245565a910UL),LC(0xf40e35855771202aUL),LC(0x106aa07032bbd1b8UL),
	LC(0x19a4c116b8d2d0c8UL),LC(0x1e376c085141ab53UL),LC(0x2748774cdf8eeb99UL),LC(0x34b0bcb5e19b48a8UL),
	LC(0x391c0cb3c5c95a63UL),LC(0x4ed8aa4ae3418acbUL),LC(0x5b9cca4f7763e373UL),LC(0x682e6ff3d6b2b8a3UL),
	LC(0x748f82ee5defb2fcUL),LC(0x78a5636f43172f60UL),LC(0x84c87814a1f0ab72UL),LC(0x8cc702081a6439ecUL),
	LC(0x90befffa23631e28UL),LC(0xa4506cebde82bde9UL),LC(0xbef9a3f7b2c67915UL),LC(0xc67178f2e372532bUL),
	LC(0xca273eceea26619cUL),LC(0xd186b8c721c0c207UL),LC(0xeada7dd6cde0eb1eUL),LC(0xf57d4f7fee6ed178UL),
	LC(0x06f067aa72176fbaUL),LC(0x0a637dc5a2c898a6UL),LC(0x113f9804bef90daeUL),LC(0x1b710b35131c471bUL),
	LC(0x28db77f523047d84UL),LC(0x32caab7b40c72493UL),LC(0x3c9ebe0a15c9bebcUL),LC(0x431d67c49c100d4cUL),
	LC(0x4cc5d4becb3e42b6UL),LC(0x597f299cfc657e2aUL),LC(0x5fcb6fab3ad6faecUL),LC(0x6c44198c4a475817UL)
};

/* 256 bit SHA register set */
typedef struct SHA512_REGS_  {
	sha512_word a;
	sha512_word b;
	sha512_word c;
	sha512_word d;
	sha512_word e;
	sha512_word f;
	sha512_word g;
	sha512_word h;
} SHA512_REGS;

/* 128 bit length */
typedef struct SHA512_LENGTH_  {
	PGPUInt64 low;
	PGPUInt64 high;
} SHA512_LENGTH;
typedef SHA512_LENGTH sha512_length;	

#ifdef SHA512_TEST
static void
sha512_print(SHA512_REGS *H)  {
#ifdef _MSC_VER
	printf( PGPTXT_DEBUG8("%016I64x %016I64x %016I64x %016I64x\n%016I64x %016I64x %016I64x %016I64x\n"),  
		H->a, H->b, H->c, H->d,  H->e, H->f, H->g, H->h
	);
#else
	printf( PGPTXT_DEBUG8("--------%08x --------%08x --------%08x --------%08x\n")
		    PGPTXT_DEBUG8("--------%08x --------%08x --------%08x --------%08x\n"),
		(unsigned)H->a, (unsigned)H->b, (unsigned)H->c, (unsigned)H->d,  
		(unsigned)H->e, (unsigned)H->f, (unsigned)H->g, (unsigned)H->h
	);
#endif
}
#define SHA512_PRINT(H) sha512_print(H)
#else
#define SHA512_PRINT(H) 
#endif


/* Shuffle the bytes into big-endian order within words, as per the
   SHA spec. 
 */
#ifndef SHA512_BIG_ENDIAN
static void sha512_64WordSwapInPlace(sha512_word * s, unsigned words)
{
	unsigned t;

	while(words--)  {
		t = ((PGPByte*)s)[0]; ((PGPByte*)s)[0] = ((PGPByte*)s)[7]; ((PGPByte*)s)[7] = t;
		t = ((PGPByte*)s)[1]; ((PGPByte*)s)[1] = ((PGPByte*)s)[6]; ((PGPByte*)s)[6] = t;
		t = ((PGPByte*)s)[2]; ((PGPByte*)s)[2] = ((PGPByte*)s)[5]; ((PGPByte*)s)[5] = t;
		t = ((PGPByte*)s)[3]; ((PGPByte*)s)[3] = ((PGPByte*)s)[4]; ((PGPByte*)s)[4] = t;
		s++;
	}
}
#else
#define sha512_64WordSwapInPlace(s, words)
#endif

static void sha512Add( sha512_length *l, unsigned u )  {
	PGPUInt64 t;

	t = l->low;
	if ( ( l->low = t + u ) < t )
		l->high++;	/* Carry from low to high */
}

static void sha512Mul8( sha512_length *l )  {
	l->high = (l->high << 3) | (l->low >> (SHA512_BITS_IN_WORD-3));
	l->low <<= 3;
}


/* initialise SHA registers */
static void sha384_init( SHA512_REGS * const H )  
{
	H->a = LC(0xcbbb9d5dc1059ed8UL);
	H->b = LC(0x629a292a367cd507UL);
	H->c = LC(0x9159015a3070dd17UL);
	H->d = LC(0x152fecd8f70e5939UL);
	H->e = LC(0x67332667ffc00b31UL);
	H->f = LC(0x8eb44a8768581511UL);
	H->g = LC(0xdb0c2e0d64f98fa7UL);
	H->h = LC(0x47b5481dbefa4fa4UL);
}
static void sha512_init( SHA512_REGS * const H )  
{
	H->a = LC(0x6a09e667f3bcc908UL);
	H->b = LC(0xbb67ae8584caa73bUL);
	H->c = LC(0x3c6ef372fe94f82bUL);
	H->d = LC(0xa54ff53a5f1d36f1UL);
	H->e = LC(0x510e527fade682d1UL);
	H->f = LC(0x9b05688c2b3e6c1fUL);
	H->g = LC(0x1f83d9abfb41bd6bUL);
	H->h = LC(0x5be0cd19137e2179UL);
}

/* Processes 512 bit message block M. 
  
	Words in M are big endian, so this function performs word swap. Placing 
	swap here saves one memcpy.

   No partial blocks here (padding is not performed in this function) */
static void sha512_process( SHA512_REGS * const H, const sha512_message M[] )  {
	int t;				/* counter */

	sha512_word T1, T2;	/* temporary variable */
	sha512_word W[80];	/* 80*64=5120 bit message schedule */

	SHA512_REGS r = *H;			

	/* fill message schedule W[i], i=[0..15], swapping words */
	swap_sha512_word( W+0,  ((sha512_word*)M)+0 );
	swap_sha512_word( W+1,  ((sha512_word*)M)+1 );
	swap_sha512_word( W+2,  ((sha512_word*)M)+2 );
	swap_sha512_word( W+3,  ((sha512_word*)M)+3 );
	swap_sha512_word( W+4,  ((sha512_word*)M)+4 );
	swap_sha512_word( W+5,  ((sha512_word*)M)+5 );
	swap_sha512_word( W+6,  ((sha512_word*)M)+6 );
	swap_sha512_word( W+7,  ((sha512_word*)M)+7 );
	swap_sha512_word( W+8,  ((sha512_word*)M)+8 );
	swap_sha512_word( W+9,  ((sha512_word*)M)+9 );
	swap_sha512_word( W+10, ((sha512_word*)M)+10 );
	swap_sha512_word( W+11, ((sha512_word*)M)+11 );
	swap_sha512_word( W+12, ((sha512_word*)M)+12 );
	swap_sha512_word( W+13, ((sha512_word*)M)+13 );
	swap_sha512_word( W+14, ((sha512_word*)M)+14 );
	swap_sha512_word( W+15, ((sha512_word*)M)+15 );

	/* fill message schedule W[i], i=[16..80] */
	for( t=16; t<80; t++ )  {
		T1 = W[t-2];
		W[t] = ( S(T1,19) ^ S(T1,61) ^ (T1>>6) )	/* sigma1( W[t-2] ) */ +
			W[t-7] + W[t-16];

		T1 = W[t-15];
		W[t] += S(T1,1) ^ S(T1,8) ^ (T1 >> 7);		/* sigma0( W[t-15] ) */

/*#ifdef SHA512_TEST
		printf( PGPTXT_DEBUG8("%016I64x\n"), W[t] );
#endif*/
	}

	/* hash */
	for( t=0; t<80; t++ )  {
		T1 = r.h +
			( S(r.e,14) ^ S(r.e,18) ^ S(r.e,41) )		/* Sum1(e) */ +
			( (r.e & r.f) ^ ((~r.e) & r.g)) +			/* Ch(e,f,g) */
			K[t] + W[t];

		T2 = ( S(r.a,28) ^ S(r.a,34) ^ S(r.a,39) )		/* Sum0(a) */ +
			( (r.a & r.b) ^ (r.a & r.c) ^ (r.b & r.c) );/* Maj(a,b,c) */

		r.h = r.g;
		r.g = r.f;
		r.f = r.e;
		r.e = r.d + T1;
		r.d = r.c;
		r.c = r.b;
		r.b = r.a;
		r.a = T1 + T2;

/* #ifdef SHA256_TEST
		printf( PGPTXT_DEBUG8("[%02d] "), t );
		SHA512_PRINT(&r);
#endif */

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

/*	SHA512_PRINT(H); */
}

/* processes up to 1024 bit message block M, output is a 512 bit hash in H. 
   Words in M are big endian. 
   Exact length of M in bytes is in 'length'. 
   Total hashed length is in total_length, also in bytes. 
   Length is expected to always be even to 8 bit (because we work with bytes) 
*/
static void sha512_finalize( SHA512_REGS * const H, 
					 const sha512_message M[] /* points to double size buffer */, 
					 unsigned length, sha512_length * const total_length )  
{
	int padding_length;
	unsigned two=0;

	pgpAssert( length < 1024/8 );

	((PGPByte *)M)[length] = 0x80;

	/* padding_length = block size - length(M) - length(10000000b) - length(total_length) */
	padding_length = 1024/8 - length - 1 - 128/8;

	if( padding_length < 0 ) { 	/* extra block */
		padding_length += 1024/8;
		two = 1;
	}

	memset( (PGPByte *)M+length+1, 0, padding_length );

	sha512Mul8( total_length );	/* total_length *= 8 */

	swap_sha512_word( (sha512_word *)((PGPByte *)M+length+1+padding_length), &total_length->high );
	swap_sha512_word( (sha512_word *)((PGPByte *)M+length+1+padding_length)+1, &total_length->low );

	sha512_process( H, M );
	if( two )
		sha512_process( H, M+1 );

	sha512_64WordSwapInPlace( (sha512_word*)H, sizeof(*H)/sizeof(sha512_word) );
}

typedef struct PGPSHA512Context_
{
	sha512_message M[2];/* partial message block */
	SHA512_REGS H;		/* SHA-512 registers */
	sha512_length l;	/* 128 bit length */
} PGPSHA512Context;

/* Initialize the SHA values */
static void
pgpSHA384Init(void *priv)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
#if PGP_DEBUG
	memset( ctx, 0xcd, sizeof(ctx) );
#endif
	ctx->l.low = ctx->l.high = 0;
	sha384_init( &(ctx->H) );
}
static void
pgpSHA512Init(void *priv)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
#if PGP_DEBUG
	memset( ctx, 0xcd, sizeof(ctx) );
#endif
	ctx->l.low = ctx->l.high = 0;
	sha512_init( &(ctx->H) );
}


/* Update SHA for a block of data. */
static void
pgpSHA384_512Update( void *priv, void const *bufIn, PGPSize len)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
	unsigned const old_tail= (unsigned)(ctx->l.low & (1024/8 - 1));

	unsigned blocks;
	unsigned tail;
	unsigned i;

	const PGPByte *buf = bufIn;

	sha512Add( &(ctx->l), len );		/* first, update number of processed bytes */

	i = sizeof(sha512_message)-old_tail;	/* bytes to add to the message block */

	if( i>len )  {	/* still have no complete block */
		pgpCopyMemoryNO( buf, ((PGPByte*)ctx->M) + old_tail, len );
		return;
	}

	if( old_tail ) {
		pgpCopyMemoryNO( buf, ((PGPByte*)ctx->M) + old_tail, i );
		buf += i;
		len -= i;

		sha512_process( &(ctx->H), (const sha512_message*)ctx->M );
	}
	
	blocks =  len / (1024/8);
	tail = len & (1024/8 - 1);

	for( i=0; i<blocks; i++ )  
		sha512_process( &(ctx->H), ((const sha512_message*)buf)+i );

	if( tail )
		pgpCopyMemoryNO( ((const sha512_message*)buf)+blocks, ctx->M, tail );
}

#ifdef SHA512_TEST
/* prints SHA-512 result after pgpSHA384_512Finalize was called, or 
   prints intermediate SHA-512 registers */
static void pgpSHA512Print( PGPSHA512Context *ctx )  {
	sha512_print( &(ctx->H) );
}
#endif

static void const *
pgpSHA384_512Finalize(void *priv)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
	sha512_finalize( &(ctx->H), (const sha512_message *)ctx->M,
		(unsigned)(ctx->l.low & (1024/8 - 1)), &(ctx->l) );
	return &(ctx->H);
}

/*
 * SHA384 has an OID of 2.16.840.1.101.3.4.2.2
 * SHA512 has an OID of 2.16.840.1.101.3.4.2.3 
 * From draft-ietf-openpgp-rfc2440bis-03.txt
 */
static PGPByte const SHA384DERprefix[] = {
	0x30, /* Universal, Constructed, Sequence */
	0x41, /* Length 65 (bytes following) */
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
				2,
			0x05, /* Universal, Primitive, NULL */
			0x00, /* Length 0 */
		0x04,	/* Universal, Primitive, Octet string */
		0x30	/* Length 48 */
				/* 48 SHA384 digest bytes go here */
};
static PGPByte const SHA512DERprefix[] = {
	0x30, /* Universal, Constructed, Sequence */
	0x51, /* Length 81 (bytes following) */
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
				3,
			0x05, /* Universal, Primitive, NULL */
			0x00, /* Length 0 */
		0x04,	/* Universal, Primitive, Octet string */
		0x40	/* Length 64 */
				/* 64 SHA512 digest bytes go here */
};

PGPHashVTBL const HashSHA384 = {
	PGPTXT_MACHINE("SHA384"), kPGPHashAlgorithm_SHA384,
	SHA384DERprefix, sizeof(SHA384DERprefix),
	384/8,
	1024/8,
	sizeof(PGPSHA512Context),
	sizeof(struct{char _a; PGPSHA512Context _b;}) -
		sizeof(PGPSHA512Context),
	pgpSHA384Init, pgpSHA384_512Update, pgpSHA384_512Finalize
};

PGPHashVTBL const HashSHA512 = {
	PGPTXT_MACHINE("SHA512"), kPGPHashAlgorithm_SHA512,
	SHA512DERprefix, sizeof(SHA512DERprefix),
	512/8,
	1024/8,
	sizeof(PGPSHA512Context),
	sizeof(struct{char _a; PGPSHA512Context _b;}) -
		sizeof(PGPSHA512Context),
	pgpSHA512Init, pgpSHA384_512Update, pgpSHA384_512Finalize
};

#ifdef SHA512_TEST
static void test(unsigned is384)  {
	unsigned i,j;
	time_t t;

	PGPByte test1[] = PGPTXT_DEBUG8("abc");
	PGPByte test2[] = PGPTXT_DEBUG8("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn")
						PGPTXT_DEBUG8("hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
	PGPByte test3[sizeof(sha512_message)];

	PGPSHA512Context ctx;

	printf(PGPTXT_DEBUG8("Beginning SHA %s test\n"), is384 ? PGPTXT_DEBUG8("384") : PGPTXT_DEBUG8("512"));

	is384 ? pgpSHA384Init( &ctx ) :	pgpSHA512Init( &ctx );
	pgpSHA384_512Update( &ctx, test1, sizeof(test1)-1 );
	pgpSHA384_512Finalize( &ctx );
	pgpSHA512Print( &ctx );

	is384 ? pgpSHA384Init( &ctx ) :	pgpSHA512Init( &ctx );
	pgpSHA384_512Update( &ctx, test2, sizeof(test2)-1 );
	pgpSHA384_512Finalize( &ctx );
	pgpSHA512Print( &ctx );

	memset(test3, 'a', sizeof(test3));
	t = time(NULL);
	for(j=0; j<1; j++ )  {
		is384 ? pgpSHA384Init( &ctx ) :	pgpSHA512Init( &ctx );
		for( i=1000000; i>=sizeof(test3); i-=sizeof(test3) )
			pgpSHA384_512Update( &ctx, test3, sizeof(test3) );
		pgpSHA384_512Update( &ctx, test3, i );
		pgpSHA384_512Finalize( &ctx );
	}
	printf( PGPTXT_DEBUG8("%d sec\n"), time(NULL)-t );

	pgpSHA512Print( &ctx );
}

void main()  {
	test(1);
	test(0);

	getchar();
}

#endif

#endif /* PGP_HAVE64 ] */
