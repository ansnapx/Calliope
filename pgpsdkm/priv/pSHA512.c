/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

  Generic implementation of SHA 384 and SHA 512. Works on any 32 bit platform.
  File sha384_512_64.c should be used instead of this file for efficiency reason, if possible.

	$Id: pSHA512.c 20640 2004-02-10 01:53:41Z ajivsov $
____________________________________________________________________________*/

#include "pgpConfig.h"
#include <string.h>

#include "pgpHash.h"
#include "pgpSHA2.h"
#include "pgpDebug.h"

#if !defined(PGP_HAVE64) || !PGP_HAVE64 /* [ */

typedef struct word64_  {
#ifdef SHA512_BIG_ENDIAN
	PGPUInt32 high;
	PGPUInt32 low;
#else
	PGPUInt32 low;		/* little endian */
	PGPUInt32 high;
#endif
} word64;
typedef word64 sha512_word;
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

/* right rotation of x by n bits, n < 32 */
static void S_l(sha512_word * const d, const sha512_word * const s, unsigned n)  {
	pgpAssert( n<32 );

	d->low = (s->low >> n) | (s->high << (sizeof(s->high)*8 - n));
	d->high = (s->high >> n) | (s->low << (sizeof(s->low)*8 - n));
}

/* right rotation for more then 32 bits; n is original_n-32 */
static void S_h(sha512_word * const d, const sha512_word * const s, unsigned n)  {
	pgpAssert( n<32 );

	d->low = (s->high >> n) | (s->low << (sizeof(s->low)*8 - n));
	d->high = (s->low >> n) | (s->high << (sizeof(s->high)*8 - n));
}

/* shift right for less then 32 bits (operator>>) */
static void shl(sha512_word * const d, const sha512_word * const s, unsigned n)  {
	d->low = (s->low >> n) | (s->high << (sizeof(s->low)*8-n));
	d->high = s->high >> n;
}

/* operator ^= */
static void xor(sha512_word * const d, const sha512_word * const s)  {
	d->low ^= s->low;
	d->high ^= s->high;
}

/* operator &= */
static void and(sha512_word * const d, const sha512_word * const s)  {
	d->low &= s->low;
	d->high &= s->high;
}

/* operator ~ */
static void neg(sha512_word * const d)  {
	d->low  = ~d->low;
	d->high = ~d->high;
}

/* operator += */
static void add(sha512_word * const d, const sha512_word * const s)  {
	PGPUInt32 t = d->low;
	d->high += (( d->low += s->low ) < t) + s->high;
}


typedef sha512_word sha512_message[16];	/* 1024 bit message */

/* constant words for SHA 384 and SHA 512 */
#ifdef SHA512_BIG_ENDIAN
#define W(a,b) a,b
#else
#define W(a,b) b,a
#endif
static const sha512_word K[80] = {
W(0x428a2f98,0xd728ae22),W(0x71374491,0x23ef65cd),W(0xb5c0fbcf,0xec4d3b2f),W(0xe9b5dba5,0x8189dbbc),
W(0x3956c25b,0xf348b538),W(0x59f111f1,0xb605d019),W(0x923f82a4,0xaf194f9b),W(0xab1c5ed5,0xda6d8118),
W(0xd807aa98,0xa3030242),W(0x12835b01,0x45706fbe),W(0x243185be,0x4ee4b28c),W(0x550c7dc3,0xd5ffb4e2),
W(0x72be5d74,0xf27b896f),W(0x80deb1fe,0x3b1696b1),W(0x9bdc06a7,0x25c71235),W(0xc19bf174,0xcf692694),
W(0xe49b69c1,0x9ef14ad2),W(0xefbe4786,0x384f25e3),W(0x0fc19dc6,0x8b8cd5b5),W(0x240ca1cc,0x77ac9c65),
W(0x2de92c6f,0x592b0275),W(0x4a7484aa,0x6ea6e483),W(0x5cb0a9dc,0xbd41fbd4),W(0x76f988da,0x831153b5),
W(0x983e5152,0xee66dfab),W(0xa831c66d,0x2db43210),W(0xb00327c8,0x98fb213f),W(0xbf597fc7,0xbeef0ee4),
W(0xc6e00bf3,0x3da88fc2),W(0xd5a79147,0x930aa725),W(0x06ca6351,0xe003826f),W(0x14292967,0x0a0e6e70),
W(0x27b70a85,0x46d22ffc),W(0x2e1b2138,0x5c26c926),W(0x4d2c6dfc,0x5ac42aed),W(0x53380d13,0x9d95b3df),
W(0x650a7354,0x8baf63de),W(0x766a0abb,0x3c77b2a8),W(0x81c2c92e,0x47edaee6),W(0x92722c85,0x1482353b),
W(0xa2bfe8a1,0x4cf10364),W(0xa81a664b,0xbc423001),W(0xc24b8b70,0xd0f89791),W(0xc76c51a3,0x0654be30),
W(0xd192e819,0xd6ef5218),W(0xd6990624,0x5565a910),W(0xf40e3585,0x5771202a),W(0x106aa070,0x32bbd1b8),
W(0x19a4c116,0xb8d2d0c8),W(0x1e376c08,0x5141ab53),W(0x2748774c,0xdf8eeb99),W(0x34b0bcb5,0xe19b48a8),
W(0x391c0cb3,0xc5c95a63),W(0x4ed8aa4a,0xe3418acb),W(0x5b9cca4f,0x7763e373),W(0x682e6ff3,0xd6b2b8a3),
W(0x748f82ee,0x5defb2fc),W(0x78a5636f,0x43172f60),W(0x84c87814,0xa1f0ab72),W(0x8cc70208,0x1a6439ec),
W(0x90befffa,0x23631e28),W(0xa4506ceb,0xde82bde9),W(0xbef9a3f7,0xb2c67915),W(0xc67178f2,0xe372532b),
W(0xca273ece,0xea26619c),W(0xd186b8c7,0x21c0c207),W(0xeada7dd6,0xcde0eb1e),W(0xf57d4f7f,0xee6ed178),
W(0x06f067aa,0x72176fba),W(0x0a637dc5,0xa2c898a6),W(0x113f9804,0xbef90dae),W(0x1b710b35,0x131c471b),
W(0x28db77f5,0x23047d84),W(0x32caab7b,0x40c72493),W(0x3c9ebe0a,0x15c9bebc),W(0x431d67c4,0x9c100d4c),
W(0x4cc5d4be,0xcb3e42b6),W(0x597f299c,0xfc657e2a),W(0x5fcb6fab,0x3ad6faec),W(0x6c44198c,0x4a475817)
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
	word64 low;
	word64 high;
} SHA512_LENGTH;
typedef SHA512_LENGTH sha512_length;	

#ifdef SHA512_TEST
static void
sha512_print(SHA512_REGS *H)  {
	printf( PGPTXT_DEBUG8("%08x%08x %08x%08x %08x%08x %08x%08x\n%08x%08x %08x%08x %08x%08x %08x%08x\n"),  
		H->a.high,H->a.low, H->b.high,H->b.low,	H->c.high,H->c.low, H->d.high,H->d.low,
		H->e.high,H->e.low, H->f.high,H->f.low,	H->g.high,H->g.low, H->h.high,H->h.low
	);
}
#define SHA512_PRINT(H) sha512_print(H)
#else
#define SHA512_PRINT(H) 
#endif


/* Shuffle the bytes into big-endian order within words, as per the
   SHA spec. 
 */
#ifndef SHA512_BIG_ENDIAN
static void sha512WordSwapInPlace(sha512_word * s, unsigned words)
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
#define sha512WordSwapInPlace(s,words)
#endif



static void sha512Add( sha512_length *l, unsigned u )  {
	PGPUInt32 t;

	t = l->low.low;
	if ( ( l->low.low = t + u ) < t )  {
		if( !(++l->low.high) ||	!(++l->high.low) )
			l->high.high++;
	}
}

static void sha512Mul8( sha512_length *l )  {
	l->high.high = (l->high.high << 3) | (l->high.low >> (sizeof(l->high.high)*8-3));
	l->high.low = (l->high.low << 3) | (l->low.high >> (sizeof(l->high.low)*8-3));
	l->low.high = (l->low.high << 3) | (l->low.low >> (sizeof(l->low.high)*8-3));
	l->low.low <<= 3;
}


/* initialise SHA registers */
static void sha384_init( SHA512_REGS * const H )  
{
	H->a.high = 0xcbbb9d5d;	H->a.low = 0xc1059ed8;
	H->b.high = 0x629a292a;	H->b.low = 0x367cd507;
	H->c.high = 0x9159015a;	H->c.low = 0x3070dd17;
	H->d.high = 0x152fecd8;	H->d.low = 0xf70e5939;
	H->e.high = 0x67332667;	H->e.low = 0xffc00b31;
	H->f.high = 0x8eb44a87;	H->f.low = 0x68581511;
	H->g.high = 0xdb0c2e0d;	H->g.low = 0x64f98fa7;
	H->h.high = 0x47b5481d;	H->h.low = 0xbefa4fa4;
}
static void sha512_init( SHA512_REGS * const H )  
{
	H->a.high = 0x6a09e667;	H->a.low = 0xf3bcc908;
	H->b.high = 0xbb67ae85;	H->b.low = 0x84caa73b;
	H->c.high = 0x3c6ef372;	H->c.low = 0xfe94f82b;
	H->d.high = 0xa54ff53a;	H->d.low = 0x5f1d36f1;
	H->e.high = 0x510e527f;	H->e.low = 0xade682d1;
	H->f.high = 0x9b05688c;	H->f.low = 0x2b3e6c1f;
	H->g.high = 0x1f83d9ab;	H->g.low = 0xfb41bd6b;
	H->h.high = 0x5be0cd19;	H->h.low = 0x137e2179;
}

/* Processes 512 bit message block M. 
  
	Words in M are big endian, so this function performs word swap. Placing 
	swap here saves one memcpy.

   No partial blocks here (padding is not performed in this function) */
static void sha512_process( SHA512_REGS * const H, const sha512_message M[] )  {
	int t;				/* counter */

	sha512_word T1, T2, T3, T4;	/* temporary variables */
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
		/* calculate W[t] = ( S(W[t-2],19) ^ S(W[t-2],61) ^ (W[t-2]>>6) ) + W[t-7] + W[t-16]; */
		S_l( &T2, W+t-2, 19 );
		S_h( &T1, W+t-2, 61 & (32-1));
		xor( &T1, &T2 );

		shl( &T2, W+t-2, 6 );
		xor( &T1, &T2 );		/* T1 = sigma1( W[t-2] ) */

		add( &T1, W+t-7 );
		add( &T1, W+t-16 );

		W[t] = T1;

		/* calculate W[t] += S(W[t-15],1) ^ S(W[t-15],8) ^ (W[t-15] >> 7); */
		S_l(&T1,W+t-15,1);
		S_l(&T2,W+t-15,8);
		xor( &T1, &T2 );

		shl( &T2, W+t-15, 7 );
		xor( &T1, &T2 );		/* T1 = sigma0( W[t-16] ) */

		add( W+t, &T1 );
/*#ifdef SHA512_TEST
		printf( PGPTXT_DEBUG8("%08x%08x\n"), W[t].high, W[t].low  );
#endif*/
	}

	/* hash */
	for( t=0; t<80; t++ )  {

		/* calculate T1 = r.h +
			( S(r.e,14) ^ S(r.e,18) ^ S(r.e,41) ) +		(= Sum1(e) ) 
			( (r.e & r.f) ^ ((~r.e) & r.g)) +			(= Ch(e,f,g) )
			K[t] + W[t]; */

		S_l( &T3, &r.e, 14 );
		S_l( &T4, &r.e, 18 );
		xor( &T3, &T4 );
		S_h( &T4, &r.e, 41 & (32-1) );
		xor( &T3, &T4 );				/* T3 = Sum1(e) */

		T1 = r.f;
		T2 = r.e;
		and( &T1, &T2 );
		neg( &T2 );
		and( &T2, &r.g );
		xor( &T1, &T2 );				/* T1 = Ch(e,f,g) */

		add( &T1, &r.h );
		add( &T1, &T3 );
		add( &T1, K+t );
		add( &T1, W+t );


		/* calculate T2 = ( S(r.a,28) ^ S(r.a,34) ^ S(r.a,39) ) +	(= Sum0(a))
			( (r.a & r.b) ^ (r.a & r.c) ^ (r.b & r.c) );			(= Maj(a,b,c)) */

		S_l( &T2, &r.a, 28 );
		S_h( &T3, &r.a, 34 & (32-1) );
		xor( &T2, &T3 );
		S_h( &T3, &r.a, 39 & (32-1) );
		xor( &T2, &T3 );				/* T2 = Sum0(a) */

		T3 = r.b;
		and( &T3, &r.a );
		T4 = r.c;
		and( &T4, &r.a );
		xor( &T3, &T4 );
		T4 = r.b;
		and( &T4, &r.c );
		xor( &T3, &T4 );					/* T3 = Maj(a,b,c) */

		add( &T2, &T3 );

		r.h = r.g;
		r.g = r.f;
		r.f = r.e;
		r.e = r.d;	add( &r.e, &T1 );
		r.d = r.c;
		r.c = r.b;
		r.b = r.a;
		r.a = T1;	add( &r.a, &T2 );

/*#ifdef SHA512_TEST
		printf( PGPTXT_DEBUG8("[%02d] "), t );
		SHA512_PRINT(&r);
#endif*/

	}

	/* finally, add new registers to old; result becomes new hash */

	/* unroll this loop */
	add( &H->a, &r.a );
	add( &H->b, &r.b );
	add( &H->c, &r.c );
	add( &H->d, &r.d );
	add( &H->e, &r.e );
	add( &H->f, &r.f );
	add( &H->g, &r.g );
	add( &H->h, &r.h );

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

	sha512WordSwapInPlace( (sha512_word*)H, sizeof(*H)/sizeof(sha512_word) );
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
	memset( ctx, 0, sizeof(*ctx) );
	sha384_init( &(ctx->H) );
}
static void
pgpSHA512Init(void *priv)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
	memset( ctx, 0, sizeof(*ctx) );
	sha512_init( &(ctx->H) );
}


/* Update SHA for a block of data. */
static void
pgpSHA384_512Update( void *priv, void const *bufIn, PGPSize len)
{
	PGPSHA512Context *ctx = (PGPSHA512Context *)priv;
	unsigned const old_tail= (unsigned)(ctx->l.low.low & (1024/8 - 1));

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
		pgpCopyMemory( ((const sha512_message*)buf)+blocks, ctx->M, tail );
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
		(unsigned)(ctx->l.low.low & (1024/8 - 1)), &(ctx->l) );
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

	printf(PGPTXT_DEBUG8("Beginning SHA %s test\n"), is384 ? PGPTXT_DEBUG("384") : PGPTXT_DEBUG("512"));

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
