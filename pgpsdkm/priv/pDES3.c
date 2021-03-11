/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pDES3.c 20640 2004-02-10 01:53:41Z ajivsov $
____________________________________________________________________________*/
/*
 * pgpDES3.c -- TripleDES EDE Encryptor
 *
 * 95/09/11 23:29:03 EDT by Richard Outerbridge
 */
#include "pgpSDKBuildFlags.h"

#ifndef PGP_DES3
#error you must define PGP_DES3 one way or the other
#endif

#if PGP_DES3	/* [ */


#include <string.h>
#include "pgpConfig.h"

#include "pgpSymmetricCipherPriv.h"
#include "pgpDES3.h"
#include "pgpMem.h"

/* The size of a scheduled DES key */
#define DES_KEYWORDS 32
#define DES_KEYBYTES (sizeof(PGPUInt32)*DES_KEYWORDS)
#define DES3_KEYWORDS (3*DES_KEYWORDS)
#define DES3_KEYBYTES (sizeof(PGPUInt32)*DES3_KEYWORDS)

#define DES3_USERKEYBYTES 32	/* buffer for wash */

/*
 * Flags in priv array to record whether key schedule is in encrypt
 * or decrypt mode
 */
#define DES3_MODE_OFFSET		(DES3_KEYBYTES + DES3_USERKEYBYTES)
#define DES3_UNDEFINED_MODE		0x00
#define DES3_ENCRYPTION_MODE	0x11
#define DES3_DECRYPTION_MODE	0x22


static PGPUInt32 const bigbyte[24] = {
	0x800000L,	0x400000L,	0x200000L, 	0x100000L,
	0x80000L,	0x40000L,	0x20000L,	0x10000L,
	0x8000L,	0x4000L,	0x2000L,	0x1000L,
	0x800L,		0x400L,		0x200L,		0x100L,
	0x80L,		0x40L,		0x20L,		0x10L,
	0x8L,		0x4L,		0x2L,		0x1L	};

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */

static PGPByte const pc1[56] = {
	56, 48, 40, 32, 24, 16,  8,	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,	18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,	 6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,	20, 12,  4, 27, 19, 11,  3 };

static PGPByte const totrot[16] = {
	 1,  2,  4,  6,  8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };

static PGPByte const pc2[48] = {
	13, 16, 10, 23,  0,  4,	 2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7,	15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54,	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,	45, 41, 49, 35, 28, 31 };

/*
 * This is a less-that-brilliant key scheduling routine.
 * It could stand optimization some time.
 *
 * cookey "cooks" the key into the desired form, from the basic one that
 * has the keys for S-boxes 1 through 8 in adjacent words of the
 * "raw" array.  I.e. the bits start out like this:
 * xxxxxxxx111111222222333333444444
 * xxxxxxxx555555666666777777888888
 * We actually want the keys to look like this:
 * 111111xx333333xx555555xx777777xx
 * 222222xx444444xx666666xx888888xx
 * Where the "xx" patterns are set to 01020300 for use by the s-box
 * lookup code in the main encrypt loop.
 */
static void
cookey (PGPUInt32 *raw, PGPUInt32 *cooked)
{
	int i;

	for (i = 0; i < 16; i++, raw += 2, cooked += 2) {
		cooked[0]  = (raw[0] & 0x00fc0000L) << 8;
		cooked[0] |= (raw[0] & 0x00000fc0L) << 12;
		cooked[0] |= (raw[1] & 0x00fc0000L) >> 8;
		cooked[0] |= (raw[1] & 0x00000fc0L) >> 4;
		cooked[0] |= 0x01020300;
		cooked[1]  = (raw[0] & 0x0003f000L) << 14;
		cooked[1] |= (raw[0] & 0x0000003fL) << 18;
		cooked[1] |= (raw[1] & 0x0003f000L) >> 2;
		cooked[1] |= (raw[1] & 0x0000003fL) << 2;
		cooked[1] |= 0x01020300;
	}
	return;
}
	
static void
deskey (PGPByte const *key, int decryptf, PGPUInt32 *outbuf)
{
	int i, j, l, m, n;
	PGPByte pc1m[56], pcr[56];
	PGPUInt32 kn[32];
	
	for (j = 0; j < 56; j++) {
		l = pc1[j];
		m = l & 07;
		pc1m[j] = ( key[l >> 3] >> (~l & 7) ) & 1;
	}
	for (i = 0; i < 16; i++ ) {
		m = (decryptf ? 15-i : i) << 1;
		n = m + 1;
		kn[m] = kn[n] = 0L;
		for (j = 0; j < 28; j++) {
			l = j + totrot[i];
			if (l >= 28)
				l -= 28;
			pcr[j] = pc1m[l];
		}
		for (j = 28; j < 56; j++) {
			l = j + totrot[i];
			if (l >= 56)
				l -= 28;
			pcr[j] = pc1m[l];
		}
		for (j = 0; j < 24; j++) {
			if (pcr[pc2[j]])
				kn[m] |= bigbyte[j];
			if (pcr[pc2[j+24]])
				kn[n] |= bigbyte[j];
		}
	}
	cookey(kn, outbuf);
	return;
}

/* S-boxes 1, 3, 5, 7, plus P permutation, rotated */
static PGPUInt32 const SP0[512] = {
	0x00404100, 0x00000000, 0x00004000, 0x00404101,
	0x00404001, 0x00004101, 0x00000001, 0x00004000,
	0x00000100, 0x00404100, 0x00404101, 0x00000100,
	0x00400101, 0x00404001, 0x00400000, 0x00000001,
	0x00000101, 0x00400100, 0x00400100, 0x00004100,
	0x00004100, 0x00404000, 0x00404000, 0x00400101,
	0x00004001, 0x00400001, 0x00400001, 0x00004001,
	0x00000000, 0x00000101, 0x00004101, 0x00400000,
	0x00004000, 0x00404101, 0x00000001, 0x00404000,
	0x00404100, 0x00400000, 0x00400000, 0x00000100,
	0x00404001, 0x00004000, 0x00004100, 0x00400001,
	0x00000100, 0x00000001, 0x00400101, 0x00004101,
	0x00404101, 0x00004001, 0x00404000, 0x00400101,
	0x00400001, 0x00000101, 0x00004101, 0x00404100,
	0x00000101, 0x00400100, 0x00400100, 0x00000000,
	0x00004001, 0x00004100, 0x00000000, 0x00404001,

	0x00000082, 0x02008080, 0x00000000, 0x02008002,
	0x02000080, 0x00000000, 0x00008082, 0x02000080,
	0x00008002, 0x02000002, 0x02000002, 0x00008000,
	0x02008082, 0x00008002, 0x02008000, 0x00000082,
	0x02000000, 0x00000002, 0x02008080, 0x00000080,
	0x00008080, 0x02008000, 0x02008002, 0x00008082,
	0x02000082, 0x00008080, 0x00008000, 0x02000082,
	0x00000002, 0x02008082, 0x00000080, 0x02000000,
	0x02008080, 0x02000000, 0x00008002, 0x00000082,
	0x00008000, 0x02008080, 0x02000080, 0x00000000,
	0x00000080, 0x00008002, 0x02008082, 0x02000080,
	0x02000002, 0x00000080, 0x00000000, 0x02008002,
	0x02000082, 0x00008000, 0x02000000, 0x02008082,
	0x00000002, 0x00008082, 0x00008080, 0x02000002,
	0x02008000, 0x02000082, 0x00000082, 0x02008000,
	0x00008082, 0x00000002, 0x02008002, 0x00008080,

	0x00000040, 0x00820040, 0x00820000, 0x10800040,
	0x00020000, 0x00000040, 0x10000000, 0x00820000,
	0x10020040, 0x00020000, 0x00800040, 0x10020040,
	0x10800040, 0x10820000, 0x00020040, 0x10000000,
	0x00800000, 0x10020000, 0x10020000, 0x00000000,
	0x10000040, 0x10820040, 0x10820040, 0x00800040,
	0x10820000, 0x10000040, 0x00000000, 0x10800000,
	0x00820040, 0x00800000, 0x10800000, 0x00020040,
	0x00020000, 0x10800040, 0x00000040, 0x00800000,
	0x10000000, 0x00820000, 0x10800040, 0x10020040,
	0x00800040, 0x10000000, 0x10820000, 0x00820040,
	0x10020040, 0x00000040, 0x00800000, 0x10820000,
	0x10820040, 0x00020040, 0x10800000, 0x10820040,
	0x00820000, 0x00000000, 0x10020000, 0x10800000,
	0x00020040, 0x00800040, 0x10000040, 0x00020000,
	0x00000000, 0x10020000, 0x00820040, 0x10000040,

	0x00080000, 0x81080000, 0x81000200, 0x00000000,
	0x00000200, 0x81000200, 0x80080200, 0x01080200,
	0x81080200, 0x00080000, 0x00000000, 0x81000000,
	0x80000000, 0x01000000, 0x81080000, 0x80000200,
	0x01000200, 0x80080200, 0x80080000, 0x01000200,
	0x81000000, 0x01080000, 0x01080200, 0x80080000,
	0x01080000, 0x00000200, 0x80000200, 0x81080200,
	0x00080200, 0x80000000, 0x01000000, 0x00080200,
	0x01000000, 0x00080200, 0x00080000, 0x81000200,
	0x81000200, 0x81080000, 0x81080000, 0x80000000,
	0x80080000, 0x01000000, 0x01000200, 0x00080000,
	0x01080200, 0x80000200, 0x80080200, 0x01080200,
	0x80000200, 0x81000000, 0x81080200, 0x01080000,
	0x00080200, 0x00000000, 0x80000000, 0x81080200,
	0x00000000, 0x80080200, 0x01080000, 0x00000200,
	0x81000000, 0x01000200, 0x00000200, 0x80080000 };

/* S-boxes 2, 4, 6, 8, plus P permutation, rotated */
static PGPUInt32 const SP1[512] = {
	0x20042008, 0x20002000, 0x00002000, 0x00042008,
	0x00040000, 0x00000008, 0x20040008, 0x20002008,
	0x20000008, 0x20042008, 0x20042000, 0x20000000,
	0x20002000, 0x00040000, 0x00000008, 0x20040008,
	0x00042000, 0x00040008, 0x20002008, 0x00000000,
	0x20000000, 0x00002000, 0x00042008, 0x20040000,
	0x00040008, 0x20000008, 0x00000000, 0x00042000,
	0x00002008, 0x20042000, 0x20040000, 0x00002008,
	0x00000000, 0x00042008, 0x20040008, 0x00040000,
	0x20002008, 0x20040000, 0x20042000, 0x00002000,
	0x20040000, 0x20002000, 0x00000008, 0x20042008,
	0x00042008, 0x00000008, 0x00002000, 0x20000000,
	0x00002008, 0x20042000, 0x00040000, 0x20000008,
	0x00040008, 0x20002008, 0x20000008, 0x00040008,
	0x00042000, 0x00000000, 0x20002000, 0x00002008,
	0x20000000, 0x20040008, 0x20042008, 0x00042000,

	0x40200800, 0x40000820, 0x40000820, 0x00000020,
	0x00200820, 0x40200020, 0x40200000, 0x40000800,
	0x00000000, 0x00200800, 0x00200800, 0x40200820,
	0x40000020, 0x00000000, 0x00200020, 0x40200000,
	0x40000000, 0x00000800, 0x00200000, 0x40200800,
	0x00000020, 0x00200000, 0x40000800, 0x00000820,
	0x40200020, 0x40000000, 0x00000820, 0x00200020,
	0x00000800, 0x00200820, 0x40200820, 0x40000020,
	0x00200020, 0x40200000, 0x00200800, 0x40200820,
	0x40000020, 0x00000000, 0x00000000, 0x00200800,
	0x00000820, 0x00200020, 0x40200020, 0x40000000,
	0x40200800, 0x40000820, 0x40000820, 0x00000020,
	0x40200820, 0x40000020, 0x40000000, 0x00000800,
	0x40200000, 0x40000800, 0x00200820, 0x40200020,
	0x40000800, 0x00000820, 0x00200000, 0x40200800,
	0x00000020, 0x00200000, 0x00000800, 0x00200820,

	0x08000004, 0x08100000, 0x00001000, 0x08101004,
	0x08100000, 0x00000004, 0x08101004, 0x00100000,
	0x08001000, 0x00101004, 0x00100000, 0x08000004,
	0x00100004, 0x08001000, 0x08000000, 0x00001004,
	0x00000000, 0x00100004, 0x08001004, 0x00001000,
	0x00101000, 0x08001004, 0x00000004, 0x08100004,
	0x08100004, 0x00000000, 0x00101004, 0x08101000,
	0x00001004, 0x00101000, 0x08101000, 0x08000000,
	0x08001000, 0x00000004, 0x08100004, 0x00101000,
	0x08101004, 0x00100000, 0x00001004, 0x08000004,
	0x00100000, 0x08001000, 0x08000000, 0x00001004,
	0x08000004, 0x08101004, 0x00101000, 0x08100000,
	0x00101004, 0x08101000, 0x00000000, 0x08100004,
	0x00000004, 0x00001000, 0x08100000, 0x00101004,
	0x00001000, 0x00100004, 0x08001004, 0x00000000,
	0x08101000, 0x08000000, 0x00100004, 0x08001004,

	0x04000410, 0x00000400, 0x00010000, 0x04010410,
	0x04000000, 0x04000410, 0x00000010, 0x04000000,
	0x00010010, 0x04010000, 0x04010410, 0x00010400,
	0x04010400, 0x00010410, 0x00000400, 0x00000010,
	0x04010000, 0x04000010, 0x04000400, 0x00000410,
	0x00010400, 0x00010010, 0x04010010, 0x04010400,
	0x00000410, 0x00000000, 0x00000000, 0x04010010,
	0x04000010, 0x04000400, 0x00010410, 0x00010000,
	0x00010410, 0x00010000, 0x04010400, 0x00000400,
	0x00000010, 0x04010010, 0x00000400, 0x00010410,
	0x04000400, 0x00000010, 0x04000010, 0x04010000,
	0x04010010, 0x04000000, 0x00010000, 0x04000410,
	0x00000000, 0x04010410, 0x00010010, 0x04000010,
	0x04010000, 0x04000400, 0x04000410, 0x00000000,
	0x04010410, 0x00010400, 0x00010400, 0x00000410,
	0x00000410, 0x00010010, 0x04000000, 0x04010400 };

/*
 * This encryption function is fairly clever in the way it does its
 * s-box lookup.  The S-boxes are indexed by bytes, rather than
 * words, because that's faster on many machines, and shifting
 * everything two bits to do the multiply by 4 is trivial.
 * Then, the indexing into the various S boxes is done by
 * adding the appropriate offset bits into the key array, so the
 * addition is done by the XOR with the key rather than having to
 * be done explicitly here.
 */
static void
des3DES (PGPByte const inblock[8], PGPByte outblock[8], PGPUInt32 const *keys)
{
	PGPUInt32 s, t, right, leftt;
	int round, iterate;
	
	leftt	= ((PGPUInt32)inblock[0] << 24)
                | ((PGPUInt32)inblock[1] << 16)
                | ((PGPUInt32)inblock[2] << 8)
                |  (PGPUInt32)inblock[3];
	right	= ((PGPUInt32)inblock[4] << 24)
                | ((PGPUInt32)inblock[5] << 16)
                | ((PGPUInt32)inblock[6] << 8)
                |  (PGPUInt32)inblock[7];

	/* Initial permutation IP */
	t = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
	right ^= t;
	leftt ^= (t << 4);
	t = ((leftt >> 16) ^ right) & 0x0000ffffL;
	right ^= t;
	leftt ^= (t << 16);
	t = ((right >> 2) ^ leftt) & 0x33333333L;
	leftt ^= t;
	right ^= (t << 2);
	t = ((right >> 8) ^ leftt) & 0x00ff00ffL;
	leftt ^= t;
	right ^= (t << 8);
	leftt = ((leftt >> 1) | (leftt << 31));
	t = (leftt ^ right) & 0x55555555L;
	leftt ^= t;
	right ^= t;
	right = ((right >> 1) | (right << 31));

	/* The main encryption loop */
	iterate = 3;
	goto Des0;
	do {
		t = right;
		right = leftt;
		leftt = t;
Des0:	
		for (round = 0; round < 8; round++) {
			s  = (right & 0xfcfcfcfc) ^ keys[0];
			t  = (((right >> 28) | (right << 4)) & 0xfcfcfcfc)
				^ keys[1];
			leftt ^= *(PGPUInt32 *)((char *)SP0+( s        & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 8 ) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 16) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 24) & 0x0fc))
			       ^ *(PGPUInt32 *)((char *)SP1+( t        & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 8 ) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 16) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 24) & 0x0fc));

			s  = (leftt & 0xfcfcfcfc) ^ keys[2];
			t  = (((leftt >> 28) | (leftt << 4)) & 0xfcfcfcfc)
				^ keys[3];
			right ^= *(PGPUInt32 *)((char *)SP0+( s        & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 8 ) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 16) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP0+((s >> 24) & 0x0fc))
			       ^ *(PGPUInt32 *)((char *)SP1+( t        & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 8 ) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 16) & 0x3fc))
			       ^ *(PGPUInt32 *)((char *)SP1+((t >> 24) & 0x0fc));
			keys += 4;
		}
	} while (--iterate);

	/* Inverse IP */
	leftt = ((leftt << 1) | (leftt >> 31));
	t = (leftt ^ right) & 0x55555555L;
	leftt ^= t;
	right ^= t;
	right = ((right << 1) | (right >> 31));
	t = ((leftt >> 8) ^ right) & 0x00ff00ffL;
	right ^= t;
	leftt ^= (t << 8);
	t = ((leftt >> 2) ^ right) & 0x33333333L;
	right ^= t;
	leftt ^= (t << 2);
	t = ((right >> 16) ^ leftt) & 0x0000ffffL;
	leftt ^= t;
	right ^= (t << 16);
	t = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
	leftt ^= t;
	right ^= (t << 4);

	outblock[0] = (PGPByte)(right >> 24);
	outblock[1] = (PGPByte)(right >> 16);
	outblock[2] = (PGPByte)(right >>  8);
	outblock[3] = (PGPByte)(right      );
	outblock[4] = (PGPByte)(leftt >> 24);
	outblock[5] = (PGPByte)(leftt >> 16);
	outblock[6] = (PGPByte)(leftt >>  8);
	outblock[7] = (PGPByte)(leftt      );
	return;
}

/*** Externally called functions ***/

static void
des3Key (void *priv, void const *key)
{
	/* Do key schedule at encrypt/decrypt time; just store key for now */
	*((PGPByte *)priv + DES3_MODE_OFFSET) = DES3_UNDEFINED_MODE;
	/* Keep a copy of the unscheduled key for Washing purposes */
	pgpCopyMemoryNO (key, (PGPByte *)priv + DES3_KEYBYTES, 24);
}

static void
scheduleKey (void *priv, PGPUInt32 mode)
{
	if (mode == DES3_ENCRYPTION_MODE) {
		if (*((PGPByte *)priv + DES3_MODE_OFFSET) != DES3_ENCRYPTION_MODE) {
			/* EDE triple-DES */
			PGPByte *key = (PGPByte *)priv + DES3_KEYBYTES;
			deskey (key   , 0, (PGPUInt32 *)priv);
			deskey (key+ 8, 1, (PGPUInt32 *)priv + DES_KEYWORDS);
			deskey (key+16, 0, (PGPUInt32 *)priv + 2*DES_KEYWORDS);
			*((PGPByte *)priv + DES3_MODE_OFFSET) = DES3_ENCRYPTION_MODE;
		}
	} else {
#ifndef UNITTEST
		pgpAssert (mode == DES3_DECRYPTION_MODE);
#endif
		if (*((PGPByte *)priv + DES3_MODE_OFFSET) != DES3_DECRYPTION_MODE) {
			/* EDE triple-DES */
			/* To decrypt, do DED with the keys in the opposite order */
			PGPByte *key = (PGPByte *)priv + DES3_KEYBYTES;
			deskey (key+16, 1, (PGPUInt32 *)priv);
			deskey (key+ 8, 0, (PGPUInt32 *)priv + DES_KEYWORDS);
			deskey (key   , 1, (PGPUInt32 *)priv + 2*DES_KEYWORDS);
			*((PGPByte *)priv + DES3_MODE_OFFSET) = DES3_DECRYPTION_MODE;
		}
	}
}

/* FIPS140 state DES3 encrypt */
static void
des3Encrypt (void *priv, void const *in, void *out)
{
	/* Make sure key schedule is in the right mode */
	scheduleKey (priv, DES3_ENCRYPTION_MODE);
	des3DES ((const PGPByte *) in, (PGPByte *) out, (PGPUInt32 const *)priv);
}

/* FIPS140 state DES3 decrypt */
static void
des3Decrypt (void *priv, void const *in, void *out)
{
	/* Make sure key schedule is in the right mode */
	scheduleKey (priv, DES3_DECRYPTION_MODE);
	des3DES ((const PGPByte *) in, (PGPByte *) out, (PGPUInt32 const *)priv);
}

/*
 * Do one 64-bit step of a Triple Tandem Davies-Meyer hash computation.
 * The hash buffer is 32 bytes long and contains H (0..7), then G (8..15),
 * then F (16..23), then 8 bytes of scratch space.  The buf is 8 bytes long.
 * xkey is a temporary key schedule buffer, with room for *4* DES
 * keys, i.e. 4*DESKEYWORDS words.
 * This and the extra data in the hash buffer are allocated by the
 * caller to reduce the amount of buffer-wiping we have to do.
 * (It's only called from des3Wash, so the interface can be a bit
 * specialized.)
 *
 * What is triple Tandem Davies-Meyer?  Well, it's a simple
 * extension of (double) Tandem Davies-Meyer, which goes
 * like this, to hash (H,G) with message block M:
 * H' = E_{G,M}(H)
 * G' = E_{M,H'}(G)
 * H ^= H'
 * G ^= G'
 *
 * The extension, to a triple-width hash (H,G,F) is just:
 * H' = E_{F,G,M}(H)
 * G' = E_{F,M,H'}(G)
 * F' = E_(M,G',H'}(F)
 * H ^= H'
 * G ^= G'
 * F ^= F'
 *
 * This schedules individual DES keys to avoid having to copy the
 * bits to contiguous buffers and to re-use the already-scheduled
 * leys.  F and H' are used twice in the same spot, and M is scheduled
 * twice for encryption.
 */
static void
des3StepTripleDM(PGPByte *hash, PGPByte const *buf, PGPUInt32 *xkey)
{
	int i;

	/* Set up triple-DES with F, G, M */
	deskey(hash+16, 0, xkey);
	deskey(hash+ 8, 1, xkey + DES_KEYWORDS);
	deskey(buf,     0, xkey + 2*DES_KEYWORDS);

	/* Compute H' and new H */
	des3DES(hash, hash+24, xkey);
	for (i = 0; i < 8; i++)
		hash[i] ^= hash[i+24];
	/* Copy encryption schedule for M out of harm's way */
	pgpCopyMemoryNO( xkey+2*DES_KEYWORDS, xkey +3*DES_KEYWORDS, DES_KEYBYTES );

	/* Set up triple-DES with F, M, H' */
	deskey(buf,     1, xkey + DES_KEYWORDS);
	deskey(hash+24, 0, xkey + 2*DES_KEYWORDS);

	/* Compute G' and new G */
	des3DES(hash+8, hash+24, xkey);
	for (i = 0; i < 8; i++)
		hash[i+8] ^= hash[i+24];

	/* Set up triple-DES with M, G', H' */
	pgpCopyMemoryNO(xkey+3*DES_KEYWORDS, xkey, DES_KEYBYTES);
	deskey(hash+24, 1, xkey + DES_KEYWORDS);

	/* Compute F' and new F */
	des3DES(hash+16, hash+24, xkey);
	for (i = 0; i < 8; i++)
		hash[i+16] ^= hash[i+24];
}

/*
 * Munge the key of the CipherContext based on the supplied bytes.
 * This is for random-number generation, so the exact technique is
 * unimportant, but it happens to use the current key as the
 * IV for computing a triple-Tandem Davies-Meyer hash of the bytes,
 * and uses the output as the new key.
 */
static void
des3Wash(void *priv, void const *bufIn, PGPSize len)
{
	PGPSize 	i;
	PGPByte 	temp[8];
	PGPUInt32 	xkey[4*DES_KEYWORDS];
	PGPByte		*buf = (PGPByte *) bufIn;
	
	/* The key is used as the IV for the hash */

	/* Do the initial blocks of the hash */
	i = len;
	while (i >= 8) {
		des3StepTripleDM((PGPByte *)priv+DES3_KEYBYTES, buf, xkey);
		buf += 8;
		i -= 8;
	}
	/*
	 * At the end, we do Damgard-Merkle strengthening, just like
	 * MD5 or SHA.  Pad with 0x80 then 0 bytes to 6 mod 8, then
	 * add the length.  We use a 16-bit length in bytes instead
	 * of a 64-bit length in bits, but that is cryptographically
	 * irrelevant, as long as the length is there.
	 */
	/* Do the first partial block - i <= 7 */
	pgpCopyMemoryNO(buf, temp, i);
	temp[i++] = 0x80;
	if (i > 6) {
		pgpClearMemory(temp+i, 8-i);
		des3StepTripleDM((PGPByte *)priv+DES3_KEYBYTES, temp, xkey);
		i = 0;
	}
	pgpClearMemory(temp+i, 6-i);
	temp[6] = (PGPByte)(len >> 8);
	temp[7] = (PGPByte)len;
	des3StepTripleDM((PGPByte *)priv+DES3_KEYBYTES, temp, xkey);

	/* Re-schedule the key */
	*((PGPByte *)priv + DES3_MODE_OFFSET) = DES3_UNDEFINED_MODE;
	scheduleKey (priv, DES3_ENCRYPTION_MODE);

	pgpClearMemory( temp,  sizeof(temp));
	pgpClearMemory( xkey,  sizeof(xkey));
}

/*
 * Define a Cipher for the generic cipher.  This is the only real
 * exported symbol -- everything else can be static, since everything
 * is referenced through function pointers!
 */
PGPCipherVTBL const cipher3DES = {
	PGPTXT_MACHINE("3DES"),
	kPGPCipherAlgorithm_3DES,
	8,			/* Blocksize */
	24,			/* Keysize */
	DES3_KEYBYTES + DES3_USERKEYBYTES + 1,
	alignof(PGPUInt32),
	des3Key,
	des3Encrypt,
	des3Decrypt,
	des3Wash,
	NULL		/* rollback doesn't apply to block cipher */
};

#ifdef UNITTEST
/* Validation set:
 *
 * Double-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cde7
 * Cipher : 7f1d 0a77 826b 8aff
 *
 ***************************************************/

#include <stdio.h>
#include <time.h>

static void
printhex(unsigned char const *buf, unsigned len)
{
	while (len--) {
		printf(PGPTXT_DEBUG8("%02X"), *buf++);
		putchar(len ? ' ' : '\n');
	}
}

int
main(void)
{
	unsigned i;
	clock_t c;

	static unsigned char const key[24] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
	};
	static unsigned char const plain[8] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe7
	};
	static unsigned char const cipher[8] = {
		0x7f, 0x1d, 0x0a, 0x77, 0x82, 0x6b, 0x8a, 0xff
	};
	unsigned char out[8];

	PGPByte priv[DES3_KEYBYTES + DES3_USERKEYBYTES + 1];

	des3Key(priv, key);
	des3Encrypt(priv, plain, out);
	printf(PGPTXT_DEBUG8("   key="));
	printhex(key, 24);
	printf(PGPTXT_DEBUG8(" plain="));
	printhex(plain, 8);
	printf(PGPTXT_DEBUG8("   out="));
	printhex(out, 8);
	printf(PGPTXT_DEBUG8("cipher="));
	printhex(cipher, 8);
	if (memcmp(cipher, out, 8) == 0)
		printf(PGPTXT_DEBUG8("Encryption successful\n"));
	else
		printf(PGPTXT_DEBUG8("### ENCRYPTION ERROR\n"));

	des3Decrypt(priv, cipher, out);
	printf(PGPTXT_DEBUG8("cipher="));
	printhex(cipher, 8);
	printf(PGPTXT_DEBUG8("   out="));
	printhex(out, 8);
	printf(PGPTXT_DEBUG8(" plain="));
	printhex(plain, 8);
	if (memcmp(plain, out, 8) == 0)
		printf(PGPTXT_DEBUG8("Decryption successful\n"));
	else
		printf(PGPTXT_DEBUG8("### DECRYPTION ERROR\n"));

	printf(PGPTXT_DEBUG8("Doing test encryptions\n"));
	c = clock();
	for (i = 0; i < 100000; i++)
		des3Encrypt(priv, out, out);
	c = clock() - c;
	printf(PGPTXT_DEBUG8("%u encryptions required %lu ticks\n"),
		i, (unsigned long)c);
	return 0;
}

#endif

#endif /* ] PGP_DES3 */



/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
