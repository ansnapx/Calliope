/*____________________________________________________________________________
    Copyright (C) 2004 PGP Corporation
    All rights reserved.

    $Id: pAES.c 59461 2007-12-21 00:43:52Z dmurphy $
____________________________________________________________________________*/


/*
 * Portions of this file are:
 *
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 26/08/2003

 This file contains the code for implementing the key schedule for AES
 (Rijndael) for block and key sizes of 16, 24, and 32 bytes. See aesopt.h
 for further details including optimisation.
*/

#include "pgpSDKBuildFlags.h"

#ifndef PGP_AES
#error you must define PGP_AES one way or the other
#endif

#if PGP_AES	/* [ */


#include "pgpConfig.h"

#include "pgpSymmetricCipherPriv.h"

#define DO_TABLES
#include "pgpAESboxes.h"
#include "pgpMem.h"
#include "pgpUsuals.h"

#if ! PGP_UNIX_DARWIN
#include <stdio.h>
#include <stdlib.h>
#endif

/************************** Originally aestab.c **************************/


#if defined(FIXED_TABLES)

#define sb_data(w) {\
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define isb_data(w) {\
    w(0x52), w(0x09), w(0x6a), w(0xd5), w(0x30), w(0x36), w(0xa5), w(0x38),\
    w(0xbf), w(0x40), w(0xa3), w(0x9e), w(0x81), w(0xf3), w(0xd7), w(0xfb),\
    w(0x7c), w(0xe3), w(0x39), w(0x82), w(0x9b), w(0x2f), w(0xff), w(0x87),\
    w(0x34), w(0x8e), w(0x43), w(0x44), w(0xc4), w(0xde), w(0xe9), w(0xcb),\
    w(0x54), w(0x7b), w(0x94), w(0x32), w(0xa6), w(0xc2), w(0x23), w(0x3d),\
    w(0xee), w(0x4c), w(0x95), w(0x0b), w(0x42), w(0xfa), w(0xc3), w(0x4e),\
    w(0x08), w(0x2e), w(0xa1), w(0x66), w(0x28), w(0xd9), w(0x24), w(0xb2),\
    w(0x76), w(0x5b), w(0xa2), w(0x49), w(0x6d), w(0x8b), w(0xd1), w(0x25),\
    w(0x72), w(0xf8), w(0xf6), w(0x64), w(0x86), w(0x68), w(0x98), w(0x16),\
    w(0xd4), w(0xa4), w(0x5c), w(0xcc), w(0x5d), w(0x65), w(0xb6), w(0x92),\
    w(0x6c), w(0x70), w(0x48), w(0x50), w(0xfd), w(0xed), w(0xb9), w(0xda),\
    w(0x5e), w(0x15), w(0x46), w(0x57), w(0xa7), w(0x8d), w(0x9d), w(0x84),\
    w(0x90), w(0xd8), w(0xab), w(0x00), w(0x8c), w(0xbc), w(0xd3), w(0x0a),\
    w(0xf7), w(0xe4), w(0x58), w(0x05), w(0xb8), w(0xb3), w(0x45), w(0x06),\
    w(0xd0), w(0x2c), w(0x1e), w(0x8f), w(0xca), w(0x3f), w(0x0f), w(0x02),\
    w(0xc1), w(0xaf), w(0xbd), w(0x03), w(0x01), w(0x13), w(0x8a), w(0x6b),\
    w(0x3a), w(0x91), w(0x11), w(0x41), w(0x4f), w(0x67), w(0xdc), w(0xea),\
    w(0x97), w(0xf2), w(0xcf), w(0xce), w(0xf0), w(0xb4), w(0xe6), w(0x73),\
    w(0x96), w(0xac), w(0x74), w(0x22), w(0xe7), w(0xad), w(0x35), w(0x85),\
    w(0xe2), w(0xf9), w(0x37), w(0xe8), w(0x1c), w(0x75), w(0xdf), w(0x6e),\
    w(0x47), w(0xf1), w(0x1a), w(0x71), w(0x1d), w(0x29), w(0xc5), w(0x89),\
    w(0x6f), w(0xb7), w(0x62), w(0x0e), w(0xaa), w(0x18), w(0xbe), w(0x1b),\
    w(0xfc), w(0x56), w(0x3e), w(0x4b), w(0xc6), w(0xd2), w(0x79), w(0x20),\
    w(0x9a), w(0xdb), w(0xc0), w(0xfe), w(0x78), w(0xcd), w(0x5a), w(0xf4),\
    w(0x1f), w(0xdd), w(0xa8), w(0x33), w(0x88), w(0x07), w(0xc7), w(0x31),\
    w(0xb1), w(0x12), w(0x10), w(0x59), w(0x27), w(0x80), w(0xec), w(0x5f),\
    w(0x60), w(0x51), w(0x7f), w(0xa9), w(0x19), w(0xb5), w(0x4a), w(0x0d),\
    w(0x2d), w(0xe5), w(0x7a), w(0x9f), w(0x93), w(0xc9), w(0x9c), w(0xef),\
    w(0xa0), w(0xe0), w(0x3b), w(0x4d), w(0xae), w(0x2a), w(0xf5), w(0xb0),\
    w(0xc8), w(0xeb), w(0xbb), w(0x3c), w(0x83), w(0x53), w(0x99), w(0x61),\
    w(0x17), w(0x2b), w(0x04), w(0x7e), w(0xba), w(0x77), w(0xd6), w(0x26),\
    w(0xe1), w(0x69), w(0x14), w(0x63), w(0x55), w(0x21), w(0x0c), w(0x7d) }

#define mm_data(w) {\
    w(0x00), w(0x01), w(0x02), w(0x03), w(0x04), w(0x05), w(0x06), w(0x07),\
    w(0x08), w(0x09), w(0x0a), w(0x0b), w(0x0c), w(0x0d), w(0x0e), w(0x0f),\
    w(0x10), w(0x11), w(0x12), w(0x13), w(0x14), w(0x15), w(0x16), w(0x17),\
    w(0x18), w(0x19), w(0x1a), w(0x1b), w(0x1c), w(0x1d), w(0x1e), w(0x1f),\
    w(0x20), w(0x21), w(0x22), w(0x23), w(0x24), w(0x25), w(0x26), w(0x27),\
    w(0x28), w(0x29), w(0x2a), w(0x2b), w(0x2c), w(0x2d), w(0x2e), w(0x2f),\
    w(0x30), w(0x31), w(0x32), w(0x33), w(0x34), w(0x35), w(0x36), w(0x37),\
    w(0x38), w(0x39), w(0x3a), w(0x3b), w(0x3c), w(0x3d), w(0x3e), w(0x3f),\
    w(0x40), w(0x41), w(0x42), w(0x43), w(0x44), w(0x45), w(0x46), w(0x47),\
    w(0x48), w(0x49), w(0x4a), w(0x4b), w(0x4c), w(0x4d), w(0x4e), w(0x4f),\
    w(0x50), w(0x51), w(0x52), w(0x53), w(0x54), w(0x55), w(0x56), w(0x57),\
    w(0x58), w(0x59), w(0x5a), w(0x5b), w(0x5c), w(0x5d), w(0x5e), w(0x5f),\
    w(0x60), w(0x61), w(0x62), w(0x63), w(0x64), w(0x65), w(0x66), w(0x67),\
    w(0x68), w(0x69), w(0x6a), w(0x6b), w(0x6c), w(0x6d), w(0x6e), w(0x6f),\
    w(0x70), w(0x71), w(0x72), w(0x73), w(0x74), w(0x75), w(0x76), w(0x77),\
    w(0x78), w(0x79), w(0x7a), w(0x7b), w(0x7c), w(0x7d), w(0x7e), w(0x7f),\
    w(0x80), w(0x81), w(0x82), w(0x83), w(0x84), w(0x85), w(0x86), w(0x87),\
    w(0x88), w(0x89), w(0x8a), w(0x8b), w(0x8c), w(0x8d), w(0x8e), w(0x8f),\
    w(0x90), w(0x91), w(0x92), w(0x93), w(0x94), w(0x95), w(0x96), w(0x97),\
    w(0x98), w(0x99), w(0x9a), w(0x9b), w(0x9c), w(0x9d), w(0x9e), w(0x9f),\
    w(0xa0), w(0xa1), w(0xa2), w(0xa3), w(0xa4), w(0xa5), w(0xa6), w(0xa7),\
    w(0xa8), w(0xa9), w(0xaa), w(0xab), w(0xac), w(0xad), w(0xae), w(0xaf),\
    w(0xb0), w(0xb1), w(0xb2), w(0xb3), w(0xb4), w(0xb5), w(0xb6), w(0xb7),\
    w(0xb8), w(0xb9), w(0xba), w(0xbb), w(0xbc), w(0xbd), w(0xbe), w(0xbf),\
    w(0xc0), w(0xc1), w(0xc2), w(0xc3), w(0xc4), w(0xc5), w(0xc6), w(0xc7),\
    w(0xc8), w(0xc9), w(0xca), w(0xcb), w(0xcc), w(0xcd), w(0xce), w(0xcf),\
    w(0xd0), w(0xd1), w(0xd2), w(0xd3), w(0xd4), w(0xd5), w(0xd6), w(0xd7),\
    w(0xd8), w(0xd9), w(0xda), w(0xdb), w(0xdc), w(0xdd), w(0xde), w(0xdf),\
    w(0xe0), w(0xe1), w(0xe2), w(0xe3), w(0xe4), w(0xe5), w(0xe6), w(0xe7),\
    w(0xe8), w(0xe9), w(0xea), w(0xeb), w(0xec), w(0xed), w(0xee), w(0xef),\
    w(0xf0), w(0xf1), w(0xf2), w(0xf3), w(0xf4), w(0xf5), w(0xf6), w(0xf7),\
    w(0xf8), w(0xf9), w(0xfa), w(0xfb), w(0xfc), w(0xfd), w(0xfe), w(0xff) }

#define rc_data(w) {\
    w(0x01), w(0x02), w(0x04), w(0x08), w(0x10),w(0x20), w(0x40), w(0x80),\
    w(0x1b), w(0x36) }

#define h0(x)   (x)

#define w0(p)   bytes2word(p, 0, 0, 0)
#define w1(p)   bytes2word(0, p, 0, 0)
#define w2(p)   bytes2word(0, 0, p, 0)
#define w3(p)   bytes2word(0, 0, 0, p)

#define u0(p)   bytes2word(f2(p), p, p, f3(p))
#define u1(p)   bytes2word(f3(p), f2(p), p, p)
#define u2(p)   bytes2word(p, f3(p), f2(p), p)
#define u3(p)   bytes2word(p, p, f3(p), f2(p))

#define v0(p)   bytes2word(fe(p), f9(p), fd(p), fb(p))
#define v1(p)   bytes2word(fb(p), fe(p), f9(p), fd(p))
#define v2(p)   bytes2word(fd(p), fb(p), fe(p), f9(p))
#define v3(p)   bytes2word(f9(p), fd(p), fb(p), fe(p))

#endif

#if defined(FIXED_TABLES) || !defined(FF_TABLES)

#define f2(x)   ((x<<1) ^ (((x>>7) & 1) * WPOLY))
#define f4(x)   ((x<<2) ^ (((x>>6) & 1) * WPOLY) ^ (((x>>6) & 2) * WPOLY))
#define f8(x)   ((x<<3) ^ (((x>>5) & 1) * WPOLY) ^ (((x>>5) & 2) * WPOLY) \
                        ^ (((x>>5) & 4) * WPOLY))
#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

#else

#define f2(x) ((x) ? pow[log[x] + 0x19] : 0)
#define f3(x) ((x) ? pow[log[x] + 0x01] : 0)
#define f9(x) ((x) ? pow[log[x] + 0xc7] : 0)
#define fb(x) ((x) ? pow[log[x] + 0x68] : 0)
#define fd(x) ((x) ? pow[log[x] + 0xee] : 0)
#define fe(x) ((x) ? pow[log[x] + 0xdf] : 0)
#define fi(x) ((x) ? pow[ 255 - log[x]] : 0)

#endif







#if defined(FIXED_TABLES)

#define d_1(t,n,b,e)       Align Const t n[256]    =   b(e)
#define d_4(t,n,b,e,f,g,h) Align Const t n[4][256] = { b(e), b(f), b(g), b(h) }
static Align Const aes_32t t_dec(r,c)[RC_LENGTH] = rc_data(w0);
#else
#define d_1(t,n,b,e)		Extern Align Const t n[256]
#define d_4(t,n,b,e,f,g,h)	Extern Align Const t n[4][256]
static Align Const aes_32t t_dec(r,c)[RC_LENGTH];
#endif


#if defined( SBX_SET )
    static d_1(aes_08t, t_dec(s,box), sb_data, h0);
#endif
#if defined( ISB_SET )
    static d_1(aes_08t, t_dec(i,box), isb_data, h0);
#endif

#if defined( FT1_SET )
    static d_1(aes_32t, t_dec(f,n), sb_data, u0);
#endif
#if defined( FT4_SET )
    static d_4(aes_32t, t_dec(f,n), sb_data, u0, u1, u2, u3);
#endif

#if defined( FL1_SET )
    static d_1(aes_32t, t_dec(f,l), sb_data, w0);
#endif
#if defined( FL4_SET )
    static d_4(aes_32t, t_dec(f,l), sb_data, w0, w1, w2, w3);
#endif

#if defined( IT1_SET )
    static d_1(aes_32t, t_dec(i,n), isb_data, v0);
#endif
#if defined( IT4_SET )
    static d_4(aes_32t, t_dec(i,n), isb_data, v0, v1, v2, v3);
#endif

#if defined( IL1_SET )
    static d_1(aes_32t, t_dec(i,l), isb_data, w0);
#endif
#if defined( IL4_SET )
    static d_4(aes_32t, t_dec(i,l), isb_data, w0, w1, w2, w3);
#endif

#if defined( LS1_SET )
#if defined( FL1_SET )
#undef  LS1_SET
#else
    static d_1(aes_32t, t_dec(l,s), sb_data, w0);
#endif
#endif

#if defined( LS4_SET )
#if defined( FL4_SET )
#undef  LS4_SET
#else
    static d_4(aes_32t, t_dec(l,s), sb_data, w0, w1, w2, w3);
#endif
#endif

#if defined( IM1_SET )
    static d_1(aes_32t, t_dec(i,m), mm_data, v0);
#endif
#if defined( IM4_SET )
    static d_4(aes_32t, t_dec(i,m), mm_data, v0, v1, v2, v3);
#endif


#if !defined(FIXED_TABLES)


#if !defined(FF_TABLES)

/*  Generate the tables for the dynamic table option

    It will generally be sensible to use tables to compute finite
    field multiplies and inverses but where memory is scarse this
    code might sometimes be better. But it only has effect during
    initialisation so its pretty unimportant in overall terms.
*/

/*  return 2 ^ (n - 1) where n is the bit number of the highest bit
    set in x with x in the range 1 < x < 0x00000200.   This form is
    used so that locals within fi can be bytes rather than words
*/

static aes_08t hibit(const aes_32t x)
{   aes_08t r = (aes_08t)((x >> 1) | (x >> 2));

    r |= (r >> 2);
    r |= (r >> 4);
    return (r + 1) >> 1;
}

/* return the inverse of the finite field element x */

static aes_08t fi(const aes_08t x)
{   aes_08t p1 = x, p2 = BPOLY, n1 = hibit(x), n2 = 0x80, v1 = 1, v2 = 0;

    if(x < 2) return x;

    for(;;)
    {
        if(!n1) return v1;

        while(n2 >= n1)
        {
            n2 /= n1; p2 ^= p1 * n2; v2 ^= v1 * n2; n2 = hibit(p2);
        }

        if(!n2) return v2;

        while(n1 >= n2)
        {
            n1 /= n2; p1 ^= p2 * n1; v1 ^= v2 * n1; n1 = hibit(p1);
        }
    }
}

#endif

/* The forward and inverse affine transformations used in the S-box */

#define fwd_affine(x) \
    (w = (aes_32t)x, w ^= (w<<1)^(w<<2)^(w<<3)^(w<<4), 0x63^(aes_08t)(w^(w>>8)))

#define inv_affine(x) \
    (w = (aes_32t)x, w = (w<<1)^(w<<3)^(w<<6), 0x05^(aes_08t)(w^(w>>8)))

static int init = 0;

void aes_gen_tables(void)
{   aes_32t  i, w;

#if defined(FF_TABLES)

    aes_08t  pow[512], log[256];

    if(init) return;
    /*  log and power tables for GF(2^8) finite field with
        WPOLY as modular polynomial - the simplest primitive
        root is 0x03, used here to generate the tables
    */

    i = 0; w = 1;
    do
    {
        pow[i] = (aes_08t)w;
        pow[i + 255] = (aes_08t)w;
        log[w] = (aes_08t)i++;
        w ^=  (w << 1) ^ (w & 0x80 ? WPOLY : 0);
    }
    while (w != 1);

#else
    if(init) return;
#endif

    for(i = 0, w = 1; i < RC_LENGTH; ++i)
    {
        t_set(r,c)[i] = bytes2word(w, 0, 0, 0);
        w = f2(w);
    }

    for(i = 0; i < 256; ++i)
    {   aes_08t    b;

        b = fwd_affine(fi((aes_08t)i));
        w = bytes2word(f2(b), b, b, f3(b));

#if defined( SBX_SET )
        t_set(s,box)[i] = b;
#endif

#if defined( FT1_SET )                 /* tables for a normal encryption round */
        t_set(f,n)[i] = w;
#endif
#if defined( FT4_SET )
        t_set(f,n)[0][i] = w;
        t_set(f,n)[1][i] = upr(w,1);
        t_set(f,n)[2][i] = upr(w,2);
        t_set(f,n)[3][i] = upr(w,3);
#endif
        w = bytes2word(b, 0, 0, 0);

#if defined( FL1_SET )                 /* tables for last encryption round (may also   */
        t_set(f,l)[i] = w;        /* be used in the key schedule)                 */
#endif
#if defined( FL4_SET )
        t_set(f,l)[0][i] = w;
        t_set(f,l)[1][i] = upr(w,1);
        t_set(f,l)[2][i] = upr(w,2);
        t_set(f,l)[3][i] = upr(w,3);
#endif

#if defined( LS1_SET )                 /* table for key schedule if t_set(f,l) above is    */
        t_set(l,s)[i] = w;      /* not of the required form                     */
#endif
#if defined( LS4_SET )
        t_set(l,s)[0][i] = w;
        t_set(l,s)[1][i] = upr(w,1);
        t_set(l,s)[2][i] = upr(w,2);
        t_set(l,s)[3][i] = upr(w,3);
#endif

        b = fi(inv_affine((aes_08t)i));
        w = bytes2word(fe(b), f9(b), fd(b), fb(b));

#if defined( IM1_SET )                 /* tables for the inverse mix column operation  */
        t_set(i,m)[b] = w;
#endif
#if defined( IM4_SET )
        t_set(i,m)[0][b] = w;
        t_set(i,m)[1][b] = upr(w,1);
        t_set(i,m)[2][b] = upr(w,2);
        t_set(i,m)[3][b] = upr(w,3);
#endif

#if defined( ISB_SET )
        t_set(i,box)[i] = b;
#endif
#if defined( IT1_SET )                 /* tables for a normal decryption round */
        t_set(i,n)[i] = w;
#endif
#if defined( IT4_SET )
        t_set(i,n)[0][i] = w;
        t_set(i,n)[1][i] = upr(w,1);
        t_set(i,n)[2][i] = upr(w,2);
        t_set(i,n)[3][i] = upr(w,3);
#endif
        w = bytes2word(b, 0, 0, 0);
#if defined( IL1_SET )                 /* tables for last decryption round */
        t_set(i,l)[i] = w;
#endif
#if defined( IL4_SET )
        t_set(i,l)[0][i] = w;
        t_set(i,l)[1][i] = upr(w,1);
        t_set(i,l)[2][i] = upr(w,2);
        t_set(i,l)[3][i] = upr(w,3);
#endif
    }
    init = 1;
}

#endif		/* !defined(FIXED_TABLES) */




/************************ Originally aescrypt.c **************************/
 /*
 ---------------------------------------------------------------------------
 Issue 28/01/2004

 This file contains the code for implementing encryption and decryption
 for AES (Rijndael) for block and key sizes of 16, 24 and 32 bytes. It
 can optionally be replaced by code written in assembler using NASM. For
 further details see the file aesopt.h
*/


#define si(y,x,k,c) (s(y,c) = word_in(x, c) ^ (k)[c])
#define so(y,x,c)   word_out(y, c, s(x,c))

#if defined(ARRAYS)
#define locals(y,x)     x[4] = {0,0,0,0}, y[4] = {0,0,0,0}
#else
#define locals(y,x)     x##0,x##1,x##2,x##3,y##0,y##1,y##2,y##3
#endif

#define l_copy(y, x)    s(y,0) = s(x,0); s(y,1) = s(x,1); \
                        s(y,2) = s(x,2); s(y,3) = s(x,3);
#define state_in(y,x,k) si(y,x,k,0); si(y,x,k,1); si(y,x,k,2); si(y,x,k,3)
#define state_out(y,x)  so(y,x,0); so(y,x,1); so(y,x,2); so(y,x,3)
#define round(rm,y,x,k) rm(y,x,k,0); rm(y,x,k,1); rm(y,x,k,2); rm(y,x,k,3)

#if defined(ENCRYPTION) && !defined(AES_ASM)

/* Visual C++ .Net v7.1 provides the fastest encryption code when using
   Pentium optimiation with small code but this is poor for decryption
   so we need to control this with the following VC++ pragmas
*/

#if defined(_MSC_VER)
#pragma optimize( "s", on )
#endif

/* Given the column (c) of the output state variable, the following
   macros give the input state variables which are needed in its
   computation for each row (r) of the state. All the alternative
   macros give the same end values but expand into different ways
   of calculating these values.  In particular the complex macro
   used for dynamically variable block sizes is designed to expand
   to a compile time constant whenever possible but will expand to
   conditional clauses on some branches (I am grateful to Frank
   Yellin for this construction)
*/

#define fwd_var(x,r,c)\
 ( r == 0 ? ( c == 0 ? s(x,0) : c == 1 ? s(x,1) : c == 2 ? s(x,2) : s(x,3))\
 : r == 1 ? ( c == 0 ? s(x,1) : c == 1 ? s(x,2) : c == 2 ? s(x,3) : s(x,0))\
 : r == 2 ? ( c == 0 ? s(x,2) : c == 1 ? s(x,3) : c == 2 ? s(x,0) : s(x,1))\
 :          ( c == 0 ? s(x,3) : c == 1 ? s(x,0) : c == 2 ? s(x,1) : s(x,2)))

#if defined(FT4_SET)
#undef  dec_fmvars
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ four_tables(x,t_use(f,n),fwd_var,rf1,c))
#elif defined(FT1_SET)
#undef  dec_fmvars
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ one_table(x,upr,t_use(f,n),fwd_var,rf1,c))
#else
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ fwd_mcol(no_table(x,t_use(s,box),fwd_var,rf1,c)))
#endif

#if defined(FL4_SET)
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ four_tables(x,t_use(f,l),fwd_var,rf1,c))
#elif defined(FL1_SET)
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ one_table(x,ups,t_use(f,l),fwd_var,rf1,c))
#else
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ no_table(x,t_use(s,box),fwd_var,rf1,c))
#endif

static aes_rval aes_encrypt(const unsigned char *in,
                        unsigned char *out, const aes_encrypt_ctx cx[1])
{   aes_32t         locals(b0, b1);
    const aes_32t   *kp = cx->ks;
#if defined( dec_fmvars )
    dec_fmvars; /* declare variables for fwd_mcol() if needed */
#endif

#if defined( AES_ERR_CHK )
    if( cx->rn != 10 && cx->rn != 12 && cx->rn != 14 )
        return aes_error;
#endif

    state_in(b0, in, kp);

#if (ENC_UNROLL == FULL)

    switch(cx->rn)
    {
    case 14:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        kp += 2 * N_COLS;
    case 12:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        kp += 2 * N_COLS;
    case 10:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 3 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 4 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 5 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 6 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 7 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 8 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 9 * N_COLS);
        round(fwd_lrnd, b0, b1, kp +10 * N_COLS);
    }

#else

#if (ENC_UNROLL == PARTIAL)
    {   aes_32t    rnd;
        for(rnd = 0; rnd < (cx->rn >> 1) - 1; ++rnd)
        {
            kp += N_COLS;
            round(fwd_rnd, b1, b0, kp);
            kp += N_COLS;
            round(fwd_rnd, b0, b1, kp);
        }
        kp += N_COLS;
        round(fwd_rnd,  b1, b0, kp);
#else
    {   aes_32t    rnd;
        for(rnd = 0; rnd < cx->rn - 1; ++rnd)
        {
            kp += N_COLS;
            round(fwd_rnd, b1, b0, kp);
            l_copy(b0, b1);
        }
#endif
        kp += N_COLS;
        round(fwd_lrnd, b0, b1, kp);
    }
#endif

    state_out(out, b0);
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(DECRYPTION) && !defined(AES_ASM)

/* Visual C++ .Net v7.1 provides the fastest encryption code when using
   Pentium optimiation with small code but this is poor for decryption
   so we need to control this with the following VC++ pragmas
*/

#if defined(_MSC_VER)
#pragma optimize( "t", on )
#endif

/* Given the column (c) of the output state variable, the following
   macros give the input state variables which are needed in its
   computation for each row (r) of the state. All the alternative
   macros give the same end values but expand into different ways
   of calculating these values.  In particular the complex macro
   used for dynamically variable block sizes is designed to expand
   to a compile time constant whenever possible but will expand to
   conditional clauses on some branches (I am grateful to Frank
   Yellin for this construction)
*/

#define inv_var(x,r,c)\
 ( r == 0 ? ( c == 0 ? s(x,0) : c == 1 ? s(x,1) : c == 2 ? s(x,2) : s(x,3))\
 : r == 1 ? ( c == 0 ? s(x,3) : c == 1 ? s(x,0) : c == 2 ? s(x,1) : s(x,2))\
 : r == 2 ? ( c == 0 ? s(x,2) : c == 1 ? s(x,3) : c == 2 ? s(x,0) : s(x,1))\
 :          ( c == 0 ? s(x,1) : c == 1 ? s(x,2) : c == 2 ? s(x,3) : s(x,0)))

#if defined(IT4_SET)
#undef  dec_imvars
#define inv_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ four_tables(x,t_use(i,n),inv_var,rf1,c))
#elif defined(IT1_SET)
#undef  dec_imvars
#define inv_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ one_table(x,upr,t_use(i,n),inv_var,rf1,c))
#else
#define inv_rnd(y,x,k,c)    (s(y,c) = inv_mcol((k)[c] ^ no_table(x,t_use(i,box),inv_var,rf1,c)))
#endif

#if defined(IL4_SET)
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ four_tables(x,t_use(i,l),inv_var,rf1,c))
#elif defined(IL1_SET)
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ one_table(x,ups,t_use(i,l),inv_var,rf1,c))
#else
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ no_table(x,t_use(i,box),inv_var,rf1,c))
#endif

static aes_rval aes_decrypt(const unsigned char *in,
                        unsigned char *out, const aes_decrypt_ctx cx[1])
{   aes_32t        locals(b0, b1);
#if defined( dec_imvars )
    dec_imvars; /* declare variables for inv_mcol() if needed */
#endif
    const aes_32t *kp = cx->ks + cx->rn * N_COLS;

#if defined( AES_ERR_CHK )
    if( cx->rn != 10 && cx->rn != 12 && cx->rn != 14 )
        return aes_error;
#endif

    state_in(b0, in, kp);

#if (DEC_UNROLL == FULL)

    switch(cx->rn)
    {
    case 14:
        round(inv_rnd,  b1, b0, kp -  1 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  2 * N_COLS);
        kp -= 2 * N_COLS;
    case 12:
        round(inv_rnd,  b1, b0, kp -  1 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  2 * N_COLS);
        kp -= 2 * N_COLS;
    case 10:
        round(inv_rnd,  b1, b0, kp -  1 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  2 * N_COLS);
        round(inv_rnd,  b1, b0, kp -  3 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  4 * N_COLS);
        round(inv_rnd,  b1, b0, kp -  5 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  6 * N_COLS);
        round(inv_rnd,  b1, b0, kp -  7 * N_COLS);
        round(inv_rnd,  b0, b1, kp -  8 * N_COLS);
        round(inv_rnd,  b1, b0, kp -  9 * N_COLS);
        round(inv_lrnd, b0, b1, kp - 10 * N_COLS);
    }

#else

#if (DEC_UNROLL == PARTIAL)
    {   aes_32t    rnd;
        for(rnd = 0; rnd < (cx->rn >> 1) - 1; ++rnd)
        {
            kp -= N_COLS;
            round(inv_rnd, b1, b0, kp);
            kp -= N_COLS;
            round(inv_rnd, b0, b1, kp);
        }
        kp -= N_COLS;
        round(inv_rnd, b1, b0, kp);
#else
    {   aes_32t    rnd;
        for(rnd = 0; rnd < cx->rn - 1; ++rnd)
        {
            kp -= N_COLS;
            round(inv_rnd, b1, b0, kp);
            l_copy(b0, b1);
        }
#endif
        kp -= N_COLS;
        round(inv_lrnd, b0, b1, kp);
    }
#endif

    state_out(out, b0);
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif





/************************** Originally aeskey.c **************************/


/* Initialise the key schedule from the user supplied key. The key
   length can be specified in bytes, with legal values of 16, 24
   and 32, or in bits, with legal values of 128, 192 and 256. These
   values correspond with Nk values of 4, 6 and 8 respectively.

   The following macros implement a single cycle in the key
   schedule generation process. The number of cycles needed
   for each cx->n_col and nk value is:

    nk =             4  5  6  7  8
    ------------------------------
    cx->n_col = 4   10  9  8  7  7
    cx->n_col = 5   14 11 10  9  9
    cx->n_col = 6   19 15 12 11 11
    cx->n_col = 7   21 19 16 13 14
    cx->n_col = 8   29 23 19 17 14
*/

#define ke4(k,i) \
{   k[4*(i)+4] = ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[4*(i)+5] = ss[1] ^= ss[0]; \
    k[4*(i)+6] = ss[2] ^= ss[1]; k[4*(i)+7] = ss[3] ^= ss[2]; \
}
#define kel4(k,i) \
{   k[4*(i)+4] = ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[4*(i)+5] = ss[1] ^= ss[0]; \
    k[4*(i)+6] = ss[2] ^= ss[1]; k[4*(i)+7] = ss[3] ^= ss[2]; \
}

#define ke6(k,i) \
{   k[6*(i)+ 6] = ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[6*(i)+ 7] = ss[1] ^= ss[0]; \
    k[6*(i)+ 8] = ss[2] ^= ss[1]; k[6*(i)+ 9] = ss[3] ^= ss[2]; \
    k[6*(i)+10] = ss[4] ^= ss[3]; k[6*(i)+11] = ss[5] ^= ss[4]; \
}
#define kel6(k,i) \
{   k[6*(i)+ 6] = ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[6*(i)+ 7] = ss[1] ^= ss[0]; \
    k[6*(i)+ 8] = ss[2] ^= ss[1]; k[6*(i)+ 9] = ss[3] ^= ss[2]; \
}

#define ke8(k,i) \
{   k[8*(i)+ 8] = ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[8*(i)+ 9] = ss[1] ^= ss[0]; \
    k[8*(i)+10] = ss[2] ^= ss[1]; k[8*(i)+11] = ss[3] ^= ss[2]; \
    k[8*(i)+12] = ss[4] ^= ls_box(ss[3],0); k[8*(i)+13] = ss[5] ^= ss[4]; \
    k[8*(i)+14] = ss[6] ^= ss[5]; k[8*(i)+15] = ss[7] ^= ss[6]; \
}
#define kel8(k,i) \
{   k[8*(i)+ 8] = ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[8*(i)+ 9] = ss[1] ^= ss[0]; \
    k[8*(i)+10] = ss[2] ^= ss[1]; k[8*(i)+11] = ss[3] ^= ss[2]; \
}

#if defined(ENCRYPTION_KEY_SCHEDULE)

#if defined(AES_128) || defined(AES_VAR)

static aes_rval
aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1])
{   aes_32t    ss[4];

    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);

#if ENC_UNROLL == NONE
    {   aes_32t i;

        for(i = 0; i < ((11 * N_COLS - 5) / 4); ++i)
            ke4(cx->ks, i);
    }
#else
    ke4(cx->ks, 0);  ke4(cx->ks, 1);
    ke4(cx->ks, 2);  ke4(cx->ks, 3);
    ke4(cx->ks, 4);  ke4(cx->ks, 5);
    ke4(cx->ks, 6);  ke4(cx->ks, 7);
    ke4(cx->ks, 8);
#endif
    kel4(cx->ks, 9);
    cx->rn = 10;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_192) || defined(AES_VAR)

static aes_rval
aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1])
{   aes_32t    ss[6];

    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);
    cx->ks[4] = ss[4] = word_in(key, 4);
    cx->ks[5] = ss[5] = word_in(key, 5);

#if ENC_UNROLL == NONE
    {   aes_32t i;

        for(i = 0; i < (13 * N_COLS - 7) / 6; ++i)
            ke6(cx->ks, i);
    }
#else
    ke6(cx->ks, 0);  ke6(cx->ks, 1);
    ke6(cx->ks, 2);  ke6(cx->ks, 3);
    ke6(cx->ks, 4);  ke6(cx->ks, 5);
    ke6(cx->ks, 6);
#endif
    kel6(cx->ks, 7);
    cx->rn = 12;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_256) || defined(AES_VAR)

static aes_rval
aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
{   aes_32t    ss[8];

    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);
    cx->ks[4] = ss[4] = word_in(key, 4);
    cx->ks[5] = ss[5] = word_in(key, 5);
    cx->ks[6] = ss[6] = word_in(key, 6);
    cx->ks[7] = ss[7] = word_in(key, 7);

#if ENC_UNROLL == NONE
    {   aes_32t i;

        for(i = 0; i < (15 * N_COLS - 9) / 8; ++i)
            ke8(cx->ks,  i);
    }
#else
    ke8(cx->ks, 0); ke8(cx->ks, 1);
    ke8(cx->ks, 2); ke8(cx->ks, 3);
    ke8(cx->ks, 4); ke8(cx->ks, 5);
#endif
    kel8(cx->ks, 6);
    cx->rn = 14;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_VAR)

static aes_rval
aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
{
    switch(key_len)
    {
#if defined( AES_ERR_CHK )
    case 16: case 128: return aes_encrypt_key128(key, cx);
    case 24: case 192: return aes_encrypt_key192(key, cx);
    case 32: case 256: return aes_encrypt_key256(key, cx);
    default: return aes_error;
#else
    case 16: case 128: aes_encrypt_key128(key, cx); return;
    case 24: case 192: aes_encrypt_key192(key, cx); return;
    case 32: case 256: aes_encrypt_key256(key, cx); return;
#endif
    }
}

#endif

#endif

#if defined(DECRYPTION_KEY_SCHEDULE)

#if DEC_ROUND == NO_TABLES
#define ff(x)   (x)
#else
#define ff(x)   inv_mcol(x)
#if defined( dec_imvars )
#define d_vars  dec_imvars
#endif
#endif

#if 1
#define kdf4(k,i) \
{   ss[0] = ss[0] ^ ss[2] ^ ss[1] ^ ss[3]; ss[1] = ss[1] ^ ss[3]; ss[2] = ss[2] ^ ss[3]; ss[3] = ss[3]; \
    ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; ss[i % 4] ^= ss[4]; \
    ss[4] ^= k[4*(i)];   k[4*(i)+4] = ff(ss[4]); ss[4] ^= k[4*(i)+1]; k[4*(i)+5] = ff(ss[4]); \
    ss[4] ^= k[4*(i)+2]; k[4*(i)+6] = ff(ss[4]); ss[4] ^= k[4*(i)+3]; k[4*(i)+7] = ff(ss[4]); \
}
#define kd4(k,i) \
{   ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; ss[i % 4] ^= ss[4]; ss[4] = ff(ss[4]); \
    k[4*(i)+4] = ss[4] ^= k[4*(i)]; k[4*(i)+5] = ss[4] ^= k[4*(i)+1]; \
    k[4*(i)+6] = ss[4] ^= k[4*(i)+2]; k[4*(i)+7] = ss[4] ^= k[4*(i)+3]; \
}
#define kdl4(k,i) \
{   ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; ss[i % 4] ^= ss[4]; \
    k[4*(i)+4] = (ss[0] ^= ss[1]) ^ ss[2] ^ ss[3]; k[4*(i)+5] = ss[1] ^ ss[3]; \
    k[4*(i)+6] = ss[0]; k[4*(i)+7] = ss[1]; \
}
#else
#define kdf4(k,i) \
{   ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[4*(i)+ 4] = ff(ss[0]); ss[1] ^= ss[0]; k[4*(i)+ 5] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[4*(i)+ 6] = ff(ss[2]); ss[3] ^= ss[2]; k[4*(i)+ 7] = ff(ss[3]); \
}
#define kd4(k,i) \
{   ss[4] = ls_box(ss[3],3) ^ t_use(r,c)[i]; \
    ss[0] ^= ss[4]; ss[4] = ff(ss[4]); k[4*(i)+ 4] = ss[4] ^= k[4*(i)]; \
    ss[1] ^= ss[0]; k[4*(i)+ 5] = ss[4] ^= k[4*(i)+ 1]; \
    ss[2] ^= ss[1]; k[4*(i)+ 6] = ss[4] ^= k[4*(i)+ 2]; \
    ss[3] ^= ss[2]; k[4*(i)+ 7] = ss[4] ^= k[4*(i)+ 3]; \
}
#define kdl4(k,i) \
{   ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[4*(i)+ 4] = ss[0]; ss[1] ^= ss[0]; k[4*(i)+ 5] = ss[1]; \
    ss[2] ^= ss[1]; k[4*(i)+ 6] = ss[2]; ss[3] ^= ss[2]; k[4*(i)+ 7] = ss[3]; \
}
#endif

#define kdf6(k,i) \
{   ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[6*(i)+ 6] = ff(ss[0]); ss[1] ^= ss[0]; k[6*(i)+ 7] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[6*(i)+ 8] = ff(ss[2]); ss[3] ^= ss[2]; k[6*(i)+ 9] = ff(ss[3]); \
    ss[4] ^= ss[3]; k[6*(i)+10] = ff(ss[4]); ss[5] ^= ss[4]; k[6*(i)+11] = ff(ss[5]); \
}
#define kd6(k,i) \
{   ss[6] = ls_box(ss[5],3) ^ t_use(r,c)[i]; \
    ss[0] ^= ss[6]; ss[6] = ff(ss[6]); k[6*(i)+ 6] = ss[6] ^= k[6*(i)]; \
    ss[1] ^= ss[0]; k[6*(i)+ 7] = ss[6] ^= k[6*(i)+ 1]; \
    ss[2] ^= ss[1]; k[6*(i)+ 8] = ss[6] ^= k[6*(i)+ 2]; \
    ss[3] ^= ss[2]; k[6*(i)+ 9] = ss[6] ^= k[6*(i)+ 3]; \
    ss[4] ^= ss[3]; k[6*(i)+10] = ss[6] ^= k[6*(i)+ 4]; \
    ss[5] ^= ss[4]; k[6*(i)+11] = ss[6] ^= k[6*(i)+ 5]; \
}
#define kdl6(k,i) \
{   ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[6*(i)+ 6] = ss[0]; ss[1] ^= ss[0]; k[6*(i)+ 7] = ss[1]; \
    ss[2] ^= ss[1]; k[6*(i)+ 8] = ss[2]; ss[3] ^= ss[2]; k[6*(i)+ 9] = ss[3]; \
}

#define kdf8(k,i) \
{   ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[8*(i)+ 8] = ff(ss[0]); ss[1] ^= ss[0]; k[8*(i)+ 9] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[8*(i)+10] = ff(ss[2]); ss[3] ^= ss[2]; k[8*(i)+11] = ff(ss[3]); \
    ss[4] ^= ls_box(ss[3],0); k[8*(i)+12] = ff(ss[4]); ss[5] ^= ss[4]; k[8*(i)+13] = ff(ss[5]); \
    ss[6] ^= ss[5]; k[8*(i)+14] = ff(ss[6]); ss[7] ^= ss[6]; k[8*(i)+15] = ff(ss[7]); \
}
#define kd8(k,i) \
{   aes_32t g = ls_box(ss[7],3) ^ t_use(r,c)[i]; \
    ss[0] ^= g; g = ff(g); k[8*(i)+ 8] = g ^= k[8*(i)]; \
    ss[1] ^= ss[0]; k[8*(i)+ 9] = g ^= k[8*(i)+ 1]; \
    ss[2] ^= ss[1]; k[8*(i)+10] = g ^= k[8*(i)+ 2]; \
    ss[3] ^= ss[2]; k[8*(i)+11] = g ^= k[8*(i)+ 3]; \
    g = ls_box(ss[3],0); \
    ss[4] ^= g; g = ff(g); k[8*(i)+12] = g ^= k[8*(i)+ 4]; \
    ss[5] ^= ss[4]; k[8*(i)+13] = g ^= k[8*(i)+ 5]; \
    ss[6] ^= ss[5]; k[8*(i)+14] = g ^= k[8*(i)+ 6]; \
    ss[7] ^= ss[6]; k[8*(i)+15] = g ^= k[8*(i)+ 7]; \
}
#define kdl8(k,i) \
{   ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[8*(i)+ 8] = ss[0]; ss[1] ^= ss[0]; k[8*(i)+ 9] = ss[1]; \
    ss[2] ^= ss[1]; k[8*(i)+10] = ss[2]; ss[3] ^= ss[2]; k[8*(i)+11] = ss[3]; \
}

#if defined(AES_128) || defined(AES_VAR)

static aes_rval
aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1])
{   aes_32t    ss[5];
#if defined( d_vars )
        d_vars;
#endif
    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
    {   aes_32t i;

        for(i = 0; i < (11 * N_COLS - 5) / 4; ++i)
            ke4(cx->ks, i);
        kel4(cx->ks, 9);
#if !(DEC_ROUND == NO_TABLES)
        for(i = N_COLS; i < 10 * N_COLS; ++i)
            cx->ks[i] = inv_mcol(cx->ks[i]);
#endif
    }
#else
    kdf4(cx->ks, 0);  kd4(cx->ks, 1);
     kd4(cx->ks, 2);  kd4(cx->ks, 3);
     kd4(cx->ks, 4);  kd4(cx->ks, 5);
     kd4(cx->ks, 6);  kd4(cx->ks, 7);
     kd4(cx->ks, 8); kdl4(cx->ks, 9);
#endif
    cx->rn = 10;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_192) || defined(AES_VAR)

static aes_rval
aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1])
{   aes_32t    ss[7];
#if defined( d_vars )
        d_vars;
#endif
    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
    cx->ks[4] = ss[4] = word_in(key, 4);
    cx->ks[5] = ss[5] = word_in(key, 5);
    {   aes_32t i;

        for(i = 0; i < (13 * N_COLS - 7) / 6; ++i)
            ke6(cx->ks, i);
        kel6(cx->ks, 7);
#if !(DEC_ROUND == NO_TABLES)
        for(i = N_COLS; i < 12 * N_COLS; ++i)
            cx->ks[i] = inv_mcol(cx->ks[i]);
#endif
    }
#else
    cx->ks[4] = ff(ss[4] = word_in(key, 4));
    cx->ks[5] = ff(ss[5] = word_in(key, 5));
    kdf6(cx->ks, 0); kd6(cx->ks, 1);
    kd6(cx->ks, 2);  kd6(cx->ks, 3);
    kd6(cx->ks, 4);  kd6(cx->ks, 5);
    kd6(cx->ks, 6); kdl6(cx->ks, 7);
#endif
    cx->rn = 12;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_256) || defined(AES_VAR)

static aes_rval
aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
{   aes_32t    ss[8];
#if defined( d_vars )
        d_vars;
#endif
    cx->ks[0] = ss[0] = word_in(key, 0);
    cx->ks[1] = ss[1] = word_in(key, 1);
    cx->ks[2] = ss[2] = word_in(key, 2);
    cx->ks[3] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
    cx->ks[4] = ss[4] = word_in(key, 4);
    cx->ks[5] = ss[5] = word_in(key, 5);
    cx->ks[6] = ss[6] = word_in(key, 6);
    cx->ks[7] = ss[7] = word_in(key, 7);
    {   aes_32t i;

        for(i = 0; i < (15 * N_COLS - 9) / 8; ++i)
            ke8(cx->ks,  i);
        kel8(cx->ks,  i);
#if !(DEC_ROUND == NO_TABLES)
        for(i = N_COLS; i < 14 * N_COLS; ++i)
            cx->ks[i] = inv_mcol(cx->ks[i]);

#endif
    }
#else
    cx->ks[4] = ff(ss[4] = word_in(key, 4));
    cx->ks[5] = ff(ss[5] = word_in(key, 5));
    cx->ks[6] = ff(ss[6] = word_in(key, 6));
    cx->ks[7] = ff(ss[7] = word_in(key, 7));
    kdf8(cx->ks, 0); kd8(cx->ks, 1);
    kd8(cx->ks, 2);  kd8(cx->ks, 3);
    kd8(cx->ks, 4);  kd8(cx->ks, 5);
    kdl8(cx->ks, 6);
#endif
    cx->rn = 14;
#if defined( AES_ERR_CHK )
    return aes_good;
#endif
}

#endif

#if defined(AES_VAR)

static aes_rval
aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1])
{
    switch(key_len)
    {
#if defined( AES_ERR_CHK )
    case 16: case 128: return aes_decrypt_key128(key, cx);
    case 24: case 192: return aes_decrypt_key192(key, cx);
    case 32: case 256: return aes_decrypt_key256(key, cx);
    default: return aes_error;
#else
    case 16: case 128: aes_decrypt_key128(key, cx); return;
    case 24: case 192: aes_decrypt_key192(key, cx); return;
    case 32: case 256: aes_decrypt_key256(key, cx); return;
#endif
    }
}

#endif

#endif


/*
 * Exported functions for PGP
 */

/*
 * Flags at beginning of priv array to record whether key schedule is in encrypt
 * or decrypt mode.
 *
 * Our API does not provide that information at keying time, so we assume it is for
 * encryption and key that way, then re-key if the encrypt/decrypt direction changes.
 */
#define AES_ENCRYPTION_MODE	0x11
#define AES_DECRYPTION_MODE	0x22


static void
aes128Key(void *priv, void const *keymaterial)
{
	PGPInt32 keySize;

	aes_gen_tables();

	keySize = 16;
	((PGPInt32 *)priv)[0] = AES_ENCRYPTION_MODE;
	((PGPInt32 *)priv)[1] = keySize;
	memcpy ((PGPByte *)priv + 4*(KS_LENGTH+3), keymaterial, keySize);
	aes_encrypt_key128( (void *)keymaterial, (void*)((PGPUInt32 *)priv+2) );
}

static void
aes192Key(void *priv, void const *keymaterial)
{
	PGPInt32 keySize;

	aes_gen_tables();

	keySize = 24;
	((PGPInt32 *)priv)[0] = AES_ENCRYPTION_MODE;
	((PGPInt32 *)priv)[1] = keySize;
	memcpy ((PGPByte *)priv + 4*(KS_LENGTH+3), keymaterial, keySize);
	aes_encrypt_key192( (void *)keymaterial, (void*)((PGPUInt32 *)priv+2) );
}

static void
aes256Key(void *priv, void const *keymaterial)
{
	PGPInt32 keySize;

	aes_gen_tables();

	keySize = 32;
	((PGPInt32 *)priv)[0] = AES_ENCRYPTION_MODE;
	((PGPInt32 *)priv)[1] = keySize;
	memcpy ((PGPByte *)priv + 4*(KS_LENGTH+3), keymaterial, keySize);
	aes_encrypt_key256( (void *)keymaterial, (void*)((PGPUInt32 *)priv+2) );
}


/* FIPS140 state AES Encrypt */
static void
aesEncrypt(void *priv, void const *in, void *out)
{
	PGPInt32 keySize;

	/* Make sure key schedule is in the right mode */
	if (((PGPInt32 *)priv)[0] != AES_ENCRYPTION_MODE) {
		keySize = ((PGPInt32 *)priv)[1];
		aes_encrypt_key ( (void *)((PGPByte *)priv + 4*(KS_LENGTH+3)), keySize,
							(void *)((PGPUInt32 *)priv+2) );
		((PGPInt32 *)priv)[0] = AES_ENCRYPTION_MODE;
	}
	aes_encrypt( (void *)in, out, (void *)((PGPUInt32 *)priv+2) );
}

/* FIPS140 state AES decrypt */
static void
aesDecrypt(void *priv, void const *in, void *out)
{
	PGPInt32 keySize;

	/* Make sure key schedule is in the right mode */
	if (((PGPInt32 *)priv)[0] != AES_DECRYPTION_MODE) {
		keySize = ((PGPInt32 *)priv)[1];
		aes_decrypt_key ( (void *)((PGPByte *)priv + 4*(KS_LENGTH+3)), keySize,
							(void *)((PGPUInt32 *)priv+2) );
		((PGPInt32 *)priv)[0] = AES_DECRYPTION_MODE;
	}
	aes_decrypt( (void *)in, out, (void *)((PGPUInt32 *)priv+2) );
}

/* AES 128 has a block size equal to the key size. This makes Davies-Meyer 
 * hash easy to implement */
static void
AES128StepDM(PGPByte /*first 16 bytes in, second 16 - out*/ hash[32], 
		PGPByte const key[8], PGPUInt32 *xkey_tmp)
{
	int i=4;

	/* make 16 byte key from a 8 byte key */
	memcpy( hash+16, key, 8 );
	aes_encrypt_key128( (void *)(hash+8), (void*)xkey_tmp );
	
	aes_encrypt( hash, hash+16, (void *)xkey_tmp );

	/* write result in first 16 bytes */
	while( i-- )
		*((PGPUInt32*)hash+i) ^= *((PGPUInt32*)hash+i+4);
}

/*
 * Munge the key of the CipherContext based on the supplied bytes.
 * This is for random-number generation, so the exact technique is
 * unimportant, but it happens to use the current key as the
 * IV for computing a tandem Davies-Meyer hash of the bytes,
 * and uses the output as the new key.
 */
static void
aes128Wash(void *priv, void const *bufIn, PGPSize len)
{
    PGPByte hash[32];	/* 16 first bytes is X_0, second 16 bytes is a scratch space */
	
	PGPUInt32   *xkey = ((PGPUInt32 *)priv ) + 2/*for mode,keylen*/;
	PGPByte     *buf = (PGPByte *) bufIn;

	PGPSize i;

	/* Read out the scheduled key for the IV 
	 * The expanded key is a linear array of PGPUInt32s 
	 */
	memcpy( hash, xkey, 16 );

	/* Do the initial blocks of the hash */
	i = len;
	while (i >= 8) {
		AES128StepDM(hash, buf, xkey);
		buf += 8;
		i -= 8;
	}
	
	/* At the end, we do Damgard-Merkle strengthening, just like
	 * MD5 or SHA.  Pad with 0x80 then 0 bytes to 6 mod 8, then
	 * add the length.  We use a 16-bit length in bytes instead
	 * of a 64-bit length in bits, but that is cryptographically
	 * irrelevant.
	 */
	
	/* Do the first partial block - i <= 7 */
	memcpy(hash+24, buf, i);
	hash[24 + i++] = 0x80;
	if (i > 6) {
		pgpClearMemory(hash+24+i, 8-i);
		AES128StepDM(hash, hash+24, xkey);
		i = 0;
	}
	
	pgpClearMemory(hash+24+i, 6-i);
	hash[30] = (PGPByte)(len >> 8);
	hash[31] = (PGPByte)len;
	AES128StepDM(hash, hash+24, xkey);

	/* Re-schedule the key for next invocation */
	aes_encrypt_key128( (void *)hash, (void*)xkey );
	
	pgpClearMemory( hash, sizeof(hash));
}

static void
aes192Wash(void *priv, void const *bufIn, PGPSize len)  {
	//pgpDebugMsg("AES 192 wash is not implemented, calling AES 128 wash");

	aes128Wash( priv, bufIn, len );
}

static void
aes256Wash(void *priv, void const *bufIn, PGPSize len)  {
	//pgpDebugMsg("AES 256 wash is not implemented, calling AES 128 wash");

	aes128Wash( priv, bufIn, len );
}


/*
 * Define a Cipher for the generic cipher.  This is the only
 * real exported thing -- everything else can be static, since everything
 * is referenced through function pointers!
 */
PGPCipherVTBL const cipherAES128 = {
	PGPTXT_MACHINE("AES128"),
	kPGPCipherAlgorithm_AES128,
	16,			/* Blocksize */
	16,			/* Keysize */
	4*(KS_LENGTH+3)+16,	/* enc/dec mode, keysize, scheduled key, raw key */
	alignof(PGPUInt32),
	aes128Key,
	aesEncrypt,
	aesDecrypt,
	aes128Wash,
	NULL		/* rollback doesn't apply to block cipher */
};
PGPCipherVTBL const cipherAES192 = {
	PGPTXT_MACHINE("AES192"),
	kPGPCipherAlgorithm_AES192,
	16,			/* Blocksize */
	24,			/* Keysize */
	4*(KS_LENGTH+3)+24,	/* enc/dec mode, keysize, scheduled key, raw key */
	alignof(PGPUInt32),
	aes192Key,
	aesEncrypt,
	aesDecrypt,
	aes192Wash,
	NULL		/* rollback doesn't apply to block cipher */
};
PGPCipherVTBL const cipherAES256 = {
	PGPTXT_MACHINE("AES256"),
	kPGPCipherAlgorithm_AES256,
	16,			/* Blocksize */
	32,			/* Keysize */
	4*(KS_LENGTH+3)+32,	/* enc/dec mode, keysize, scheduled key, raw key */
	alignof(PGPUInt32),
	aes256Key,
	aesEncrypt,
	aesDecrypt,
	aes256Wash,
	NULL		/* rollback doesn't apply to block cipher */
};



#if defined(UNITTEST) && UNITTEST

/* Test vectors, first line from each ECB known answer test */

/* 128 bit key */
PGPByte K1[] = {
	0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12
};
PGPByte P1[] = {
	0x50, 0x68, 0x12, 0xA4, 0x5F, 0x08, 0xC8, 0x89,
	0xB9, 0x7F, 0x59, 0x80, 0x03, 0x8B, 0x83, 0x59
};
PGPByte C1[] = {
	0xD8, 0xF5, 0x32, 0x53, 0x82, 0x89, 0xEF, 0x7D,
	0x06, 0xB5, 0x06, 0xA4, 0xFD, 0x5B, 0xE9, 0xC9
};

/* 192 bit key */
PGPByte K2[] = {
	0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
	0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C
};
PGPByte P2[] = {
	0x2D, 0x33, 0xEE, 0xF2, 0xC0, 0x43, 0x0A, 0x8A,
	0x9E, 0xBF, 0x45, 0xE8, 0x09, 0xC4, 0x0B, 0xB6
};
PGPByte C2[] = {
	0xDF, 0xF4, 0x94, 0x5E, 0x03, 0x36, 0xDF, 0x4C,
	0x1C, 0x56, 0xBC, 0x70, 0x0E, 0xFF, 0x83, 0x7F
};

/* 256 bit key */
PGPByte K3[] = {
	0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
	0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C,
	0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26
};
PGPByte P3[] = {
	0x83, 0x4E, 0xAD, 0xFC, 0xCA, 0xC7, 0xE1, 0xB3,
	0x06, 0x64, 0xB1, 0xAB, 0xA4, 0x48, 0x15, 0xAB
};
PGPByte C3[] = {
	0x19, 0x46, 0xDA, 0xBF, 0x6A, 0x03, 0xA2, 0xA2,
	0xC3, 0xD0, 0xB0, 0x50, 0x80, 0xAE, 0xD6, 0xFC
};



int
main(void)
{	/* Test driver for AES cipher */
	PGPByte priv[4*(KS_LENGTH+3)+32]; /* size from cipherAES256 */
	PGPByte X[16], Y[16];
	int i;

	PGPByte t[16];

#if !defined(FIXED_TABLES)
	aes_gen_tables();
#endif
	
	for( i=0; i<16; i++ )
		t[i] = i;

	aes128Key(priv, K1);
	aesEncrypt(priv, P1, X);
	if (memcmp(C1, X, sizeof(X)) == 0)
		printf (PGPTXT_DEBUG8("Encryption test 1 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON ENCRYPTION TEST 1\n"));
	aesDecrypt(priv, C1, Y);
	if (memcmp(P1, Y, sizeof(Y)) == 0)
		printf (PGPTXT_DEBUG8("Decryption test 1 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON DECRYPTION TEST 1\n"));

	aes128Wash( priv, t, 16 ); 
	aesDecrypt(priv, C1, Y);
	printf (PGPTXT_DEBUG8("Repeated decryption test 1 with washed key:\n"));
	for( i=0; i<16; i++ )  {
		printf(PGPTXT_DEBUG8("%02x "), Y[i]);
	}
	printf(PGPTXT_DEBUG8("\n"));

	aes192Key(priv, K2);
	aesEncrypt(priv, P2, X);
	if (memcmp(C2, X, sizeof(X)) == 0)
		printf (PGPTXT_DEBUG8("Encryption test 2 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON ENCRYPTION TEST 2\n"));
	aesDecrypt(priv, C2, Y);
	if (memcmp(P2, Y, sizeof(Y)) == 0)
		printf (PGPTXT_DEBUG8("Decryption test 2 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON DECRYPTION TEST 2\n"));

	aes256Key(priv, K3);
	aesEncrypt(priv, P3, X);
	if (memcmp(C3, X, sizeof(X)) == 0)
		printf (PGPTXT_DEBUG8("Encryption test 3 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON ENCRYPTION TEST 3\n"));
	aesDecrypt(priv, C3, Y);
	if (memcmp(P3, Y, sizeof(Y)) == 0)
		printf (PGPTXT_DEBUG8("Decryption test 3 passed\n"));
	else
		printf (PGPTXT_DEBUG8("ERROR ON DECRYPTION TEST 3\n"));

	
	/* perform bulk encryption test */
	 {
		time_t t0, t1;
		int i=0;

		t0 = time(NULL);
		while( i++ < 1024*1024*50 )
			aesEncrypt(priv, P3, X);
		t1 = time(t1);

		printf("%d seconds total for AES256 encryption, %.02g sec/Mb\n", t1-t0, (t1-t0)/(16.*50) );
	 }
		
	return 0;	/* normal exit */
} /* main */

#endif /* UNITTEST */





#endif /* ] PGP_AES */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
