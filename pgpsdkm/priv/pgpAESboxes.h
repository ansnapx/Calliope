/*____________________________________________________________________________
    Copyright (C) 2004 PGP Corporation
    All rights reserved.

    $Id: pgpAESboxes.h 36634 2005-06-28 03:15:50Z ajivsov $
____________________________________________________________________________*/

/* Top level optimization preference: 
   compile for the best speed possible (PGP_AES_SPEED=2), for
   good speed with less static data (PGP_AES_SPEED=1), or
   for small size (PGP_AES_SPEED=0).
   PGP_AES_SPEED=1 has a bias toward speed.
   PGP_AES_SPEED=0 is not compatible with gcc -O3 (crash in this file),
   so optimization by size is expected with PGP_AES_SPEED=0.
*/
#ifndef PGP_AES_SPEED
#if !defined(PGP_SYMBIAN) || !PGP_SYMBIAN
	#define PGP_AES_SPEED 2
#else
	#define PGP_AES_SPEED 1
#endif
#endif

/**************************** Originally aes.h ******************************/

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
 Issue 28/01/2004

 This file contains the definitions required to use AES in C. See aesopt.h
 for optimisation details.
*/

#if !defined( _AES_H )
#define _AES_H


#include "pgpAES.h"

#define AES_128     /* define if AES with 128 bit keys is needed    */
#define AES_192     /* define if AES with 192 bit keys is needed    */
#define AES_256     /* define if AES with 256 bit keys is needed    */
#define AES_VAR     /* define if a variable key size is needed      */

/* The following must also be set in assembler files if being used  */

#define AES_ENCRYPT /* if support for encryption is needed          */
#define AES_DECRYPT /* if support for decryption is needed          */
#undef  AES_ERR_CHK /* for parameter checks & error return codes    */


typedef PGPByte		aes_08t;
typedef PGPUInt32	aes_32t;


#define AES_BLOCK_SIZE  16  /* the AES block size in bytes          */
#define N_COLS           4  /* the number of columns in the state   */

/* The key schedule length is 11, 13 or 15 16-byte blocks for 128,  */
/* 192 or 256-bit keys respectively. That is 176, 208 or 240 bytes  */
/* or 44, 52 or 60 32-bit words. For simplicity this code allocates */
/* the maximum 60 word array for the key schedule for all key sizes */

#if defined( AES_VAR ) || defined( AES_256 )
#define KS_LENGTH       60
#elif defined( AES_192 )
#define KS_LENGTH       52
#else
#define KS_LENGTH       44
#endif

#if defined( AES_ERR_CHK )
#define aes_ret     int
#define aes_good    0
#define aes_error  -1
#else
#define aes_ret     void
#endif

#if !defined( AES_DLL )                 /* implement normal/DLL functions   */
#define aes_rval    aes_ret
#else
#define aes_rval    aes_ret __declspec(dllexport) _stdcall
#endif

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_32t rn;
} aes_encrypt_ctx;

typedef struct
{   aes_32t ks[KS_LENGTH];
    aes_32t rn;
} aes_decrypt_ctx;

/* This routine must be called before first use if non-static       */
/* tables are being used                                            */

void aes_gen_tables(void);
/* renamed for clarity */
#define gen_tabs aes_gen_tables

/* The key length (klen) is input in bytes when it is in the range  */
/* 16 <= klen <= 32 or in bits when in the range 128 <= klen <= 256 */

#if defined( AES_ENCRYPT )

#if 0
#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_encrypt_key128(const unsigned char *in_key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_encrypt_key192(const unsigned char *in_key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_encrypt_key256(const unsigned char *in_key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_encrypt_key(const unsigned char *in_key, int key_len, aes_encrypt_ctx cx[1]);
#endif

aes_rval aes_encrypt(const unsigned char *in_blk, unsigned char *out_blk, const aes_encrypt_ctx cx[1]);
#endif /* 0 */
#endif

#if defined( AES_DECRYPT )

#if 0
#if defined(AES_128) || defined(AES_VAR)
aes_rval aes_decrypt_key128(const unsigned char *in_key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
aes_rval aes_decrypt_key192(const unsigned char *in_key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
aes_rval aes_decrypt_key256(const unsigned char *in_key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
aes_rval aes_decrypt_key(const unsigned char *in_key, int key_len, aes_decrypt_ctx cx[1]);
#endif

aes_rval aes_decrypt(const unsigned char *in_blk,  unsigned char *out_blk, const aes_decrypt_ctx cx[1]);
#endif /* 0 */
#endif



/**************************** Originally aesopt.h ******************************/


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
 Issue 28/01/2004

 My thanks go to Dag Arne Osvik for devising the schemes used here for key
 length derivation from the form of the key schedule

 This file contains the compilation options for AES (Rijndael) and code
 that is common across encryption, key scheduling and table generation.

 OPERATION

 These source code files implement the AES algorithm Rijndael designed by
 Joan Daemen and Vincent Rijmen. This version is designed for the standard
 block size of 16 bytes and for key sizes of 128, 192 and 256 bits (16, 24
 and 32 bytes).

 This version is designed for flexibility and speed using operations on
 32-bit words rather than operations on bytes.  It can be compiled with
 either big or little endian internal byte order but is faster when the
 native byte order for the processor is used.

 THE CIPHER INTERFACE

 The cipher interface is implemented as an array of bytes in which lower
 AES bit sequence indexes map to higher numeric significance within bytes.

  aes_08t                 (an unsigned  8-bit type)
  aes_32t                 (an unsigned 32-bit type)
  struct aes_encrypt_ctx  (structure for the cipher encryption context)
  struct aes_decrypt_ctx  (structure for the cipher decryption context)
  aes_rval                the function return type

  C subroutine calls:

  aes_rval aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
  aes_rval aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
  aes_rval aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
  aes_rval aes_encrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_encrypt_ctx cx[1]);

  aes_rval aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
  aes_rval aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
  aes_rval aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
  aes_rval aes_decrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_decrypt_ctx cx[1]);

 IMPORTANT NOTE: If you are using this C interface with dynamic tables make sure that
 you call genTabs() before AES is used so that the tables are initialised.

 C++ aes class subroutines:

     Class AESencrypt  for encryption

      Construtors:
          AESencrypt(void)
          AESencrypt(const unsigned char *key) - 128 bit key
      Members:
          aes_rval key128(const unsigned char *key)
          aes_rval key192(const unsigned char *key)
          aes_rval key256(const unsigned char *key)
          aes_rval encrypt(const unsigned char *in, unsigned char *out) const

      Class AESdecrypt  for encryption
      Construtors:
          AESdecrypt(void)
          AESdecrypt(const unsigned char *key) - 128 bit key
      Members:
          aes_rval key128(const unsigned char *key)
          aes_rval key192(const unsigned char *key)
          aes_rval key256(const unsigned char *key)
          aes_rval decrypt(const unsigned char *in, unsigned char *out) const

    COMPILATION

    The files used to provide AES (Rijndael) are

    a. aes.h for the definitions needed for use in C.
    b. aescpp.h for the definitions needed for use in C++.
    c. aesopt.h for setting compilation options (also includes common code).
    d. aescrypt.c for encryption and decrytpion, or
    e. aeskey.c for key scheduling.
    f. aestab.c for table loading or generation.
    g. aescrypt.asm for encryption and decryption using assembler code.
    h. aescrypt.mmx.asm for encryption and decryption using MMX assembler.

    To compile AES (Rijndael) for use in C code use aes.h and set the
    defines here for the facilities you need (key lengths, encryption
    and/or decryption). Do not define AES_DLL or AES_CPP.  Set the options
    for optimisations and table sizes here.

    To compile AES (Rijndael) for use in in C++ code use aescpp.h but do
    not define AES_DLL

    To compile AES (Rijndael) in C as a Dynamic Link Library DLL) use
    aes.h and include the AES_DLL define.

    CONFIGURATION OPTIONS (here and in aes.h)

    a. set AES_DLL in aes.h if AES (Rijndael) is to be compiled as a DLL
    b. You may need to set PLATFORM_BYTE_ORDER to define the byte order.
    c. If you want the code to run in a specific internal byte order, then
       ALGORITHM_BYTE_ORDER must be set accordingly.
    d. set other configuration options decribed below.
*/


/*  CONFIGURATION - USE OF DEFINES

    Later in this section there are a number of defines that control the
    operation of the code.  In each section, the purpose of each define is
    explained so that the relevant form can be included or excluded by
    setting either 1's or 0's respectively on the branches of the related
    #if clauses.

    PLATFORM SPECIFIC INCLUDES AND BYTE ORDER IN 32-BIT WORDS

    To obtain the highest speed on processors with 32-bit words, this code
    needs to determine the byte order of the target machine. The following
    block of code is an attempt to capture the most obvious ways in which
    various environemnts define byte order. It may well fail, in which case
    the definitions will need to be set by editing at the points marked
    **** EDIT HERE IF NECESSARY **** below.  My thanks go to Peter Gutmann
    for his assistance with this endian detection nightmare.
*/

#define BRG_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define BRG_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if PGP_WORDSBIGENDIAN
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#elif PGP_WORDSLITTLEENDIAN
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#else
#  error Failed to include pgpBase.h for endianness
#endif


/*  SOME LOCAL DEFINITIONS  */

#define NO_TABLES              0
#define ONE_TABLE              1
#define FOUR_TABLES            4
#define NONE                   0
#define PARTIAL                1
#define FULL                   2

#if defined(bswap32)
#define aes_sw32    bswap32
#elif defined(bswap_32)
#define aes_sw32    bswap_32
#else
#define brot(x,n)   (((aes_32t)(x) <<  n) | ((aes_32t)(x) >> (32 - n)))
#define aes_sw32(x) ((brot((x),8) & 0x00ff00ff) | (brot((x),24) & 0xff00ff00))
#endif

/*  1. FUNCTIONS REQUIRED

    This implementation provides subroutines for encryption, decryption
    and for setting the three key lengths (separately) for encryption
    and decryption. When the assembler code is not being used the following
    definition blocks allow the selection of the routines that are to be
    included in the compilation.
*/
#if defined( AES_ENCRYPT )
#define ENCRYPTION
#define ENCRYPTION_KEY_SCHEDULE
#endif

#if defined( AES_DECRYPT )
#define DECRYPTION
#define DECRYPTION_KEY_SCHEDULE
#endif

/*  2. ASSEMBLER SUPPORT

    This define (which can be on the command line) enables the use of the
    assembler code routines for encryption and decryption with the C code
    only providing key scheduling
*/
#if 0 && !defined(AES_ASM)
#define AES_ASM
#endif

/*  3. BYTE ORDER WITHIN 32 BIT WORDS

    The fundamental data processing units in Rijndael are 8-bit bytes. The
    input, output and key input are all enumerated arrays of bytes in which
    bytes are numbered starting at zero and increasing to one less than the
    number of bytes in the array in question. This enumeration is only used
    for naming bytes and does not imply any adjacency or order relationship
    from one byte to another. When these inputs and outputs are considered
    as bit sequences, bits 8*n to 8*n+7 of the bit sequence are mapped to
    byte[n] with bit 8n+i in the sequence mapped to bit 7-i within the byte.
    In this implementation bits are numbered from 0 to 7 starting at the
    numerically least significant end of each byte (bit n represents 2^n).

    However, Rijndael can be implemented more efficiently using 32-bit
    words by packing bytes into words so that bytes 4*n to 4*n+3 are placed
    into word[n]. While in principle these bytes can be assembled into words
    in any positions, this implementation only supports the two formats in
    which bytes in adjacent positions within words also have adjacent byte
    numbers. This order is called big-endian if the lowest numbered bytes
    in words have the highest numeric significance and little-endian if the
    opposite applies.

    This code can work in either order irrespective of the order used by the
    machine on which it runs. Normally the internal byte order will be set
    to the order of the processor on which the code is to be run but this
    define can be used to reverse this in special situations

    NOTE: Assembler code versions rely on PLATFORM_BYTE_ORDER being set
*/
#if 1 || defined(AES_ASM)
#define ALGORITHM_BYTE_ORDER PLATFORM_BYTE_ORDER
#elif 0
#define ALGORITHM_BYTE_ORDER BRG_LITTLE_ENDIAN
#elif 0
#define ALGORITHM_BYTE_ORDER BRG_BIG_ENDIAN
#else
#error The algorithm byte order is not defined
#endif

/*  4. FAST INPUT/OUTPUT OPERATIONS.

    On some machines it is possible to improve speed by transferring the
    bytes in the input and output arrays to and from the internal 32-bit
    variables by addressing these arrays as if they are arrays of 32-bit
    words.  On some machines this will always be possible but there may
    be a large performance penalty if the byte arrays are not aligned on
    the normal word boundaries. On other machines this technique will
    lead to memory access errors when such 32-bit word accesses are not
    properly aligned. The option SAFE_IO avoids such problems but will
    often be slower on those machines that support misaligned access
    (especially so if care is taken to align the input  and output byte
    arrays on 32-bit word boundaries). If SAFE_IO is not defined it is
    assumed that access to byte arrays as if they are arrays of 32-bit
    words will not cause problems when such accesses are misaligned.
*/
#if 1 && !defined(_MSC_VER) && !defined(PGP_OSX)
#define SAFE_IO
#endif

/*  5. LOOP UNROLLING

    The code for encryption and decrytpion cycles through a number of rounds
    that can be implemented either in a loop or by expanding the code into a
    long sequence of instructions, the latter producing a larger program but
    one that will often be much faster. The latter is called loop unrolling.
    There are also potential speed advantages in expanding two iterations in
    a loop with half the number of iterations, which is called partial loop
    unrolling.  The following options allow partial or full loop unrolling
    to be set independently for encryption and decryption
*/
#if PGP_AES_SPEED==2
#define ENC_UNROLL  FULL
#elif PGP_AES_SPEED==1
#define ENC_UNROLL  PARTIAL
#else
#define ENC_UNROLL  NONE
#endif

#if PGP_AES_SPEED==2
#define DEC_UNROLL  FULL
#elif PGP_AES_SPEED==1
#define DEC_UNROLL  PARTIAL
#else
#define DEC_UNROLL  NONE
#endif

/*  6. FAST FINITE FIELD OPERATIONS

    If this section is included, tables are used to provide faster finite
    field arithmetic (this has no effect if FIXED_TABLES is defined).
*/

#if PGP_AES_SPEED==2
#define FF_TABLES
#endif

/*  7. INTERNAL STATE VARIABLE FORMAT

    The internal state of Rijndael is stored in a number of local 32-bit
    word varaibles which can be defined either as an array or as individual
    names variables. Include this section if you want to store these local
    varaibles in arrays. Otherwise individual local variables will be used.
*/
#if 1
#define ARRAYS
#endif

/* In this implementation the columns of the state array are each held in
   32-bit words. The state array can be held in various ways: in an array
   of words, in a number of individual word variables or in a number of
   processor registers. The following define maps a variable name x and
   a column number c to the way the state array variable is to be held.
   The first define below maps the state into an array x[c] whereas the
   second form maps the state into a number of individual variables x0,
   x1, etc.  Another form could map individual state colums to machine
   register names.
*/

#if defined(ARRAYS)
#define s(x,c) x[c]
#else
#define s(x,c) x##c
#endif

/*  8. FIXED OR DYNAMIC TABLES

    When this section is included the tables used by the code are compiled
    statically into the binary file.  Otherwise the subroutine gen_tabs()
    must be called to compute them before the code is first used.
*/

#if 0
 *  Setting this macro increases executable image size on the disk by 20K because,
 *  unlike uninitialized statis data, initialized arrays must persist on disk. 
 *  The speed to initialize the tables once at startup is comparable to the time to
 *  encrypt one block. This will be done only once at SDK initialization. Compare this
 *  with extra time required to fetch larger executable from disk.
 *  The only reason why FIXED_TABLES needs to be 1 is when there is no easy way to call
 *  gen_tabs(), which is not a problem for SDK. 
 */
#define FIXED_TABLES
#endif

/*  9. TABLE ALIGNMENT

    On some sytsems speed will be improved by aligning the AES large lookup
    tables on particular boundaries. This define should be set to a power of
    two giving the desired alignment. It can be left undefined if alignment
    is not needed.  This option is specific to the Microsft VC++ compiler -
    it seems to sometimes cause trouble for the VC++ version 6 compiler.
*/

#if 1 && defined(_MSC_VER) && (_MSC_VER >= 1300)
#define TABLE_ALIGN 64
#endif

/*  10. INTERNAL TABLE CONFIGURATION

    This cipher proceeds by repeating in a number of cycles known as 'rounds'
    which are implemented by a round function which can optionally be speeded
    up using tables.  The basic tables are each 256 32-bit words, with either
    one or four tables being required for each round function depending on
    how much speed is required. The encryption and decryption round functions
    are different and the last encryption and decrytpion round functions are
    different again making four different round functions in all.

    This means that:
      1. Normal encryption and decryption rounds can each use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.
      2. The last encryption and decryption rounds can also use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.

    Include or exclude the appropriate definitions below to set the number
    of tables used by this implementation.
*/

#if PGP_AES_SPEED   /* set tables for the normal encryption round ( ~70% slower )*/
#define ENC_ROUND   FOUR_TABLES
#elif 0
#define ENC_ROUND   ONE_TABLE
#else
#define ENC_ROUND   NO_TABLES
#endif

#if PGP_AES_SPEED==2   /* set tables for the last encryption round (~5% slower) */
#define LAST_ENC_ROUND  FOUR_TABLES
#elif PGP_AES_SPEED==1
#define LAST_ENC_ROUND  ONE_TABLE
#else
#define LAST_ENC_ROUND  NO_TABLES
#endif

#if PGP_AES_SPEED   /* set tables for the normal decryption round (~70% slower) */
#define DEC_ROUND   FOUR_TABLES
#elif 0
#define DEC_ROUND   ONE_TABLE
#else
#define DEC_ROUND   NO_TABLES
#endif

#if PGP_AES_SPEED==2   /* set tables for the last decryption round (~5% slower) */
#define LAST_DEC_ROUND  FOUR_TABLES
#elif PGP_AES_SPEED==1
#define LAST_DEC_ROUND  ONE_TABLE
#else
#define LAST_DEC_ROUND  NO_TABLES
#endif

/*  The decryption key schedule can be speeded up with tables in the same
    way that the round functions can.  Include or exclude the following
    defines to set this requirement.
*/
#if PGP_AES_SPEED==2
#define KEY_SCHED   FOUR_TABLES
#elif 1
#define KEY_SCHED   ONE_TABLE
#else
#define KEY_SCHED   NO_TABLES
#endif

/* END OF CONFIGURATION OPTIONS */

#define RC_LENGTH   (5 * (AES_BLOCK_SIZE / 4 - 2))

/* Disable or report errors on some combinations of options */

#if ENC_ROUND == NO_TABLES && LAST_ENC_ROUND != NO_TABLES
#undef  LAST_ENC_ROUND
#define LAST_ENC_ROUND  NO_TABLES
#elif ENC_ROUND == ONE_TABLE && LAST_ENC_ROUND == FOUR_TABLES
#undef  LAST_ENC_ROUND
#define LAST_ENC_ROUND  ONE_TABLE
#endif

#if ENC_ROUND == NO_TABLES && ENC_UNROLL != NONE
#undef  ENC_UNROLL
#define ENC_UNROLL  NONE
#endif

#if DEC_ROUND == NO_TABLES && LAST_DEC_ROUND != NO_TABLES
#undef  LAST_DEC_ROUND
#define LAST_DEC_ROUND  NO_TABLES
#elif DEC_ROUND == ONE_TABLE && LAST_DEC_ROUND == FOUR_TABLES
#undef  LAST_DEC_ROUND
#define LAST_DEC_ROUND  ONE_TABLE
#endif

#if DEC_ROUND == NO_TABLES && DEC_UNROLL != NONE
#undef  DEC_UNROLL
#define DEC_UNROLL  NONE
#endif

/*  upr(x,n):  rotates bytes within words by n positions, moving bytes to
               higher index positions with wrap around into low positions
    ups(x,n):  moves bytes by n positions to higher index positions in
               words but without wrap around
    bval(x,n): extracts a byte from a word

    NOTE:      The definitions given here are intended only for use with
               unsigned variables and with shift counts that are compile
               time constants
*/

#if (ALGORITHM_BYTE_ORDER == BRG_LITTLE_ENDIAN)
#define upr(x,n)        (((aes_32t)(x) << (8 * (n))) | ((aes_32t)(x) >> (32 - 8 * (n))))
#define ups(x,n)        ((aes_32t) (x) << (8 * (n)))
#define bval(x,n)       ((aes_08t)((x) >> (8 * (n))))
#define bytes2word(b0, b1, b2, b3)  \
        (((aes_32t)(b3) << 24) | ((aes_32t)(b2) << 16) | ((aes_32t)(b1) << 8) | (b0))
#endif

#if (ALGORITHM_BYTE_ORDER == BRG_BIG_ENDIAN)
#define upr(x,n)        (((aes_32t)(x) >> (8 * (n))) | ((aes_32t)(x) << (32 - 8 * (n))))
#define ups(x,n)        ((aes_32t) (x) >> (8 * (n))))
#define bval(x,n)       ((aes_08t)((x) >> (24 - 8 * (n))))
#define bytes2word(b0, b1, b2, b3)  \
        (((aes_32t)(b0) << 24) | ((aes_32t)(b1) << 16) | ((aes_32t)(b2) << 8) | (b3))
#endif

#if defined(SAFE_IO)

#define word_in(x,c)    bytes2word(((aes_08t*)(x)+4*c)[0], ((aes_08t*)(x)+4*c)[1], \
                                   ((aes_08t*)(x)+4*c)[2], ((aes_08t*)(x)+4*c)[3])
#define word_out(x,c,v) { ((aes_08t*)(x)+4*c)[0] = bval(v,0); ((aes_08t*)(x)+4*c)[1] = bval(v,1); \
                          ((aes_08t*)(x)+4*c)[2] = bval(v,2); ((aes_08t*)(x)+4*c)[3] = bval(v,3); }

#elif (ALGORITHM_BYTE_ORDER == PLATFORM_BYTE_ORDER)

#define word_in(x,c)    (*((aes_32t*)(x)+(c)))
#define word_out(x,c,v) (*((aes_32t*)(x)+(c)) = (v))

#else

#define word_in(x,c)    aes_sw32(*((aes_32t*)(x)+(c)))
#define word_out(x,c,v) (*((aes_32t*)(x)+(c)) = aes_sw32(v))

#endif

/* the finite field modular polynomial and elements */

#define WPOLY   0x011b
#define BPOLY     0x1b

/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

#define m1  0x80808080
#define m2  0x7f7f7f7f
#define gf_mulx(x)  ((((x) & m2) << 1) ^ ((((x) & m1) >> 7) * BPOLY))

/* The following defines provide alternative definitions of gf_mulx that might
   give improved performance if a fast 32-bit multiply is not available. Note
   that a temporary variable u needs to be defined where gf_mulx is used.

#define gf_mulx(x) (u = (x) & m1, u |= (u >> 1), ((x) & m2) << 1) ^ ((u >> 3) | (u >> 6))
#define m4  (0x01010101 * BPOLY)
#define gf_mulx(x) (u = (x) & m1, ((x) & m2) << 1) ^ ((u - (u >> 7)) & m4)
*/

/* Work out which tables are needed for the different options   */

#if defined( AES_ASM )
#if defined( ENC_ROUND )
#undef  ENC_ROUND
#endif
#define ENC_ROUND   FOUR_TABLES
#if defined( LAST_ENC_ROUND )
#undef  LAST_ENC_ROUND
#endif
#define LAST_ENC_ROUND  FOUR_TABLES
#if defined( DEC_ROUND )
#undef  DEC_ROUND
#endif
#define DEC_ROUND   FOUR_TABLES
#if defined( LAST_DEC_ROUND )
#undef  LAST_DEC_ROUND
#endif
#define LAST_DEC_ROUND  FOUR_TABLES
#if defined( KEY_SCHED )
#undef  KEY_SCHED
#define KEY_SCHED   FOUR_TABLES
#endif
#endif

#if defined(ENCRYPTION) || defined(AES_ASM)
#if ENC_ROUND == ONE_TABLE
#define FT1_SET
#elif ENC_ROUND == FOUR_TABLES
#define FT4_SET
#else
#define SBX_SET
#endif
#if LAST_ENC_ROUND == ONE_TABLE
#define FL1_SET
#elif LAST_ENC_ROUND == FOUR_TABLES
#define FL4_SET
#elif !defined(SBX_SET)
#define SBX_SET
#endif
#endif

#if defined(DECRYPTION) || defined(AES_ASM)
#if DEC_ROUND == ONE_TABLE
#define IT1_SET
#elif DEC_ROUND == FOUR_TABLES
#define IT4_SET
#else
#define ISB_SET
#endif
#if LAST_DEC_ROUND == ONE_TABLE
#define IL1_SET
#elif LAST_DEC_ROUND == FOUR_TABLES
#define IL4_SET
#elif !defined(ISB_SET)
#define ISB_SET
#endif
#endif

#if defined(ENCRYPTION_KEY_SCHEDULE) || defined(DECRYPTION_KEY_SCHEDULE)
#if KEY_SCHED == ONE_TABLE
#define LS1_SET
#define IM1_SET
#elif KEY_SCHED == FOUR_TABLES
#define LS4_SET
#define IM4_SET
#elif !defined(SBX_SET)
#define SBX_SET
#endif
#endif

/* generic definitions of Rijndael macros that use tables    */

#define no_table(x,box,vf,rf,c) bytes2word( \
    box[bval(vf(x,0,c),rf(0,c))], \
    box[bval(vf(x,1,c),rf(1,c))], \
    box[bval(vf(x,2,c),rf(2,c))], \
    box[bval(vf(x,3,c),rf(3,c))])

#define one_table(x,op,tab,vf,rf,c) \
 (     tab[bval(vf(x,0,c),rf(0,c))] \
  ^ op(tab[bval(vf(x,1,c),rf(1,c))],1) \
  ^ op(tab[bval(vf(x,2,c),rf(2,c))],2) \
  ^ op(tab[bval(vf(x,3,c),rf(3,c))],3))

#define four_tables(x,tab,vf,rf,c) \
 (  tab[0][bval(vf(x,0,c),rf(0,c))] \
  ^ tab[1][bval(vf(x,1,c),rf(1,c))] \
  ^ tab[2][bval(vf(x,2,c),rf(2,c))] \
  ^ tab[3][bval(vf(x,3,c),rf(3,c))])

#define vf1(x,r,c)  (x)
#define rf1(r,c)    (r)
#define rf2(r,c)    ((8+r-c)&3)

/* perform forward and inverse column mix operation on four bytes in long word x in */
/* parallel. NOTE: x must be a simple variable, NOT an expression in these macros.  */

#if defined(FM4_SET)    /* not currently used */
#define fwd_mcol(x)     four_tables(x,t_use(f,m),vf1,rf1,0)
#elif defined(FM1_SET)  /* not currently used */
#define fwd_mcol(x)     one_table(x,upr,t_use(f,m),vf1,rf1,0)
#else
#define dec_fmvars      aes_32t g2
#define fwd_mcol(x)     (g2 = gf_mulx(x), g2 ^ upr((x) ^ g2, 3) ^ upr((x), 2) ^ upr((x), 1))
#endif

#if defined(IM4_SET)
#define inv_mcol(x)     four_tables(x,t_use(i,m),vf1,rf1,0)
#elif defined(IM1_SET)
#define inv_mcol(x)     one_table(x,upr,t_use(i,m),vf1,rf1,0)
#else
#define dec_imvars      aes_32t g2, g4, g9
#define inv_mcol(x)     (g2 = gf_mulx(x), g4 = gf_mulx(g2), g9 = (x) ^ gf_mulx(g4), g4 ^= g9, \
                        (x) ^ g2 ^ g4 ^ upr(g2 ^ g9, 3) ^ upr(g4, 2) ^ upr(g9, 1))
#endif

#if defined(FL4_SET)
#define ls_box(x,c)     four_tables(x,t_use(f,l),vf1,rf2,c)
#elif   defined(LS4_SET)
#define ls_box(x,c)     four_tables(x,t_use(l,s),vf1,rf2,c)
#elif defined(FL1_SET)
#define ls_box(x,c)     one_table(x,upr,t_use(f,l),vf1,rf2,c)
#elif defined(LS1_SET)
#define ls_box(x,c)     one_table(x,upr,t_use(l,s),vf1,rf2,c)
#else
#define ls_box(x,c)     no_table(x,t_use(s,box),vf1,rf2,c)
#endif




/**************************** Originally aestab.h ******************************/


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
 Issue 28/01/2004

 This file contains the code for declaring the tables needed to implement
 AES. The file aesopt.h is assumed to be included before this header file.
 If there are no global variables, the definitions here can be used to put
 the AES tables in a structure so that a pointer can then be added to the
 AES context to pass them to the AES routines that need them.   If this
 facility is used, the calling program has to ensure that this pointer is
 managed appropriately.  In particular, the value of the t_dec(in,it) item
 in the table structure must be set to zero in order to ensure that the
 tables are initialised. In practice the three code sequences in aeskey.c
 that control the calls to gen_tabs() and the gen_tabs() routine itself will
 have to be changed for a specific implementation. If global variables are
 available it will generally be preferable to use them with the precomputed
 FIXED_TABLES option that uses static global tables.

 The following defines can be used to control the way the tables
 are defined, initialised and used in embedded environments that
 require special features for these purposes

    the 't_dec' construction is used to declare fixed table arrays
    the 't_set' construction is used to set fixed table values
    the 't_use' construction is used to access fixed table values

    256 byte tables:

        t_xxx(s,box)    => forward S box
        t_xxx(i,box)    => inverse S box

    256 32-bit word OR 4 x 256 32-bit word tables:

        t_xxx(f,n)      => forward normal round
        t_xxx(f,l)      => forward last round
        t_xxx(i,n)      => inverse normal round
        t_xxx(i,l)      => inverse last round
        t_xxx(l,s)      => key schedule table
        t_xxx(i,m)      => key schedule table

    Other variables and tables:

        t_xxx(r,c)      => the rcon table
*/


#define t_dec(m,n) pgpAEStab_##m##n
#define t_set(m,n) pgpAEStab_##m##n
#define t_use(m,n) pgpAEStab_##m##n

#if defined(FIXED_TABLES)
#define Const const
#else
#define Const
#endif

#if defined(DO_TABLES)
#define Extern
#else
#define Extern extern
#endif

#if defined(_MSC_VER) && defined(TABLE_ALIGN)
#define Align __declspec(align(TABLE_ALIGN))
#else
#define Align
#endif



#endif  /* defined(_AES_H) */
