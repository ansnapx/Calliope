/*
 * pgpStr2Key.h -- A PGP String to Key Conversion System
 *
 * $Id: pgpStr2Key.h 27239 2004-09-09 23:04:46Z ajivsov $
 */
#ifndef Included_pgpStr2Key_h
#define Included_pgpStr2Key_h

#include "pgpUsuals.h"	/* For PGPByte */

/*
 * The PGPStringToKey objects are encoded using the follow table:
 *
 * type		number	s2k arguments
 * ----		-----	-------------
 * simple	\000	hash specifier
 * salted	\001	hash specifier + salt8
 * itersalt	\003	hash specifier + salt8 + (compressed) count
 * literal	\004	no arguments, just use input as output
 * literalshared \005	like literal but flags secret-sharing at higher level
 * itersalt16	 100	hash specifier + salt16 + (compressed) count
 *
 */

enum PGPStringToKeyType_
{
	kPGPStringToKey_Simple = 0,
	kPGPStringToKey_Salted = 1,
	kPGPStringToKey_IteratedSalted = 3,
	kPGPStringToKey_Literal = 4,
	kPGPStringToKey_LiteralShared = 5,

	kPGPStringToKey_IteratedSalted_16 = 100,

	PGP_ENUM_FORCE( PGPStringToKeyType )
};
PGPENUM_TYPEDEF( PGPStringToKeyType_, PGPStringToKeyType );


PGP_BEGIN_C_DECLARATIONS

#include "pgpOpaqueStructs.h"
#include "pgpMemoryMgr.h"


struct PGPStringToKey {
	void *priv;
	PGPByte const *encoding;	/* For transmission */
	unsigned encodelen;
	void (*destroy) (struct PGPStringToKey *s2k);
	int (*stringToKey) (struct PGPStringToKey const *s2k, PGPByte const *str,
			    PGPSize slen, PGPByte *key, size_t klen);
};


/* Deallocate the structure */
#define pgpS2Kdestroy(s2k) (s2k)->destroy(s2k)

/* Turn a string into a key */
#define pgpStringToKey(s2k,s,sl,k,kl) (s2k)->stringToKey(s2k,s,sl,k,kl)

/*
 * Decodes a byte string into a PGPStringToKey object.  Returns either an
 * error <0 or the length >=0 of the encoded string2key data found in
 * the buffer.  If s2k is non-NULL, a structure is allocated and
 * returned.
 */
int  pgpS2Kdecode (PGPStringToKey **s2k,
	PGPMemoryMgrRef memMgr, PGPByte const *buf, size_t len);

/*
 * Returns the default PGPStringToKey based on the setting in the
 * environment.  This is expected to be the usual way to get such
 * structures.
 */
PGPStringToKey  *pgpS2Kdefault (PGPMemoryMgrRef memMgr, const PGPByte salt[8]);

/*
 * Return old default PGPStringToKey compatible with PGP V3 */
PGPStringToKey  *pgpS2KdefaultV3(PGPMemoryMgrRef memMgr,
					  PGPRandomContext const *rc);

/* Allocate a structure given the type, using default for hash */
PGPStringToKey *pgpS2Kcreate(PGPMemoryMgrRef memMgr,
	PGPStringToKeyType s2ktype, const PGPByte salt[8]);

int  pgpS2KisOldVers (PGPStringToKey const *s2k);

/*
 * Specific PGPStringToKey creation functions.  Use these functions to
 * specifically request a certain string to key algorithm.
 */
PGPStringToKey  *pgpS2Ksimple (PGPMemoryMgrRef memMgr,
				     PGPHashVTBL const *h);
PGPStringToKey  *pgpS2Ksalted (PGPMemoryMgrRef memMgr,
				     PGPHashVTBL const *h,
				     PGPByte const *salt8);
PGPStringToKey  *pgpS2Kitersalt (PGPMemoryMgrRef memMgr,
				       PGPHashVTBL const *h,
				       PGPByte const *salt8,
				       PGPUInt32 bytes);
PGPStringToKey  *pgpS2Kliteral (PGPMemoryMgrRef memMgr);
PGPStringToKey  *pgpS2KliteralShared (PGPMemoryMgrRef memMgr);


PGP_END_C_DECLARATIONS

#endif /* Included_pgpStr2Key_h */
