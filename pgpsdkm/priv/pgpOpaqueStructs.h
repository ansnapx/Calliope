/*____________________________________________________________________________
	pgpOpaqueStructs.h
	
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pgpOpaqueStructs.h 59758 2008-01-10 20:29:11Z vinnie $
____________________________________________________________________________*/
#ifndef Included_pgpOpaqueStructs_h	/* [ */
#define Included_pgpOpaqueStructs_h



typedef struct PGPPubKey		PGPPubKey;
typedef struct PGPSecKey		PGPSecKey;
typedef struct PGPToken			PGPToken;
typedef struct PGPKeySpec		PGPKeySpec;
typedef struct PGPSigSpec		PGPSigSpec;
typedef struct PGPRandomContext	PGPRandomContext;
typedef struct PGPEnv			PGPEnv;
typedef struct PGPUICb			PGPUICb;
typedef struct PGPESK			PGPESK;
typedef struct PGPConvKey		PGPConvKey;
typedef struct PGPFile			PGPFile;
typedef struct PGPFileError		PGPFileError;
typedef struct PGPFileRead		PGPFileRead;
typedef struct PGPStringToKey	PGPStringToKey;
typedef struct PGPPkAlg			PGPPkAlg;
typedef struct PGPFifoContext	PGPFifoContext;
typedef struct PGPPassCache		PGPPassCache;
typedef struct PGPFileSpec		PGPFileSpec;
typedef struct MemPool			MemPool;
typedef struct PGPKeyIDPriv		PGPKeyIDPriv;
typedef struct PGPSigData		PGPSigData;
typedef struct PGPTBS *			PGPTBSRef;

typedef struct PGPHashList					PGPHashList;
typedef struct PGPHashList *				PGPHashListRef;

typedef struct PGPHashVTBL					PGPHashVTBL;
typedef struct PGPPublicKeyContext			PGPPublicKeyContext;
typedef struct PGPPrivateKeyContext			PGPPrivateKeyContext;
typedef struct PGPCipherVTBL				PGPCipherVTBL;
typedef struct PGPHashContext				PGPHashContext;
typedef struct PGPCFBContext				PGPCFBContext;
typedef struct PGPCBCContext				PGPCBCContext;
typedef struct PGPEMEContext				PGPEMEContext;
typedef struct PGPEME2Context				PGPEME2Context;
typedef struct PGPSymmetricCipherContext	PGPSymmetricCipherContext;

typedef struct PGPRandomVTBL				PGPRandomVTBL;



#endif /* ] Included_pgpOpaqueStructs_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
