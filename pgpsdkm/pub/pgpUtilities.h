/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.
	
	This file contains miscellaneous utility functions needed for the PGPsdk.

	$Id: pgpUtilities.h 59819 2008-01-12 06:57:15Z ajivsov $
____________________________________________________________________________*/

#ifndef Included_pgpUtilities_h	/* [ */
#define Included_pgpUtilities_h

#if ! PGP_UNIX_DARWIN
#include <time.h>
#endif

#include "pgpPubTypes.h"
#include "pgpMemoryMgr.h"

#if PGP_MACINTOSH	/* [ */
#include <Files.h>
#elif PGP_OSX
	struct FSSpec;
#endif	/* ] PGP_MACINTOSH */

#if PGP_MACINTOSH
#pragma options align=mac68k	/* [ */
#endif

enum PGPNotificationReason_
{
	kPGPNotification_KeyDBChanged			= 0,
	kPGPNotification_PassphraseCacheChanged	= 1,
	
	PGP_ENUM_FORCE( PGPNotificationReason_ )
};

PGPENUM_TYPEDEF( PGPNotificationReason_, PGPNotificationReason );

enum PGPLanguage_
{
	kPGPLanguage_Default     = 0,
	kPGPLanguage_English     = 1,
	kPGPLanguage_Japanese    = 2,
	kPGPLanguage_German      = 3,
	kPGPLanguage_Spanish     = 4,
			    
	PGP_ENUM_FORCE( PGPLanguage_ )
};

PGPENUM_TYPEDEF( PGPLanguage_, PGPLanguage );

#if PGP_MACINTOSH || PGP_OSX	/* [ */

#define kPGPMacFileCreator_PGPkeys			'pgpK'
#define kPGPMacFileCreator_PGPtools			'pgpM'
#define kPGPMacFileCreator_PGPnet			'PGPn'
#define kPGPMacFileCreator_PGPdisk			'pgpD'
#define kPGPMacFileCreator_PGPadmin			'PGPa'
#define kPGPMacFileCreator_DecryptedBinary	'\?\?\?\?'
#define kPGPMacFileCreator_DecryptedText	'ttxt'

#define kPGPMacFileType_ArmorFile			'TEXT'
#define kPGPMacFileType_EncryptedData		'pgEF'
#define kPGPMacFileType_SignedData			'pgSF'
#define kPGPMacFileType_DetachedSig			'pgDS'
#define kPGPMacFileType_RandomSeed			'pgRS'
#define kPGPMacFileType_PrivRing			'pgRR'
#define kPGPMacFileType_PubRing				'pgPR'
#define kPGPMacFileType_Groups				'pgGR'
#define kPGPMacFileType_NetHosts			'pgHO'
#define kPGPMacFileType_NetRules			'pgRU'
#define kPGPMacFileType_Preferences			'pref'
#define kPGPMacFileType_DecryptedText		'TEXT'
#define kPGPMacFileType_DecryptedBinary		'BINA'
#define kPGPMacFileType_KeyShares			'pgSK'
#define kPGPMacFileType_Exported509Keys		'pgX5'

#endif	/* ] PGP_MACINTOSH */

PGP_BEGIN_C_DECLARATIONS

/*____________________________________________________________________________
	PGPsdk initialization

	Call PGPsdkXXXInit() before using that particular library.
	Call PGPsdkXXXCleanup() when you are done (but after disposing of any
		PGPContexts).
	
	You may call PGPsdkXXXInit multiple times (with no effect), but be sure
	to call the matching PGPsdkXXXCleanup() for each call to PGPsdkXXXInit().
____________________________________________________________________________*/
#define kPGPFlags_ForceLocalExecution	0x2
#define kPGPFlags_SuppressCacheThread	0x4

PGPError	PGPsdkInit( PGPFlags options );
PGPError	PGPsdkSetLanguage( PGPFileSpecRef langStringsHome, PGPLanguage lang );
PGPError	PGPsdkCleanup( void );

PGPError	PGPsdkNetworkLibInit( PGPFlags options );
PGPError	PGPsdkNetworkLibCleanup( void );

PGPError	PGPsdkUILibInit( PGPFlags options );
PGPError	PGPsdkUILibCleanup( void );

PGPError	PGPLoadPluginModule( PGPContextRef context,
				PGPFileSpecRef moduleFile, PGPFileSpecRef sigFile,
				PGPUInt32 *nCipher, PGPUInt32 *nHash, PGPUInt32 *nPubkey );


/*____________________________________________________________________________
	PGPsdk version information
	
	A version in the PGPsdk is expressed as follows:
	
	Major version (1 byte)
	Minor version (1 byte)
	Bug fix revision (1 byte)
	Reserved (1 byte)
	
	example: 1.7.1 = 0x01070100		
____________________________________________________________________________*/

PGPUInt32	PGPGetPGPsdkVersion( void );

/*____________________________________________________________________________
	PGPsdk version string
	
	Return a C string of the form:

	"PGPsdk 3.0 Copyright (C) 2003 PGP Corporation
____________________________________________________________________________*/

#undef 		PGPGetPGPsdkVersionString
PGPError	PGPGetPGPsdkVersionString( PGPChar8 versionString[ 256 ] );

/*____________________________________________________________________________
	PGPsdk API version information
	
	The API version of the PGPsdk is distinct from the externally visible
	version number. The API version is revised only when API changes are made,
	while the external version is changed whenever any code is changed, API or
	otherwise. The format of the API version is identical to the format of the
	external version. A change in the major API version implies incompatability
	with previous API versions while a change in the minor version implies API
	additions which maintain backwards compatability.
_____________________________________________________________________________*/

PGPUInt32	PGPGetPGPsdkAPIVersion( void );

/*____________________________________________________________________________
	PGPsdk context manipulation
_____________________________________________________________________________*/
	
typedef struct PGPCustomContextInfo
{
	PGPUInt32			sdkAPIVersion;	/* Use kPGPsdkAPIVersion */
	PGPMemoryMgrRef		memoryMgr;
	PGPUserValue		userValue;	

} PGPCustomContextInfo;


PGPError 	PGPNewContext( PGPUInt32 sdkAPIVersion, PGPContextRef *newContext );
PGPError 	PGPNewContextCustom( const PGPCustomContextInfo *contextInfo,
					PGPContextRef *newContext );

PGPError 	PGPFreeContext( PGPContextRef context );

PGPError 	PGPGetContextUserValue( PGPContextRef context,
					PGPUserValue *userValue );
PGPError 	PGPSetContextUserValue( PGPContextRef context,
					PGPUserValue userValue );

PGPError	PGPContextGetRandomBytes(PGPContextRef context,
					void *buf, PGPSize len );

PGPUInt32	PGPContextReserveRandomBytes(PGPContextRef context,
					PGPUInt32 minSize );

PGPMemoryMgrRef	PGPPeekContextMemoryMgr( PGPContextRef context );

/*____________________________________________________________________________
	PGP file management
	
	All files in PGP are represented using an opage data type PGPFileSpecRef.
	These data types are created using a fully qualified path or, on the
	Macintosh, an FSSpec. The 
____________________________________________________________________________*/

#if PGP_MACINTOSH || PGP_OSX	/* [ */

PGPError 	PGPNewFileSpecFromFSSpec( PGPContextRef context, const struct FSSpec *spec,
					PGPFileSpecRef *ref );
PGPError 	PGPGetFSSpecFromFileSpec( PGPFileSpecRef fileRef, struct FSSpec *spec );

#endif

#if ! PGP_MACINTOSH

#undef 		PGPNewFileSpecFromFullPath
PGPError 	PGPNewFileSpecFromFullPath( PGPContextRef context,
					const PGPChar8 *path, PGPFileSpecRef *ref );
/*
** The full path is an allocated object which needs to be deallocated with
** PGPFreeData()
*/

#undef 		PGPGetFullPathFromFileSpec
PGPError 	PGPGetFullPathFromFileSpec( PGPFileSpecRef fileRef,
					PGPChar8 **fullPathPtr);

#endif

PGPError 	PGPCopyFileSpec( PGPFileSpecRef fileRef, PGPFileSpecRef *ref );
PGPError 	PGPFreeFileSpec( PGPFileSpecRef fileRef );

#undef 		PGPRenameFile
PGPError	PGPRenameFile( PGPFileSpecRef fileRef, const PGPChar8 *newName );
PGPError	PGPDeleteFile( PGPFileSpecRef fileRef );
	
/*____________________________________________________________________________
	PGP time/date functions
____________________________________________________________________________*/

PGPTime 	PGPGetTime(void);

/* these use time_t type as returned by time() in Std C libraries */
time_t 		PGPGetStdTimeFromPGPTime( PGPTime theTime );
PGPTime 	PGPGetPGPTimeFromStdTime( time_t theTime );

/* year, month, day may be NULL if desired */
void 		PGPGetYMDFromPGPTime( PGPTime theTime, PGPUInt16 *year,
					PGPUInt16 *month, PGPUInt16 *day );

#if PGP_MACINTOSH || PGP_OSX	/* [ */

PGPUInt32 	PGPTimeToMacTime( PGPTime theTime );
PGPTime 	PGPTimeFromMacTime( PGPUInt32 theTime );

#endif	/* ] PGP_MACINTOSH */

/*____________________________________________________________________________
	MacBinary support

	Examine the input file to see if it's a MacBinary file.  If it is
	not a MacBinary file, then the original file is unaltered.
	Otherwise, the file is converted and the original file is deleted.
	
	The resulting file is designated by 'outPGPSpec' and may have a different
	name than the original.
	
	If the file is a TEXT file, appropriate line-end conversion is done.
	
	creator and type code pointers may be
	null but otherwise contain the mac creator and type.
	
	This routine can be called on a Mac, but generally doesn't need to be.
____________________________________________________________________________*/

PGPError	PGPMacBinaryToLocal( PGPFileSpecRef inSpec,
					PGPFileSpecRef * outSpec, PGPUInt32 * macCreator,
					PGPUInt32 * macTypeCode );

/*____________________________________________________________________________
	Notification callbacks on PGPKeyDB changes from SDK Service
_____________________________________________________________________________*/
	
typedef void (*PGPNotificationHandlerProc)( PGPUserValue userValue,
											PGPNotificationReason reason,
											PGPUInt32 param1,
											PGPUInt32 param2 );

PGPError	PGPSetNotificationCallback( PGPNotificationHandlerProc proc,
					PGPUserValue userValue );

/*____________________________________________________________________________
Disk and File Wipe Pattern Support
____________________________________________________________________________*/
 
PGPError PGPNewWipePatternContext ( PGPContextRef				context,
									PGPInt32					numPasses,
									PGPWipePatternContextRef 	*outRef);

/* fill a 1024 byte, long word alligned buffer with a pattern to wipe with */
PGPError PGPWipePatternNext( PGPWipePatternContextRef   ref,
							 void * buffer, PGPSize bufferSize);

PGPError PGPWipePatternRewind( PGPWipePatternContextRef wipeRef);

PGPError PGPFreeWipePatternContext(PGPWipePatternContextRef ref);
 
PGPError PGPWipeFile( PGPContextRef   	context, 
					  PGPInt32			numPasses,
					  PGPOptionListRef 	firstOption, 
					  ...);

/*____________________________________________________________________________
FIPS 140-2 Support
____________________________________________________________________________*/

enum PGPsdkSelfTest_
{
	kPGPsdkSelfTest_Invalid		= 0,
	kPGPsdkSelfTest_FirstTest   = 1,

	kPGPsdkSelfTest_3DES 		= 1,
	kPGPsdkSelfTest_DSA  		= 2,
	kPGPsdkSelfTest_AES  		= 3,
	kPGPsdkSelfTest_RSA  		= 4,
	kPGPsdkSelfTest_SHA  		= 5,
	kPGPsdkSelfTest_HMAC  		= 6,
	kPGPsdkSelfTest_EC  		= 7,
	kPGPsdkSelfTest_PRNG   		= 8,
	kPGPsdkSelfTest_Integrity   = 9,

	kPGPsdkSelfTest_LastTest	= kPGPsdkSelfTest_Integrity,

	PGP_ENUM_FORCE( PGPsdkSelfTest_ )
};

PGPENUM_TYPEDEF( PGPsdkSelfTest_, PGPsdkSelfTest );

PGPError	PGPEnableFIPSMode(void);
PGPError	PGPGetSDKErrorState(void);
PGPError	PGPResetSDKErrorState(void);
PGPError	PGPRunSDKSelfTest(PGPsdkSelfTest whichTest);
PGPError	PGPRunAllSDKSelfTests(void);

typedef unsigned ***PGPStringToKeyRef;

PGPError PGPSDKM_PUBLIC_API PGPNewS2KDefault( PGPMemoryMgrRef memMgr, const PGPByte salt[16], PGPStringToKeyRef *s2k );
PGPError PGPSDKM_PUBLIC_API PGPNewS2K( PGPMemoryMgrRef memMgr, PGPUInt32 hashIterations, const PGPByte salt[16], PGPStringToKeyRef *s2k );
void PGPSDKM_PUBLIC_API PGPFreeS2K(PGPStringToKeyRef s2k);
PGPError PGPSDKM_PUBLIC_API PGPGetS2K( PGPStringToKeyRef s2k, PGPByte const *passphrase, PGPSize passphraseLen, PGPByte *keyOut, size_t keyLenOut );

PGPError	PGPSDKM_PUBLIC_API PGPPKCS1Pack(PGPMemoryMgrRef memMgr, PGPByte const *in, PGPSize len, 
				const PGPByte seed[20]/*size SHA1*/, PGPByte *out, PGPSize out_bytes);
PGPError	PGPSDKM_PUBLIC_API PGPPKCS1Unpack(PGPMemoryMgrRef memMgr, 
			const PGPByte *in, PGPSize len, 
				PGPByte *out /* size len */, PGPSize *out_bytes );


PGP_END_C_DECLARATIONS

#if PGP_MACINTOSH
#pragma options align=reset			/* ] */
#endif

#endif /* ] Included_pgpUtilities_h */

/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
