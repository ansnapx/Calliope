
/* Mini SDK public APIs use mini_* namespace. 
 *
 * This allows easier sharing of sources with main SDK if files remain similiar. 
 * It is not possible to use identical API names because the APIs are 
 * incompatible in general: miniSDK doesn't use SDK context and replaces it with 
 * memory manager.
 *
 * Declare minisdk API functions that we use, comes before SDK headers. Alphabetically sorted.
 */

#define	PGPCBCDecrypt			mini_PGPCBCDecrypt
#define PGPCBCEncrypt			mini_PGPCBCEncrypt
#define PGPContinueHash			mini_PGPContinueHash
#define PGPCopyEMEContext		mini_PGPCopyEMEContext
#define PGPCopyEME2Context		mini_PGPCopyEME2Context
#define pgpCRC32Buffer			mini_pgpCRC32Buffer
#define pgpCRC32			mini_pgpCRC32
#define PGPEMEDecrypt			mini_PGPEMEDecrypt
#define PGPEMEEncrypt			mini_PGPEMEEncrypt
#define PGPEME2Decrypt			mini_PGPEME2Decrypt
#define PGPEME2Encrypt			mini_PGPEME2Encrypt
#define PGPFinalizeHash			mini_PGPFinalizeHash
#define PGPFreeCBCContext		mini_PGPFreeCBCContext
#define PGPFreeDataExternal		mini_PGPFreeDataExternal
#define PGPFreeEMEContext		mini_PGPFreeEMEContext
#define PGPFreeEME2Context		mini_PGPFreeEME2Context
#define PGPFreeHashContext		mini_PGPFreeHashContext
#define PGPFreeMemoryMgrExternal	mini_PGPFreeMemoryMgrExternal
#define PGPFreeS2K			mini_PGPFreeS2K
#define PGPFreeSymmetricCipherContext	mini_PGPFreeSymmetricCipherContext
#define PGPGetS2K			mini_PGPGetS2K
#define PGPGetSymmetricCipherSizes	mini_PGPGetSymmetricCipherSizes
#define PGPInitCBC			mini_PGPInitCBC
#define PGPInitEME			mini_PGPInitEME
#define PGPInitEME2				mini_PGPInitEME2
#define PGPInitSymmetricCipher		mini_PGPInitSymmetricCipher
#define PGPNewCBCContext		mini_PGPNewCBCContext
#define PGPNewDataExternal		mini_PGPNewDataExternal
#define PGPNewEMEContext		mini_PGPNewEMEContext
#define PGPNewEME2Context		mini_PGPNewEME2Context
#define PGPNewFixedSizeMemoryMgr	mini_PGPNewFixedSizeMemoryMgr
#define PGPNewMemoryMgrExternal		mini_PGPNewMemoryMgrExternal
#define PGPNewMemoryMgrPosix		mini_PGPNewMemoryMgrPosix
#define PGPNewMemoryMgrPosix		mini_PGPNewMemoryMgrPosix
#define PGPNewS2KDefault		mini_PGPNewS2KDefault
#define PGPNewS2K			mini_PGPNewS2K
#define PGPNewSymmetricCipherContext	mini_PGPNewSymmetricCipherContext
#define PGPPKCS1Pack			mini_PGPPKCS1Pack
#define PGPPKCS1Unpack			mini_PGPPKCS1Unpack
#define PGPSymmetricCipherDecrypt	mini_PGPSymmetricCipherDecrypt
#define PGPSymmetricCipherEncrypt	mini_PGPSymmetricCipherEncrypt
#define PGPInitCFB				mini_PGPInitCFB
#define	PGPNewCFBContext		mini_PGPNewCFBContext
#define	PGPCFBEncrypt			mini_PGPCFBEncrypt
#define	PGPCFBDecrypt			mini_PGPCFBDecrypt
#define	PGPCFBGetSymmetricCipher	mini_PGPCFBGetSymmetricCipher
#define	PGPEMEGetSymmetricCipher	mini_PGPEMEGetSymmetricCipher
#define	PGPEME2GetSymmetricCipher	mini_PGPEME2GetSymmetricCipher

