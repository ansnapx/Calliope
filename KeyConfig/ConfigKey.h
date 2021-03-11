#pragma once

#define FILF_POOL_TAG 'FliF'

enum FILFILE_CIPHER_SYM
{
	FILFILE_CIPHER_SYM_NULL		= 0,
	FILFILE_CIPHER_SYM_AES128	= 1,
	FILFILE_CIPHER_SYM_AES192	= 2,
	FILFILE_CIPHER_SYM_AES256	= 3,
	FILFILE_CIPHER_SYM_MASK		= 7,

	FILFILE_CIPHER_SYM_AUTOCONF = 0xffff,
};

enum FILFILE_CIPHER_MODE
{
	FILFILE_CIPHER_MODE_NULL	 = 0,
	FILFILE_CIPHER_MODE_CTR		 = 1,
	FILFILE_CIPHER_MODE_CFB		 = 2,
	FILFILE_CIPHER_MODE_EME		 = 3,
	FILFILE_CIPHER_MODE_EME_2	 = 4,

	FILFILE_CIPHER_MODE_MASK	 = 0xf
};

typedef struct FILFILE_HEADER_BLOCK
{
	// NOTE: all numeric values are little endian (Intel).
	ULONG			Magic;			// usually: 'FliF' -> FilF;
	ULONG			Version;		// Major:       upper 16bit -- Minor: lower 16bit
	ULONG			Cipher;			// Cipher mode: upper 16bit -- symmetric cipher: lower 16bit
	ULONG			BlockSize;		// Header size inclusive Payload, aligned (at least) on sector boundary
	ULONG			PayloadSize;	// Payload size, the Payload follows directly this block and is opaque for the driver
	ULONG			PayloadCrc;		// Crc32 of Payload
	ULONG			Deepness;		// AutoConfig files only: Deepness of correspondig Entity [~0u:=INFINITE, 0:=1, ..., N:=N+1]
	ULONG			Reserved;		// not used yet

	LARGE_INTEGER	Nonce;			// Nonce, unique for each file, combined with file Offset forms an IV
	UCHAR			FileKey[32];	// Encrypted FileKey (FEK), using EntityKey (DEK) and symmetric cipher directly. 
	// Its size is exactly the same as the EntityKey it was encrypted with.
}FileHeaderBlock,*pFileHeaderBlock;

class CConfigKey
{
public:
	CConfigKey(void);
public:
	~CConfigKey(void);
private:
	ULONG Crc32(char const* buffer, ULONG bufferSize);
public:
	BOOL CreateKey(char* buffer);
};
