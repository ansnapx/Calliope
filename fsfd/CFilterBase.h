////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterBase.h: interface for the CFilterBase class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERBASE_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERBASE_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef _NET_SHARE
#define _NET_SHARE
#endif

//////////////////////////////////////////
// Lock hierarchy is defined as follows:
//
// 1. Entities
// 2. Context
// 3. Files/Directories
//
/////////////////////////////////////////
                       
// Define the cipher mode to be used
//#define FILFILE_USE_CTR 1
//#define FILFILE_USE_CFB 1
#define FILFILE_USE_EME 1

#ifdef FILFILE_USE_CTR
#define FILFILE_USE_PADDING 0
#elif defined(FILFILE_USE_CFB)
#define FILFILE_USE_PADDING 1
#elif defined(FILFILE_USE_EME)
#define FILFILE_USE_PADDING 1
#endif

// The kernel does not have this defined:
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ~0u
#endif

// Define if we should take care of WDE's meta data file. 
#define FILFILE_WDE_CARETAKER
#ifdef FILFILE_WDE_CARETAKER
WCHAR const c_wdeMetaPath[] = L"\\PGPWDE01";
#endif

// When defined, attach to WebDAV Redirector otherwise don't
#define FILFILE_SUPPORT_WEBDAV

#include "pgpBuild.h"
#if PGPVERSIONMAJOR == 9
 #if PGPVERSIONMINOR < 10
  #undef FILFILE_SUPPORT_WEBDAV
 #endif
#endif

#define STATUS_FORBID_SHARE  0xDFFFFFFF

enum FILFILE_FILTER_TYPE
{
	FILFILE_FILTER_FILE_SYSTEM	= 0x9301,
	FILFILE_FILTER_VOLUME		= 0x9302,
	FILFILE_FILTER_CONTROL		= 0x9a03,
};

enum FILFILE_STATE_TYPE
{
	FILFILE_STATE_NULL					= 0x0,

	FILFILE_STATE_FILE					= 0x1,		// file object tracking
	FILFILE_STATE_DIR					= 0x2,		// dir  object tracking
	FILFILE_STATE_CREATE				= FILFILE_STATE_FILE | FILFILE_STATE_DIR,
	
	FILFILE_STATE_ACCESS_DENY_DIR		= 0x4,		// deny access to encrypted Directories
	FILFILE_STATE_ACCESS_DENY_FILE		= 0x8,		// deny access to encrypted Files
	FILFILE_STATE_ACCESS_DENY			= FILFILE_STATE_ACCESS_DENY_DIR | FILFILE_STATE_ACCESS_DENY_FILE,

	FILFILE_STATE_TRIGGER				= 0x10,		// trigger user mode part if Key is unknown
													
	FILFILE_STATE_VALID_REG				= FILFILE_STATE_ACCESS_DENY,
	FILFILE_STATE_VALID_USER			= FILFILE_STATE_CREATE | FILFILE_STATE_ACCESS_DENY | FILFILE_STATE_TRIGGER,

	FILFILE_WIPE_ON_DELETE				= 0x20,		// Wipe local files on delete
};

enum FILFILE_DEVICE_TYPE
{
	FILFILE_DEVICE_NULL					= 0x0,
	FILFILE_DEVICE_FILE_SYSTEM			= 0x1,
	FILFILE_DEVICE_VOLUME				= 0x2,
	FILFILE_DEVICE_REDIRECTOR_CIFS		= 0x4,
	FILFILE_DEVICE_REDIRECTOR_NETWARE	= 0x8,
	FILFILE_DEVICE_REDIRECTOR_WEBDAV	= 0x10,

	FILFILE_DEVICE_REDIRECTOR			= FILFILE_DEVICE_REDIRECTOR_CIFS | FILFILE_DEVICE_REDIRECTOR_NETWARE | FILFILE_DEVICE_REDIRECTOR_WEBDAV,
};

enum FILFILE_REQUESTOR_TYPE
{
	FILFILE_REQUESTOR_NULL		= 0,
	FILFILE_REQUESTOR_REMOTE	= 1,	// SRV, remote request
	FILFILE_REQUESTOR_SYSTEM	= 2,	// *System*, also used by local Redirectors, e.g. CSC
	FILFILE_REQUESTOR_USER		= 3,	// UserMode 
};

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

// TODO: Make this available to clients
#define FILFILE_CIPHER_MODE_DEFAULT (FILFILE_CIPHER_MODE_EME << 16);

///////////////////////////////////////////////////////////////////
// Encrypted File Layout := [Header | EncData | Tail]
//
// Header := [Block | Payload | Padding to next boundary] 
// Tail	  := [Padding | Filler]
// with sizeof(Padding + Filler) := block size of cipher mode used
///////////////////////////////////////////////////////////////////

struct FILFILE_HEADER_BLOCK
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
};

struct FILFILE_READ_WRITE
{
	UCHAR*			Buffer;
	MDL*			Mdl;
	LARGE_INTEGER	Offset;	
	ULONG			Length;
	ULONG			Flags;
	UCHAR			Major;
	BOOLEAN			Wait;
};

enum FILFILE_SYSTEM_FLAGS
{
	FILFILE_SYSTEM_NULL			= 0x0,

	FILFILE_SYSTEM_WIN2000		= 0x01,
	FILFILE_SYSTEM_WINXP		= 0x02,
	FILFILE_SYSTEM_WIN2003		= 0x04,
	FILFILE_SYSTEM_WINVISTA		= 0x08,		// Used for Windows Server 2008 too
	FILFILE_SYSTEM_WIN7			= 0x10,

	FILFILE_SYSTEM_TERMINAL		= 0x20,
};

enum FILFILE_TRACK_FLAGS
{
	TRACK_NO					= 0x0,			// create result
	TRACK_YES					= 0x1,			// create result
	TRACK_DEFERRED				= 0x2,			// create result
	TRACK_CANCEL				= 0x4,			// create result
	
	TRACK_TYPE_FILE				= 0x8,			// path type
	TRACK_TYPE_DIRECTORY		= 0x10,			// path type
	TRACK_TYPE_RESOLVED			= TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY,

	TRACK_CHECK_VOLUME			= 0x20,			// check also volume names, used on redirectors
	TRACK_CHECK_SHORT			= 0x40,			// resolve short names, if any
	TRACK_SHORT_COMPONENT		= 0x80,			// short name component detected
	TRACK_MATCH_EXACT			= 0x100,		// matched exactly

	TRACK_AUTO_CONFIG			= 0x200,		// AutoConfig file, triggered by or found valid one

	TRACK_BEYOND_EOF			= 0x400,		// during write
	TRACK_PADDING				= 0x800,		// during write, padding involved or needs to be updated
	TRACK_ALIGNMENT				= 0x1000,		// during write, special alignment handling needed
	TRACK_NOCACHE				= 0x2000,		// during read/write
	TRACK_USE_CACHE				= 0x4000,		// during write and for header queries

	TRACK_HAVE_KEY				= 0x8000,		// FileKey is already known
	TRACK_NO_PAYLOAD			= 0x10000,		// dito

	TRACK_ALTERNATE_STREAM		= 0x20000,		// ADS syntax in name
	TRACK_CIFS					= 0x40000,		// LanMan  redirector
	TRACK_NETWARE				= 0x80000,		// NetWare redirector
	TRACK_WEBDAV				= 0x100000,		// WebDAV  redirector
	TRACK_REDIR					= TRACK_CIFS | TRACK_WEBDAV | TRACK_NETWARE,

	TRACK_ESCAPE				= 0x200000,		// ongoing 'escape' operation
	TRACK_WILDCARD				= 0x400000,		// wildcard in name

	TRACK_SYSTEM				= 0x800000,		// file/folder is related to SYSTEM
	TRACK_IE_CACHE				= 0x1000000,	// file/folder is related to IE Cache

	TRACK_APP_LIST				= 0x2000000,	// Application List involved
	TRACK_SHARE_DIRTORY         =0x4000000,           //访问共享标志
	TRACK_READ_ONLY             =0x6000000,     //只读访问

	#ifdef FILFILE_SUPPORT_WEBDAV				// Unsupported device types:
	 TRACK_UNSUPPORTED			= TRACK_NETWARE,
	#else
	 TRACK_UNSUPPORTED			= TRACK_NETWARE | TRACK_WEBDAV,
	#endif
};

#define FILE_XDISK_IMAGE_TYPE     0x1002

enum FILFILE_ENTITY_FLAGS
{
	ENTITY_NULL				= 0x0,
	ENTITY_REGULAR			= 0x1,
	ENTITY_NEGATIVE			= 0x2,
	ENTITY_PURGE			= 0x4,
	ENTITY_DISCARD			= 0x8,
	ENTITY_ANYWAY			= 0x10,
	ENTITY_AUTO_CONFIG		= 0x20,
};

//////////////////////////////////

#include "CFilterKey.h"
#include "CFilterEntity.h"
#include "CFilterHeader.h"

//////////////////////////////////

struct FILFILE_TRACK_CONTEXT
{
	ULONG				State;
	ULONG				Requestor;
	LUID				Luid;
	CFilterHeader		Header;
	CFilterEntity		Entity;			
	CFilterKey			EntityKey;
};

struct FILFILE_CRYPT_CONTEXT
{
	LARGE_INTEGER		Nonce;
	LARGE_INTEGER		Offset;
	ULONG				Value;			// depends on context
	CFilterKey			Key;
};

//////////////////////////////////

#include "CFilterVolume.h"
#include "CFilterCallback.h"
#include "CFilterWiper.h"
#include "CFilterHeaderCache.h"
#include "CFilterProcess.h"

//////////////////////////////////

struct FILFILE_COMMON_EXTENSION
{
    USHORT			Type;
    USHORT			Size;

	DEVICE_OBJECT*	Device;
};

struct FILFILE_CONTROL_EXTENSION
{
	FILFILE_COMMON_EXTENSION	Common;

	bool                        bReadOnly;

	DRIVER_OBJECT*				Driver;
	LPWSTR						RegistryPath;

	PEPROCESS					SystemProcess;
	ULONG						SystemVersion;
	UNICODE_STRING				SystemPath;

	ERESOURCE					Lock;				// Guards: Volumes, CDO Entities

	LIST_ENTRY					Volumes;
	LONG						VolumesCount;
	ULONG						VolumeNextIdentifier;

	CFilterContext				Context;
	CFilterProcess				Process;			// Tracks PID to image name	
	CFilterCallbackDisp			Callback;			// Callback dispatcher
	CFilterHeaderCache			HeaderCache;		// Cache Headers - currently only used by the management interface
	CFilterEntityCont			Entities;			// Inactive Entities
	CFilterWiper				Wiper;
};

struct FILFILE_VOLUME_EXTENSION
{
    FILFILE_COMMON_EXTENSION	Common;

	LIST_ENTRY					Link;
	DEVICE_OBJECT*				Real;

    DEVICE_OBJECT*				Lower;
	ULONG						LowerType;
	UNICODE_STRING				LowerName;

	CFilterVolume				Volume;
	bool						System;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterBase  
{
	typedef NTSTATUS (NTAPI* f_mupProvider)(FILE_OBJECT *file, ULONG level, void* buffer, ULONG *bufferSize);

public:

	enum c_constants		{ c_sectorSize  = 512 };

	static DEVICE_OBJECT*	AttachSafe(DEVICE_OBJECT *device, DEVICE_OBJECT *target);

	static NTSTATUS			SimpleSend(DEVICE_OBJECT *device, IRP *irp);
	static NTSTATUS			SimpleCompletion(DEVICE_OBJECT* device, IRP *irp, void *context);
	static NTSTATUS			SimpleCompletionFree(DEVICE_OBJECT *device, IRP *irp, void *context);

	static ULONG			GetAttributes(DEVICE_OBJECT *device, FILE_OBJECT *file);
	static ULONG			GetDeviceType(UNICODE_STRING *deviceName);
	static DEVICE_OBJECT*	GetDeviceObject(FILE_OBJECT *file);
	static ULONG			GetNetworkProvider(FILFILE_VOLUME_EXTENSION *extension, FILE_OBJECT *file);
	static ULONG			GetTicksFromSeconds(ULONG seconds);
	static NTSTATUS			GetLuid(LUID *luid, IO_SECURITY_CONTEXT *security = 0);

	static bool				IsCached(FILE_OBJECT *file);
	static bool				IsStackBased(FILE_OBJECT *file);

	static NTSTATUS			ReadWrite(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* readWrite);
	static NTSTATUS			ReadNonAligned(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* target);
	static NTSTATUS			WriteNonAligned(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* source);
	static NTSTATUS			ZeroData(DEVICE_OBJECT *device, FILE_OBJECT *file, LARGE_INTEGER *start, LARGE_INTEGER *end);
	
	static NTSTATUS			SendCleanupClose(DEVICE_OBJECT *device, FILE_OBJECT *file, bool cleanupOnly = false);
	static NTSTATUS			LockFile(FILE_OBJECT *file, bool acquire);
	static bool				TearDownCache(FILE_OBJECT *file, ULONG loop, ULONG timeout);
	static NTSTATUS			FlushAndPurgeCache(FILE_OBJECT *file, bool flush = true, bool pin = true);

	static NTSTATUS			CreateFile(DEVICE_OBJECT *device, UNICODE_STRING* path, ULONG access, ULONG share, ULONG options, ULONG	attribs = 0, FILE_OBJECT** created = 0, HANDLE *fileHandle = 0);

	static NTSTATUS			GetLongName(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, UNICODE_STRING *path, void *buffer, ULONG bufferSize, USHORT shortNameStart);
	static NTSTATUS			QueryFileNameInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_NAME_INFORMATION **fileNameInfo);
	static NTSTATUS			QueryDirectoryInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_INFORMATION_CLASS	fileInfo, void*	buffer, ULONG bufferSize, UNICODE_STRING* fileName, ULONG fileIndex = 0);
	static NTSTATUS			QueryFileInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_INFORMATION_CLASS fileInfo, void* buffer, ULONG bufferSize);

	static NTSTATUS			GetFileSize(DEVICE_OBJECT *device, FILE_OBJECT *file, LARGE_INTEGER *fileSize);
	static NTSTATUS			SetFileSize(DEVICE_OBJECT *device, FILE_OBJECT* file, LARGE_INTEGER *fileSize);
	static NTSTATUS			SetFileInfo(DEVICE_OBJECT *device, FILE_OBJECT* file, FILE_INFORMATION_CLASS fileInfo, void* buffer, ULONG bufferSize);
	
	static NTSTATUS			SimpleRename(DEVICE_OBJECT *device, FILE_OBJECT *file, LPCWSTR fileName, ULONG fileNameLength, BOOLEAN replace);
	
	static NTSTATUS			QueryRegistryLong(LPCWSTR keyPath,   LPCWSTR valueName, ULONG *value);
	static NTSTATUS			QueryRegistryString(LPCWSTR keyPath, LPCWSTR valueName, LPWSTR wstr, ULONG *wstrLength);
	static NTSTATUS			QueryRegistrySubKeys(LPCWSTR keyPath, ULONG *subKeys);

	static NTSTATUS			ParseDeviceName(LPCWSTR path, ULONG pathLength, UNICODE_STRING *deviceName = 0, ULONG *deviceType = 0);
	static NTSTATUS			ResolveSymbolicLink(UNICODE_STRING *linkSource, UNICODE_STRING *linkTarget);
	static NTSTATUS			GetSystemPath(UNICODE_STRING *systemPath);
	static NTSTATUS			GetMacAddress(UCHAR macAddr[6]);
	static ULONG			Crc32(UCHAR const* buffer, ULONG bufferSize);
	static ULONG			Hash(LPCWSTR path, ULONG pathLength);

							// DATA
	static ULONG			s_timeoutKeyRequest;
	static ULONG			s_timeoutRandomRequest;

	static f_mupProvider	s_mupGetProviderInfo;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline 
ULONG CFilterBase::GetTicksFromSeconds(ULONG seconds)
{
	// translate seconds to ticks according to timer hardware used
	return (ULONG) (SECONDS(seconds) / KeQueryTimeIncrement());
}

inline
NTSTATUS CFilterBase::SetFileSize(DEVICE_OBJECT *device, FILE_OBJECT* file, LARGE_INTEGER *fileSize)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(fileSize);

	return SetFileInfo(device, file, FileEndOfFileInformation, (void*) fileSize, sizeof(LARGE_INTEGER));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFILTERBASE_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
