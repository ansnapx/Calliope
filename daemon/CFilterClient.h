/////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterClient.h: interface for the CFilterClient class.
//
// Author: Michael Alexander Priske
//
/////////////////////////////////////////////////////////////////////////////////////////
#if !defined(AFX_CFilterClient_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFilterClient_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "IoControl.h"		// Located in FSFD directory
#include "CDfsResolver.h"
/////////////////////////////////////////////////////////////////////////////////////////

class CFilterClient  
{
	enum NetProvider
	{
		NETWORK_PROVIDER_NULL		= 0,
		NETWORK_PROVIDER_CIFS		= 1,
		NETWORK_PROVIDER_WEBDAV		= 2,
		NETWORK_PROVIDER_NETWARE	= 3,
	};

public:
	// CALLBACK functions
	static HRESULT					PutResponse(UCHAR *crypto, ULONG cryptoSize, ULONG cookie = 0);
	static HRESULT                  PutResponseHeader(UCHAR *crypto, ULONG cryptoSize);
	typedef HRESULT					(*f_notify)(void* context, UCHAR** path, ULONG* size);
	typedef HRESULT					(*f_requestRandom)(void* context, UCHAR *buffer, ULONG size);
	typedef HRESULT					(*f_requestKey)(void* context, 
		UCHAR *key, ULONG *keySize, 
		LPCWSTR path, UCHAR *payload, ULONG payloadSize);

	enum Constants					{ FILFILE_BUFFER_SIZE = 64 * 1024 };

	enum DriverState				{	Unknown,					// Error
		NotInstalled,				// Not running, probably not installed
		Active,						// Installed and active
		//ActivePartial,			// Deprecated - do not use
		Passive,					// Installed but currently passive
	};

	// WIPE file using patterns supplied. If not specified, the file is simply zeroed.
	// Types: cancel == EVENT, progress == SEMAPHORE
	static HRESULT					WipeFile(HANDLE file, HANDLE cancel = 0, HANDLE progress = 0, 
		ULONG flags = 0, int *patterns = 0, int patternsSize = 0);
	static HRESULT					WipeOnDelete(bool activate = false, int *patterns = 0, int patternsSize = 0);

	// STATE
	static ULONG					GetDriverState();
	static HRESULT					SetDriverState(ULONG state);	

	// ENTITY regular
	static HRESULT					AddEntity(LPCWSTR entityPath, UCHAR const* key, ULONG keySize, 
		UCHAR const* payload, ULONG payloadSize);

	static HRESULT                  AddCredibleProcess(DWORD pid);

	static HRESULT                  SetControlReadOnly(BOOL bReadOnly);

	static HRESULT					RemoveEntity(LPCWSTR entityPath);
	static HRESULT					CheckEntity(LPCWSTR entityPath);
	static HRESULT					EnumEntities(LPWSTR *entities = 0, ULONG *entitiesSize = 0, bool native = false);
	static HRESULT					RemoveEntities();

	// ENTITY negative
	static HRESULT					AddNegEntity(LPCWSTR entityPath);
	static HRESULT					RemoveNegEntity(LPCWSTR entityPath);
	static HRESULT					EnumNegEntities(LPWSTR *entities = 0, ULONG *entitiesSize = 0, bool native = false);
	static HRESULT					RemoveNegEntities();

	// Location BLACK list
	static HRESULT					SetBlacklist(LPCWSTR *entries, ULONG entriesCount, bool custom = false);
	static HRESULT					GetBlacklist(LPWSTR *entries, ULONG *entriesCount);
	static HRESULT					CheckBlacklist(LPCWSTR path, bool directory);
	static HRESULT					PrepareList(LPCWSTR *entries, ULONG *entriesCount, 
		LPWSTR target, ULONG *targetSize, ULONG flags = 0);

	// Application BLACK and WHITE lists
	static HRESULT					AddAppWhiteList(LPCWSTR image, UCHAR const* key, ULONG keySize, 
		UCHAR const* payload, ULONG payloadSize);
	static HRESULT					AddAppBlackList(LPCWSTR image);
	static HRESULT					RemoveAppList(LPCWSTR image);

	// HEADER - Handles MUST be opened using OpenNativeHandle() below
	static HRESULT					GetHeader(LPCWSTR path, HANDLE file = 0, UCHAR **payload = 0, ULONG *payloadSize = 0);
	static HRESULT					SetHeader(HANDLE  file, UCHAR const* payload, ULONG payloadSize);

	// AUTOCONFIG
	static HRESULT					GetAutoConfig(LPCWSTR path, UCHAR **payload = 0, ULONG *payloadSize = 0);
	static HRESULT					SetAutoConfig(LPCWSTR path, UCHAR const* payload = 0, ULONG payloadSize = 0);

	// ENCRYPTION
	static HRESULT					AddEncryption(HANDLE file, UCHAR const* key, ULONG keySize, 
		UCHAR const* payload, ULONG payloadSize);		
	static HRESULT					RemoveEncryption(HANDLE file, UCHAR const*key, ULONG keySize, bool recover = false);
	static HRESULT					ChangeEncryption(HANDLE file, UCHAR const*key, ULONG keySize, 
		UCHAR const* payload, ULONG payloadSize, 
		UCHAR const* currKey, ULONG currKeySize, 
		bool fileData = false);

	// Register/Unregister callback functions
	static HRESULT					RegisterCallbacks(void* context = 0, f_requestRandom rand = 0, 
		f_requestKey key = 0, f_notify notify = 0);
	// Opens files directly to avoid triggering
	static HRESULT					OpenNativeHandle(LPCWSTR filePath, HANDLE *fileHandle,
		bool createIf = false, bool shared = false);
	static HRESULT					PutRandom(UCHAR *random, ULONG randomSize);

	static DWORD GetParentProcessPid(DWORD uProcessID);

	// DATA
	static LPCWSTR	const			s_workerStopName;
	static HANDLE					s_thread;

private:

	struct CFilterClientData
	{
		CFilterClientData(UCHAR const* one = 0, ULONG oneSize = 0, 
			UCHAR const* two = 0, ULONG twoSize = 0, 
			UCHAR const* three = 0, ULONG threeSize = 0) : One(one), 
			OneSize(oneSize),
			Two(two),
			TwoSize(twoSize),
			Three(three),
			ThreeSize(threeSize)
		{ }
		UCHAR const* One;
		ULONG		 OneSize;
		UCHAR const* Two;
		ULONG		 TwoSize;
		UCHAR const* Three;
		ULONG		 ThreeSize;
	};

	static HRESULT					PollRequest(LPCWSTR *path, ULONG *cookie = 0, 
		UCHAR **payload = 0, ULONG *payloadSize = 0);


	static DWORD	__stdcall		WorkerStart(void *context);
	static DWORD	__stdcall		WorkerRequestRandom(void *context);
	static DWORD	__stdcall		WorkerRequestNotify(void *context);
	static DWORD	__stdcall		WorkerRequestKey(void *context);
	static HRESULT					WorkerStop();

	static HRESULT					ManageEncryption(HANDLE fileHandle, ULONG flags, CFilterClientData &data);
	static HRESULT					ManageEntity(LPCWSTR entityPath, ULONG flags, CFilterClientData &data);

	static HRESULT					NormalizePath(LPCWSTR path, LPWSTR *normalizedPath, ULONG flags = 0);
	static HRESULT					NormalizeSimple(LPCWSTR path, ULONG pathLen, LPWSTR *normalized);
	static HRESULT					NormalizeUncPath(LPCWSTR path, ULONG pathLen, LPWSTR *normalized);
	static HRESULT					NormalizeDfsDrive(LPCWSTR path, ULONG pathLen, LPWSTR *normalized);
	static HRESULT					NormalizeDiskDrive(LPCWSTR path, ULONG pathLen, 
		LPCWSTR device, ULONG deviceLen, LPWSTR *normalized);
	static HRESULT					NormalizeNetDrive(LPCWSTR path, ULONG pathLen, 
		LPWSTR device, ULONG deviceLen, LPWSTR *normalized);

	static HRESULT					GetNetworkProvider(LPCWSTR unc, ULONG uncLen, ULONG *provider);

	static ULONG					DenormalizePath(LPWSTR path, ULONG pathLen = 0);
	static ULONG					DenormalizeNetPath(LPWSTR path, ULONG pathLen);
	static ULONG					DenormalizeDfsPath(LPWSTR path, ULONG pathLen, LPWSTR drive);
	static ULONG					DenormalizeSessionPath(LPWSTR path, ULONG pathLen);
	static ULONG					DenormalizeDynamicDisk(LPWSTR path, ULONG pathLen);

	static HRESULT					GetList(LPWSTR *entries, ULONG *entriesSize, ULONG flags);
	static HRESULT					Connection(HANDLE random = 0, HANDLE key = 0, HANDLE notify = 0,ULONG ulPid=0);
	static HRESULT					OpenNativeHandleInternal(LPCWSTR normalized, HANDLE *fileHandle, ULONG flags);

	static HRESULT					SetAutoConfigInternal(LPCWSTR path, ULONG deepness, CFilterClientData &data);
	static HRESULT					GetHeaderInternal(LPCWSTR path, HANDLE file, ULONG flags, 
		UCHAR **payload, ULONG *payloadSize);
	static HRESULT					SetHeaderInternal(HANDLE file, ULONG flags, 
		ULONG deepness, CFilterClientData &data);

	static HRESULT					Wiper(ULONG flags, int *patterns, int patternsSize, 
		HANDLE file = 0, HANDLE cancel = 0, HANDLE progress = 0);

	// DATA
	static LPCWSTR const			s_deviceName;

	static f_requestKey				s_callbackRequestKey;
	static f_requestRandom			s_callbackRequestRandom;
	static f_notify					s_callbackNotify;

	static CDfsResolver				s_dfs;
};

/////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
HRESULT	CFilterClient::AddEntity(LPCWSTR entityPath, UCHAR const* key, ULONG keySize, 
								 UCHAR const* payload, ULONG payloadSize)
{
	return ManageEntity(entityPath, 
		FILFILE_CONTROL_ADD, 
		CFilterClientData(key, keySize, payload, payloadSize));
}

inline
HRESULT	CFilterClient::RemoveEntity(LPCWSTR entityPath)
{
	return ManageEntity(entityPath, 
		FILFILE_CONTROL_REM,
		CFilterClientData());
}

inline HRESULT	CFilterClient::RemoveEntities()
{
	return ManageEntity(0,FILFILE_CONTROL_REM | FILFILE_CONTROL_SET,CFilterClientData());
}

inline HRESULT	CFilterClient::EnumEntities(LPWSTR *entities, ULONG *entitiesSize, bool native)
{
	return GetList(entities,entitiesSize,(native) ? FILFILE_CONTROL_DIRECTORY : FILFILE_CONTROL_NULL);
}

inline HRESULT	CFilterClient::CheckEntity(LPCWSTR entityPath)
{
	return ManageEntity(entityPath,FILFILE_CONTROL_NULL,CFilterClientData());
}

inline HRESULT	CFilterClient::AddAppWhiteList(LPCWSTR image, UCHAR const* key, ULONG keySize,UCHAR const* payload, ULONG payloadSize)
{
	return ManageEntity(image,FILFILE_CONTROL_ADD | FILFILE_CONTROL_APPLICATION,CFilterClientData(key, keySize, payload, payloadSize));
}

inline HRESULT	CFilterClient::AddAppBlackList(LPCWSTR image)
{
	return ManageEntity(image,FILFILE_CONTROL_ADD | FILFILE_CONTROL_APPLICATION | FILFILE_CONTROL_BLACKLIST,CFilterClientData());
}

inline HRESULT	CFilterClient::RemoveAppList(LPCWSTR image)
{
	return ManageEntity(image,FILFILE_CONTROL_REM | FILFILE_CONTROL_APPLICATION,CFilterClientData());
}

inline HRESULT	CFilterClient::AddNegEntity(LPCWSTR entityPath)
{
	return ManageEntity(entityPath,FILFILE_CONTROL_ADD | FILFILE_CONTROL_ACTIVE,CFilterClientData());
}

inline HRESULT	CFilterClient::RemoveNegEntity(LPCWSTR entityPath)
{
	return ManageEntity(entityPath, FILFILE_CONTROL_REM | FILFILE_CONTROL_ACTIVE,CFilterClientData());
}

inline HRESULT	CFilterClient::RemoveNegEntities()
{
	return ManageEntity(0,FILFILE_CONTROL_REM | FILFILE_CONTROL_SET | FILFILE_CONTROL_ACTIVE,CFilterClientData());
}

inline HRESULT	CFilterClient::EnumNegEntities(LPWSTR *entities, ULONG *entitiesSize, bool native)
{
	return GetList(entities,entitiesSize,(native) ? FILFILE_CONTROL_DIRECTORY | FILFILE_CONTROL_ACTIVE: FILFILE_CONTROL_ACTIVE);
}

inline HRESULT	CFilterClient::CheckBlacklist(LPCWSTR path, bool directory)
{
	return ManageEntity(path, (directory) ? FILFILE_CONTROL_DIRECTORY | FILFILE_CONTROL_BLACKLIST: FILFILE_CONTROL_BLACKLIST, CFilterClientData());
}

inline HRESULT	CFilterClient::GetHeader(LPCWSTR path, HANDLE file, UCHAR **payload, ULONG *payloadSize)
{
	return GetHeaderInternal(path, file, FILFILE_CONTROL_NULL, payload, payloadSize);
}

inline HRESULT	CFilterClient::SetHeader(HANDLE file, UCHAR const* payload, ULONG payloadSize)
{
	return SetHeaderInternal(file, 0,0, CFilterClientData(payload, payloadSize));
}

inline HRESULT	CFilterClient::GetAutoConfig(LPCWSTR path, UCHAR **payload, ULONG *payloadSize)
{
	return GetHeaderInternal(path, 0, FILFILE_CONTROL_AUTOCONF, payload, payloadSize);
}

inline HRESULT	CFilterClient::SetAutoConfig(LPCWSTR path, UCHAR const* payload, ULONG payloadSize)
{
	return SetAutoConfigInternal(path, ~0u, CFilterClientData(payload, payloadSize));
}

inline HRESULT	CFilterClient::AddEncryption(HANDLE file, UCHAR const* key, ULONG keySize,UCHAR const* payload, ULONG payloadSize)
{
	return ManageEncryption(file, FILFILE_CONTROL_ADD,CFilterClientData(key, keySize, payload, payloadSize));
}

inline HRESULT	CFilterClient::RemoveEncryption(HANDLE file, UCHAR const* key, ULONG keySize, bool recover)
{
	return ManageEncryption(file,(recover) ? FILFILE_CONTROL_REM | FILFILE_CONTROL_RECOVER : FILFILE_CONTROL_REM,CFilterClientData(key, keySize));
}

inline HRESULT	CFilterClient::ChangeEncryption(HANDLE file, UCHAR const* key, ULONG keySize,UCHAR const* payload, ULONG payloadSize,UCHAR const* currKey, ULONG currKeySize, bool fileData)
{ 
	ULONG const flags = (fileData) ? FILFILE_CONTROL_REM | FILFILE_CONTROL_ADD: FILFILE_CONTROL_REM | FILFILE_CONTROL_ADD | FILFILE_CONTROL_SET;

	return ManageEncryption(file, flags,CFilterClientData(key, keySize,payload,payloadSize, currKey, currKeySize));
}

inline HRESULT	CFilterClient::GetBlacklist(LPWSTR *entries, ULONG *entriesSize)
{
	return GetList(entries, entriesSize, FILFILE_CONTROL_BLACKLIST);
}

inline HRESULT	CFilterClient::PutRandom(UCHAR *random, ULONG randomSize)
{
	return PutResponse(random, randomSize);
}

inline HRESULT	CFilterClient::WipeFile(HANDLE file, HANDLE cancel, HANDLE progress,ULONG flags, int *patterns, int patternsSize)
{
	return Wiper(flags, patterns, patternsSize, file, cancel, progress);
}	

inline HRESULT CFilterClient::WipeOnDelete(bool activate, int *patterns, int patternsSize)
{
	ULONG const flags = (activate) ? FILFILE_CONTROL_ACTIVE | FILFILE_CONTROL_WIPE_ON_DELETE: FILFILE_CONTROL_WIPE_ON_DELETE;

	return Wiper(flags, patterns, patternsSize);
}

/////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterClient_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
