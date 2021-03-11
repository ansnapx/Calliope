////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterClient.cpp: implementation of the CFilterClient class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include <windows.h>
#include <wchar.h>
#include <assert.h>
#include <psapi.h>
#include <Iphlpapi.h>
#include <tlhelp32.h>
#include "CFilterClient.h"

#pragma comment(lib,"psapi.lib")

#if FILFILE_CONTROL_VERSION >= 2
#pragma message("CFilterClient: Control V2 used.")
#else
#pragma message("CFilterClient: Control V1 used.")
#endif

#pragma warning(disable: 4267) // "conversion from 'size_t' to 'ULONG', possible loss of data"
#pragma warning(disable: 4996) // "This function or variable may be unsafe..."

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// STATICS

LPCWSTR	const CFilterClient::s_deviceName		= L"\\\\.\\XAzFileCrypt";
LPCWSTR	const CFilterClient::s_workerStopName	= L"XAzFileCryptCallbackStop";

HANDLE CFilterClient::s_thread = 0;

CFilterClient::f_requestRandom	CFilterClient::s_callbackRequestRandom = 0;
CFilterClient::f_requestKey		CFilterClient::s_callbackRequestKey	   = 0;
CFilterClient::f_notify			CFilterClient::s_callbackNotify		   = 0;

CDfsResolver CFilterClient::s_dfs;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::GetNetworkProvider(LPCWSTR unc, ULONG uncLen, ULONG *provider)
{
	assert(unc);
	assert(uncLen);
	assert(provider);

	LPWSTR path = (LPWSTR) unc;

	// The stupid function below fails if path ends with a backslash. 
	if(unc[uncLen - 1] == L'\\')
	{
		// Allocate temporary one without
		path = (LPWSTR) malloc(uncLen * sizeof(WCHAR));

		if(!path)
		{
			return E_OUTOFMEMORY;
		}

		wcsncpy(path, unc, uncLen - 1);

		path[uncLen - 1] = UNICODE_NULL;
	}

	NETRESOURCE net;
	memset(&net, 0, sizeof(net));
	net.lpRemoteName = path;

	LPWSTR system = 0;
	UCHAR buffer[1024] = {0};

	DWORD bufferResult = sizeof(buffer);

	DWORD err = WNetGetResourceInformation(&net, (void*) buffer, &bufferResult, &system);

	if(path != unc)
	{
		free(path);
	}

	if(NO_ERROR != err)
	{
		return HRESULT_FROM_WIN32(err);
	}

	NETRESOURCE *result = (NETRESOURCE*) buffer;

	assert(result->lpProvider);

	if(!_wcsicmp(result->lpProvider, L"Microsoft Windows Network"))
	{
		*provider = NETWORK_PROVIDER_CIFS;

		return S_OK;
	}
	else if(!_wcsicmp(result->lpProvider, L"Web Client Network"))
	{
		*provider = NETWORK_PROVIDER_WEBDAV;

		return S_OK;
	}
	else if(!_wcsicmp(result->lpProvider, L"Netware Services"))
	{
		*provider = NETWORK_PROVIDER_NETWARE;

		return S_OK;
	}

	return E_INVALIDARG;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizeSimple(LPCWSTR path, ULONG pathLen, LPWSTR *normalized)
{
	assert(path);
	assert(pathLen);
	assert(normalized);

	// Just make copy
	ULONG const size = (pathLen + g_filFileAutoConfigNameLength + 1 + 1) * sizeof(WCHAR);

	LPWSTR resolved = (LPWSTR) malloc(size);
	if(!resolved)
	{
		return E_OUTOFMEMORY;
	}

	memset(resolved, 0, size);

	wcscpy(resolved, path);

	*normalized = resolved;

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizeNetDrive(LPCWSTR path, ULONG pathLen, LPWSTR device, ULONG deviceLen, LPWSTR *normalized)
{
	assert(path);
	assert(pathLen);
	assert(device);
	assert(deviceLen);
	assert(normalized);

	// Look for Session component, used by Terminal Services
	if((deviceLen > 25) && (device[25] == L';'))
	{
		ULONG index;

		// Strip it
		for(index = 26; index < deviceLen; ++index)
		{
			if(device[index] == L'\\')
			{
				break;
			}
		}

		if(index < deviceLen)
		{
			memmove(device + 24, device + index, (deviceLen - index) * sizeof(WCHAR));

			deviceLen -= index - 24; 

			device[deviceLen] = UNICODE_NULL;
		}
	}

	ULONG const size = (deviceLen + pathLen + g_filFileAutoConfigNameLength + 1 + 1) * sizeof(WCHAR);

	LPWSTR resolved = (LPWSTR) malloc(size);

	if(!resolved)
	{
		return E_OUTOFMEMORY;
	}

	memset(resolved, 0, size);

	wcscpy(resolved, device);
	wcscpy(resolved + deviceLen, path + 2);

	*normalized = resolved;

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizeDiskDrive(LPCWSTR path, ULONG pathLen, LPCWSTR device, ULONG deviceLen, LPWSTR *normalized)
{
	assert(path);
	assert(pathLen);
	assert(device);
	assert(deviceLen);
	assert(normalized);

	ULONG const size = (deviceLen + pathLen + g_filFileAutoConfigNameLength) * sizeof(WCHAR);

	LPWSTR resolved = (LPWSTR) malloc(size);

	if(!resolved)
	{
		return E_OUTOFMEMORY;
	}

	memset(resolved, 0, size);

	wcscpy(resolved, device);
	wcscpy(resolved + deviceLen, path + 2);

	*normalized = resolved;

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizeUncPath(LPCWSTR path, ULONG pathLen, LPWSTR *normalized)
{
	assert(path);
	assert(pathLen);
	assert(normalized);

	ULONG provider = NETWORK_PROVIDER_NULL;

	// Get the network provider
	HRESULT hr = GetNetworkProvider(path, pathLen, &provider);

	if(FAILED(hr))
	{
		return hr;
	}

	LPWSTR resolved = 0;

	if(NETWORK_PROVIDER_CIFS == provider)
	{
		// Try to resolve potentially DFS path
		if(SUCCEEDED(s_dfs.ResolvePath(path, pathLen, &resolved)))
		{
			assert(resolved);

			pathLen = wcslen(resolved);

			memmove(resolved + 25, resolved + 2, (pathLen - 2) * sizeof(WCHAR));

			// Terminate
			resolved[25 + pathLen - 2] = UNICODE_NULL;

			wcsncpy(resolved, L"\\Device\\LanmanRedirector\\", 25);
		}
	}

	if(!resolved)
	{
		ULONG const size = (32 + pathLen + g_filFileAutoConfigNameLength) * sizeof(WCHAR);

		resolved = (LPWSTR) malloc(size);

		if(!resolved)
		{
			return E_OUTOFMEMORY;
		}

		memset(resolved, 0, size);

		switch(provider)
		{
		case NETWORK_PROVIDER_CIFS:
			wcscpy(resolved, L"\\Device\\LanmanRedirector\\");
			break;

		case NETWORK_PROVIDER_WEBDAV:
			wcscpy(resolved, L"\\Device\\WebDavRedirector\\");
			break;

			/*
			case NETWORK_PROVIDER_NETWARE:
			wcscpy(resolved, L"\\Device\\NetWareRedirector\\");
			break;
			*/

		default:
			break;
		}

		wcscat(resolved, path + 2);
	}

	*normalized = resolved;

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizeDfsDrive(LPCWSTR path, ULONG pathLen, LPWSTR *normalized)
{
	assert(path);
	assert(pathLen);
	assert(normalized);

	LPWSTR resolved = 0;

	// Drive is directly connected to DFS namespace
	HRESULT hr = s_dfs.ResolveDrive(path, pathLen, &resolved);

	if(SUCCEEDED(hr))
	{
		pathLen = wcslen(resolved);

		memmove(resolved + 25, resolved + 2, (pathLen - 2) * sizeof(WCHAR));

		// Terminate
		resolved[25 + pathLen - 2] = UNICODE_NULL;

		wcsncpy(resolved, L"\\Device\\LanmanRedirector\\", 25);

		*normalized = resolved;
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::NormalizePath(LPCWSTR path, LPWSTR *normalizedPath, ULONG flags)
{
	if(!path || !normalizedPath)
	{
		return E_INVALIDARG;
	}

	ULONG const pathLen = wcslen(path);

	if(pathLen < 3)
	{
		return E_INVALIDARG;
	}

	HRESULT hr = E_INVALIDARG;

	LPWSTR normalized = 0;

	if(path[1] == L':')
	{
		// Path contains drive letter
		WCHAR drive[4]	  = { path[0], L':', UNICODE_NULL, UNICODE_NULL};
		WCHAR device[256] = {0};

		// Resolve drive letter. Ignore returned length of this function as it's wrong
		if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
		{
			ULONG const deviceLen = wcslen(device);

			if(deviceLen > 8)
			{
				if(!_wcsnicmp(device + 8, L"LanmanRedirector\\", 25 - 8) ||
					!_wcsnicmp(device + 8, L"WebDavRedirector\\", 25 - 8))
				{
					// Generic network-based drive
					hr = NormalizeNetDrive(path, pathLen, device, deviceLen, &normalized);
				}	
				else if(!_wcsnicmp(device + 8, L"WinDFS\\", 15 - 8) ||
					!_wcsnicmp(device + 8, L"Mup\\DFSClient\\", 21 - 8))
				{
					// Drive is connected to DFS namespace
					hr = NormalizeDfsDrive(path, pathLen, &normalized);
				}
				else
				{
					// Assume disk-based drive
					hr = NormalizeDiskDrive(path, pathLen, device, deviceLen, &normalized);
				}
			}
		}
		else
		{
			hr = HRESULT_FROM_WIN32(::GetLastError());
		}
	}
	else if((path[0] == L'\\') && (path[1] == L'\\'))
	{
		// UNC path
		hr = NormalizeUncPath(path, pathLen, &normalized);
	}
	else if(!_wcsnicmp(path, L"\\Device\\", 8))
	{
		// Path is already normalized, so just make a copy
		hr = NormalizeSimple(path, pathLen, &normalized);
	}

	if(SUCCEEDED(hr))
	{
		if(flags)
		{
			ULONG normalizedLen = wcslen(normalized);

			// Ensure trailing backslash?
			if(flags & (FILFILE_CONTROL_DIRECTORY | FILFILE_CONTROL_AUTOCONF))
			{
				if(normalized[normalizedLen - 1] != L'\\')
				{
					normalized[normalizedLen]	  = L'\\';
					normalized[normalizedLen + 1] = UNICODE_NULL;

					normalizedLen++;
				}
			}

			// Append AutoConfig name?
			if(flags & FILFILE_CONTROL_AUTOCONF)
			{
				wcscpy(normalized + normalizedLen, g_filFileAutoConfigName);
			}
		}

		*normalizedPath = normalized;
		normalized = 0;
	}

	if(normalized)
	{
		free(normalized);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CFilterClient::DenormalizeSessionPath(LPWSTR path, ULONG pathLen)
{
	assert(path);
	assert(pathLen);
	assert(pathLen > 26);

	ULONG newLen = 0;

	WCHAR drive[4]	  = { path[26], L':', UNICODE_NULL, UNICODE_NULL};
	WCHAR device[256] = {0};

	// Estimate real length of target path
	if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
	{
		// Exact sub-match?
		if(wcsstr(path, device))
		{
			ULONG const deviceLen = wcslen(device);

			path[0] = path[26];
			path[1] = L':';

			memmove(path + 2, path + deviceLen, (pathLen - deviceLen) * sizeof(WCHAR));

			newLen = pathLen - deviceLen + 2;

			memset(path + newLen, 0, (pathLen - newLen) * sizeof(WCHAR));
		}
	}

	return newLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CFilterClient::DenormalizeNetPath(LPWSTR path, ULONG pathLen)
{
	assert(path);
	assert(pathLen);

	// Lanman Session info and drive letter?
	if((pathLen > 27) && (path[25] == L';') && (path[27] == L':'))
	{
		return DenormalizeSessionPath(path, pathLen);
	}

	ULONG mask = ::GetLogicalDrives();

	ULONG newLen = 0;
	WCHAR device[256];

	// Try matching device path with remote drive letter. Prefer standard CIFS drives
	for(ULONG index = 0; index < 26; ++index)
	{
		if( !(mask & (1 << index)))
		{
			continue;
		}

		WCHAR drive[] = { WCHAR (L'A' + index), L':', UNICODE_NULL };

		// Query only remote drives
		if(DRIVE_REMOTE != ::GetDriveType(drive))
		{
			// Mask off
			mask &= ~(1 << index);

			continue;
		}

		memset(device, 0, sizeof(device));

		if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
		{
			ULONG const deviceLen = wcslen(device);

			ULONG semicolon = 0;

			// Drive syntax on WXP, W2k?
			if((deviceLen > 25) && (device[25] == L';')) 
			{
				semicolon = 25;
			}
			else if((deviceLen > 22) && (device[22] == L';')) 
			{
				// on Vista	DFS
				semicolon = 22;
			}

			if(semicolon)
			{
				LPWSTR const serverShare = wcschr(device + semicolon, L'\\');
				assert(serverShare);
				ULONG serverShareLen = wcslen(serverShare);

				if(!wcsnicmp(path + 24, serverShare, serverShareLen))
				{
					serverShareLen += 24;

					assert(pathLen >= serverShareLen);
					memmove(path + 2, path + serverShareLen, (pathLen - serverShareLen + 1) * sizeof(WCHAR));

					newLen = pathLen - serverShareLen + 2;

					// Substitute device prefix with drive letter
					path[0] = drive[0];
					path[1] = drive[1];

					break;
				}
			}
		}
	}

	if(!newLen)
	{
		// Check whether remove drive belongs to DFS namespace
		for(ULONG index = 0; index < 26; ++index)
		{
			if(mask & (1 << index))
			{
				WCHAR drive[] = { WCHAR (L'A' + index), L':', UNICODE_NULL};

				assert(DRIVE_REMOTE == ::GetDriveType(drive));

				memset(device, 0, sizeof(device));

				if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
				{
					ULONG const deviceLen = wcslen(device);

					if(deviceLen > 12)
					{
						if(!_wcsnicmp(device + 8, L"WinDFS\\", 15 - 8) ||
							!_wcsnicmp(device + 8, L"Mup\\DFSClient\\", 21 - 8))
						{
							// Returned drive belongs to DFS namespace
							newLen = s_dfs.ResolveDevice(path, pathLen, drive);

							// Resolved?
							if(newLen)
							{
								break;
							}
						}
					}
				}
			}
		}
	}

	if(!newLen)
	{
		// Fallback: just strip device prefix
		memmove(path + 1, path + 24, (pathLen - 24) * sizeof(WCHAR));

		newLen = pathLen - 24 + 1;
	}

	assert(newLen);

	// Clear unused chars
	memset(path + newLen, 0, (pathLen - newLen) * sizeof(WCHAR));

	return newLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CFilterClient::DenormalizeDynamicDisk(LPWSTR path, ULONG pathLen)
{
	assert(path);
	assert(pathLen);

	// Try matching physical Dynamic Disk to a Symbolic Link that points to it.
	//
	// Well, this approach is not fully exact. But since Dynamic disks are very uncommon and the result 
	// is primarily used for display purposes, I can live with that. The UI folks may complain...

	if(pathLen < 57)
	{
		return pathLen;
	}

	ULONG const mask = ::GetLogicalDrives();

	// Get physical Block Number
	ULONG blockNumber = path[55] - L'0';

	if(path[56] != L'\\')
	{
		blockNumber *= 10;
		blockNumber += path[56] - L'0';
	}

	ULONG symbolicLinkCount		  = 0;
	UCHAR symbolicLinkNumbers[27] = {0};

	ULONG index;

	// Retrieve numbers of all symbolic links
	for(index = 0; index < 26; ++index)
	{
		if( !(mask & (1 << index)))
		{
			continue;
		}

		WCHAR const drive[3] = {WCHAR (L'A' + index), L':', 0};

		if(DRIVE_FIXED != ::GetDriveType(drive))
		{
			continue;
		}

		WCHAR device[256] = {0};

		if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
		{
			if((wcslen(device) >= 26) && !_wcsnicmp(device + 8, L"HarddiskDmVolumes\\", 26 - 8))
			{
				// Volume or Stripe set ?
				LPCWSTR deviceName = wcsstr(device, L"\\Volume");

				if(!deviceName)
				{
					deviceName = wcsstr(device, L"\\Stripe");
				}

				if(deviceName)
				{
					ULONG number = deviceName[7] - L'0';

					if(deviceName[8])
					{
						number *= 10;
						number += deviceName[8] - L'0';
					}

					symbolicLinkNumbers[index] = (UCHAR) number;

					symbolicLinkCount++;
				}
			}
		}
	}

	if(symbolicLinkCount)
	{
		// Select best match for candidate
		for(index = 2; index < 26; ++index)
		{
			if(symbolicLinkNumbers[index])
			{
				// Direct match?
				if(symbolicLinkNumbers[index] == (UCHAR) blockNumber)
				{
					break;
				}
				// If there is only one, so use it
				if(symbolicLinkCount == 1)
				{
					break;
				}
			}
		}

		if(index >= 26)
		{
			//
			// TODO: Implement smart heuristic. Maybe nearest numeric match or similar
			// 
		}

		if(index < 26)
		{
			WCHAR const drive[3] = {WCHAR (L'A' + index), L':', 0};
			WCHAR device[256]	 = {0};

			if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
			{
				path[0] = drive[0];
				path[1] = drive[1];

				ULONG const start = (symbolicLinkNumbers[index] > 10) ? 57 : 56;

				memmove(path + 2, path + start, (pathLen - start) * sizeof(WCHAR));

				ULONG const newLen = pathLen - start + 2;

				memset(path + newLen, 0, (pathLen - newLen) * sizeof(WCHAR));

				pathLen = newLen;
			}
		}
	}

	return pathLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CFilterClient::DenormalizePath(LPWSTR path, ULONG pathLen)
{
	if(!path)
	{
		return 0;
	}

	if(!pathLen)
	{
		pathLen = wcslen(path);

		if(!pathLen)
		{
			return 0;
		}
	}

	// Already denormalized?
	if(wcsnicmp(path, L"\\Device\\", 8))
	{
		return pathLen;
	}

	// Network-based?
	if(pathLen >= 25)
	{
		if(!_wcsnicmp(path + 8, L"LanmanRedirector\\", 25 - 8) ||
			!_wcsnicmp(path + 8, L"WebDavRedirector\\", 25 - 8))
		{
			return DenormalizeNetPath(path, pathLen);
		}
	}

	// Physical Dynamic Disk? Handle links to those below
	if((pathLen >= 41) && !_wcsnicmp(path + 8, L"HarddiskDmVolumes\\PhysicalDmVolumes\\", 41 - 8))
	{
		return DenormalizeDynamicDisk(path, pathLen);
	}

	ULONG const mask = ::GetLogicalDrives();

	// Try to match the device path on existing drive letters
	for(ULONG index = 0; index < 26; ++index)
	{
		if( !(mask & (1 << index)))
		{
			continue;
		}

		WCHAR const drive[3] = {WCHAR (L'A' + index), L':', 0};
		ULONG const type     = ::GetDriveType(drive);

		// Filter out particular drives
		if((DRIVE_FIXED == type) || (DRIVE_REMOVABLE == type) || (DRIVE_CDROM == type) || (DRIVE_RAMDISK == type))
		{
			WCHAR device[256] = {0};

			if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
			{
				// The returned length of the above function is always wrong
				ULONG const deviceLen = wcslen(device);

				// Sub-match?
				if((pathLen > deviceLen) && !_wcsnicmp(device, path, deviceLen))
				{
					// Substitute device prefix with drive letter
					path[0] = drive[0];
					path[1] = drive[1];

					memmove(path + 2, path + deviceLen, (pathLen - deviceLen) * sizeof(WCHAR));

					ULONG const newLen = pathLen - deviceLen + 2;

					// Clear unused chars
					memset(path + newLen, 0, (pathLen - newLen) * sizeof(WCHAR));

					pathLen = newLen;

					break;
				}
			}
		}
	}

	return pathLen;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::PrepareList(LPCWSTR *entries, ULONG *entriesCount, LPWSTR target, ULONG *targetSize, ULONG flags)
{
	if(!entries || !entriesCount || !target || !targetSize)
	{
		return E_INVALIDARG;
	}

	/* We do not support ancient DOS wildcards:
	#define DOS_STAR        (L'<')
	#define DOS_QM          (L'>')
	#define DOS_DOT         (L'"')
	*/

	LPWSTR temp = (LPWSTR) malloc(FILFILE_BUFFER_SIZE);

	if(!temp)
	{
		return E_OUTOFMEMORY;
	}

	HRESULT hr = S_OK;

	ULONG current	= 0;
	ULONG count		= 0;

	for(ULONG index = 0; index < *entriesCount; ++index)
	{
		memset(temp, 0, FILFILE_BUFFER_SIZE);

		bool wildcard = false;
		bool subst    = false;
		bool path	  = false;
		bool tilda	  = false;

		LPCWSTR entry  = entries[index];
		ULONG entryLen = 0;

		// Look for wildcards and/or substitutes
		while(entry[entryLen])
		{
			temp[entryLen] = entry[entryLen];

			switch(entry[entryLen])
			{
			case L'?':
			case L'*':
				wildcard = true;
				break;
			case L'%':
				subst = true;
				break;
			case L'\\':
				path = true;
				break;
			case L'~':
				tilda = true;
				break;
			default:
				break;
			}

			entryLen++;
		}

		if(subst)
		{
			// Have Windows substitute the strings
			if(!::ExpandEnvironmentStrings(entry, temp, FILFILE_BUFFER_SIZE / sizeof(WCHAR)))
			{
				continue;
			}

			entryLen = wcslen(temp);

			if(wcschr(temp, L'~'))
			{
				tilda = true;
			}
		}

		if(tilda)
		{
			LPWSTR shortName = (LPWSTR) malloc((entryLen + 1) * sizeof(WCHAR));

			if(shortName)
			{
				wcscpy(shortName, temp);

				// This stupid function fails if one directory component does not exist
				entryLen = ::GetLongPathName(shortName, temp, FILFILE_BUFFER_SIZE / sizeof(WCHAR));

				if(!entryLen)
				{
					LPWSTR last = 0;

					// Cut off one by one until it succeeds...
					for(;;)
					{
						LPWSTR const back = wcsrchr(shortName, L'\\');

						if(!back)
						{
							break;
						}

						*back = UNICODE_NULL;

						if(last)
						{
							*last = L'\\';
						}

						entryLen = ::GetLongPathName(shortName, temp, FILFILE_BUFFER_SIZE / sizeof(WCHAR));

						if(entryLen)
						{
							*back = L'\\';

							wcscat(temp, back);

							entryLen = wcslen(temp);

							break;
						}

						last = back;
					}
				}

				free(shortName);
			}
		}

		if(wildcard)
		{
			// Wildcards are only allowed with files
			if(path)
			{
				// Enforce that
				continue;
			}

			// Change to upcase as the wildcard matching logic relies on that
			::CharUpper(temp);
		}

		// Blacklist?
		if(flags & FILFILE_CONTROL_SET)
		{
			// Normalize path, if such
			if((temp[1] == L':') || (temp[0] == L'\\' && (temp[1] == L'\\')))
			{
				entryLen = 0;

				LPWSTR normalized = 0;

				// Ensure directory type
				hr = NormalizePath(temp, &normalized, flags | FILFILE_CONTROL_DIRECTORY);

				if(SUCCEEDED(hr))
				{
					wcscpy(temp, normalized);

					entryLen = wcslen(temp);

					free(normalized);
				}
			}
		}
		else
		{
			// Whitelist: Only FQ entries are alllowed. Check for drive or UNC syntax
			if(entryLen < 3)
			{
				continue;
			}
			if((temp[1] != L':') && ((temp[0] != L'\\') || (temp[1] != L'\\')))
			{
				continue;
			}
		}

		if(!entryLen)
		{
			continue;
		}

		// Check remaining buffer size supplied by caller
		if((current + entryLen + 1) >= (*targetSize / sizeof(WCHAR)))
		{
			hr = E_FAIL;
			break;
		}

		// Copy into target buffer
		wcscpy(target + current, temp);

		current += 1 + entryLen;

		count++;
	}

	free(temp);

	if(SUCCEEDED(hr))
	{
		// Update target size
		*targetSize = (current + 1) * sizeof(WCHAR);
		// Update entries count
		*entriesCount = count;
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::SetBlacklist(LPCWSTR *entries, ULONG entriesCount, bool custom)
{
	ULONG controlSize		 = sizeof(FILFILE_CONTROL) + FILFILE_BUFFER_SIZE;
	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(!control)
	{
		return E_OUTOFMEMORY;
	}

	memset(control, 0, controlSize);

	control->Magic	    = FILFILE_CONTROL_MAGIC;
	control->Version    = FILFILE_CONTROL_VERSION;
	control->Size	    = sizeof(FILFILE_CONTROL);
	control->PathOffset	= sizeof(FILFILE_CONTROL);
	control->Value1		= 0;
	control->Flags		= FILFILE_CONTROL_BLACKLIST | FILFILE_CONTROL_ADD | FILFILE_CONTROL_SHARED;

	if(custom)
	{
		control->Flags &= ~FILFILE_CONTROL_SHARED;
	}

	HRESULT hr		 = S_OK;
	ULONG targetSize = FILFILE_BUFFER_SIZE;

	if(entries && entriesCount)
	{
		hr = PrepareList(entries, 
			&entriesCount, 
			(LPWSTR)((UCHAR*) control + sizeof(FILFILE_CONTROL)), 
			&targetSize, 
			FILFILE_CONTROL_SET);
	}

	if(SUCCEEDED(hr))
	{
		if(entriesCount)
		{
			control->PathLength = targetSize * sizeof(WCHAR); 
			control->Size	   += control->PathLength;
			control->Value1		= entriesCount;
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			ULONG junk = 0;

			hr = S_OK;

			// call driver
			if(!::DeviceIoControl(device, IOCTL_FILFILE_SET_BLACKLIST, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}
	}

	free(control);

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CFilterClient::GetDriverState()
{
	DriverState state = NotInstalled;

	FILFILE_CONTROL control;
	memset(&control, 0, sizeof(control));

	control.Magic	= FILFILE_CONTROL_MAGIC;
	control.Version = FILFILE_CONTROL_VERSION;
	control.Size	= sizeof(FILFILE_CONTROL);
	control.Flags	= FILFILE_CONTROL_NULL;

	HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

	if(INVALID_HANDLE_VALUE != device)
	{
		ULONG outSize = 0;

		FILFILE_CONTROL_OUT out;
		memset(&out, 0, sizeof(out));

		// call driver
		if(::DeviceIoControl(device, IOCTL_FILFILE_GET_STATE, &control, control.Size, &out, sizeof(out), &outSize, 0))
		{	
			state = Passive;

			if(out.Flags == FILFILE_CONTROL_ACTIVE)
			{
				// fully active
				state = Active;
			}
		}

		::CloseHandle(device);
	}

	return state;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::SetDriverState(ULONG state)
{
	if((state != Passive) && (state != Active))
	{
		return E_INVALIDARG;
	}

	FILFILE_CONTROL control;
	memset(&control, 0, sizeof(control));

	control.Magic	= FILFILE_CONTROL_MAGIC;
	control.Version = FILFILE_CONTROL_VERSION;
	control.Size	= sizeof(FILFILE_CONTROL);
	control.Flags	= FILFILE_CONTROL_SET;

	if(state == Active)
	{
		// fully active
		control.Flags |= FILFILE_CONTROL_ACTIVE | FILFILE_CONTROL_ADD; 
	}

	HRESULT hr = E_NOINTERFACE;

	HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, 0,0, OPEN_EXISTING, 0,0);

	if(INVALID_HANDLE_VALUE != device)
	{
		hr = S_OK;
		ULONG junk = 0;

		// call driver
		if(!::DeviceIoControl(device, IOCTL_FILFILE_SET_STATE, &control, control.Size, 0,0, &junk, 0))
		{
			DWORD dwError=::GetLastError();
			hr = HRESULT_FROM_WIN32(dwError);
		}
		::CloseHandle(device);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::ManageEntity(LPCWSTR path, ULONG flags, CFilterClientData &data)
{
	// Data layout: One   := Entity Key (DEK)
	//				Two	  := Header Payload
	//				Three := n/a

	HRESULT hr = S_OK;
	LPWSTR normalized  	   = 0;
	ULONG normalizedLength = 0;

	if( !(flags & FILFILE_CONTROL_SET))
	{
		if(!path)
		{
			return E_INVALIDARG;
		}

		if((flags & FILFILE_CONTROL_ADD) && !(flags & (FILFILE_CONTROL_ACTIVE | FILFILE_CONTROL_BLACKLIST)))
		{
			if(flags & FILFILE_CONTROL_APPLICATION)
			{
				// Valid Entity Key (DEK)?
				if(!data.One || !data.OneSize)
				{
					return E_INVALIDARG;
				}
			}

			// Valid Header Payload?
			if(!data.Two || !data.TwoSize)
			{
				return E_INVALIDARG;
			}
			// verify max Header size
			if(data.TwoSize > (FILFILE_HEADER_MAX_SIZE - FILFILE_HEADER_META_SIZE))
			{
				return E_INVALIDARG;
			}
		}

		// Application WL/BL?
		if(flags & FILFILE_CONTROL_APPLICATION)
		{
			WCHAR const badChars[] = {L'\\', L'*', L'?', L'\n'};

			// Check given path for unsupported chars
			for(ULONG index = 0; index < sizeof(badChars)/sizeof(badChars[0]); ++index)
			{
				if(wcschr(path, badChars[index]))
				{
					return E_INVALIDARG;
				}
			}

			normalized = const_cast<LPWSTR>(path);
		}
		else
		{
			hr = NormalizePath(path, &normalized, flags);

			if(FAILED(hr))
			{
				return hr;
			}
		}

		normalizedLength = (wcslen(normalized) + 1) * sizeof(WCHAR);
	}

	hr = E_OUTOFMEMORY;

	ULONG const controlSize = sizeof(FILFILE_CONTROL) + normalizedLength + data.OneSize + data.TwoSize + data.ThreeSize;

	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		ULONG offset = sizeof(FILFILE_CONTROL);

		control->Magic	    = FILFILE_CONTROL_MAGIC;
		control->Version    = FILFILE_CONTROL_VERSION;
		control->Size	    = controlSize;
		control->Flags		= flags & ~FILFILE_CONTROL_DIRECTORY;

		if(normalized)
		{
			memcpy((UCHAR*) control + offset, normalized, normalizedLength);

			control->PathOffset	= offset;
			control->PathLength	= normalizedLength;

			offset += control->PathLength;
		}

		// Add regular Entity?
		if((flags & FILFILE_CONTROL_ADD) == FILFILE_CONTROL_ADD)
		{
			if(data.OneSize)
			{
				// Entity Key (DEK)
				control->CryptoSize	  = data.OneSize;
				control->CryptoOffset = offset;

				memcpy((char*) control + control->CryptoOffset, data.One, data.OneSize);
				offset += control->CryptoSize;
			}

			// Header Payload
			control->PayloadSize   = data.TwoSize;
			control->PayloadOffset = offset;

			memcpy((char*) control + control->PayloadOffset, data.Two, data.TwoSize);
			offset += control->PayloadSize;
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			hr = S_OK;

			ULONG junk = 0;

			// call driver
			if(!::DeviceIoControl(device, IOCTL_FILFILE_ENTITY, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());

				if((FILFILE_CONTROL_NULL == flags) || (flags & FILFILE_CONTROL_BLACKLIST))
				{
					if(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr)
					{
						// 'Not found' is a valid query result
						hr = S_FALSE;
					}
				}
				else if(flags & FILFILE_CONTROL_REM)
				{
					if(HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == hr)
					{
						// there are still open files referencing the FileKey
						hr = S_FALSE;
					}
				}
			}

			::CloseHandle(device);
		}

		memset(control, 0, controlSize);

		free(control);
	}

	if(normalized && (normalized != path))
	{
		free(normalized);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::GetList(LPWSTR *entries, ULONG *entriesSize, ULONG flags)
{
	if(flags & FILFILE_CONTROL_BLACKLIST)
	{
		if(!entries || !entriesSize)
		{
			return E_INVALIDARG;
		}
	}

	HRESULT hr = E_OUTOFMEMORY;

	// Simple Boolean query?
	if(!entries || !entriesSize)
	{
		FILFILE_CONTROL control;
		memset(&control, 0, sizeof(control));

		control.Magic	= FILFILE_CONTROL_MAGIC;
		control.Version = FILFILE_CONTROL_VERSION;
		control.Size	= sizeof(FILFILE_CONTROL);
		control.Flags	= flags;

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			hr = S_OK;

			ULONG junk = 0;

			// call driver
			if(!::DeviceIoControl(device, IOCTL_FILFILE_ENUM_ENTITIES, &control, control.Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());

				if(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr)
				{
					hr = S_FALSE;
				}
			}

			::CloseHandle(device);
		}

		return hr;
	}

	ULONG const bufferSize = FILFILE_BUFFER_SIZE;
	LPWSTR buffer		   = (LPWSTR) malloc(bufferSize);

	if(buffer)
	{
		memset(buffer, 0, bufferSize);

		FILFILE_CONTROL control;
		memset(&control, 0, sizeof(control));

		control.Magic	 = FILFILE_CONTROL_MAGIC;
		control.Version  = FILFILE_CONTROL_VERSION;
		control.Size	 = sizeof(FILFILE_CONTROL);
		control.Flags	 = flags;

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			ULONG const ctrlCode = (flags & FILFILE_CONTROL_BLACKLIST) ? IOCTL_FILFILE_GET_BLACKLIST : IOCTL_FILFILE_ENUM_ENTITIES; 

			ULONG outSize = 0;

			// call driver
			if(::DeviceIoControl(device, ctrlCode, &control, control.Size, buffer, bufferSize, &outSize, 0))
			{
				hr = S_FALSE;

				if(outSize)
				{	
					hr = S_OK;

					if(entries && entriesSize)
					{
						outSize /= sizeof(WCHAR);	

						// cook entries ?
						if( !(flags & FILFILE_CONTROL_DIRECTORY))
						{
							ULONG index = 0;

							while(index < outSize)
							{
								if(!buffer[index])
								{
									break;
								}

								LPWSTR const current = buffer + index;

								ULONG len = wcslen(current);

								// denormalize entries inplace
								ULONG const newLen = DenormalizePath(current, len);

								if(newLen && (newLen < len))
								{
									::MoveMemory(current + newLen, current + len, (outSize - (index + len)) * sizeof(WCHAR));

									outSize -= len - newLen;

									memset(current + outSize, 0, (len - newLen) * sizeof(WCHAR));

									len = newLen;
								}

								index += 1 + len;
							}
						}

						hr = E_OUTOFMEMORY;

						*entries = (LPWSTR) malloc(outSize * sizeof(WCHAR));

						if(*entries)
						{
							memcpy(*entries, buffer, outSize * sizeof(WCHAR));

							*entriesSize = outSize;

							hr = S_OK;
						}
					}
				}
			}
			else
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		free(buffer);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::OpenNativeHandle(LPCWSTR path, HANDLE *file, bool createIf, bool shared)
{
	if(!path || !file)
	{
		return E_INVALIDARG;
	}

	LPWSTR normalized = 0;

	HRESULT hr = NormalizePath(path, &normalized);

	if(SUCCEEDED(hr))
	{
		ULONG flags = FILFILE_CONTROL_NULL;

		if(createIf)
		{
			flags |= FILFILE_CONTROL_ADD;
		}
		if(shared)
		{
			flags |= FILFILE_CONTROL_SHARED;
		}

		hr = OpenNativeHandleInternal(normalized, file, flags);

		free(normalized);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::OpenNativeHandleInternal(LPCWSTR normalized, HANDLE *file, ULONG flags)
{
	if(!normalized || !file)
	{
		return E_INVALIDARG;
	}

	HRESULT hr = E_OUTOFMEMORY;

	ULONG const normalizedLength = (wcslen(normalized) + 1) * sizeof(WCHAR);
	ULONG const controlSize		 = sizeof(FILFILE_CONTROL) + normalizedLength;

	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		control->Magic	    = FILFILE_CONTROL_MAGIC;
		control->Version    = FILFILE_CONTROL_VERSION;
		control->Size	    = controlSize;
		control->Flags		= flags;
		control->PathLength	= normalizedLength;
		control->PathOffset	= sizeof(FILFILE_CONTROL);

		memcpy((char*) control + control->PathOffset, normalized, normalizedLength);

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			FILFILE_CONTROL_OUT out;
			memset(&out, 0, sizeof(out));

			ULONG outSize = 0;

			// call driver
			if(::DeviceIoControl(device, IOCTL_FILFILE_OPEN_FILE, control, control->Size, &out, sizeof(out), &outSize, 0))
			{
				hr = E_FAIL;

				if(out.Value)
				{
					*file = (HANDLE)(ULONG_PTR) out.Value;

					hr = S_OK;
				}
			}
			else 
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		free(control);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::GetHeaderInternal(LPCWSTR path, HANDLE file, ULONG flags, UCHAR **payload, ULONG *payloadSize)
{
	if(!path && !file)
	{
		return E_INVALIDARG;
	}

	HRESULT hr = S_OK;

	LPWSTR normalized	   = 0;
	ULONG normalizedLength = 0;

	if(path)
	{
		hr = NormalizePath(path, &normalized, flags);

		if(FAILED(hr))
		{
			return hr;
		}

		normalizedLength = (wcslen(normalized) + 1) * sizeof(WCHAR);
	}

	hr = E_OUTOFMEMORY;

	ULONG const controlSize = sizeof(FILFILE_CONTROL) + normalizedLength;

	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		hr = S_OK;

		control->Magic	 = FILFILE_CONTROL_MAGIC;
		control->Version = FILFILE_CONTROL_VERSION;
		control->Size	 = controlSize;
		control->Flags	 = flags & FILFILE_CONTROL_AUTOCONF;

		if(normalized)
		{
			control->PathLength	= normalizedLength;
			control->PathOffset	= sizeof(FILFILE_CONTROL);

			memcpy((UCHAR*) control + control->PathOffset, normalized, normalizedLength);
		}

		// defaults
		ULONG bufferSize = 0;
		UCHAR *buffer    = 0;

		// Payload data requested ?
		if(payload && payloadSize)
		{
			hr = E_OUTOFMEMORY;

			bufferSize = FILFILE_HEADER_MAX_SIZE;
			buffer     = (UCHAR*) malloc(bufferSize);

			if(buffer)
			{
				memset(buffer, 0, bufferSize);

				hr = S_OK;
			}
		}

		if(SUCCEEDED(hr))
		{
			hr = E_NOINTERFACE;

			HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

			if(INVALID_HANDLE_VALUE != device)
			{
				ULONG outSize = 0;

				// If caller supplied file handle, use it
				if(file)
				{
					hr = S_OK;

					assert(file != INVALID_HANDLE_VALUE);

					control->Flags  |= FILFILE_CONTROL_HANDLE;
					control->Value1  = (ULONG_PTR) file;

					if(!::DeviceIoControl(device, IOCTL_FILFILE_GET_HEADER, control, control->Size, buffer, bufferSize, &outSize, 0))
					{
						hr = HRESULT_FROM_WIN32(::GetLastError());
					}
				}
				else
				{
					// First try a lookup in HeaderCache. If failed, open file and read data
					for(ULONG step = 0; step < 2; ++step)
					{ 
						if(1 == step)
						{
							// We had a cache miss
							hr = OpenNativeHandleInternal(normalized, 
								&file, 
								(flags & FILFILE_CONTROL_AUTOCONF) | FILFILE_CONTROL_SHARED);

							if(FAILED(hr))
							{
								if(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr)
								{
									hr = E_FAIL;
								}
								break;
							}

							control->Flags  |= FILFILE_CONTROL_HANDLE;
							control->Value1  = (ULONG_PTR) file;
						}

						if(::DeviceIoControl(device, 
							IOCTL_FILFILE_GET_HEADER, 
							control, 
							control->Size, 
							buffer, 
							bufferSize, 
							&outSize, 
							0))
						{
							hr = S_OK;
							break;
						}
						else 
						{
							hr = HRESULT_FROM_WIN32(::GetLastError());

							if((HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr) || 
								(HRESULT_FROM_WIN32(ERROR_GEN_FAILURE) == hr))
							{
								hr = E_FAIL;
								break;
							}
						}
					}

					if(file && (INVALID_HANDLE_VALUE != file))
					{
						::CloseHandle(file);
					}
				}

				if(SUCCEEDED(hr))
				{
					// Payload data requested?
					if(payload && payloadSize)
					{
						hr = E_FAIL;

						if(outSize >= sizeof(FILFILE_CONTROL_OUT))
						{
							hr = E_OUTOFMEMORY;

							FILFILE_CONTROL_OUT *const out = (FILFILE_CONTROL_OUT*) buffer;

							*payload = (UCHAR*) malloc(out->PayloadSize);

							if(*payload)
							{
								*payloadSize = out->PayloadSize;

								memcpy(*payload, buffer + sizeof(FILFILE_CONTROL_OUT), out->PayloadSize);

								hr = S_OK;
							}
						}
					}
				}

				::CloseHandle(device);
			}
		}

		free(buffer);
		free(control);
	}

	free(normalized);

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::SetHeaderInternal(HANDLE file, ULONG flags, ULONG deepness, CFilterClientData &data)
{
	// Data layout: One   := Header Payload
	//				Two	  := n/a
	//				Three := n/a

	if(!file || (INVALID_HANDLE_VALUE == file))
	{
		return E_INVALIDARG;
	}

	// verify max Header size
	if(data.OneSize > (FILFILE_HEADER_MAX_SIZE - FILFILE_HEADER_META_SIZE))
	{
		return E_INVALIDARG;
	}

	HRESULT hr = E_OUTOFMEMORY;

	ULONG const controlSize  = sizeof(FILFILE_CONTROL) + data.OneSize + data.TwoSize;
	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		control->Magic	 = FILFILE_CONTROL_MAGIC;
		control->Version = FILFILE_CONTROL_VERSION;
		control->Size	 = controlSize;
		control->Flags	 = FILFILE_CONTROL_HANDLE;
		control->Value1	 = (ULONG_PTR) file;

		// Header is optional
		if(data.One && data.OneSize)
		{
			control->PayloadSize   = data.OneSize;
			control->PayloadOffset = sizeof(FILFILE_CONTROL);

			memcpy((char*) control + control->PayloadOffset, data.One, data.OneSize);
		}

		if(flags & FILFILE_CONTROL_AUTOCONF)
		{
			control->Flags  |= FILFILE_CONTROL_AUTOCONF;
			control->Value2  = deepness;
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			hr		   = S_OK;
			ULONG junk = 0;

			if(!::DeviceIoControl(device, IOCTL_FILFILE_SET_HEADER, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		free(control);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::SetAutoConfigInternal(LPCWSTR path, ULONG deepness, CFilterClientData &data)
{
	// Data layout: One   := Header Payload
	//				Two	  := n/a
	//				Three := n/a

	if(!path)
	{
		return E_INVALIDARG;
	}

	LPWSTR normalized = 0;

	// Normalize path and append AutoConfig name
	HRESULT hr = NormalizePath(path, &normalized, FILFILE_CONTROL_AUTOCONF);

	if(FAILED(hr))
	{
		return hr;
	}

	ULONG flags = FILFILE_CONTROL_AUTOCONF;

	if(data.One && data.OneSize)
	{
		flags |= FILFILE_CONTROL_ADD;
	}

	HANDLE file = INVALID_HANDLE_VALUE;

	for(ULONG loop = 0; loop < 20; ++loop)
	{
		hr = OpenNativeHandleInternal(normalized, &file, flags);

		if(SUCCEEDED(hr) || (hr != HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION)))
		{
			break;
		}

		::Sleep(50);
	}

	// Delete failure of non-existing files is not an error
	if(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr)
	{
		hr = S_FALSE;
	}

	if(S_OK == hr)
	{
		// Write AutoConfig file
		hr = SetHeaderInternal(file, flags, deepness, data);

		::CloseHandle(file);
	}

	free(normalized);

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::ManageEncryption(HANDLE fileHandle, ULONG flags, CFilterClientData &data)
{
	// Data layout: One   := Session Key
	//				Two	  := Header Payload
	//				Three := current Session Key, if Session Key will change

	// check input parameters
	if(!fileHandle || (INVALID_HANDLE_VALUE == fileHandle))
	{
		return E_INVALIDARG;
	}
	// valid Session Key ?
	if(!data.One || !data.OneSize)
	{
		return E_INVALIDARG;
	}
	if(flags & FILFILE_CONTROL_ADD)
	{
		// valid Header ?
		if(!data.Two || !data.TwoSize)
		{
			return E_INVALIDARG;
		}
		// verify max Header size
		if(data.TwoSize > (FILFILE_HEADER_MAX_SIZE - FILFILE_HEADER_META_SIZE))
		{
			return E_INVALIDARG;
		}

		if(flags & FILFILE_CONTROL_REM)
		{
			// valid current Session Key ?
			if(!data.Three || !data.ThreeSize)
			{
				return E_INVALIDARG;
			}
		}
	}

	HRESULT hr = E_OUTOFMEMORY;

	ULONG const controlSize = sizeof(FILFILE_CONTROL) + data.OneSize + data.TwoSize + data.ThreeSize;

	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		ULONG offset = sizeof(FILFILE_CONTROL);

		control->Magic	    = FILFILE_CONTROL_MAGIC;
		control->Version    = FILFILE_CONTROL_VERSION;
		control->Size	    = controlSize;
		control->Flags		= flags | FILFILE_CONTROL_HANDLE;
		control->Value1		= (ULONG_PTR) fileHandle;

		// Session Key
		control->CryptoSize	  = data.OneSize;
		control->CryptoOffset = offset;

		memcpy((char*) control + control->CryptoOffset, data.One, data.OneSize);

		offset += control->CryptoSize;

		if(flags & FILFILE_CONTROL_ADD)
		{
			// Header
			control->PayloadSize   = data.TwoSize;
			control->PayloadOffset = offset;

			memcpy((char*) control + control->PayloadOffset, data.Two, data.TwoSize);

			offset += control->PayloadSize;

			// change Session Key ?
			if(flags & FILFILE_CONTROL_REM)
			{
				// current Session Key
				control->DataSize	= data.ThreeSize;
				control->DataOffset = offset;

				memcpy((UCHAR*) control + control->DataOffset, data.Three, data.ThreeSize);
			}
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			hr		   = S_OK;
			ULONG junk = 0;

			if(!::DeviceIoControl(device, IOCTL_FILFILE_ENCRYPTION, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		memset(control, 0, controlSize);

		free(control);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::PollRequest(LPCWSTR *path, ULONG *cookie, UCHAR **payload, ULONG *payloadSize)
{
	if(!path)
	{
		return E_INVALIDARG;
	}

	HRESULT hr = E_OUTOFMEMORY;

	ULONG const bufferSize  = (cookie) ?  2 * FILFILE_HEADER_MAX_SIZE : FILFILE_BUFFER_SIZE;
	UCHAR *buffer			= (UCHAR*) malloc(bufferSize);

	if(buffer)
	{
		memset(buffer, 0, bufferSize);

		FILFILE_CONTROL control;
		memset(&control, 0, sizeof(control));

		control.Magic	 = FILFILE_CONTROL_MAGIC;
		control.Version  = FILFILE_CONTROL_VERSION;
		control.Size	 = sizeof(FILFILE_CONTROL);
		control.Flags	 = FILFILE_CONTROL_NOTIFY;

		if(cookie)
		{
			control.Flags = FILFILE_CONTROL_AUTOCONF;
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			ULONG outSize = 0;

			// poll REQUEST
			if(::DeviceIoControl(device, IOCTL_FILFILE_CALLBACK_REQUEST, &control, control.Size, buffer, bufferSize, &outSize, 0))
			{
				hr = E_FAIL;

				if(outSize >= sizeof(FILFILE_CONTROL_OUT))
				{
					hr = E_OUTOFMEMORY;

					FILFILE_CONTROL_OUT *const out = (FILFILE_CONTROL_OUT*) buffer;

					LPWSTR denormalized = (LPWSTR) malloc(out->PathSize + sizeof(WCHAR));

					if(denormalized)
					{
						memset(denormalized, 0, out->PathSize + sizeof(WCHAR));

						ULONG bufferOffset = sizeof(FILFILE_CONTROL_OUT);

						wcsncpy(denormalized, (LPWSTR)(buffer + bufferOffset), out->PathSize / sizeof(WCHAR));
						bufferOffset += out->PathSize; 

						// transform kernel device path into UserMode device name
						ULONG len = DenormalizePath(denormalized);

						// if this is our AutoConfig file, cut off its name to get only the directory
						LPWSTR const separator = wcsrchr(denormalized, L'\\');

						if(separator && !_wcsicmp(separator + 1, g_filFileAutoConfigName))
						{
							separator[0] = 0;
						}

						*path = denormalized;

						hr = S_OK;

						if(out->PayloadSize)
						{
							UCHAR *autoConf = (UCHAR*) malloc(out->PayloadSize);

							if(autoConf)
							{	
								// put Payload
								memcpy(autoConf, buffer + bufferOffset, out->PayloadSize);
								bufferOffset += out->PayloadSize;

								if(cookie)
								{
									*cookie = (ULONG) out->Value;
								}

								if(payload && payloadSize)
								{
									*payload	 = autoConf;
									*payloadSize = out->PayloadSize;
								}
								else
								{
									free(autoConf);
								}
							}
							else
							{
								free(denormalized);

								*path = 0;

								hr = E_OUTOFMEMORY;
							}
						}

						if(SUCCEEDED(hr))
						{
							if(out->Flags & FILFILE_CONTROL_NOTIFY)
							{
								hr = (out->Flags & FILFILE_CONTROL_REM) ? S_FALSE : S_OK;
							}
						}
					}
				}
			}

			::CloseHandle(device);
		}

		free(buffer);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::PutResponse(UCHAR *crypto, ULONG cryptoSize, ULONG cookie)
{
	HRESULT hr = E_OUTOFMEMORY;

	ULONG const controlSize  = sizeof(FILFILE_CONTROL) + cryptoSize;
	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		control->Magic	 = FILFILE_CONTROL_MAGIC;
		control->Version = FILFILE_CONTROL_VERSION;
		control->Size	 = sizeof(FILFILE_CONTROL);
		control->Flags	 = FILFILE_CONTROL_NULL;
		control->Value1  = cookie;

		if(crypto && cryptoSize)
		{
			control->CryptoOffset = sizeof(FILFILE_CONTROL);
			control->CryptoSize	  = cryptoSize;

			control->Size += cryptoSize;

			memcpy((UCHAR*) control + control->CryptoOffset, crypto, cryptoSize);

			if(!cookie)
			{
				control->Flags = FILFILE_CONTROL_RANDOM;
			}
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{	
			hr		   = S_OK;
			ULONG junk = 0;

			if(!::DeviceIoControl(device, IOCTL_FILFILE_CALLBACK_RESPONSE, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		memset(control, 0, controlSize);

		free(control);
	}

	return hr;
}


HRESULT CFilterClient::PutResponseHeader(UCHAR *crypto, ULONG cryptoSize)
{
	HRESULT hr = E_OUTOFMEMORY;

	ULONG const controlSize  = sizeof(FILFILE_CONTROL) + cryptoSize;
	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		control->Magic	 = FILFILE_CONTROL_MAGIC;
		control->Version = FILFILE_CONTROL_VERSION;
		control->Size	 = sizeof(FILFILE_CONTROL);
		control->Flags	 = FILFILE_CONTROL_NULL;
		//control->Value1  = cookie;

		if(crypto && cryptoSize)
		{
			control->CryptoOffset = sizeof(FILFILE_CONTROL);
			control->CryptoSize	  = cryptoSize;

			control->Size += cryptoSize;

			memcpy((UCHAR*) control + control->CryptoOffset, crypto, cryptoSize);
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{	
			hr		   = S_OK;
			ULONG junk = 0;

			if(!::DeviceIoControl(device, IOCTL_FILFILE_CALLBACK_RESPONSE_HEADER, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		memset(control, 0, controlSize);

		free(control);
	}

	return hr;
}

HRESULT    CFilterClient::AddCredibleProcess(DWORD pid)
{
	FILFILE_CONTROL control;
	memset(&control, 0, sizeof(control));

	// default is disconnect
	control.Magic	 = FILFILE_CONTROL_MAGIC;
	control.Version  = FILFILE_CONTROL_VERSION;
	control.Size	 = sizeof(FILFILE_CONTROL);
	control.Flags	 = FILFILE_CONTROL_REM;

	// valid handles and corresponding callback funcs specified ?
	if(pid>0)
	{
		// Random requests
		control.Value1 = (ULONG_PTR) pid;
		control.Flags  = FILFILE_CONTROL_ADD;
	}

	HRESULT hr = E_NOINTERFACE;

	HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

	if(INVALID_HANDLE_VALUE != device)
	{
		hr		   = S_OK;
		ULONG junk = 0;

		if(!::DeviceIoControl(device, IOCTL_FILFILE_ADD_CREDIBLE_PROCESS, &control, control.Size, 0,0, &junk, 0))
		{
			hr = HRESULT_FROM_WIN32(::GetLastError());
		}

		::CloseHandle(device);
	}

	return hr;
}


HRESULT CFilterClient::SetControlReadOnly(BOOL bReadOnly)
{
	FILFILE_CONTROL control;
	memset(&control, 0, sizeof(control));

	// default is disconnect
	control.Magic	 = FILFILE_CONTROL_MAGIC;
	control.Version  = FILFILE_CONTROL_VERSION;
	control.Flags  = FILFILE_CONTROL_ADD;
	control.PathLength=(bReadOnly==TRUE?1:0);

	control.Size	 = sizeof(FILFILE_CONTROL)+sizeof(ULONG);

	HRESULT hr = E_NOINTERFACE;

	HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

	if(INVALID_HANDLE_VALUE != device)
	{
		
		hr		   = S_OK;
		ULONG junk = 0;

		if(!::DeviceIoControl(device, IOCTL_FILFILE_SET_READONLY, &control, control.Size, 0,0, &junk, 0))
		{
			hr = HRESULT_FROM_WIN32(::GetLastError());
		}

		::CloseHandle(device);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::Connection(HANDLE random, HANDLE key, HANDLE notify,ULONG ulPid)
{
	FILFILE_CONTROL control;
	memset(&control, 0, sizeof(control));

	// default is disconnect
	control.Magic	 = FILFILE_CONTROL_MAGIC;
	control.Version  = FILFILE_CONTROL_VERSION;
	control.Size	 = sizeof(FILFILE_CONTROL);
	control.Flags	 = FILFILE_CONTROL_REM;

	// valid handles and corresponding callback funcs specified ?
	if(random && s_callbackRequestRandom)
	{
		// Random requests
		control.Value1 = (ULONG_PTR) random;
		control.Flags  = FILFILE_CONTROL_ADD;
	}
	if(key && s_callbackRequestKey)
	{
		// Key requests
		control.Value2 = (ULONG_PTR) key;
		control.Flags  = FILFILE_CONTROL_ADD;
	}
	if(notify && s_callbackNotify)
	{
		// Notification requests
		control.Value3 = (ULONG_PTR) notify;
		control.Flags  = FILFILE_CONTROL_ADD;
	}

	HRESULT hr = E_NOINTERFACE;

	HANDLE device = ::CreateFile(s_deviceName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

	if(INVALID_HANDLE_VALUE != device)
	{
		hr		   = S_OK;
		ULONG junk = 0;

		if(!::DeviceIoControl(device, IOCTL_FILFILE_CALLBACK_CONNECTION, &control, control.Size, 0,0, &junk, 0))
		{
			hr = HRESULT_FROM_WIN32(::GetLastError());
		}

		::CloseHandle(device);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::RegisterCallbacks(void* context, f_requestRandom rand, f_requestKey key, f_notify notify)
{
	// already connected OR disconnecting ?
	if(s_thread)
	{
		WorkerStop();
	}
	else if(!rand && !key && !notify)
	{
		WorkerStop();

		// disconnect anyway, in case the Worker died unexpectedly
		Connection();
	}

	s_callbackRequestKey	= 0;
	s_callbackRequestRandom = 0;
	s_callbackNotify	  	= 0;

	// at least one callback to be registered ?
	if(rand || key || notify)
	{
		s_callbackRequestRandom = rand;
		s_callbackRequestKey	= key;
		s_callbackNotify		= notify;

		// start dispatching Worker
		DWORD id = 0;
		HANDLE thread = ::CreateThread(0,0, WorkerStart, context, 0, &id);

		if(!thread)
		{
			return HRESULT_FROM_WIN32(::GetLastError());
		}

		if(WAIT_TIMEOUT != ::WaitForSingleObject(thread, 200))
		{
			::CloseHandle(thread);

			// couldn't connect to driver
			return E_NOINTERFACE;
		}

		s_thread = thread;
	}

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CFilterClient::Wiper(ULONG flags, int *patterns, int patternsSize, HANDLE file, HANDLE cancel, HANDLE progress)
{
	if(0 == (flags & FILFILE_CONTROL_WIPE_ON_DELETE))
	{
		if(!file || (INVALID_HANDLE_VALUE == file))
		{
			return E_INVALIDARG;
		}
	}

	HRESULT hr = E_OUTOFMEMORY;

	ULONG const controlSize	 = sizeof(FILFILE_CONTROL) + patternsSize;
	FILFILE_CONTROL *control = (FILFILE_CONTROL*) malloc(controlSize);

	if(control)
	{
		memset(control, 0, controlSize);

		control->Magic	    = FILFILE_CONTROL_MAGIC;
		control->Version    = FILFILE_CONTROL_VERSION;
		control->Size	    = controlSize;
		control->Flags		= flags;

		if(0 == (flags & FILFILE_CONTROL_WIPE_ON_DELETE))
		{
			control->Value1	= (ULONG_PTR) file;			// file to be wiped
			control->Value2	= (ULONG_PTR) cancel;		// cancel event,	   optional
			control->Value3	= (ULONG_PTR) progress;		// progress semaphore, optional
		}

		// pattern vector ?
		if(patterns && patternsSize)
		{
			control->PayloadOffset = sizeof(FILFILE_CONTROL);
			control->PayloadSize   = patternsSize;

			memcpy((char*) control + control->PayloadOffset, patterns, patternsSize);
		}

		hr = E_NOINTERFACE;

		HANDLE device = ::CreateFile(s_deviceName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,0);

		if(INVALID_HANDLE_VALUE != device)
		{
			hr		   = S_OK;
			ULONG junk = 0;

			// call driver
			if(!::DeviceIoControl(device, IOCTL_FILFILE_WIPER, control, control->Size, 0,0, &junk, 0))
			{
				hr = HRESULT_FROM_WIN32(::GetLastError());
			}

			::CloseHandle(device);
		}

		free(control);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD __stdcall CFilterClient::WorkerRequestRandom(void* context)
{
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	HRESULT hr = E_UNEXPECTED;

	//UCHAR *prandom=NULL;

	if(s_callbackRequestRandom)
	{
		// call registered function
		UCHAR random[FILFILE_RANDOM_REQUEST_SIZE]={
			0x10,0x6b,0xf4,0xd2,0xaa,0x03,0xbf,0x43,0x15,0xae,0x7d,0xc4,0xca,0x23,0xa9,0x83,0x3d,0xcd,0x11,0x0c,0xfa,0x09,0xcb,0x6f,0x2c,0x34,0xd9,0xd5,0xab,0x8e,0x89,0x8f,0x03,0xdf,0x49,0x8e,0x3b,
			0x0a,0xcc,0xa9,0x86,0x6d,0x22,0x79,0x1a,0xcb,0x18,0x14,0xa4,0x62,0xfe,0x2a,0x80,0xbe,0xa2,0x50,0x78,0xe4,0x5c,0x00,0xe5,0xe5,0x8b,0x72,0x88,0x02,0x67,0x00,0x9e,0x6a,0xb9,0x5b,0x75,0x2d,
			0xbd,0x39,0xa0,0x96,0x1a,0x08,0x96,0x19,0x68,0x4d,0x53,0x38,0x3d,0x79,0xa7,0xe2,0xba,0xfe,0x1c,0x54,0x98,0x56,0xf3,0x2f,0x48,0x12,0xa1,0x53,0x48,0x76,0xaa,0xf1,0x70,0x91,0xf8,0xe0,0xf5,
			0x78,0xf9,0x14,0x9c,0x15,0xf2,0x17,0xbd,0x15,0xf7,0xeb,0x5a,0x7e,0x86,0x6d,0x81,0x4e,0xf5,0xca,0x99,0x89,0xed,0x22,0xd9,0x7b,0x80,0x14,0x7e,0xe4,0xb4,0x84,0x13,0x51,0x0e,0xad,0xc9,0x6f,
			0xb0,0x30,0x8a,0x74,0x8f,0x0e,0xa5,0x89,0xec,0x40,0x4f,0x84,0x51,0x69,0xd6,0xe0,0x42,0xf1,0xd6,0x88,0x87,0x8a,0x94,0xf6,0x65,0xfb,0xca,0xe3,0x98,0x04,0xe4,0x4f,0x9e,0x6a,0x3f,0xdd,0xc0,
			0xef,0xec,0xb3,0x86,0xfa,0x46,0x37,0x3e,0xdf,0x63,0xae,0x49,0xb3,0x36,0x35,0x42,0xaf,0xcc,0xbd,0x05,0xc5,0xc2,0x90,0x28,0x46,0x7b,0xeb,0x46,0x0a,0x53,0x71,0xab,0xd4,0xd9,0xbd,0x20,0x2d,
			0xfe,0x0f,0xab,0xd8,0xd7,0xb2,0xae,0xf6,0xe3,0xbd,0x10,0x16,0x1c,0xc2,0x6c,0xab,0xcd,0x8a,0x8c,0xc2,0x89,0x33,0xfd,0x84,0x4e,0x52,0xb1,0x84,0x54,0xac,0x6c,0x03,0x00,0x0d,0x65,0x83,0xe8,
			0x3f,0x4a,0x9b,0x97,0x99,0x98,0x3c,0x03,0xf5,0xcb,0x5b,0xae,0xcb,0xcc,0x25,0xfc,0xfd,0x76,0xa2,0xbb,0xb2,0x95,0x7b,0x68,0xc9,0xa5,0x4e,0x12,0xd5,0xc7,0xdf,0xaf,0xc0,0x49,0x61,0x33,0x6f,
			0x1a,0xe0,0x91,0xc9,0xda,0x4e,0xce,0x8c,0x86,0xd3,0x01,0x16,0x4f,0x3b,0xba,0x68,0x09,0x8f,0x68,0x50,0xd4,0x00,0x23,0x83,0xd8,0x2a,0x44,0x40,0x0c,0xc3,0x24,0x76,0x98,0x5e,0x99,0xc7,0xd7,
			0xec,0x41,0x63,0xfc,0x58,0x76,0xf9,0x1f,0xf4,0x86,0x90,0xfa,0x23,0x41,0x02,0x78,0x54,0xd5,0x91,0x90,0xcd,0xa8,0x7d,0xf0,0xe6,0xc2,0xf6,0x1e,0x3c,0x3e,0x95,0xa3,0xaa,0x4c,0x84,0x8a,0xdc,
			0xd3,0x3c,0x61,0x9a,0x12,0x2f,0x93,0xe8,0x30,0xbb,0xed,0x42,0xcc,0xed,0x00,0xf1,0x15,0x8d,0xc7,0x24,0x7b,0x92,0x7e,0x90,0xcc,0xb2,0xa3,0x5b,0xdc,0x65,0x41,0x1a,0xb9,0x6e,0xd3,0x6a,0x26,
			0xfc,0xeb,0x2a,0x06,0xdd,0xdd,0x78,0x66,0xaa,0x8b,0xd8,0xa4,0xba,0xe6,0xa9,0x80,0x93,0x8e,0xbf,0x60,0x25,0xab,0xe6,0x93,0x08,0xc5,0x72,0x34,0x4d,0xca,0x38,0x73,0x6f,0x4a,0x27,0x44,0xd5,
			0x22,0x5c,0x69,0xdb,0x7a,0xdc,0x54,0x26,0xd7,0x25,0x36,0x95,0x2d,0xff,0xfd,0xa5,0x31,0x9a,0x3c,0xa2,0xc4,0x9f,0xef,0xe2,0x0c,0x07,0x9b,0xfd,0x39,0x74,0x3b,0xaf,0x36,0xae,0xed,0x4c,0x2b,
			0x4e,0x40,0x6c,0xe8,0x4d,0xdd,0x7e,0xff,0x08,0x6c,0x1a,0xe7,0x0b,0x05,0xab,0xc1,0xd0,0xda,0xa1,0xe5,0xb5,0xd9,0x42,0x0d,0x54,0x22,0xf7,0x30,0xe1,0x7f,0x2e,0x6c,0x65,0x8a,0x2e,0xa1,0x17,
			0xe2,0x48,0x45,0xeb,0x1b,0x9e,0x8b,0x69,0xc9,0x81,0xe7,0x5b,0xa7,0x18,0xd4,0x50,0x33,0xdc,0x4b,0xd0,0xda,0x4d,0x03,0x58,0xf0,0x9f,0x17,0x15,0xfe,0xc5,0x8d,0x09,0x11,0x71,0x93,0xa6,0x31,
			0x08,0xb7,0xe8,0x3d,0x6d,0xc7,0x8e,0xc9,0x8d,0xb3,0xc2,0x81,0x41,0xca,0xb3,0x39,0x88,0x96,0x7e,0xd4,0xbb,0x70,0xfa,0x8d,0x53,0xf2,0xab,0x44,0xc8,0x32,0x7e,0x98,0x25,0xfa,0xb5,0x1a,0xb1,
			0x62,0xb3,0xc5,0x59,0xf7,0x54,0xe4,0x46,0x9a,0xe0,0x75,0xc7,0x37,0xd4,0x32,0x94,0x5b,0x4d,0x06,0x4d,0xbc,0x92,0x34,0xe2,0x8d,0x0d,0xf2,0x2f,0x6c,0x9c,0xd9,0x83,0x92,0x4d,0x10,0x64,0x61,
			0xcb,0xfc,0xb9,0x35,0xad,0x82,0xfa,0xb9,0xd4,0x9a,0xcf,0x52,0x26,0xc6,0x9b,0xa7,0x84,0x85,0x78,0xaa,0x22,0x91,0xf7,0xc3,0x5d,0xe3,0x7a,0x38,0x8f,0xd5,0x5d,0xf5,0x86,0x16,0xf8,0xad,0x01,
			0x8b,0x72,0xdc,0x01,0x17,0x72,0xf0,0x17,0xca,0x67,0x2b,0x60,0xf2,0x8a,0x63,0x7e,0xf7,0x3d,0x33,0x83,0xc8,0x25,0x1b,0x59,0xd9,0x78,0x82,0x60,0x17,0x4b,0x9e,0x3d,0x0d,0x0d,0x4b,0x0d,0xdb,
			0xc8,0x36,0x5c,0xc2,0xaf,0xd9,0x4d,0x0b,0x3f,0x8b,0x05,0x03,0x55,0x93,0x6d,0xb3,0x45,0x63,0xc5,0x91,0x26,0x1e,0xd1,0x9f,0xd0,0x44,0xf2,0xc3,0x9b,0x47,0xd3,0x96,0x4e,0x1a,0x66,0xa1,0xa5,
			0x0e,0x8c,0xb4,0x62,0xa1,0x11,0x65,0x54,0x92,0xb5,0x70,0x2a,0x71,0xe8,0x51,0x82,0xc4,0x11,0x84,0xc9,0x9c,0xc0,0xfd,0x19,0x10,0x90,0x73,0x3f,0x6e,0x6a,0x3d,0xde,0xb9,0x40,0x33,0x81,0x6f,
			0x6d,0xbd,0x19,0x16,0x11,0x57,0x62,0xdc,0xc5,0xcb,0x35,0xff,0x0a,0xa0,0x1c,0xd8,0x6a,0x54,0xe3,0xc5,0x9c,0x53,0xf1,0xa9,0x4e,0x5a,0xa4,0x19,0xfd,0xee,0xda,0x9a,0x5d,0x2d,0xcd,0xb6,0x65,
			0x16,0xa2,0xb6,0x2f,0x49,0x34,0x25,0x11,0x05,0x8e,0x73,0x74,0x18,0x7b,0xb7,0xa5,0x55,0xe1,0xc4,0xfc,0x74,0x26,0x5c,0x1d,0x76,0x36,0x8e,0x1f,0xf0,0x22,0x22,0xf6,0xfa,0x79,0x83,0x27,0x64,
			0x8a,0xe3,0xc4,0xc5,0x2d,0xa0,0x14,0x64,0xf2,0x5f,0x0d,0xdc,0xc6,0xc0,0x17,0x58,0xe9,0x10,0x8c,0xd0,0xfb,0x7d,0xa8,0x84,0x7e,0xea,0x43,0xa8,0x8f,0x41,0x81,0xa7,0x27,0xd7,0xfc,0x01,0x91,
			0x8b,0x2e,0xbe,0x26,0xad,0x7e,0xe8,0x0f,0xf6,0xe8,0x6a,0xb2,0x5f,0x06,0x68,0xb2,0x2d,0x1d,0x08,0x9c,0xec,0xb5,0xeb,0x26,0x98,0x41,0x7a,0xc7,0x71,0xce,0xdd,0x87,0x60,0x9a,0xbb,0x92,0x30,
			0x2f,0xa6,0xac,0xd5,0xe2,0xe2,0x85,0xbe,0xca,0x2c,0x73,0x7e,0xa8,0x3b,0x1f,0xe9,0xc9,0x7f,0x5b,0xed,0x5a,0x37,0xd6,0x2f,0x26,0x9b,0x71,0x6c,0x8f,0xad,0x4a,0x0a,0x5f,0x3a,0xdc,0x00,0x4a,
			0x6c,0x8c,0x8d,0x55,0x63,0x7d,0xcf,0x3e,0x48,0xd9,0x85,0x63,0xfa,0x7a,0x66,0x0b,0x5e,0xb4,0x06,0xc3,0x2c,0xce,0x77,0x11,0x77,0x1b,0xe7,0x37,0x9d,0xa0,0xa9,0x2f,0x39,0xb0,0x29,0x7c,0xe1,
			0xd1,0x81,0xee,0x25,0x24,0x3c,0x1e,0x22,0x68,0x36,0x35,0x44,0xf4,0x37,0x7e,0x5f,0xbc,0x66,0x9d,0x2e,0x13,0x60,0x96,0xd9,0x16
		};

		hr = s_callbackRequestRandom(context, random, sizeof(random));

		if(SUCCEEDED(hr))
		{
			// give random data to driver
			hr = PutResponse(random, sizeof(random));
		}
		else
		{
			// cancel request
			PutResponse(0,0);
		}

		memset(random, 0, sizeof(random));
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD __stdcall CFilterClient::WorkerRequestNotify(void* context)
{
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	HRESULT hr = E_UNEXPECTED;

	// Notification event:
	UCHAR* path = NULL;
	ULONG Size=0;
	
	if(s_callbackNotify)
	{
			// call registered function
		hr=s_callbackNotify(context, &path,&Size);
	}

	if(SUCCEEDED(hr))
	{
		hr = PutResponseHeader(path,Size);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD __stdcall CFilterClient::WorkerRequestKey(void* context)
{
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	LPCWSTR path      = 0;
	ULONG cookie      = 0;
	UCHAR *payload	  = 0;
	ULONG payloadSize = 0;

	// retrieve key request parameters from driver
	HRESULT hr = PollRequest(&path, &cookie, &payload, &payloadSize);

	if(SUCCEEDED(hr))
	{
		hr = E_UNEXPECTED;

		if(s_callbackRequestKey)
		{
			UCHAR key[32]={0xc6,0x45,0x48,0x4e,0x36,0x47,0xb9,0xc7,0x4d,0xe9,0xad,0xc3,0x77,0x10,0x44,0x80,
				           0x9c,0x07,0xed,0x31,0xc3,0x0f,0xf1,0xc9,0x1c,0xf5,0x26,0xe2,0x71,0x2e,0x0c,0xb4};
			ULONG keySize = sizeof(key);

			// call registered function
			hr = s_callbackRequestKey(context, key, &keySize, path, payload, payloadSize);

			if(SUCCEEDED(hr))
			{
				// give retrieved key to driver
				hr = PutResponse(key, keySize, cookie);
			}
			else
			{
				// cancel request
				PutResponse(0,0, cookie);
			}

			memset(key, 0, sizeof(key));
		}

		free(payload);
		free((void*) path);
	}

	return hr;
}



DWORD CFilterClient::GetParentProcessPid(DWORD uProcessID)
{
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// 找不到的话，默认进程名为“???”
	//lstrcpy(ProcessName, L"???");
	if(!::Process32First(hProcessSnap, &processEntry))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}
	do 
	{
		if(uProcessID==processEntry.th32ProcessID)
		{
			CloseHandle(hProcessSnap);
			return processEntry.th32ParentProcessID;
		}
	}
	while(::Process32Next(hProcessSnap, &processEntry));

	CloseHandle(hProcessSnap);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD __stdcall CFilterClient::WorkerStart(void* context)
{
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	HANDLE events[4];

	// create events
	events[0] = ::CreateEvent(0, true, false, s_workerStopName);// Stop
	events[1] = ::CreateEvent(0, true, false, 0);				// Random request
	events[2] = ::CreateEvent(0, true, false, 0);				// Key request
	events[3] = ::CreateEvent(0, true, false, 0);				// Notifications

	if(!events[0] || !events[1] || !events[2] || !events[3])
	{
		return HRESULT_FROM_WIN32(::GetLastError());
	}


	HRESULT hr = Connection(events[1], events[2], events[3]);

	if(SUCCEEDED(hr))
	{
		for(;;)
		{
#ifdef FILFILE_UNIT_TEST
			wprintf(L"\nWorker: waiting ...");
#endif

			ULONG const wait = ::WaitForMultipleObjects(4, events, false, INFINITE);

			// stop or error ?
			if((wait == WAIT_OBJECT_0) || (wait == WAIT_FAILED))
			{
				break;
			}

			DWORD id	  = 0;
			HANDLE thread = 0;

			if(wait == WAIT_OBJECT_0 + 1)
			{
				// Random request:
				if(s_callbackRequestRandom)
				{
					// create dedicated thread to handle this
					thread = ::CreateThread(0,0, WorkerRequestRandom, context, 0, &id);
				}

				::ResetEvent(events[1]);
			}
			else if(wait == WAIT_OBJECT_0 + 2)
			{
				// Key request:
				if(s_callbackRequestKey)
				{
					// create dedicated thread to handle this
					thread = ::CreateThread(0,0, WorkerRequestKey, context, 0, &id);
				}

				::ResetEvent(events[2]);
			}
			else //if(wait == WAIT_OBJECT_0 + 3)
			{
				// Notification:	
				if(s_callbackNotify)
				{
					// create dedicated thread to handle this
					thread = ::CreateThread(0,0, WorkerRequestNotify, context, 0, &id);
				}

				::ResetEvent(events[3]);
			}

			if(thread)
			{
				::CloseHandle(thread);
			}
		}

		// disconnect
		Connection();
	}

	::CloseHandle(events[3]);
	::CloseHandle(events[2]);
	::CloseHandle(events[1]);
	::CloseHandle(events[0]);

	if(s_thread)
	{
		::CloseHandle(s_thread);
		s_thread = 0;
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CFilterClient::WorkerStop()
{
	// use named event to be able stopping the Worker from within different processes
	HANDLE event = ::CreateEvent(0, true, false, s_workerStopName);

	if(event)
	{
		ULONG win32Error = ::GetLastError();

		// connected to existing event ?
		if(ERROR_ALREADY_EXISTS == win32Error)
		{
			win32Error = NO_ERROR;

			::SetEvent(event);

			if(s_thread)
			{
				// if within same process, wait for thread termination
				::WaitForSingleObject(s_thread, INFINITE);
			}
		}
		else
		{
			win32Error = ERROR_FILE_NOT_FOUND;
		}

		::CloseHandle(event);

		return HRESULT_FROM_WIN32(win32Error);
	}

	return HRESULT_FROM_WIN32(::GetLastError());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
