////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CDfsResolver.cpp: implementation of the CDfsResolver class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include <windows.h>
#include <wchar.h>
#include <assert.h>

#include <lm.h>
#include <lmdfs.h>

#pragma warning(disable: 4267) // "conversion from 'size_t' to 'ULONG', possible loss of data"
#pragma warning(disable: 4996) // "This function or variable may be unsafe..."

#include "CDfsResolver.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CDfsResolver::CDfsResolverEntry::Init(LPCWSTR unc, ULONG uncLen, ULONG uncValid, LPCWSTR server, LPCWSTR share, ULONG timeout)
{
	assert(unc);
	assert(uncLen);

	assert(uncLen >= uncValid);

	memset(this, 0, sizeof(*this));

	m_unc = (LPWSTR) malloc((uncLen + 1) * sizeof(WCHAR));

	if(!m_unc)
	{
		return E_OUTOFMEMORY;
	}

	wcsncpy(m_unc, unc, uncLen);

	// Terminate
	m_unc[uncLen] = UNICODE_NULL;

	m_uncLen	= uncLen;
	m_uncValid  = (uncValid) ? uncValid : uncLen;

	if(server && share)
	{
		uncLen = wcslen(server) + wcslen(share) + 3 + 1;

		m_resolved = (LPWSTR) malloc(uncLen * sizeof(WCHAR));

		if(!m_resolved)
		{
			free(m_unc);

			m_unc	 = 0;
			m_uncLen = 0;
			uncValid = 0;

			return E_OUTOFMEMORY;
		}

		m_resolvedLen = swprintf(m_resolved, L"\\\\%s\\%s", server, share);
	}

	ULONG const tick = ::GetTickCount();

	m_tick = tick + (timeout * 1000);

	// Wraped?
	if(m_tick < tick)
	{
		m_tick = ~0u;
	}

	return S_OK;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
void CDfsResolver::CDfsResolverEntry::Close()
{
	if(m_unc)
	{
		free(m_unc);
	}

	if(m_resolved)
	{
		free(m_resolved);
	}

	memset(this, 0, sizeof(*this));
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

CDfsResolver::~CDfsResolver()
{
	if(m_map)
	{
		for(ULONG index = 0; index < m_count; ++index)
		{
			m_map[index].Close();
		}

		free(m_map);
		m_map = 0;
	}

	m_count	   = 0;
	m_capacity = 0;

	::DeleteCriticalSection(&m_lock);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CDfsResolver::CacheValidate()
{
	if(m_count)
	{
		ULONG const tick = ::GetTickCount();

		for(LONG index = m_count - 1; index >= 0; --index)
		{	
			if(tick > m_map[index].m_tick)
			{
				m_map[index].Close();

				m_count--;

				if((ULONG) index < m_count)
				{
					memmove(m_map + index, 
							m_map + index + 1, 
							(m_count - index) * sizeof(CDfsResolverEntry));
				}

				memset(m_map + m_count, 0, sizeof(CDfsResolverEntry));
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CDfsResolver::CacheAdd(LPCWSTR unc, ULONG uncLen, ULONG uncValid, ULONG timeout, LPCWSTR server, LPCWSTR share)
{
	assert(unc);
	assert(uncLen);
	assert(timeout);

	assert(m_capacity >= m_count);

	// Cache buffer to be extended?
	if(m_count == m_capacity)
	{
		ULONG const capacity = m_capacity + c_increment;

		CDfsResolverEntry *const map = (CDfsResolverEntry*) malloc(capacity * sizeof(CDfsResolverEntry));

		if(!map)
		{
			return ~0u;
		}

		m_capacity = capacity;

		memset(map, 0, capacity * sizeof(CDfsResolverEntry));

		if(m_map)
		{
			memcpy(map, m_map, m_count * sizeof(CDfsResolverEntry));

			free(m_map);
		}

		m_map = map;
	}

	if(FAILED(m_map[m_count].Init(unc, uncLen, uncValid, server, share, timeout)))
	{
		return ~0u;
	}

	return m_count++;
}	

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CDfsResolver::CacheLookup(LPCWSTR unc, ULONG uncLen)
{
	assert(unc);
	assert(uncLen);

	if(m_count)
	{
		// Search in already resolved paths
		for(ULONG index = 0; index < m_count; ++index)
		{
			if(m_map[index].m_uncLen == uncLen)
			{
				if(!_wcsnicmp(m_map[index].m_unc, unc, uncLen))
				{
					return index;
				}
			}
		}	
	}

	return ~0u;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CDfsResolver::ResolveDFSTarget(LPWSTR target, LPWSTR device, ULONG deviceLen, ULONG depth)
{
	assert(target);
	assert(device);

	// Max recursion depth reached?
	if(depth > 1)
	{
		return ERROR_NO_MORE_FILES;
	}

	ULONG targetLen = wcslen(target);

	if(!targetLen)
	{
	   return ERROR_INVALID_PARAMETER;
	}

	// Ensure trailing backslash
	if(target[targetLen - 1] != L'\\')
	{
		target[targetLen] = L'\\';

		targetLen++;

		target[targetLen] = UNICODE_NULL;
	}

	target[targetLen]	  = L'*';
	target[targetLen + 1] = UNICODE_NULL;

	WIN32_FIND_DATA findData;
	memset(&findData, 0, sizeof(findData));
		
	HANDLE const find = ::FindFirstFile(target, &findData);

	if(INVALID_HANDLE_VALUE == find)
	{
		return ::GetLastError();
	}

	ULONG err = ERROR_PATH_NOT_FOUND;

	// Loop through directories and try to match with valid DFS targets
	do
	{
		if( !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))		
		{
			// Files cannot be DFS Links
			continue;
		}

		// Filter out "." and ".."
		if(findData.cFileName[0] == L'.')
		{
			if(!findData.cFileName[1])
			{
				continue;
			}
			if((findData.cFileName[1] == L'.') && !findData.cFileName[2])
			{
				continue;
			}
		}

		ULONG const pathLen = targetLen + wcslen(findData.cFileName);

		// Check our bounds
		if(pathLen >= c_bufferSize / sizeof(WCHAR))
		{
			assert(false);
			continue;
		}

		wcscpy(target + targetLen, findData.cFileName);

		ULONG pos = ~0u;

		// Try to resolve target server/share
		if(S_OK == FindTarget(target, pathLen, &pos))
		{
			assert(pos < m_count);
			assert(m_map[pos].m_resolved);
			assert(m_map[pos].m_resolvedLen);

			// Does it match with given server/share?
			if(!wcsnicmp(device + 24, 
						 m_map[pos].m_resolved + 1, 
						 m_map[pos].m_resolvedLen - 1))
			{	

				// Default to simple link
				LPWSTR start = target + targetLen - 1;

				// Deep link?				
				if(depth)
				{
					// Find its start
					LPWSTR const link = wcsrchr(target, L'\\');
					assert(link);

					link[0] = UNICODE_NULL;

					start = wcsrchr(target, L'\\');
					assert(start);

					link[0] = L'\\';
				}

				// Copy link
				wcscpy(device + 2, start);

				// Estimate start of path components
				start = device + 24 + m_map[pos].m_resolvedLen - 1;

				// Move path components to final position
				memmove(device + wcslen(device),
						start, 
						((device + deviceLen) - start + 1) * sizeof(WCHAR));

				err = NO_ERROR;

				break;
			}
			else
			{
				WCHAR targetNext[c_bufferSize + 2] = {0};

				wcscpy(targetNext, target);

				// Target already queried?
				if(wcsnicmp(target, m_map[pos].m_resolved, m_map[pos].m_resolvedLen))
				{
					assert(c_bufferSize >= m_map[pos].m_resolvedLen);
					// Take next level
					wcscpy(targetNext, m_map[pos].m_resolved);
				}

				// Recursive call
				err = ResolveDFSTarget(targetNext, device, deviceLen, depth + 1);

				// Matched?
				if(NO_ERROR == err)
				{
					break;
				}
			}
		}
	}
	while(::FindNextFile(find, &findData));

	::FindClose(find);

	return err;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG CDfsResolver::ResolveDevice(LPWSTR device, ULONG deviceLen, LPCWSTR drive)
{
	assert(device);
	assert(deviceLen);
	assert(drive);

	// Ensure normalized device syntax
	assert(!wcsnicmp(device, L"\\Device\\LanmanRedirector\\", 25));

	WCHAR target[c_bufferSize + 2] = {0};
	ULONG targetLen  = c_bufferSize / sizeof(WCHAR);

	// Get target drive is connected to
	ULONG err = ::WNetGetConnection(drive, target, &targetLen);

	if(NO_ERROR != err)
	{
		return 0;
	}

	targetLen = wcslen(target);

	// Check the share entirely
	target[targetLen]	  = L'\\';
	target[targetLen + 1] = UNICODE_NULL;

	// Check for directory directly within DFS Root
	if(!wcsnicmp(target + 1, device + 24, targetLen))
	{
		// Substitute device prefix and server/share with drive letter
		device[0] = drive[0];
		device[1] = drive[1];

		memmove(device + 2,
				device + 24 + targetLen - 1, 
				(deviceLen - (24 + targetLen - 2)) * sizeof(WCHAR));

		return wcslen(device);
	}

	::EnterCriticalSection(&m_lock);

	// See whether this url belongs to DFS namespace, involve our cache
	if(S_OK != FindTarget(target, targetLen))
	{
		::LeaveCriticalSection(&m_lock);

		return 0;
	}

	// The target belongs to the DFS namespace so try to find a way to it.
	// This is a bit tricky as there are no back pointers and we cannot call the 
	// DFS APIs due to interop issues (NetAPP). So we try to match the first
	// valid path from the given drive to the target that works. Note that this 
	// can be ambiguous when multiple links point to the same target...

	err = ResolveDFSTarget(target, device, deviceLen);

	::LeaveCriticalSection(&m_lock);

	if(NO_ERROR != err)
	{
		return 0;
	}

	// Copy drive letter
	device[0] = drive[0];
	device[1] = drive[1];

	return wcslen(device);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CDfsResolver::FindTarget(LPWSTR unc, ULONG uncLen, ULONG *cachePos)
{
	assert(unc);
	assert(uncLen);
	
	// First look up path in cache
	ULONG pos = CacheLookup(unc, uncLen);

	if(pos != ~0u)
	{
		assert(pos < m_count);

		if(cachePos)
		{
			*cachePos = pos;
		}

		// Positive entry?
		return (m_map[pos].m_resolved) ? S_OK : S_FALSE;
	}

	HRESULT hr = S_OK;
	ULONG err  = ERROR_SUCCESS;

	// Ping target so that it is in the System's DFS cache we are going to query. 
	// This also ensures that we use the same target as other local components 
	// in fault-tolerant and/or load-balanced scenarios.
	ULONG const attr = ::GetFileAttributes(unc);

	if(attr == INVALID_FILE_ATTRIBUTES)
	{
		err = ::GetLastError();		

		// Skip DFS API if path is invalid
		if(err != ERROR_BAD_NET_NAME)
		{
			err = ERROR_SUCCESS;
		}
	}

	if(ERROR_SUCCESS == err)
	{
		DFS_INFO_4 *dfsInfo = 0;

		// Have DFS link resolved. Use client-only API to avoid issues with DFS implementations
		// that do not fully support the MSFT DFS APIs. NetApp is one of those...
		err = ::NetDfsGetClientInfo(unc, 0,0,4, (unsigned char**) &dfsInfo);

		if(ERROR_SUCCESS == err)
		{
			// Default is first entry
			LPCWSTR const entry = dfsInfo->EntryPath;

			LPCWSTR server = dfsInfo->Storage->ServerName;
			LPCWSTR share  = dfsInfo->Storage->ShareName;

			// Note: The returned Volume state is always DFS_VOLUME_STATE_INCONSISTENT, 
			// so we ignore them here

			// If more than one target were returned,
			if(dfsInfo->NumberOfStorages > 1)
			{
				// look for first target that is online and/or active
				for(ULONG index = 0; index < dfsInfo->NumberOfStorages; ++index)
				{
					if(dfsInfo->Storage[index].State & (DFS_STORAGE_STATE_ONLINE | DFS_STORAGE_STATE_ACTIVE))
					{
						server = dfsInfo->Storage[index].ServerName;
						share  = dfsInfo->Storage[index].ShareName;

						break;
					}
				}
			}

			hr = E_OUTOFMEMORY;

			ULONG const entryLen = wcslen(entry);

			assert(entryLen + 1 <= uncLen);
			assert(!wcsnicmp(unc + 1, entry, entryLen));

			// Add positive entry to cache
			pos = CacheAdd(unc, uncLen, entryLen + 1, dfsInfo->Timeout, server, share);

			if(pos != ~0u)
			{
				if(cachePos)
				{
					*cachePos = pos;
				}

				hr = S_OK;
			}

			::NetApiBufferFree(dfsInfo);
		}
	}

	if(ERROR_SUCCESS != err)
	{
		hr = S_FALSE;

		// Add negative entry to cache
		if(~0u == CacheAdd(unc, uncLen))
		{
			hr = E_OUTOFMEMORY;
		}
	}

	return hr;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CDfsResolver::ResolveTarget(LPWSTR path, ULONG pathLen)
{
	assert(path);
	assert(pathLen);

	ULONG backs = 0;

	// Count number of backslashes
	for(ULONG index = 0; index < pathLen; ++index)
	{
		if(path[index] == L'\\')
		{
			backs++;
		}
	}

	if(backs < 4)
	{
		// Invalid DFS path. Probably a simple UNC path
		return S_FALSE;
	}

	// Serialize cache access and all calls to the DFS API
	::EnterCriticalSection(&m_lock);

	// Discard outdated cache entries
	CacheValidate();

	ULONG cachePos = ~0u;

	// Check if first component is a valid DFS namespace component
	HRESULT hr = FindTarget(path, pathLen, &cachePos);

	if(S_OK == hr)
	{
		assert(cachePos != ~0u);
		assert(cachePos < m_count);

		for(;;)
		{
			CDfsResolverEntry const*const entry = m_map + cachePos;

			assert(pathLen == entry->m_uncLen);
			assert(pathLen >= entry->m_uncValid);

			// Substitute DFS link by its target
			LONG const delta = entry->m_uncValid - entry->m_resolvedLen;

			if(delta)
			{
				memmove(path + entry->m_resolvedLen, 
						path + entry->m_uncValid, 
						(pathLen - entry->m_uncValid + 1) * sizeof(WCHAR));

				pathLen -= delta;
			}
			else
			{
				// DFS Root itself?
				if(!wcsnicmp(entry->m_resolved, entry->m_unc, entry->m_uncValid))
				{
					break;
				}
			}

			wcsncpy(path, entry->m_resolved, entry->m_resolvedLen);

			// Resolve substituted path again
			hr = FindTarget(path, pathLen, &cachePos);

			// Error or end of DFS chain?
			if(S_OK != hr)
			{
				break;
			}
		}	
	}

	::LeaveCriticalSection(&m_lock);

	return hr;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT	CDfsResolver::Resolve(LPCWSTR path, LPWSTR *resolved)
{
	if(!path || !resolved)
	{
		return E_INVALIDARG;
	}

	ULONG const pathLen = wcslen(path);

	if(pathLen < 3)
	{
		return E_INVALIDARG;
	}

	// Check for drive letter syntax
	if(path[1] == L':')
	{
		return ResolveDrive(path, pathLen, resolved);
	}

	return ResolvePath(path, pathLen, resolved);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CDfsResolver::ResolvePath(LPCWSTR path, ULONG pathLen, LPWSTR *resolved)
{
	if(!path || !resolved)
	{
		return E_INVALIDARG;
	}

	if(!pathLen)
	{
		pathLen = wcslen(path);
	}

	// Check pre-conditions
	if(pathLen < 5)
	{
		return E_INVALIDARG;
	}
	if((path[0] != L'\\') || (path[1] != L'\\'))
	{
		return E_INVALIDARG;
	}

	// Skip trailing backslash, if any
	bool const trailingBack = path[pathLen - 1] == L'\\';
	
	if(trailingBack)
	{
		pathLen--;
	}

	ULONG backs = 0;

	// Count number of backslashes
	for(ULONG index = 0; index < pathLen; ++index)
	{
		if(path[index] == L'\\')
		{
			backs++;
		}
	}

	if(backs < 4)
	{
		// Invalid DFS path. Probably a simple UNC path
		return E_UNEXPECTED;
	}

	// Estimate max buffer size needed
	ULONG const bufferSize = (pathLen + (backs * 256)) * sizeof(WCHAR);

	// Operate on local copy
	LPWSTR buffer = (LPWSTR) malloc(bufferSize);

	if(!buffer)
	{
		return E_OUTOFMEMORY;
	}

	memset(buffer, 0, bufferSize);

	wcsncpy(buffer, path, pathLen);

	HRESULT hr = ResolveTarget(buffer, pathLen);

	if(SUCCEEDED(hr))
	{
		if(trailingBack)
		{
			// Preserve trailing backslash in result
			wcscat(buffer, L"\\");
		}

		*resolved = buffer;
	}
	else
	{
		free(buffer);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT CDfsResolver::ResolveDrive(LPCWSTR path, ULONG pathLen, LPWSTR *resolved)
{
	if(!path || !resolved)
	{
		return E_INVALIDARG;
	}

	if(!pathLen)
	{
		pathLen = wcslen(path);
	}

	if(pathLen < 3)
	{
		return E_INVALIDARG;
	}

	ULONG uncSize = pathLen * sizeof(WCHAR) + 4 * 256;
	LPWSTR unc    = (LPWSTR) malloc(uncSize);

	if(!unc)
	{
		return E_OUTOFMEMORY;
	}

	memset(unc, 0, uncSize);

	uncSize /= sizeof(WCHAR);

	WCHAR const drive[3] = {path[0], L':', UNICODE_NULL};

	// Get target given drive is connected to
	ULONG const err = ::WNetGetConnection(drive, unc, &uncSize);

	if(NO_ERROR != err)
	{
		free(unc);

		return HRESULT_FROM_WIN32(err);
	}

	if(pathLen > 3)
	{
		// Build full path, but use target instead of drive letter
		wcscpy(unc + wcslen(unc), path + 2);
	}

	pathLen = wcslen(unc);

	// Have path resolver deal with it
	HRESULT hr = ResolveTarget(unc, pathLen);

	if(SUCCEEDED(hr))
	{
		*resolved = unc;
	}
	else
	{
		free(unc);
	}

	return hr;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
