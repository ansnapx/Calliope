////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CDfsResolver.h: interface for the CDfsResolver class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CDfsResolver_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CDfsResolver_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CDfsResolver  
{
	// Cache resolved DFS names, use aged positive/negative cache entries

	enum constants
	{
		c_increment		= 4,
		c_timeout		= 300,	// 300 sec, timeout used for negative entries
		c_bufferSize	= 512,
	};

	struct CDfsResolverEntry
	{
		HRESULT		Init(LPCWSTR unc, ULONG uncLen, ULONG uncValid, LPCWSTR server, LPCWSTR share, ULONG timeout);
		void		Close();	

		LPWSTR		m_unc;		
		ULONG		m_uncLen;
		ULONG		m_uncValid;

		LPWSTR		m_resolved;
		ULONG		m_resolvedLen;
		ULONG		m_tick;
	};

public:
								CDfsResolver() : m_map(0), m_count(0), m_capacity(0)
								{ ::InitializeCriticalSection(&m_lock); }
								~CDfsResolver();

	HRESULT						Resolve(LPCWSTR path, LPWSTR *resolved);
	HRESULT						ResolvePath(LPCWSTR path, ULONG pathLen, LPWSTR *resolved);
	HRESULT						ResolveDrive(LPCWSTR path, ULONG pathLen, LPWSTR *resolved);
	ULONG						ResolveDevice(LPWSTR device, ULONG deviceLen, LPCWSTR drive);
	
private:
	
	HRESULT						FindTarget(LPWSTR unc, ULONG uncLen, ULONG *cachePos = 0);
	HRESULT						ResolveTarget(LPWSTR path, ULONG pathLen);
	ULONG						ResolveDFSTarget(LPWSTR target, LPWSTR device, ULONG deviceLen, ULONG depth = 0);

	void						CacheValidate();
	ULONG						CacheLookup(LPCWSTR unc, ULONG uncLen);
	ULONG						CacheAdd(LPCWSTR unc, ULONG uncLen, ULONG uncValid = 0,
										 ULONG timeout = c_timeout, 
										 LPCWSTR server = 0, LPCWSTR share = 0);
	
								// DATA
	CDfsResolverEntry*			m_map;
	ULONG						m_count;
	ULONG						m_capacity;

	CRITICAL_SECTION			m_lock;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CDfsResolver_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
