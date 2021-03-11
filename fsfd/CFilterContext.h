////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterContext.h: interface for the CFilterContext class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterContext__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
#define AFX_CFilterContext__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CFilterBase.h"
#include "CFilterFile.h"
#include "CFilterDirectory.h"
#include "CFilterHeader.h"
#include "CFilterTracker.h"
#include "CFilterRandomizer.h"
#include "CFilterAppList.h"
#include "CFilterBlackList.h"

#ifdef FILFILE_USE_CTR
#include "CFilterCipherCTR.h"
#elif defined(FILFILE_USE_CFB)
#include "CFilterCipherCFB.h"
#elif defined(FILFILE_USE_EME)
#include "CFilterCipherEME.h"
#endif

class CFilterPath;

////////////////////////////////////

class CFilterContext  
{
	friend class CFilterVolume;

public:

	enum c_constants
	{
		// The block size depends on the cipher block mode used:
		#ifdef FILFILE_USE_CTR
		 c_cipherMode	= FILFILE_CIPHER_MODE_CTR,
		 c_blockSize	= CFilterCipherCTR::c_blockSize,
		 c_tail			= 0,
		#elif defined(FILFILE_USE_CFB)
		 c_cipherMode	= FILFILE_CIPHER_MODE_CFB,
		 c_blockSize	= CFilterCipherCFB::c_blockSize,
		 c_tail			= c_blockSize,
		#elif defined(FILFILE_USE_EME)
		 c_cipherMode	= FILFILE_CIPHER_MODE_EME,
		 c_blockSize	= CFilterCipherEME::c_blockSize,
		 c_tail			= c_blockSize,
        #endif
		
		c_lookAsideSize		= 256 - 4, // bytes
		c_ignoresIncrement  = 8,
	};

	NTSTATUS					Init();
	NTSTATUS					InitDeferred(LPCWSTR regPath = 0);
	void						Close();

	CFilterHeaderCont&			Headers();
	CFilterTracker&				Tracker();
	CFilterBlackListDisp&		BlackList();
	CFilterAppList&				AppList();

	void*						AllocateLookaside();
	void						FreeLookaside(void* mem);

	NTSTATUS					Randomize(UCHAR *target, ULONG size);
	
	NTSTATUS					GenerateNonce(LARGE_INTEGER *nonce);
	NTSTATUS					GenerateFileKey(CFilterKey *fileKey);
	NTSTATUS					Purge(ULONG entityIdentifier, ULONG flags);
        
								// STATIC
	static NTSTATUS				Encode(UCHAR *buffer, ULONG size, FILFILE_CRYPT_CONTEXT *crypt);
	static NTSTATUS				Decode(UCHAR *buffer, ULONG size, FILFILE_CRYPT_CONTEXT *crypt);
	static bool					EncodeFileKey(CFilterKey const *entityKey, CFilterKey *fileKey, bool dec);
	
	static ULONG				ComputePadding(ULONG size);
	static ULONG				ComputeFiller(ULONG  size);
	static ULONG				GetPadding(UCHAR const* buffer, ULONG size);
	static ULONG				AddPadding(UCHAR *buffer, ULONG size);

	ULONG						AddPaddingFiller(UCHAR* buffer, ULONG size);
	
private:
								// DATA
	NPAGED_LOOKASIDE_LIST*		m_lookAside;

	CFilterFileCont				m_files;			// Tracked file streams, sorted by FCB
	ERESOURCE					m_filesResource;

	CFilterDirectoryCont		m_directories;		// Tracked directories, sorted by FO
	ERESOURCE					m_directoriesResource;

	CFilterTracker				m_tracker;			// State info for particular FOs, sorted by FO

	CFilterHeaderCont			m_headers;			// Headers 

	CFilterBlackListDisp		m_blackList;		
	CFilterAppList				m_appList;

	LARGE_INTEGER				m_nonce;			// Next Nonce value to be used
	FAST_MUTEX					m_nonceLock;

public:

	CFilterRandomizer			m_randomizerHigh;	// Used for FileKeys - will call into Usermode for random data
	CFilterRandomizer			m_randomizerLow;	// Used for Header padding, Filler and wiping - no Usermode calls at all
	
	UCHAR						m_macCrc;			// simple check sum over MAC address, if any
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
CFilterHeaderCont& CFilterContext::Headers()
{
	return m_headers;
}

inline
CFilterTracker& CFilterContext::Tracker()
{
	return m_tracker;
}

inline
CFilterBlackListDisp& CFilterContext::BlackList()
{
	return m_blackList;
}

inline
CFilterAppList& CFilterContext::AppList()
{
	return m_appList;
}

inline
NTSTATUS CFilterContext::Randomize(UCHAR *target, ULONG size)
{
	ASSERT(target);
	ASSERT(size);

	// request LOW quality random
    return m_randomizerLow.Get(target, size);
}

inline
NTSTATUS CFilterContext::GenerateFileKey(CFilterKey *fileKey)
{
	ASSERT(fileKey);
	ASSERT(fileKey->m_size);
	ASSERT(sizeof(fileKey->m_key) >= fileKey->m_size);

	// request HIGH quality random
	return m_randomizerHigh.Get(fileKey->m_key, fileKey->m_size);
}

inline
void* CFilterContext::AllocateLookaside()
{
	ASSERT(m_lookAside);

	return ExAllocateFromNPagedLookasideList(m_lookAside);
}

inline
void CFilterContext::FreeLookaside(void* mem)
{
	ASSERT(mem);
	ASSERT(m_lookAside);

	ExFreeToNPagedLookasideList(m_lookAside, mem);
}

inline
ULONG CFilterContext::ComputePadding(ULONG size)
{
	#if FILFILE_USE_PADDING
 	 return c_blockSize - (size & (c_blockSize - 1));
	#endif

	return 0;
}

inline
ULONG CFilterContext::ComputeFiller(ULONG size)
{
	#if FILFILE_USE_PADDING
 	 return size & (c_blockSize - 1);
	#endif

	return 0;
}

inline
ULONG CFilterContext::GetPadding(UCHAR const* buffer, ULONG size)
{
	ASSERT(size >= c_blockSize);

	#ifdef FILFILE_USE_CFB
	 return CFilterCipherCFB::GetPadding(buffer, size);
	#elif defined(FILFILE_USE_EME)
	 return CFilterCipherEME::GetPadding(buffer, size);
	#endif

	// CTR uses no padding at all
	return  0;
}

inline
ULONG CFilterContext::AddPadding(UCHAR *buffer, ULONG size)
{
	#ifdef FILFILE_USE_CFB
 	 return CFilterCipherCFB::AddPadding(buffer, size);
	#elif defined(FILFILE_USE_EME) 
	 return CFilterCipherEME::AddPadding(buffer, size);
	#endif

	// CTR uses no padding at all
	return  0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterContext__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
