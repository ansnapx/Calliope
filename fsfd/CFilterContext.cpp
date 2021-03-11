////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterContext.cpp: implementation of the CFilterContext class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "RijndaelCoder.h"

#include "CFilterContext.h"

#ifdef FILFILE_USE_CTR
#pragma message("*** Using CTR ***")
#elif defined(FILFILE_USE_CFB)
#pragma message("*** Using CFB ***")
#elif defined(FILFILE_USE_EME)
#pragma message("*** Using EME ***")
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterContext::Init()
{
	PAGED_CODE();

	m_nonce.QuadPart  = 0;
	m_macCrc		  = 0;

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	
	m_lookAside = (NPAGED_LOOKASIDE_LIST*) ExAllocatePool(NonPagedPool, sizeof(NPAGED_LOOKASIDE_LIST));

	if(m_lookAside)
	{
		// init lookaside list used for small (fast) allocations
		ExInitializeNPagedLookasideList(m_lookAside, 0,0,0, c_lookAsideSize, FILF_POOL_TAG, 0);

		status = ExInitializeResourceLite(&m_filesResource);

		if(NT_SUCCESS(status))
		{
			status = ExInitializeResourceLite(&m_directoriesResource);

			if(NT_SUCCESS(status))
			{
				// Initialize various objects
				m_files.Init();
				m_directories.Init();
				m_tracker.Init();
				m_headers.Init();
				
				m_randomizerLow.Init(false);
				m_randomizerHigh.Init(true);

				m_blackList.Init();
				m_appList.Init();
			}
		}
	}

	ExInitializeFastMutex(&m_nonceLock);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterContext::InitDeferred(LPCWSTR regPath)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(regPath);

	NTSTATUS status = STATUS_SUCCESS;

	// already initialized ?
	if(!m_macCrc)
	{
		UCHAR macAddr[6];
		RtlFillMemory(&macAddr, sizeof(macAddr), 0xaa);

		// get active MAC address, if any
		status = CFilterBase::GetMacAddress(macAddr);

		// compute very simple checksum
		for(ULONG index = 0; index < sizeof(macAddr); ++index)
		{
			m_macCrc += macAddr[index];
		}

		// If sum is null, select non-null value to query for MAC address only once
		if(!m_macCrc)
		{
			m_macCrc = 5;

			// Use first non-null value
			for(LONG index = sizeof(macAddr) - 1; index >= 0; --index)
			{
				if(macAddr[index])
				{
					m_macCrc = macAddr[index];

					break;
				}
			}
		}

		DBGPRINT(("CFilterContext::InitDeferred() MAC Checksum[0x%x]\n", m_macCrc));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterContext::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();

	m_appList.Close();
	m_blackList.Close();

	m_randomizerLow.Close();
	m_randomizerHigh.Close();

	m_tracker.Close();

	// free File Tracker
	ExAcquireResourceExclusiveLite(&m_filesResource, true);
	m_files.Close();
	ExDeleteResourceLite(&m_filesResource);

	// free Directory Tracker
	ExAcquireResourceExclusiveLite(&m_directoriesResource, true);
	m_directories.Close();
	ExDeleteResourceLite(&m_directoriesResource);

	m_nonce.QuadPart = 0;

	m_headers.Close();
		
	if(m_lookAside)
	{
		ExDeleteNPagedLookasideList(m_lookAside);

		ExFreePool(m_lookAside);
		m_lookAside = 0;
	}

	FsRtlExitFileSystem();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterContext::GenerateNonce(LARGE_INTEGER *nonce)
{
	ASSERT(nonce);

	PAGED_CODE();

	LARGE_INTEGER candidate;
	KeQuerySystemTime(&candidate);

	// MAC crc not initialized ?
	if(!m_macCrc)
	{
		InitDeferred();
	}

	if(m_macCrc != 0xff)
	{
		// Override highest byte with MAC crc, if any. It will change
		// only every ~20 years and to make the Nonce *more* unique
		// - especially among users on a network (different MACs).
		UCHAR *temp = (UCHAR*) &candidate.QuadPart;

		temp[7] = m_macCrc;
	}

	ExAcquireFastMutex(&m_nonceLock);
	
	// if already used, just increment last one used
	if((ULONGLONG) candidate.QuadPart <= (ULONGLONG) m_nonce.QuadPart)
	{
		candidate.QuadPart = m_nonce.QuadPart + 1;
	}

	// Save last Nonce
	*nonce = m_nonce = candidate;

	ExReleaseFastMutex(&m_nonceLock);

	#if DBG
	{
		// check new Nonce against active ones
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_filesResource, true);

		for(ULONG index = 0; index < m_files.Size(); ++index)
		{
			CFilterFile *const filterFile = m_files.Get(index);
			ASSERT(filterFile);

			if(candidate.QuadPart == filterFile->m_link.m_nonce.QuadPart)
			{
				DBGPRINT(("GenerateNonce -WARN: Nonce[0x%I64x] already used\n", candidate));

				// should never come here ...
				ASSERT(false);
				break;
			}
		}

		ExReleaseResourceLite(&m_filesResource);
		FsRtlExitFileSystem();
	}
	#endif

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterContext::EncodeFileKey(CFilterKey const *entityKey, CFilterKey *fileKey, bool dec)
{
	ASSERT(entityKey);
	ASSERT(fileKey);

	PAGED_CODE();

	// Use always a 256 bit key to encrypt the FileKey,
	// fill remaining bytes of given EntityKey with zeros.

	UCHAR key[32];
	RtlZeroMemory(key, sizeof(key));

	ASSERT(sizeof(key) >= entityKey->m_size);
	RtlCopyMemory(key, entityKey->m_key, entityKey->m_size);

	RijndealCoder<AES_256> aes;
	if(!aes.Init(key, dec))
	{	
		// Caution: We come here if size for FixedMgr is too small
		ASSERT(false);

		return false;
	}

	// encrypt/decrypt two halfes (128 bit each) using the cipher in a CBC-like fashion
	if(dec)
	{
		// decrypt 2nd half
		aes.DecodeBlock(fileKey->m_key + aes.c_blockSize);
	}
	else
	{
		// encrypt 1st half
		aes.EncodeBlock(fileKey->m_key);
	}

	// XOR 1st (encrypted) half with 2nd (plain) half
	ULONG *s = (ULONG*) (fileKey->m_key);
	ULONG *t = (ULONG*) (fileKey->m_key + aes.c_blockSize);

	*t++ ^= *s++;
	*t++ ^= *s++;
	*t++ ^= *s++;
	*t   ^= *s;

	if(dec)
	{
		// decrypt 1st half
		aes.DecodeBlock(fileKey->m_key);
	}
	else
	{
		// encrypt 2nd half
		aes.EncodeBlock(fileKey->m_key + aes.c_blockSize);
	}

	// be paranoid
	RtlZeroMemory(key, sizeof(key));

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterContext::AddPaddingFiller(UCHAR *buffer, ULONG size)
{
	ULONG padding = 0;

	#if FILFILE_USE_PADDING
	{
		padding = AddPadding(buffer, size);

		if(padding < c_blockSize)
		{
			// fill with random	data
			Randomize(buffer + size + padding, c_blockSize - padding);
		}

		DBGPRINT(("AddPaddingFiller: add Padding[0x%x] Filler[0x%x]\n", padding, c_blockSize - padding));
	}
	#endif

	return padding;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterContext::Purge(ULONG entityIdentifier, ULONG flags)
{
	PAGED_CODE();

	ASSERT(entityIdentifier != ~0u);
	ASSERT(flags & (ENTITY_DISCARD | ENTITY_PURGE));

	NTSTATUS status = STATUS_SUCCESS;

	DBGPRINT(("Purge: Dirs[%d] Files[%d] EntityIdentifier[0x%x] Flags[0x%x]\n", m_directories.Size(), 
																				m_files.Size(), 
																				entityIdentifier,
																				flags));
	FsRtlEnterFileSystem();

	// Discard tracked FOs?
	if(flags & ENTITY_DISCARD)
	{
		if(m_directories.Size())
		{
			// Directories:
			ExAcquireResourceExclusiveLite(&m_directoriesResource, true);

			for(ULONG pos = 0; pos < m_directories.Size(); ++pos)
			{
				CFilterDirectory *const filterDirectory = m_directories.Get(pos);
				ASSERT(filterDirectory);

				if(!entityIdentifier || (entityIdentifier == filterDirectory->m_entityIdentifier))
				{
					DBGPRINT(("Purge: Discard directory FO[0x%p]\n", filterDirectory->m_file));

					m_directories.Remove(0, pos);
				}
			}

			ExReleaseResourceLite(&m_directoriesResource);
		}

		if(m_files.Size())
		{
			// Files:
			ExAcquireResourceExclusiveLite(&m_filesResource, true);

			for(ULONG pos = 0; pos < m_files.Size(); ++pos)
			{
				CFilterFile *const filterFile = m_files.Get(pos);
				ASSERT(filterFile);

				if(filterFile)
				{
					if(!entityIdentifier || (entityIdentifier == filterFile->m_link.m_entityIdentifier))
					{
						DBGPRINT(("Purge: Discard file FO[0x%p]\n", filterFile->Tracked()));

						m_files.Remove(pos);
					}
				}
			}

			ExReleaseResourceLite(&m_filesResource);
		}

		FsRtlExitFileSystem();

		return STATUS_SUCCESS;
	}

	// Typical purge:

	ASSERT(flags & ENTITY_PURGE);

	// Directories:
	if(m_directories.Size())
	{
		ExAcquireResourceExclusiveLite(&m_directoriesResource, true);

		for(ULONG index = 0; index < m_directories.Size(); ++index)
		{
			CFilterDirectory *const filterDirectory = m_directories.Get(index);
			ASSERT(filterDirectory);

			if(filterDirectory->m_entityIdentifier == entityIdentifier)
			{
				DBGPRINT(("Purge: active DIRECTORY Reference, FO[0x%p]\n", filterDirectory->m_file));

				// Invalidate identifier
				filterDirectory->m_entityIdentifier = ~0u;
			}
		}

		ExReleaseResourceLite(&m_directoriesResource);
	}

	// Files:
	if(m_files.Size())
	{
		// Phase 1: Take snapshot of currently tracked FOs that
		// match given (every, if no specified) Entity identifier
		ExAcquireSharedWaitForExclusive(&m_filesResource, true);
		
		FILE_OBJECT **snap	  = 0;
		ULONG const snapCount = m_files.Size();

		if(snapCount)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;

			snap = (FILE_OBJECT**) ExAllocatePool(PagedPool, snapCount * sizeof(FILE_OBJECT*));

			if(snap)
			{
				RtlZeroMemory(snap, snapCount * sizeof(FILE_OBJECT*));

				status = STATUS_SUCCESS;

				// Copy tracked FO into snapshot array
				for(ULONG index = 0; index < snapCount; ++index)
				{
					CFilterFile *const filterFile = m_files.Get(index);

					if(filterFile && filterFile->Tracked())
					{
						FILE_OBJECT *const file = filterFile->Tracked();

						ASSERT(!CFilterBase::IsStackBased(file));
	
						// Skip doomed ones
						if(filterFile->m_link.m_entityIdentifier != ~0u)
						{
							if(!entityIdentifier || (entityIdentifier == filterFile->m_link.m_entityIdentifier))
							{
								if(CFilterBase::IsCached(file))
								{
									// Copy
									snap[index] = file;
								}
							}
						}
					}
				}

				ExReleaseResourceLite(&m_filesResource);
				// Let exclusive waiters proceed first
				ExAcquireSharedWaitForExclusive(&m_filesResource, true);

				// Phase 2: Purge FOs from our snapshot, but only those which are still tracked
				for(ULONG index = 0; index < snapCount; ++index)
				{
					FILE_OBJECT *const file = snap[index];

					// Valid?
					if(file && file->FsContext)
					{
						// Still tracked?
						if(m_files.Check(file))
						{
							// Pin FO
							ObReferenceObject(file);

							// Do not block the close operation that could be triggered 
							ExReleaseResourceLite(&m_filesResource);

							DBGPRINT(("Purge: FO[0x%p] FCB[0x%p] at [%d] Flush/Purge\n", file, file->FsContext, index));

							// Flush'n'Purge without pinning
							if(NT_ERROR(CFilterBase::FlushAndPurgeCache(file, true, false)))
							{
								DBGPRINT(("Purge -WARN: FO[0x%p] purging has failed\n", file));

								// Inform caller about
								status = STATUS_OBJECT_NAME_COLLISION;
							}

							// Unpin FO
							ObDereferenceObject(file);

							ExAcquireSharedWaitForExclusive(&m_filesResource, true);
						}
					}
				}
			}
		}

		ExReleaseResourceLite(&m_filesResource);

		if(snap)
		{
			ExFreePool(snap);
		}

		if(m_files.Size())
		{
			ExAcquireResourceExclusiveLite(&m_filesResource, true);

			DBGPRINT(("Purge: active files [%d]\n", m_files.Size()));

			// Phase 3: Mark remaing FOs as doomed
			for(ULONG index = 0; index < m_files.Size(); ++index)
			{
				CFilterFile *const filterFile = m_files.Get(index);

				if(filterFile)
				{
					if(!entityIdentifier || (entityIdentifier == filterFile->m_link.m_entityIdentifier))
					{
						// Zero out sensitive data
						filterFile->m_link.m_fileKey.Clear();
						filterFile->m_link.m_nonce.QuadPart = 0;

						// Tag Entity identifier as doomed
						filterFile->m_link.m_entityIdentifier = ~0u;
						
						if(!filterFile->m_refCount)
						{
							FILE_OBJECT *const file = filterFile->Tracked();
							
							if(!file || !CFilterBase::IsCached(file))
							{
								DBGPRINT(("Purge: FO[0x%p] FCB[0x%p] Orphaned, remove\n", file, filterFile->m_fcb));
							
								m_files.Remove(index);
								index--;
							}						
						}
					}
				}
			}

			ExReleaseResourceLite(&m_filesResource);
		}
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterContext::Encode(UCHAR *buffer, ULONG size, FILFILE_CRYPT_CONTEXT *crypt)
{
	ASSERT(buffer);
	ASSERT(crypt);
	ASSERT(size);
    
	ASSERT(crypt->Nonce.QuadPart);
	ASSERT(crypt->Key.m_cipher);
	ASSERT(crypt->Key.m_size);
				  
	NTSTATUS status = STATUS_SUCCESS;
	
#ifdef FILFILE_USE_CTR
	// CTR
	DBGPRINT(("Encode(CTR) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherCTR cipher(crypt);
#elif defined(FILFILE_USE_CFB)
	// CFB
	DBGPRINT(("Encode(CFB) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherCFB cipher(crypt);
#elif defined(FILFILE_USE_EME)
	// EME
	DBGPRINT(("Encode(EME) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherEME cipher;
	status = cipher.Init(crypt);
#endif

	if(NT_SUCCESS(status))
	{
		status = cipher.Encode(buffer, size);
	}
	else
	{
		// Hmm, really bad...
		ASSERT(false);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterContext::Decode(UCHAR *buffer, ULONG size, FILFILE_CRYPT_CONTEXT *crypt)
{
	ASSERT(buffer);
	ASSERT(crypt);
	ASSERT(size);
    
	ASSERT(crypt->Nonce.QuadPart);
	ASSERT(crypt->Key.m_cipher);
	ASSERT(crypt->Key.m_size);

	NTSTATUS status = STATUS_SUCCESS;
	
#ifdef FILFILE_USE_CTR
	// CTR
	DBGPRINT(("Decode(CTR) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherCTR cipher(crypt);
#elif defined (FILFILE_USE_CFB)
	// CFB
	DBGPRINT(("Decode(CFB) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherCFB cipher(crypt);
#elif defined(FILFILE_USE_EME)
	// EME
	DBGPRINT(("Decode(EME) Size[0x%x] Offset[0x%I64x] Key[0x%x] Nonce[0x%I64x]\n", size, crypt->Offset, *((ULONG*) crypt->Key.m_key), crypt->Nonce));

	CFilterCipherEME cipher;
	status = cipher.Init(crypt);
#endif

	if(NT_SUCCESS(status))
	{
		status = cipher.Decode(buffer, size);
	}
	else
	{
		// Hmmm, really bad...
		ASSERT(false);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
