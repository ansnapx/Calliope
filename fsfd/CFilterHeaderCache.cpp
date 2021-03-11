////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterHeaderCache.cpp: implementation of the CFilterHeaderCache class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterHeader.h"
#include "CFilterHeaderCache.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::CFilterHeaderCacheEntry::Init(LPWSTR path, ULONG pathLen, ULONG hash, CFilterHeader *header)
{
	ASSERT(path);
	ASSERT(pathLen);

	PAGED_CODE();
	
	RtlZeroMemory(this, sizeof(*this));

	m_path		= path;
	m_pathLen	= pathLen;
	m_hash		= hash;

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	m_tick = tick.LowPart;

	// Header is optional
	if(header && header->m_payload)
	{
		ASSERT(header->m_payloadSize);

		// reference Header
		m_header	 = header->m_payload;
		m_headerSize = header->m_payloadSize;
	}

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeaderCache::CFilterHeaderCacheEntry::Close()
{
	PAGED_CODE();

	if(m_path)
	{
		ExFreePool(m_path);
	}

	if(m_header)
	{
		ExFreePool(m_header);
	}

	RtlZeroMemory(this, sizeof(*this));
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Init(LPCWSTR regPath)
{
	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	KeInitializeEvent(&m_workerStop, NotificationEvent, false);

	NTSTATUS status = ExInitializeResourceLite(&m_lock);

	if(NT_ERROR(status))
	{
		return status;
	}

	ULONG timeout = c_timeout;

	if(regPath)
	{
		// Customized timeout value?
		if(NT_SUCCESS(CFilterBase::QueryRegistryLong(regPath, L"HeaderCacheTimeout", &timeout)))
		{
			DBGPRINT(("HeaderCacheInit: registry timeout in seconds[%d]\n", timeout));
		}
	}

	// Translate seconds into ticks on this machine
	m_timeout = CFilterBase::GetTicksFromSeconds(timeout);

	DBGPRINT(("HeaderCacheInit: timeout in ticks[0x%x]\n", m_timeout));

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeaderCache::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();

	m_timeout = 0;

	Clear();

	WorkerStop();

	if(m_headers)
	{
		ExAcquireResourceExclusiveLite(&m_lock, true);

		ExFreePool(m_headers);
		m_headers  = 0;

		m_capacity = 0;

		ExReleaseResourceLite(&m_lock);
	}

	ExDeleteResourceLite(&m_lock);
	FsRtlExitFileSystem();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeaderCache::Clear()
{
	PAGED_CODE();

	if(m_count)
	{
		ASSERT(m_headers);

		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&m_lock, true);

		for(ULONG index = 0; index < m_count; ++index)
		{
			m_headers[index].Close();
		}

		m_count = 0;

		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS CFilterHeaderCache::WorkerStart()
{
	NTSTATUS status = STATUS_SUCCESS;

	if(!m_worker)
	{
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, 0, OBJ_KERNEL_HANDLE, 0,0);

		status = PsCreateSystemThread(&m_worker, THREAD_ALL_ACCESS, &oa, 0,0, Worker, this);

		if(NT_ERROR(status))
		{
			DBGPRINT(("WorkerStart -ERROR: PsCreateSystemThread() failed with [0x%x]\n", status));
		}
		else
		{
			ASSERT(m_worker);
		}
	}

	return status;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NTSTATUS CFilterHeaderCache::WorkerStop()
{
	NTSTATUS status = STATUS_SUCCESS;

	if(m_worker)
	{
		void *thread = 0;

		// Use W2k compatible way to wait for worker
		status = ObReferenceObjectByHandle(m_worker, 
										   THREAD_ALL_ACCESS,
										   0, 
										   KernelMode, 
										   &thread,
										   0);
		if(NT_SUCCESS(status))
		{
			ASSERT(thread);

			// Trigger stop
			KeSetEvent(&m_workerStop, EVENT_INCREMENT, true);

			KeWaitForSingleObject(thread, Executive, KernelMode, false, 0);

			ObDereferenceObject(thread);
		}
	}

	return status;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterHeaderCache::Worker(void *context)
{
	PAGED_CODE();

	// No need to operate in the runtime range, so lower our priority
	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY - 1);

	CFilterHeaderCache *const me = (CFilterHeaderCache*) context;
	ASSERT(me);

	LARGE_INTEGER timeout;
	timeout.QuadPart = RELATIVE(SECONDS(c_scavenging));

	ULONG idle = 0;

	NTSTATUS status = STATUS_SUCCESS;

	for(;;)
	{
		DBGPRINT(("Worker: Waiting...\n"));

		status = KeWaitForSingleObject((void*) &me->m_workerStop, 
									   Executive, 
									   KernelMode,
									   false, 
									   &timeout);

		if((STATUS_SUCCESS == status) || NT_ERROR(status))
		{
			DBGPRINT(("Worker: Stopping\n"));
			break;
		}

		DBGPRINT(("Worker: Validate\n"));

		// Validate entries
		if(me->Validate())
		{
			idle = 0;
		}
		else
		{
			// Cache is empty. Check idle count
			if(++idle > 5)
			{
				DBGPRINT(("Worker: Exiting\n"));
				break;
			}

			DBGPRINT(("Worker: Validate idle count[%d]\n", idle));
		}
	}

	HANDLE const worker = me->m_worker;
	me->m_worker = 0;

	ASSERT(worker);
	ZwClose(worker);

	PsTerminateSystemThread(status);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterHeaderCache::Search(LPCWSTR path, ULONG pathLen, ULONG hash, ULONG tick)
{
	ASSERT(path);
	ASSERT(pathLen);
	ASSERT(hash);

	PAGED_CODE();

	// Lock must be already held

	ASSERT(m_count <= m_capacity);
	
	// Start at end with newest entries
	for(LONG index = m_count - 1; index >= 0; --index)
	{
		ASSERT(m_headers);
		ASSERT(m_headers[index].m_path);
		ASSERT(m_headers[index].m_pathLen);

		// Ignore tick? 
		if(tick)
		{
			LONG delta = tick - m_headers[index].m_tick;

			if(delta < 0)
			{
				delta = -delta;
			}

			// Outdated?
			if((ULONG) delta > m_timeout)
			{
				// This one and following entries are outdated, so stop searching
				break;
			}
		}

		if(hash == m_headers[index].m_hash)
		{
			if(m_headers[index].m_pathLen == pathLen)
			{
				if(!_wcsnicmp(m_headers[index].m_path, path, pathLen / sizeof(WCHAR)))
				{
					return index;
				}
			}
		}
	}

	return ~0u;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Query(LPCWSTR path, ULONG pathLen, CFilterHeader *header)
{
	ASSERT(path);
	ASSERT(pathLen);
	ASSERT(header);

	PAGED_CODE();

	ASSERT(m_count <= m_capacity);

	if(!m_count)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	pathLen /= sizeof(WCHAR);

	// Strip trailing zeros
	while(pathLen > 1)
	{
		if(path[pathLen - 1])
		{
			break;
		}

		pathLen--;
	}

	pathLen *= sizeof(WCHAR);

	ULONG const hash = CFilterBase::Hash(path, pathLen);
	
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	ULONG const pos = Search(path, pathLen, hash, tick.LowPart);

	// Found?
	if(pos != ~0u)
	{
		ASSERT(pos < m_count);
		ASSERT(m_headers);

		CFilterHeaderCacheEntry const*const entry = m_headers + pos;

		DBGPRINT(("HeaderCacheQuery: Found [%ws] HeaderSize[0x%x]\n", entry->m_path, entry->m_headerSize));

		// Positive entry (with valid Header) ?
		if(entry->m_header)
		{
			ASSERT(entry->m_headerSize);

			header->m_payload	  = entry->m_header;
			header->m_payloadSize = entry->m_headerSize;
		}

		status = STATUS_SUCCESS;
	}
	
	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Add(LPWSTR path, ULONG pathLen, CFilterHeader *header)
{
	ASSERT(path);
	ASSERT(pathLen);

	PAGED_CODE();

	// Deactivated?
	if(!m_timeout)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Strip trailing zeros
	while(pathLen > sizeof(WCHAR))
	{
		if(path[(pathLen / sizeof(WCHAR)) - 1])
		{
			break;
		}

		pathLen -= sizeof(WCHAR);
	}

	ULONG const hash = CFilterBase::Hash(path, pathLen);

	ASSERT(m_count <= m_capacity);

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	// Remove, if exists
	Remove(path, pathLen, hash);

	// Extend buffer?
	if(m_count == m_capacity)
	{
		ULONG const capacity = m_capacity + c_increment;

		CFilterHeaderCacheEntry *temp = (CFilterHeaderCacheEntry*) ExAllocatePool(PagedPool, capacity * sizeof(CFilterHeaderCacheEntry));

		if(!temp)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(temp, capacity * sizeof(CFilterHeaderCacheEntry));

		m_capacity = capacity;

		if(m_count)
		{
			ASSERT(m_headers);

			RtlCopyMemory(temp, m_headers, m_count * sizeof(CFilterHeaderCacheEntry));

			ExFreePool(m_headers);
		}

		m_headers = temp;
	}

	ASSERT(m_count <= m_capacity);

	// Initialize inplace, take ownership of Path and Header
	m_headers[m_count].Init(path, pathLen, hash, header);

	m_count++;

	DBGPRINT(("HeaderCacheAdd: [%ws] Sizes[%d,%d] HeaderSize[0x%x]\n", path, m_count, m_capacity, header->m_payloadSize));

	ExReleaseResourceLite(&m_lock);

	// Start worker, if not running
	WorkerStart();

	FsRtlExitFileSystem();

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Remove(LPCWSTR path, ULONG pathLen)
{
	ASSERT(path);
	ASSERT(pathLen);

	PAGED_CODE();

	if(!m_count)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	// Strip trailing zeros
	while(pathLen > sizeof(WCHAR))
	{
		if(path[(pathLen / sizeof(WCHAR)) - 1])
		{
			break;
		}

		pathLen -= sizeof(WCHAR);
	}

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	ULONG const hash = CFilterBase::Hash(path, pathLen);

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	ULONG pos = Search(path, pathLen, hash);

	if(~0u != pos)
	{
		ExReleaseResourceLite(&m_lock);

		ExAcquireResourceExclusiveLite(&m_lock, true);

		// Still valid?
		if((pos >= m_count) || 
		   (hash != m_headers[pos].m_hash) || 
		   _wcsnicmp(m_headers[pos].m_path, path, pathLen / sizeof(WCHAR)))
		{
			pos = ~0u;
		}

		// Remove with position hint
		status = Remove(path, pathLen, hash, pos);
	}
	
	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Remove(LPCWSTR path, ULONG pathLen, ULONG hash, ULONG pos)
{
	ASSERT(path);
	ASSERT(pathLen);

	PAGED_CODE();

	// Lock must be held exclusively

	ASSERT(m_count <= m_capacity);

	if(!m_count)
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	
	// Invalid position given?
	if(~0u == pos)
	{
		// Search for entry
		pos = Search(path, pathLen, hash);

		if(~0u == pos)
		{
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}

	ASSERT(pos < m_count);
	ASSERT(m_headers);
	ASSERT(!_wcsnicmp(m_headers[pos].m_path, path, pathLen / sizeof(WCHAR)));

	DBGPRINT(("HeaderCacheRemove: [%ws]\n", path));

	m_headers[pos].Close();

	m_count--;
	
	if(pos < m_count)
	{
		// Close gap
		RtlMoveMemory(m_headers + pos, 
					  m_headers + pos + 1, 
					  (m_count - pos) * sizeof(CFilterHeaderCacheEntry));
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterHeaderCache::Validate()
{
	PAGED_CODE();

	if(!m_count)
	{
		// Nothing to do
		return false;
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	LARGE_INTEGER tick;
	KeQueryTickCount(&tick);

	ASSERT(m_count <= m_capacity);

	ULONG pos = 0;

	// Search for first valid entry
	while(pos < m_count)
	{
		ASSERT(m_headers);

		LONG delta = tick.LowPart - m_headers[pos].m_tick;

		if(delta < 0)
		{
			delta = -delta;
		}

		// Valid (not outdated)?
		if((ULONG) delta < m_timeout)
		{
			break;
		}

		DBGPRINT(("HeaderCacheValidate: discard [%ws]\n", m_headers[pos].m_path));

		m_headers[pos].Close();

		pos++;
	}
	
	if(pos)
	{
		// Gap to be closed?
		if(pos < m_count)
		{
			// Close gap
			RtlMoveMemory(m_headers, 
						  m_headers + pos, 
						  (m_count - pos) * sizeof(CFilterHeaderCacheEntry));
		}

		m_count -= pos;

		ASSERT(m_count <= m_capacity);

		if(!m_count)
		{
			ExFreePool(m_headers);
			m_headers  = 0;
			m_capacity = 0;
		}

		DBGPRINT(("HeaderCacheValidate: new Sizes[%d,%d]\n", m_count, m_capacity));
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return true;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Inject(CFilterPath *source, CFilterHeader *header)
{
	ASSERT(source);
	ASSERT(header);

	PAGED_CODE();

	// Deactivated?
	if(!m_timeout)
	{
		return STATUS_SUCCESS;
	}

	// Do not cache headers of Alternate Data Streams
	if(source->m_flags & TRACK_ALTERNATE_STREAM)
	{
		DBGPRINT(("HeaderCacheInject: Ignore ADS\n"));

		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_SUCCESS;

	ULONG pathLength  = 0;

	LPWSTR path	= source->CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE, 
								 &pathLength);

	if(!path)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ASSERT(pathLength);

	CFilterHeader temp;

	if(header->m_payload)
	{
		status = temp.Init(header->m_payload, header->m_payloadSize);
	}

	if(NT_SUCCESS(status))
	{
		// Takes over path and Header ownership
		status = Add(path, pathLength, &temp);
	}

	if(NT_ERROR(status))
	{
		temp.Close();

		ExFreePool(path);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterHeaderCache::Remove(FILFILE_VOLUME_EXTENSION *extension, FILE_OBJECT *file)
{
	ASSERT(file);
	ASSERT(extension);

	PAGED_CODE();

	if(!m_count)
	{
		return STATUS_SUCCESS;
	}

	FILE_NAME_INFORMATION *fileNameInfo = 0;
	NTSTATUS status = CFilterBase::QueryFileNameInfo(extension->Lower, file, &fileNameInfo);
		
	if(NT_SUCCESS(status))
	{
		ASSERT(fileNameInfo);

		UNICODE_STRING lower = extension->LowerName;

		// Estimate type of underlying redirector
		if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
		{
			ULONG const type = CFilterBase::GetNetworkProvider(extension, file);

			if(type & FILFILE_DEVICE_REDIRECTOR_CIFS)
			{
				lower.Buffer		= L"\\Device\\LanmanRedirector";
				lower.Length		= 24 * sizeof(WCHAR);
				lower.MaximumLength = lower.Length + sizeof(WCHAR);
			}
			else if(type & FILFILE_DEVICE_REDIRECTOR_WEBDAV)
			{
				lower.Buffer		= L"\\Device\\WebDavRedirector";
				lower.Length		= 24 * sizeof(WCHAR);
				lower.MaximumLength = lower.Length + sizeof(WCHAR);
			}
			else if(type & FILFILE_DEVICE_REDIRECTOR_NETWARE)
			{
				lower.Buffer		= L"\\Device\\NetWareRedirector";
				lower.Length		= 25 * sizeof(WCHAR);
				lower.MaximumLength = lower.Length + sizeof(WCHAR);
			}
		}

		CFilterPath path;

		// Build composite path
		status = path.Build(fileNameInfo->FileName, 
							fileNameInfo->FileNameLength, 
							&lower);

		if(NT_SUCCESS(status))
		{
			status = Remove(path.m_volume, path.m_volumeLength);

			path.Close();
		}

		ExFreePool(fileNameInfo);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
