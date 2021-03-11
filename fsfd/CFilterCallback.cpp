////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCallback.cpp: implementation of the CFilterCallback class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "IoControl.h"
#include "CFilterControl.h"

#include "CFilterCallback.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE 

NTSTATUS CFilterCallback::Init(LUID const* luid)
{
	ASSERT(luid);

	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	m_luid = *luid;

	ExInitializeFastMutex(&m_lock);

	KeInitializeEvent(&m_randomReady, SynchronizationEvent, false);
	KeInitializeEvent(&m_keyReady,    SynchronizationEvent, false);
	KeInitializeEvent(&m_notifyReady, SynchronizationEvent, false);

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterCallback::Close(bool wake)
{
	PAGED_CODE();

	ExAcquireFastMutex(&m_lock);

	if(m_randomTrigger)
	{
		KeClearEvent(m_randomTrigger);

		ObDereferenceObject(m_randomTrigger);
		m_randomTrigger = 0;
	}
	if(m_keyTrigger)
	{
		KeClearEvent(m_keyTrigger);

		ObDereferenceObject(m_keyTrigger);
		m_keyTrigger = 0;
	}
	if(m_notifyTrigger)
	{
		KeClearEvent(m_notifyTrigger);

		ObDereferenceObject(m_notifyTrigger);
		m_notifyTrigger = 0;
	}

	if(m_random)
	{
		ExFreePool(m_random);
		m_random = 0;
	}
	m_randomSize = 0;

	if(m_notify)
	{
		ExFreePool(m_notify);
		m_notify = 0;
	}
	m_notifySize = 0;
	m_notifyFlags  = 0;

	if(m_keyPath)
	{
		ExFreePool(m_keyPath);
		m_keyPath = 0;
	}
	m_keyPathLength	 = 0;

	m_keyCookie		 = 0;
	m_keyPayload	 = 0;
	m_keyPayloadSize = 0;

	m_key.Clear();

	ExReleaseFastMutex(&m_lock);

	if(wake)
	{
		// wake up potentially waiting threads
		KeSetEvent(&m_keyReady,    EVENT_INCREMENT, false);
		KeSetEvent(&m_randomReady, EVENT_INCREMENT, false);
		KeSetEvent(&m_notifyReady, EVENT_INCREMENT, false);

		LARGE_INTEGER time;
		time.QuadPart = RELATIVE(MILLISECONDS(100));

		KeDelayExecutionThread(KernelMode, false, &time);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::Connect(HANDLE random, HANDLE key, HANDLE notify)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	if(m_randomTrigger || m_keyTrigger || m_notifyTrigger)
	{
		// Cleanup of currently connected client, if any
		Close(true);
	}

	ExAcquireFastMutex(&m_lock);

	if(random)
	{
		DBGPRINT(("CallbackConnect: Random Provider connected with LUID[0x%I64x]\n", m_luid));

		status = ObReferenceObjectByHandle(random, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (void**) &m_randomTrigger, 0);
	}

	if(key && NT_SUCCESS(status))
	{
		DBGPRINT(("CallbackConnect: Key Provider connected with LUID[0x%I64x]\n", m_luid));

		status = ObReferenceObjectByHandle(key, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (void**) &m_keyTrigger, 0);

		if(NT_SUCCESS(status))
		{
			// Initialize Cookie
			m_keyCookie = 1;
		}
	}

	if(notify && NT_SUCCESS(status))
	{
		DBGPRINT(("CallbackConnect: Notify connected with LUID[0x%I64x]\n", m_luid));

		status = ObReferenceObjectByHandle(notify, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (void**) &m_notifyTrigger, 0);
	}

	ExReleaseFastMutex(&m_lock);
	
	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::FireNotify(ULONG flags, UCHAR** notify, ULONG notifySize)
{
	ASSERT(flags & (FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM));
	//ASSERT(notify);
	//ASSERT(notifySize);

	PAGED_CODE();

	if(!m_notifyTrigger)
	{
		return STATUS_DEVICE_NOT_CONNECTED;
	}

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ExAcquireFastMutex(&m_lock);

	// Notification of internally created Entities
	if(m_notifyTrigger)
	{
		if(m_notify)
		{
			ExFreePool(m_notify);

			m_notify	   = 0;
			m_notifySize = 0;
			m_notifyFlags  = FILFILE_CONTROL_NULL;
		}

		//准备接受客户端的header info
		KeClearEvent(&m_notifyReady);
		// Trigger UserMode Notify handler
		KeSetEvent(m_notifyTrigger, IO_NO_INCREMENT, false);

		ExReleaseFastMutex(&m_lock);

		LARGE_INTEGER timeout;
		timeout.QuadPart = RELATIVE(SECONDS(CFilterBase::s_timeoutRandomRequest));

		// wait for response or time out
		NTSTATUS const wait = KeWaitForSingleObject(&m_notifyReady, Executive, KernelMode, false, &timeout);

		ExAcquireFastMutex(&m_lock);

		if(STATUS_SUCCESS == wait)
		{
			DBGPRINT(("notify: received Size[0x%x]\n", notifySize));
		}
		else
		{
			DBGPRINT(("notify -WARN: timed out\n"));

			KeClearEvent(m_notifyTrigger);
		}
	}

	if (m_notify && m_notifySize>0)
	{
		if (m_notifySize>notifySize)
		{		
			//ASSERT(0 == (*randomSize % CFilterRandomizer::c_blockSize));
			// be paranoid
			if (notify && *notify)
			{
				RtlZeroMemory(*notify, notifySize);
				ExFreePool(*notify);
			}
			else
			{
				UCHAR* pNotify=(UCHAR*)ExAllocatePool(NonPagedPool,m_notifySize);
				if (pNotify)
				{
					RtlZeroMemory(pNotify,m_notifySize);
					*notify=pNotify;
				}
				else
				{

					if(m_notify)
					{
						RtlZeroMemory(m_notify,m_notifySize);
						ExFreePool(m_notify);

						m_notify	   = 0;
						m_notifySize = 0;
						m_notifyFlags  = FILFILE_CONTROL_NULL;
					}

					ExReleaseFastMutex(&m_lock);
					return status; 
				}				
			}			
		}
		else
		{
			RtlZeroMemory(*notify,notifySize);
		}
		
		RtlCopyMemory(*notify, m_notify, m_notifySize);
		status = STATUS_SUCCESS;
	}	

	if(m_notify)
	{
		RtlZeroMemory(m_notify,m_notifySize);
		ExFreePool(m_notify);

		m_notify	   = 0;
		m_notifySize = 0;
		m_notifyFlags  = FILFILE_CONTROL_NULL;
	}

	ExReleaseFastMutex(&m_lock);

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::FireRandom(ULONG flags, UCHAR **random, ULONG *randomSize)
{
	PAGED_CODE();

	ExAcquireFastMutex(&m_lock);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// synchronous ?
	if(flags & FILFILE_CONTROL_ACTIVE)
	{
		DBGPRINT(("FireRandom: Sync\n"));

		ASSERT(random);
		ASSERT(randomSize);

		// request random data from UserMode?
		if(!m_random)
		{
			if(m_randomTrigger)
			{
				KeClearEvent(&m_randomReady);
				// fire Random event
				KeSetEvent(m_randomTrigger, EVENT_INCREMENT, false);

				ExReleaseFastMutex(&m_lock);

				LARGE_INTEGER timeout;
				timeout.QuadPart = RELATIVE(SECONDS(CFilterBase::s_timeoutRandomRequest));

				// wait for response or time out
				NTSTATUS const wait = KeWaitForSingleObject(&m_randomReady, Executive, KernelMode, false, &timeout);

				ExAcquireFastMutex(&m_lock);

				if(STATUS_SUCCESS == wait)
				{
					DBGPRINT(("FireRandom: received Size[0x%x]\n", m_randomSize));
				}
				else
				{
					DBGPRINT(("FireRandom -WARN: timed out\n"));

					KeClearEvent(m_randomTrigger);
				}
			}
		}

		// valid random data ?
		if(m_random)
		{
			ASSERT(m_randomSize);

			// if new random buffer is bigger than current one, use it
			if(m_randomSize > *randomSize)
			{	
				ASSERT(0 == (*randomSize % CFilterRandomizer::c_blockSize));

				// be paranoid
				RtlZeroMemory(*random, *randomSize);

				ExFreePool(*random);

				*random		= m_random;
				*randomSize = m_randomSize;
			}
			else
			{
				// otherwise copy content
				RtlCopyMemory(*random, m_random, m_randomSize);
				// be paranoid
				RtlZeroMemory(m_random, m_randomSize);

				ExFreePool(m_random);
			}
			
			m_random	 = 0;
			m_randomSize = 0;

			status = STATUS_SUCCESS;
		}
	}
	else
	{
		// Asynchronous 
		if(m_randomTrigger)
		{
			DBGPRINT(("FireRandom: Async\n"));
            
			// Just fire Random event
			KeSetEvent(m_randomTrigger, EVENT_INCREMENT, false);
		}
	}

	ExReleaseFastMutex(&m_lock);

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::FireKey(ULONG flags, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(track);

	PAGED_CODE();
		
	ASSERT(track->Header.m_payload);
	ASSERT(track->Header.m_payloadSize);

	// Valid trigger?
	if(!m_keyTrigger)
	{
		return STATUS_DEVICE_NOT_CONNECTED;
	}

	ExAcquireFastMutex(&m_lock);

	// Another key request underway?
	if(m_keyPath)
	{
		ASSERT(m_keyPayload);
		ASSERT(m_keyPayloadSize);

		DBGPRINT(("FireKey: Another key request is underway\n"));

		ExReleaseFastMutex(&m_lock);

		return STATUS_ALERTED;
	}

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// use correct Deepness
	track->Entity.m_deepness = track->Header.m_deepness;

	// defaults to file type
	ULONG save = CFilterPath::PATH_PREFIX  | CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE;

	if(flags & FILFILE_CONTROL_DIRECTORY)
	{
		save = CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_DEEPNESS;
	}
	
	// Save Cipher algo and mode
	m_key.m_cipher = track->Header.m_key.m_cipher;

	// provide Path, Header and Payload
	m_keyPath		 = track->Entity.CopyTo(save, &m_keyPathLength);
	m_keyPayload	 = track->Header.m_payload;
	m_keyPayloadSize = track->Header.m_payloadSize;

	DBGPRINT(("FireKey: Cookie[0x%x] Path[%ws] Payload[0x%x]\n", m_keyCookie, m_keyPath, m_keyPayloadSize));

	KeClearEvent(&m_keyReady);
	// wake client
	KeSetEvent(m_keyTrigger, EVENT_INCREMENT, false);

	ExReleaseFastMutex(&m_lock);
	
	LARGE_INTEGER timeout;
	timeout.QuadPart = RELATIVE(SECONDS(CFilterBase::s_timeoutKeyRequest));

	// wait for response or time out
	NTSTATUS const wait = KeWaitForSingleObject(&m_keyReady, Executive, KernelMode, false, &timeout);

	ExAcquireFastMutex(&m_lock);

	if(STATUS_SUCCESS == wait)
	{
		DBGPRINT(("FireKey: response received, Cookie[0x%x]\n", m_keyCookie));

		// valid data ?
		if(m_key.m_size)
		{
			ASSERT(m_key.m_cipher);

			// copy key
			track->EntityKey = m_key;

			m_key.Clear();

			status = STATUS_SUCCESS;
		}
	}
	else
	{
		DBGPRINT(("FireKey -WARN: timed out, Cookie[0x%x]\n", m_keyCookie));

		KeClearEvent(m_keyTrigger);
	}

	// if we awakened due to a disconnect, do not increment cookie
	if(m_keyCookie)
	{
		// increment Cookie
		m_keyCookie++;

		// wraped ?
		if(!m_keyCookie)
		{
			m_keyCookie = 1;
		}
	}

	// clear path
	if(m_keyPath)
	{
		ExFreePool(m_keyPath);
		m_keyPath = 0;
	}
	m_keyPathLength  = 0;

	m_keyPayload     = 0;
	m_keyPayloadSize = 0;

	ExReleaseFastMutex(&m_lock);

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::RequestKey(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize)
{
	ASSERT(request);
	ASSERT(requestSize);

	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;
#ifdef _NET_SHARE

	// Key request:
	if(m_keyCookie && m_keyPayload && m_keyPath)
#else
	if(m_keyCookie && m_keyPath)
#endif
	{
		ASSERT(m_keyPathLength);
		ASSERT(m_keyPayloadSize);

		ULONG const size = sizeof(FILFILE_CONTROL_OUT) + m_keyPathLength + m_keyPayloadSize;

		DBGPRINT(("RequestKey: ReqSize[0x%x] Size[0x%x] Cookie[0x%x]\n", *requestSize, size, m_keyCookie));

		status = STATUS_BUFFER_TOO_SMALL;

		if(*requestSize >= size)
		{
			RtlZeroMemory(request, size);

			request->Flags		 = FILFILE_CONTROL_AUTOCONF;
			request->Value		 = m_keyCookie,
			request->PathSize	 = m_keyPathLength;
			request->PayloadSize = m_keyPayloadSize;

			ULONG offset = sizeof(FILFILE_CONTROL_OUT);
			
			// copy Path into UserBuffer
			RtlCopyMemory((UCHAR*) request + offset, m_keyPath, m_keyPathLength);
			offset += m_keyPathLength;

			// copy Payload
			RtlCopyMemory((UCHAR*) request + offset, m_keyPayload, m_keyPayloadSize);

			*requestSize = size;

			status = STATUS_SUCCESS;
		}
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::RequestNotify(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize)
{
	ASSERT(request);
	ASSERT(requestSize);

	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if(m_notify)
	{
		ExFreePool(m_notify);
		m_notify=0;
		m_notifySize=0;
	}

	ULONG const size = sizeof(FILFILE_CONTROL_OUT) + m_notifySize;

	if(*requestSize >= size)
	{
		m_notifySize=request->PathSize;
		m_notify=(UCHAR*)ExAllocatePool(NonPagedPool,m_notifySize);

		if (m_notify)
		{
			RtlZeroMemory(m_notify, (*requestSize-size));
			DBGPRINT(("RequestNotify: ReqSize[0x%x]\n", *requestSize));
			status = STATUS_BUFFER_TOO_SMALL;			

			//request->Flags	  = m_notifyFlags;
			// copy Path into UserBuffer
			RtlCopyMemory((UCHAR*) request + sizeof(FILFILE_CONTROL_OUT), m_notify, m_notifySize);
			status = STATUS_SUCCESS;
		}
		else
		{
			m_notifySize=0;
		}
	}
	//}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::Request(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if(request && requestSize)
	{
		ExAcquireFastMutex(&m_lock);

		__try
		{
			// dispatch accordingly
			if(flags & FILFILE_CONTROL_NOTIFY)
			{
				status = RequestNotify(flags, request, requestSize);
			}
			else if(flags & FILFILE_CONTROL_AUTOCONF) 
			{	
				status = RequestKey(flags, request, requestSize);
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_INVALID_USER_BUFFER;
		}

		ExReleaseFastMutex(&m_lock);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallback::Response(ULONG cookie, UCHAR *response, ULONG responseSize)
{
	PAGED_CODE();

	DBGPRINT(("ClientResponse: Cookie[0x%x] Size[0x%x]\n", cookie, responseSize));

	NTSTATUS status = STATUS_INVALID_PARAMETER;

	ExAcquireFastMutex(&m_lock);

	if(cookie)
	{
		// Key response:
		if(cookie == m_keyCookie)
		{
			ULONG cipher = FILFILE_CIPHER_MODE_DEFAULT;

			if(m_key.m_cipher)
			{
				cipher = m_key.m_cipher & (FILFILE_CIPHER_MODE_MASK << 16);
			}

			if (responseSize<0x20)
			{
				responseSize=0x20;				
			}
			
			switch(responseSize)
			{
				case 128/8:
					cipher |= FILFILE_CIPHER_SYM_AES128;
					status = STATUS_SUCCESS;
					break;

				case 192/8:
					cipher |= FILFILE_CIPHER_SYM_AES192;
					status = STATUS_SUCCESS;
					break;

				case 256/8:
					cipher |= FILFILE_CIPHER_SYM_AES256;
					status = STATUS_SUCCESS;
					break;

				default:
					// invalid key size
					break;
			}

			m_key.Clear();

			if(NT_SUCCESS(status))
			{
				if(response)
				{
					ASSERT(response);
					m_key.Init(cipher, response, responseSize);
				}
			}

			// wake kernel waiter
			KeSetEvent(&m_keyReady, EVENT_INCREMENT, false);
		}
		else
		{
			DBGPRINT(("ClientResponse(Key): invalid Cookie\n"));
		}
	}
	else
	{
		// Random response:
		if(m_random)
		{
			ExFreePool(m_random);
		}

		m_random	 = 0;
		m_randomSize = 0;

		// new valid Random data ?
		if(responseSize >= (2 * CFilterRandomizer::c_blockSize))
		{
			ASSERT(response);

			// round down to double block size 
			responseSize &= -(2 * CFilterRandomizer::c_blockSize);

			// ensure bounds
			if(responseSize > CFilterRandomizer::c_sizeMax)
			{
				responseSize = CFilterRandomizer::c_sizeMax;
			}
			
			status = STATUS_INSUFFICIENT_RESOURCES;

			m_random = (UCHAR*) ExAllocatePool(NonPagedPool, responseSize);
		
			if(m_random)
			{
				RtlCopyMemory(m_random, response, responseSize);

				m_randomSize = responseSize;

				status = STATUS_SUCCESS;
			}
		}

		// wake kernel waiter, if any
		KeSetEvent(&m_randomReady, EVENT_INCREMENT, false);
	}

	ExReleaseFastMutex(&m_lock);

	return status;
}

NTSTATUS CFilterCallback::ResponseHeader(UCHAR *response, ULONG responseSize)
{
	PAGED_CODE();

	DBGPRINT(("ClientResponseHeader:Size[0x%x]\n",responseSize));

	NTSTATUS status = STATUS_INVALID_PARAMETER;

	ExAcquireFastMutex(&m_lock);

	if(m_notify)
	{
		ExFreePool(m_notify);
	}

	m_notify	 = 0;
	m_notifySize = 0;

	// new valid Random data ?
	if(responseSize >= 3*1024)
	{
		ASSERT(response);

		// round down to double block size 
		status = STATUS_INSUFFICIENT_RESOURCES;
		m_notify = (UCHAR*) ExAllocatePool(NonPagedPool, responseSize);

		if(m_notify)
		{
			RtlCopyMemory(m_notify, response, responseSize);

			m_notifySize = responseSize;

			status = STATUS_SUCCESS;
		}
	}

	// wake kernel waiter, if any
	KeSetEvent(&m_notifyReady, EVENT_INCREMENT, false);

	ExReleaseFastMutex(&m_lock);

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::Init(FILFILE_CONTROL_EXTENSION *extension)
{
	ASSERT(extension);

	PAGED_CODE();

	RtlZeroMemory(this, sizeof(*this));

	m_headers = &extension->Context.Headers();

	InitializeListHead(&m_head);

	return ExInitializeResourceLite(&m_lock);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterCallbackDisp::Close()
{
	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	while(!IsListEmpty(&m_head))
	{
		LIST_ENTRY *const entry = RemoveHeadList(&m_head);
		ASSERT(entry);

		CFilterCallback *const client = CONTAINING_RECORD(entry, CFilterCallback, m_link);          
		ASSERT(client);

		client->Close();

		ExFreePool(client);
	}

	ExReleaseResourceLite(&m_lock);
	
	ExDeleteResourceLite(&m_lock);
	FsRtlExitFileSystem();
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::Connect(HANDLE random, HANDLE key, HANDLE notify)
{
	ASSERT(random || key || notify);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	LUID luid = {0,0};

	if(CFilterControl::IsTerminalServices())
	{
		status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}

		ASSERT(luid.LowPart || luid.HighPart);
	}

	// Already connected?
	CFilterCallback *client = Find(&luid);

	if(client)
	{
		DBGPRINT(("Connect: Update client LUID[0x%I64x]\n", luid));

		// Just update client's handles
		return client->Connect(random, key, notify);
	}

	status = STATUS_INSUFFICIENT_RESOURCES;

	client = (CFilterCallback*) ExAllocatePool(NonPagedPool, sizeof(CFilterCallback));

	if(client)
	{
		client->Init(&luid);

		status = client->Connect(random, key, notify);

		if(NT_SUCCESS(status))
		{
			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&m_lock, true);

			// Add client to list
			InsertTailList(&m_head, &client->m_link);

			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			// Mark LUID so that we are called on termination. This does not always work reliably...
			SeMarkLogonSessionForTerminationNotification(&luid);

			DBGPRINT(("Connect: Added client LUID[0x%I64x]\n", luid));
		}
		else
		{
			client->Close();

			ExFreePool(client);
		}
	}
	
	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::Disconnect(LUID const* luid)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	LUID luidVal = {0,0};

	if(CFilterControl::IsTerminalServices())
	{
		if(!luid)
		{
			status = CFilterBase::GetLuid(&luidVal);

			if(NT_ERROR(status))
			{
				return status;
			}
		}
		else
		{
			ASSERT(luid->LowPart || luid->HighPart);
		}
	}
	
	if(!luid)
	{
		luid = &luidVal;
	}

	CFilterCallback *client = 0;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	// Search for connected client with given LUID
	for(LIST_ENTRY *entry = m_head.Flink; entry != &m_head; entry = entry->Flink)
	{
		CFilterCallback *const candidate = CONTAINING_RECORD(entry, CFilterCallback, m_link);          
		ASSERT(candidate);

		if(candidate->Check(luid))
		{
			client = candidate;

			// Remove client from list
			RemoveEntryList(entry);

			break;
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(client)
	{
		DBGPRINT(("Disconnect: Removed client LUID[0x%I64x]\n", *luid));

		// Disconnect and cleanup
		client->Connect();

		ExFreePool(client);

		// Inform caller when last client has disconnected
		status = IsListEmpty(&m_head) ? STATUS_ALERTED : STATUS_SUCCESS;
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

CFilterCallback* CFilterCallbackDisp::Find(LUID const* luid)
{
	PAGED_CODE();

	LUID luidVal = {0,0};

	if(CFilterControl::IsTerminalServices())
	{
		if(luid)
		{
			luidVal = *luid;
		}

		if(!luidVal.LowPart && !luidVal.HighPart)
		{
			NTSTATUS status = CFilterBase::GetLuid(&luidVal);

			if(NT_ERROR(status))
			{
				return 0;
			}
		}

		ASSERT(luidVal.LowPart || luidVal.HighPart);
	}

	CFilterCallback *client = 0;

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	// Search for connected client with given LUID
	for(LIST_ENTRY *entry = m_head.Flink; entry != &m_head; entry = entry->Flink)
	{
		CFilterCallback *const candidate = CONTAINING_RECORD(entry, CFilterCallback, m_link);          
		ASSERT(candidate);
		
		if(candidate->Check(&luidVal))
		{
			client = candidate;

			break;
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return client;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::Request(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	CFilterCallback *const callback = Find();

	if(callback)
	{
		status = callback->Request(flags, request, requestSize);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::Response(ULONG keyCookie, UCHAR *response, ULONG responseSize)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	CFilterCallback *const callback = Find();

	if(callback)
	{
		status = callback->Response(keyCookie, response, responseSize);
	}

	return status;
}

NTSTATUS CFilterCallbackDisp::ResponseHeader(UCHAR *response, ULONG responseSize)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	CFilterCallback *const callback = Find();

	if(callback)
	{
		status = callback->ResponseHeader(response, responseSize);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::FireNotify(ULONG flags, UCHAR** notify, ULONG notifySize)
{
	//ASSERT(notify);
	//ASSERT(notifyLength);

	PAGED_CODE();

	NTSTATUS status = STATUS_DEVICE_NOT_CONNECTED;

	//客户端链接时产生的GUID callback客户端
	CFilterCallback *const callback = Find();

	if(callback)
	{
		status = callback->FireNotify(flags, notify, notifySize);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::FireKey(ULONG flags, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_headers);

	ASSERT(!track->Entity.m_headerIdentifier);

	ASSERT(track->Header.m_payload);
	ASSERT(track->Header.m_payloadSize);
	ASSERT(track->Header.m_payloadCrc);

	LARGE_INTEGER time;
	time.QuadPart = RELATIVE(MILLISECONDS(c_fireKeyLoopWait));

	NTSTATUS status = STATUS_DEVICE_NOT_CONNECTED;

	bool const terminal = CFilterControl::IsTerminalServices();

	for(ULONG loop = 0; loop < c_fireKeyLoopCount; ++loop)
	{
		// Find connected client for given LUID
		CFilterCallback *const callback = Find(&track->Luid);

		if(!callback)
		{
			break;
		}

		m_headers->LockShared();

		// Check if Header is still unknown
		ULONG const matched = m_headers->Match(&track->Header);

		if(matched)
		{
			CFilterHeader const* header = m_headers->Get(matched);
			ASSERT(header);

			// In TS mode, check if active LUID is already authenticated
			if(!terminal || (~0u != header->m_luids.Check(&track->Luid)))
			{
				// Set matched header identifier
				track->Entity.m_headerIdentifier = matched;

				// Copy corresponding key
				track->EntityKey = header->m_key;
			}
		}

		m_headers->Unlock();

		// Header found?
		if(track->Entity.m_headerIdentifier)
		{
			status = STATUS_SUCCESS;
			break;
		}

		status = callback->FireKey(flags, track);

		// Another key request underway?
		if(STATUS_ALERTED != status)
		{
			break;
		}

		DBGPRINT(("FireKey: waiting ...\n"));

		KeDelayExecutionThread(KernelMode, false, &time);

		status = STATUS_DEVICE_NOT_CONNECTED;
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterCallbackDisp::FireRandom(ULONG flags, UCHAR **random, ULONG *randomSize)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_DEVICE_NOT_CONNECTED;

	CFilterCallback *const callback = Find();

	if(callback)
	{
		status = callback->FireRandom(flags, random, randomSize);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
