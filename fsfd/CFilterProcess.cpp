///////////////////////////////////////////////////////////////////////////////
//
// CFilterProcess.cpp: implementation of the CFilterProcess class.
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterEngine.h"
#include "CFilterProcess.h"
#include "CFilterControl.h"

#ifndef _PSSETCREATEPROCESS_H
#define _PSSETCREATEPROCESS_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

	NTSTATUS PsSetCreateProcessNotifyRoutineMustSuccess(IN PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
												   IN BOOLEAN Remove
		                                            );

#ifdef __cplusplus
}
#endif // __cplusplus

#endif


///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterProcess::CFilterProcessEntry::Init(ULONG pid,UNICODE_STRING const* image)
{
	ASSERT(pid);
	//ASSERT(image);

	PAGED_CODE();

	//空间初始化0
	RtlZeroMemory(this, sizeof(*this));

	m_image=NULL;
	m_pid = pid;
	m_state=0;
	m_imageLength=0;
	
	if (image)
	{
		//劈分最后的路径
		// Separate last path component
		ULONG pos = image->Length / sizeof(WCHAR);
		ASSERT(pos);

		while(--pos)
		{
			if(image->Buffer[pos] == L'\\')
			{
				break;
			}
		}

		ASSERT(pos);
		ASSERT(image->Length > (pos * sizeof(WCHAR)));

		ULONG length = image->Length - (pos * sizeof(WCHAR));

		m_image = (LPWSTR) ExAllocatePool(PagedPool, length);

		if(!m_image)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		length -= sizeof(WCHAR);

		// Save image name 
		RtlCopyMemory(m_image, image->Buffer + pos + 1, length);

		m_imageLength = length;

		m_image[length / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterProcess::CFilterProcessEntry::Close()
{
	PAGED_CODE();

	if(m_image)
	{
		ExFreePool(m_image);
	}

	if (m_link)
	{
		m_link->m_fileKey.Clear();
		ExFreePool(m_link);
		m_link=NULL;
	}

	RtlZeroMemory(this, sizeof(*this));
}

NTSTATUS    CFilterProcess::CFilterProcessEntry::AddLink(ULONG pid,CFilterContextLink* newlink)
{
	//ASSERT(pid);
	NTSTATUS status=STATUS_SUCCESS;

	if (pid)
	{
		m_pid=pid;
	}

	if (m_link)
	{
		m_link->m_fileKey.Clear();
		ExFreePool(m_link);
		m_link=NULL;
	}

	m_link=newlink;

	return status;
}

bool   CFilterProcess::CFilterProcessEntry::GetLink(CFilterContextLink* link)
{
	bool bHas=true;
	if (link)
	{
		RtlZeroMemory(link,sizeof(CFilterContextLink));
		RtlCopyMemory(link,m_link,sizeof(CFilterContextLink));
	}
	else
	{
		bHas=false;
	}
	return bHas;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// STATICS

CFilterProcess *CFilterProcess::s_instance = 0;
ULONG CFilterProcess::s_ulParentPid=0u;
CFilterContextLink* s_Cryptolink=0;

///////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterProcess::Init()
{
	//空间初始化0
	RtlZeroMemory(this, sizeof(*this));

	NTSTATUS status = ExInitializeResourceLite(&m_lock);

	if(NT_SUCCESS(status))
	{
		// Register our notify handlers as early as possible because
		// the system only supports a maximum of eight.
		status = PsSetCreateProcessNotifyRoutineMustSuccess(Notify, false);

	//	if(NT_SUCCESS(status))
	//	{
			//status = PsSetLoadImageNotifyRoutine(LoadImage);	

			if(NT_SUCCESS(status))
			{
				// Enable tracker
				s_instance = this;
				s_ulParentPid=0u;
				m_size=0;
				m_capacity=0;
			}
			else
			{
				// Unregister in case of error
				PsSetCreateProcessNotifyRoutineMustSuccess(Notify, true);
			}
	//	}
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterProcess::Close(bool destroy)
{
	PAGED_CODE();
	
	FsRtlEnterFileSystem();

	

	if(m_entries)
	{
		ASSERT(m_size <= m_capacity);
		ExAcquireResourceExclusiveLite(&m_lock, true);

		for(ULONG pos = 0; pos < m_size; ++pos)
		{
			m_entries[pos].Close();
		}

		ExFreePool(m_entries);
		m_entries = 0;

		m_size	   = 0;
		m_capacity = 0;

		ExReleaseResourceLite(&m_lock);
	}

	if(destroy)
	{
		// Unregister our callbacks
		s_instance = 0;
		PsSetCreateProcessNotifyRoutineMustSuccess(Notify, true);

	#if DBG
		// Hmm, just the following function is not available
		// on Windows 2000, whereas the others are.
		// PsRemoveLoadImageNotifyRoutine(LoadImage);
	#endif
	
 		ExDeleteResourceLite(&m_lock);
	}

	FsRtlExitFileSystem();
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterProcess::MarkForTermination(ULONG pid, bool enable)
{
	ASSERT(pid);

	PAGED_CODE();

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	ULONG pos = ~0u;

	if(Search(pid, &pos))
	{
		ASSERT(pos < m_size);
		ASSERT(m_entries);

		m_entries[pos].m_state = (enable) ? 1 : 0;

		status = STATUS_SUCCESS;
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterProcess::Search(ULONG pid, ULONG *pos)
{
	
	PAGED_CODE();
	//ExAcquireResourceSharedLite(&m_seachLock, true);
	if (m_entries)
	{
		ASSERT(pid);
		ASSERT(m_entries);
		ASSERT(m_size <= m_capacity);
#if DBG
		{
			// Verify binary search property
			for(ULONG index = 0; index + 1 < m_size; ++index)
			{
				if(m_entries[index].m_pid >= m_entries[index + 1].m_pid)
				{
					ASSERT(TRUE);
				}
			}
		}
#endif
		if (m_size==0)
		{
			*pos=0;
		//	ExReleaseResourceLite(&m_seachLock);
			return false;
		}

		ULONG left  = 0;
		ULONG right = m_capacity;
		ULONG uPos=0;

		// Binary Search
		while(left < right)
		{
			ASSERT(m_entries);

			if(m_entries[left].m_pid>0 && m_entries[left].m_pid == pid)
			{
				*pos=left;
				//ExReleaseResourceLite(&m_seachLock);
				return true;
			}
			else if(m_entries[left].m_pid<=0)
			{
				if(pos)
				{
					if (*pos==~0u)
					{
						*pos=left;
					}
				}
			}
			else if(m_entries[left].m_pid>0)
			{
				uPos++;
			}

			if (uPos>=m_size)
			{
				if (*pos!=~0u)
				{
					break;
				}				
			}
			left++;
		}
	}
//	ExReleaseResourceLite(&m_seachLock);
	return false;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterProcess::Add(ULONG pid, UNICODE_STRING const* image)
{
	ASSERT(pid);
	//ASSERT(image);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	ULONG pos = ~0u;

	if(Search(pid, &pos))
	{
		ASSERT(pos < m_size);

		// Ignore it. This is usually the case for Dlls
		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();

		return STATUS_OBJECT_NAME_COLLISION;
	}

	//ASSERT(pos != ~0u);

	//内存池的容量 用完 则重新分配一个新的内存池
	if(m_capacity == m_size)
	{
		ULONG const capacity = m_capacity + c_incrementCount;

		CFilterProcessEntry *entries = (CFilterProcessEntry*) ExAllocatePool(PagedPool, 
																			 capacity * sizeof(CFilterProcessEntry));
		if(!entries)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		//初始化进程过滤链表
		RtlZeroMemory(entries, capacity * sizeof(CFilterProcessEntry));

		m_capacity = capacity;	

		if(m_size)
		{
			ASSERT(m_entries);
			//复制原始过滤链表的内容到新的链表中
			RtlCopyMemory(entries, m_entries, m_size * sizeof(CFilterProcessEntry));
			//释放原始过滤链表
			ExFreePool(m_entries);
		}
		//新的过滤链表建立
		m_entries = entries;
	}

	///ASSERT(pos <= m_size);
	ASSERT(m_entries);
	NTSTATUS status=STATUS_SUCCESS;

	if (pos!=~0u && pos<m_capacity)
	{
		status = m_entries[pos].Init(pid, image);

		if(NT_SUCCESS(status))
		{
			m_size++;
		}
	}


	//if(pos < m_size)
	//{
	//	RtlMoveMemory(m_entries + pos + 1, 
		//			  m_entries + pos, 
		//			  (m_size - pos) * sizeof(CFilterProcessEntry));
	//}
	
	

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return status;
}

#pragma  PAGEDCODE

NTSTATUS CFilterProcess::AddFilterLink(ULONG pid,CFilterContextLink* link)
{
	ASSERT(pid);
	ASSERT(link);
	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);
	NTSTATUS status=STATUS_SUCCESS;

	if (pid)
	{


		ULONG pos = ~0u;

		if(!Search(pid, &pos))
		{
			ASSERT(pos < m_size);

			// Ignore it. This is usually the case for Dlls
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();

			return STATUS_OBJECT_NAME_COLLISION;
		}


		CFilterContextLink* linknew=NULL;
		if (link)
		{		
			linknew= (CFilterContextLink*) ExAllocatePool(PagedPool,sizeof(CFilterContextLink));

			if(!linknew)
			{
				ExReleaseResourceLite(&m_lock);
				FsRtlExitFileSystem();

				return STATUS_INSUFFICIENT_RESOURCES;
			}

			//初始化进程过滤链表
			RtlZeroMemory(linknew,sizeof(CFilterContextLink));
			ASSERT(link);
			RtlCopyMemory(linknew, link, sizeof(CFilterContextLink));
		}

		ASSERT(m_entries);
		if (m_entries)
		{
			m_entries[pos].AddLink(pid,linknew);
		}
	}
	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();
	
	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterProcess::Remove(ULONG pid)
{
	ASSERT(pid);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_lock, true);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	ASSERT(m_size <= m_capacity);

	ULONG pos = ~0u;

	bool terminate = false;

	// Search for pid
	if(Search(pid, &pos))
	{

		if (pos!=~0u && pos<m_capacity)
		{
			ASSERT(pos < m_capacity);
			ASSERT(m_entries);

			DBGPRINT(("CFilterProcess: Remove PID[0x%x] [%ws]\n", pid, m_entries[pos].m_image));

			// Marked for manual termination?
			if(m_entries[pos].m_state)
			{
				terminate = true;
			}

			m_entries[pos].Close();

			m_size--;

		//	if(pos < m_size)
		//	{
		//		RtlMoveMemory(m_entries + pos, 
			//		m_entries + pos + 1, 
			//		(m_size - pos) * sizeof(CFilterProcessEntry));
		///	}

		//	RtlZeroMemory(m_entries + m_size, sizeof(CFilterProcessEntry));		

			status = STATUS_SUCCESS;
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	if(terminate)
	{
		// Call our Logon Termination manually for cleanup
		CFilterEngine::LogonTermination();
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

LPCWSTR	CFilterProcess::Find(ULONG pid, ULONG *imageLength)
{
	ASSERT(pid);
	ASSERT(imageLength);

	PAGED_CODE();

	// Lock must be held

	ULONG pos = ~0u;

	if(Search(pid, &pos))
	{
		ASSERT(m_entries);
		ASSERT(pos < m_size);

		*imageLength = m_entries[pos].m_imageLength;

		return m_entries[pos].m_image;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE
bool  CFilterProcess::IsTrustProcess(IRP *irp)
{
	ASSERT(irp);
	PAGED_CODE();

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);

	bool bTrust=false;
	ULONG const pid = IoGetRequestorProcessId(irp);

	if(pid)
	{
		if (s_instance->s_ulParentPid >0 && pid==s_instance->s_ulParentPid)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();
			return true;
		}

		if (s_instance->s_ulParentPid<=0)
		{
			ExReleaseResourceLite(&m_lock);
			FsRtlExitFileSystem();
			return false;
		}


		if(m_entries)
		{
			ULONG left  = 0;
			ULONG right = m_capacity;
			ULONG uPos=0;

			// Binary Search
			while(left < right)
			{
				ASSERT(m_entries);
				//ULONG const middle = left + (right - left) / 2;

				if(m_entries[left].m_pid>0 && m_entries[left].m_pid == pid)
				{
					bTrust=true;
					break;
				}
				else if(m_entries[left].m_pid>0)
				{
					uPos++;
				}

				if (uPos>=m_size)
				{
					break;
				}

				left++;
			}
		}
	}
	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();
	return bTrust;
}


#pragma PAGEDCODE

bool CFilterProcess::GetFilterLink(ULONG pid,CFilterContextLink* link)
{

	ASSERT(pid);
	ASSERT(link);
	PAGED_CODE();
	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&m_lock, true);
	bool bTrust=false;
	if (pid)
	{
		ULONG pos = ~0u;

		if(Search(pid, &pos))
		{
			ASSERT(m_entries);
			if (m_entries)
			{
				bTrust=m_entries[pos].GetLink(link);
			}
		}
	}

	ExReleaseResourceLite(&m_lock);
	FsRtlExitFileSystem();

	return bTrust;
}


#pragma PAGEDCODE

bool CFilterProcess::Match(IRP *irp, UNICODE_STRING *image)
{
	ASSERT(irp);
	ASSERT(image);

	PAGED_CODE();

	ASSERT(image->Buffer);
	ASSERT(image->Length);
	
	ULONG const pid = IoGetRequestorProcessId(irp);

	bool matched = false;

	// Not system process?
	if(pid)
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_lock, true);

		ULONG pos = ~0u;

		if(Search(pid, &pos))
		{
			ASSERT(m_entries);
			ASSERT(pos < m_size);

			if(m_entries[pos].m_imageLength == image->Length)
			{
				if(!_wcsnicmp(m_entries[pos].m_image, 
							  image->Buffer, 
							  image->Length / sizeof(WCHAR)))
				{
					matched = true;
				}
			}
		}

		ExReleaseResourceLite(&m_lock);
		FsRtlExitFileSystem();
	}

	return matched;
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterProcess::Notify(HANDLE parent, HANDLE pid, BOOLEAN create)
{
	// Ignore creations as they were already catched by LoadImage()
	if(create)
	{
		if(s_instance)
		{
			if (s_ulParentPid>0 ) 
			{
				if (s_ulParentPid==(ULONG)(ULONG_PTR)parent)
				{
					s_instance->Add((ULONG)(ULONG_PTR) pid, NULL);
				}
				else
				{
					ULONG pos=~0u;
					if (s_instance->Search((ULONG)(ULONG_PTR)parent,&pos))
					{
						s_instance->Add((ULONG)(ULONG_PTR) pid, NULL);
					}					
				}
				
			}
		}
	}
	else
	{
		if(s_instance)
		{
			if (s_ulParentPid>0)
			{
				if (s_ulParentPid==(ULONG)(ULONG_PTR)pid)
				{
					s_instance->Close(false);
				}
				else
				{
					ULONG pos=~0u;
					if (s_instance->Search((ULONG)(ULONG_PTR)parent,&pos))
					{
						s_instance->Remove((ULONG)(ULONG_PTR) pid);
					}					
				}				
			}		
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterProcess::LoadImage(UNICODE_STRING *name, HANDLE pid, IMAGE_INFO *info)
{
	// Ignore driver binaries
	//if(pid)
	//{
		//if(s_instance)
		//{
			//s_instance->Add((ULONG)(ULONG_PTR) pid, name);
		//}
	//}
}
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
