////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterVolume.cpp: implementation of the CFilterVolume class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "IoControl.h"
#include "CFilterNormalizer.h"
#include "CFilterControl.h"
#include "CFilterContext.h"
#include "CFilterEngine.h"
#include "CFilterCipherManager.h"
#include "CFilterFile.h"
#include "CFilterDirectory.h"
#include "CFilterAppList.h"

#include "CFilterVolume.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::Init(FILFILE_VOLUME_EXTENSION *extension, ULONG volumeIdentifier)
{
	ASSERT(extension);

	PAGED_CODE();

	ASSERT(volumeIdentifier);

	m_extension		 = extension;
	m_nextIdentifier = volumeIdentifier << 24;

	m_context = &CFilterControl::Extension()->Context;

	m_entities.Init();
	m_negatives.Init();

	NTSTATUS status = ExInitializeResourceLite(&m_entitiesResource);

	if(NT_SUCCESS(status))
	{
		status = ExInitializeResourceLite(&m_negativesResource);
	}

	ASSERT(NT_SUCCESS(status));

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::Close()
{
	PAGED_CODE();

	// Discard Regulars
	RemoveEntities(ENTITY_REGULAR | ENTITY_DISCARD | ENTITY_ANYWAY);
	m_entities.Close();
	ExDeleteResourceLite(&m_entitiesResource);

	// Discard Negatives
	RemoveEntities(ENTITY_NEGATIVE | ENTITY_ANYWAY);
	m_negatives.Close();
	ExDeleteResourceLite(&m_negativesResource);

	m_context		 = 0;
	m_extension		 = 0;
	m_nextIdentifier = 0;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterVolume::IsRemoteRequest(FILFILE_TRACK_CONTEXT *track, IRP *createIrp)
{
	ASSERT(track);
	ASSERT(createIrp);

	PAGED_CODE();

	// not already initialized ?
	if(FILFILE_REQUESTOR_NULL == track->Requestor)
	{
		track->Requestor = FILFILE_REQUESTOR_USER;

		// system process ?
		if(PsGetCurrentProcess() == CFilterControl::Extension()->SystemProcess)
		{
			ASSERT(IoGetCurrentIrpStackLocation(createIrp)->MajorFunction == IRP_MJ_CREATE);

			IO_SECURITY_CONTEXT *ioSecurity = IoGetCurrentIrpStackLocation(createIrp)->Parameters.Create.SecurityContext;
			ASSERT(ioSecurity);

			PACCESS_TOKEN token = ioSecurity->AccessState->SubjectSecurityContext.ClientToken;

			if(!token)
			{
				token = ioSecurity->AccessState->SubjectSecurityContext.PrimaryToken;
			}

			ASSERT(token);

			if(token)
			{
				TOKEN_SOURCE *source = 0;

				// get requestor from token
				NTSTATUS status = SeQueryInformationToken(token, TokenSource, (void**) &source);

				if(NT_SUCCESS(status))
				{
					#if DBG
					{
						char temp[TOKEN_SOURCE_LENGTH + 1];
						
						RtlZeroMemory(temp, sizeof(temp));
						RtlCopyMemory(temp, source->SourceName, TOKEN_SOURCE_LENGTH);

						DBGPRINT(("IsRemoteRequest: TokenSource[%s]\n", temp));
					}
					#endif
					
					// try to match (case-insensitive) with well known token sources
					switch(*((ULONG*) source->SourceName) & 0xdfdfdfdf)
					{
						case 'MLTN':	// NtLmSsp
						case 'BREK':	// Kerberos
							track->Requestor = FILFILE_REQUESTOR_REMOTE;
							break;

						case 'SYS*':	// *SYSTEM*
							track->Requestor = FILFILE_REQUESTOR_SYSTEM;
							break;

						//case 'RESU':	// User32
						default:
							break;
					}

					ExFreePool(source);
				}
				else
				{
					DBGPRINT(("IsRemoteRequest -ERROR: SeQueryInformationToken() failed [0x%08x]\n", status));
				}
			}
		}
	}

	return (FILFILE_REQUESTOR_REMOTE == track->Requestor);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterVolume::IsSpecific(FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(track);

	PAGED_CODE();

	ASSERT(flags & (TRACK_AUTO_CONFIG | TRACK_SYSTEM | TRACK_IE_CACHE));

	CFilterPath const*const path = &track->Entity;

	if(flags & TRACK_SYSTEM)
	{
		// System device?
		if(m_extension->System)
		{
			ASSERT(0 == (path->m_flags & (TRACK_CIFS | TRACK_NETWARE | TRACK_WEBDAV)));

			UNICODE_STRING const*const systemPath = &CFilterControl::Extension()->SystemPath;

			// Skip system path, usually at [\WINDOWS]
			if(systemPath->Buffer && path->m_volume)
			{
				ASSERT(systemPath->Length);
				ASSERT(path->m_volumeLength);

				if(path->m_volumeLength + path->m_directoryLength + sizeof(WCHAR) >= systemPath->Length)
				{
					//LPCWSTR prefix = L"\\Device\\HarddiskVolume1\\Windows\\Temp";
					WCHAR prefix[128]={0};
					if (systemPath->Length<=128-5)
					{
						wcscpy(prefix,systemPath->Buffer);
						wcscat(prefix,L"temp");
					}
					else
					{
						wcscpy(prefix, L"\\Device\\HarddiskVolume1\\Windows\\Temp");
					}
					
					USHORT len2=(USHORT)wcslen(prefix);
					USHORT len3=(USHORT)wcslen(path->m_volume);
					if (len3>len2)
					{
						if (!_wcsnicmp(path->m_volume,prefix,len2))
						{
							return false;
						}
					}
					else
					{
						if(!_wcsnicmp(path->m_volume, systemPath->Buffer, systemPath->Length / sizeof(WCHAR)))
						{
							return true;
						}
					}					
				}
			}
		}
	}

	if((flags & TRACK_IE_CACHE) && !CFilterControl::s_transIEcache)
	{
		// System device?
		if(m_extension->System)
		{
			ASSERT(0 == (path->m_flags & (TRACK_CIFS | TRACK_NETWARE | TRACK_WEBDAV)));

			ULONG const dirLen = path->m_directoryLength / sizeof(WCHAR);

			// IE Cache location varies among versions, defaults to WXP, W2k, W2k3:
			LPCWSTR prefix = L"\\Documents and Settings\\";
			LPCWSTR suffix = L"\\Local Settings\\Temporary Internet Files\\Content.IE5\\";

			ULONG prefixLen = 24;
			ULONG suffixLen = 53;
			ULONG depth     = 5;

			if(CFilterControl::IsWindowsVistaOrLater())
			{
				prefix = L"\\Users\\";
				suffix = L"\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\";

				suffixLen = 70;
				prefixLen = 7;
				depth     = 8;
			}

			if(path->m_directoryDepth >= depth)
			{
				if((dirLen >= prefixLen + suffixLen) && !_wcsnicmp(path->m_directory, prefix, prefixLen))
				{
					ULONG index = prefixLen;

					// Skip over user name
					do
					{
						index++;
						ASSERT(index < dirLen);
					}
					while(path->m_directory[index] != L'\\');

					if((dirLen - index >= suffixLen - 1) &&	!_wcsnicmp(path->m_directory + index, suffix, suffixLen))
					{
						return true;
					}
				}
			}
		}
	}

	if(flags & TRACK_AUTO_CONFIG)
	{
		if(path->m_file)
		{
			if(path->m_fileLength == (g_filFileAutoConfigNameLength * sizeof(WCHAR)))
			{
				if(!_wcsnicmp(path->m_file, g_filFileAutoConfigName, g_filFileAutoConfigNameLength))
				{
					return true;
				}
			}
		}
	}
	
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::GetEntityInfo(ULONG identifier, CFilterEntity *target)
{
	ASSERT(identifier);
	ASSERT(target);

	PAGED_CODE();

	ASSERT(identifier != ~0u);

	NTSTATUS status = STATUS_NO_SUCH_DEVICE;

	// directed to this Volume ?
	if((identifier & 0xff000000) == (m_nextIdentifier & 0xff000000))
	{
		FsRtlEnterFileSystem();
		ExAcquireSharedStarveExclusive(&m_entitiesResource, true);

		CFilterEntity const*const entity = m_entities.GetFromIdentifier(identifier);

		if(entity)
		{
			target->m_deepness         = entity->m_deepness;
			target->m_directoryDepth   = entity->m_directoryDepth;
			target->m_flags			   = entity->m_flags & (TRACK_AUTO_CONFIG | TRACK_TYPE_RESOLVED);

			target->m_identifier	   = entity->m_identifier;
			target->m_headerIdentifier = entity->m_headerIdentifier;			
			target->m_headerBlocksize  = entity->m_headerBlocksize;			

			status = STATUS_SUCCESS;
		}

		ExReleaseResourceLite(&m_entitiesResource);
		FsRtlExitFileSystem();
	}
	else
	{
		DBGPRINT(("GetEntityInfo: identifier[0x%x] is from different Volume, search there\n", identifier));

		// identifier is from different Volume
		DEVICE_OBJECT *volume = 0;
		
		// get that Volume
		status = CFilterControl::GetVolumeDevice(identifier, &volume);

		if(NT_SUCCESS(status))
		{
			ASSERT(volume);
			
			FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
			ASSERT(extension);

			// ensure we have selected the right Volume
			ASSERT((extension->Volume.m_nextIdentifier & 0xff000000) == (identifier & 0xff000000));

			// recursively call ourself for different Volume
			status = extension->Volume.GetEntityInfo(identifier, target);

			ObDereferenceObject(volume);
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::UpdateEntity(ULONG identifier, CFilterPath *path)
{
	ASSERT(identifier);
	ASSERT(identifier != ~0u);

	ASSERT(path);

	PAGED_CODE();

	// Rename existing file Entity
	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

	CFilterEntity *const entity = m_entities.GetFromIdentifier(identifier);

	if(entity)
	{
		if(entity->GetType() == path->GetType())
		{
			// Preserve deepness
			ULONG const deepness = entity->m_deepness;

			// Exchange both Entities' paths
			entity->Swap(path);

			entity->m_deepness = deepness;
		}
	}

	ExReleaseResourceLite(&m_entitiesResource);
	FsRtlExitFileSystem();
	
	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::UpdateEntity(ULONG currIdentifier, ULONG newIdentifier)
{
	ASSERT(currIdentifier);
	ASSERT(currIdentifier != ~0u);

	ASSERT(newIdentifier);
	ASSERT(newIdentifier != ~0u);

	PAGED_CODE();

	DBGPRINT(("UpdateEntity: exchange[0x%08x] with[0x%08x]\n", currIdentifier, newIdentifier));

	// update all DIRECTORIES that reference this Entity
	if(m_context->m_directories.Size())
	{
		ExAcquireResourceExclusiveLite(&m_context->m_directoriesResource, true);

		ULONG const count = m_context->m_directories.Size();
		
		for(ULONG index = 0; index < count; ++index)
		{
			CFilterDirectory *const filterDirectory = m_context->m_directories.Get(index);
			ASSERT(filterDirectory);

			if(filterDirectory->m_entityIdentifier == currIdentifier)
			{
				filterDirectory->m_entityIdentifier = newIdentifier;
			}
		}

		ExReleaseResourceLite(&m_context->m_directoriesResource);
	}

	// update all FILES that reference this Entity
	if(m_context->m_files.Size())
	{
		ExAcquireResourceExclusiveLite(&m_context->m_filesResource, true);

		ULONG const count = m_context->m_files.Size();
		
		for(ULONG index = 0; index < count; ++index)
		{
			CFilterFile *const filterFile = m_context->m_files.Get(index);
			ASSERT(filterFile);

			if(filterFile->m_link.m_entityIdentifier == currIdentifier)
			{
				filterFile->m_link.m_entityIdentifier = newIdentifier;
			}
		}

		ExReleaseResourceLite(&m_context->m_filesResource);
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE 

NTSTATUS CFilterVolume::PurgeEntities(ULONG flags, LUID const* luid)
{
	ASSERT(flags & ENTITY_PURGE);
	ASSERT( !(flags & ENTITY_DISCARD));

	PAGED_CODE();

	#if DBG
	{
		if(CFilterControl::IsTerminalServices() && !(flags & ENTITY_ANYWAY))
		{
			ASSERT(luid);
			ASSERT(luid->HighPart || luid->LowPart);
		}
	}
	#endif

	if(flags & ENTITY_ANYWAY)
	{
		luid = 0;
	}
	
	ExAcquireResourceSharedLite(&m_entitiesResource, true);

	ULONG const count = m_entities.Size();

	if(!count)
	{
		ExReleaseResourceLite(&m_entitiesResource);

		return STATUS_SUCCESS;
	}

	ULONG *const identifiers = (ULONG*) ExAllocatePool(PagedPool, count * sizeof(ULONG));

	if(!identifiers)
	{
		ExReleaseResourceLite(&m_entitiesResource);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(identifiers, count * sizeof(ULONG));

	for(ULONG pos = 0; pos < count; ++pos)
	{
		CFilterEntity *const entity = m_entities.GetFromPosition(pos);
		ASSERT(entity);

		// Check LUID?
		if(luid)
		{
			if(entity->m_luids.Size() > 1)
			{
				continue;
			}
			if(~0u == entity->m_luids.Check(luid))
			{
				continue;
			}
		}

		ASSERT(entity->m_identifier);

		identifiers[pos] = entity->m_identifier;
	}

	ExReleaseResourceLite(&m_entitiesResource);

	// Purge without holding the lock
	for(ULONG pos = 0; pos < count; ++pos)
	{
		if(identifiers[pos])
		{
			m_context->Purge(identifiers[pos], ENTITY_PURGE);
		}
	}

	ExFreePool(identifiers);

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::RemoveEntities(ULONG flags, LUID const* luid)
{
	PAGED_CODE();

	#if DBG
	{
		if(CFilterControl::IsTerminalServices() && !(flags & ENTITY_ANYWAY))
		{
			ASSERT(luid);
			ASSERT(luid->HighPart || luid->LowPart);
		}
	}
	#endif

	NTSTATUS status = STATUS_SUCCESS;

	FsRtlEnterFileSystem();

	if(flags & ENTITY_NEGATIVE)
	{
		// Negative Entities
		if(m_negatives.Size())
		{
			ExAcquireResourceExclusiveLite(&m_negativesResource, true);

			for(LONG pos = m_negatives.Size() - 1; pos >= 0; --pos)
			{
				// In TS mode and if not ANYWAY mode, check for negative Entity's owner
				if(luid && !(flags & ENTITY_ANYWAY))
				{
					CFilterEntity *const neg = m_negatives.GetFromPosition(pos);
					ASSERT(neg);

					if(~0u == neg->m_luids.Check(luid))
					{
						// Not owned
						continue;
					}
				}

				m_negatives.RemoveRaw(pos, true);
			}

			ExReleaseResourceLite(&m_negativesResource);
		}
	}
	
	if(flags & ENTITY_REGULAR)
	{
		// Regular Entities
		if(m_entities.Size())
		{
			// Purge Entities?
			if(flags & ENTITY_PURGE)
			{
				PurgeEntities(flags, luid);

				// Purge only once
				flags &= ~ENTITY_PURGE;
			}

			// Remove Entities
			ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

			for(LONG pos = m_entities.Size() - 1; pos >= 0; --pos)
			{
				if(NT_ERROR(RemoveEntity((CFilterPath*) 0, luid, pos, flags)))
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			ExReleaseResourceLite(&m_entitiesResource);
		}
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::RemoveEntity(ULONG identifier, ULONG type, ULONG flags, LUID const* luid)
{
	ASSERT(identifier && (identifier != ~0u));

	PAGED_CODE();

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

//	LPWSTR notify	   = 0;
//	ULONG notifyLength = 0;

	ULONG pos = ~0u;

	CFilterEntity *const entity = m_entities.GetFromIdentifier(identifier, &pos);

	if(entity)
	{
		ASSERT(pos != ~0u);

		// Verify type
		if((entity->m_flags & type) == type)
		{
			DBGPRINT(("RemoveEntity: Identifier[0x%x] Type[%d]\n", identifier, entity->GetType()));

			ASSERT(entity->m_flags & type);

			// Copy Entity path
		//	notify = entity->CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_DEEPNESS, 
							//		&notifyLength);

			// Remove Entity independently of LUIDs
			status = RemoveEntity(0, luid, pos, flags);
		}
	}

	ExReleaseResourceLite(&m_entitiesResource);
	FsRtlExitFileSystem();

	//if(notify)
	//{
		// Notify client, which is currently only interested in directory notifications
	//	if(TRACK_TYPE_DIRECTORY == type)
	//	{
	//		if(NT_SUCCESS(CFilterControl::Callback().FireNotify(FILFILE_CONTROL_DIRECTORY | FILFILE_CONTROL_REM,
	//														notify, 
	//														notifyLength)))
	//	{
			// Function has taken ownership of path string
	//		notify = 0;
	//	}
	//	}
//
	//	if(notify)
	//	{
	//		ExFreePool(notify);
	//	}
	//}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::RemoveEntity(FILE_OBJECT *file, ULONG flags)
{
	ASSERT(file);

	PAGED_CODE();

	LUID luid = {0,0};

	NTSTATUS status = STATUS_SUCCESS;

	bool const terminal = CFilterControl::IsTerminalServices();
	
	if(terminal && !(flags & ENTITY_ANYWAY))
	{
		status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}
	}

	FILE_NAME_INFORMATION *fileNameInfo = 0;

	// Retrieve file path from file system
	status = CFilterBase::QueryFileNameInfo(m_extension->Lower, file, &fileNameInfo);
	
	if(NT_SUCCESS(status))
	{
		ASSERT(fileNameInfo);

		CFilterPath path;
		status = path.Init(fileNameInfo->FileName, 
						   fileNameInfo->FileNameLength, 
						   m_extension->LowerType,
						   &m_extension->LowerName);

		if(NT_SUCCESS(status))
		{
			path.SetType(TRACK_TYPE_FILE);

			if(flags & ENTITY_AUTO_CONFIG)
			{
				path.m_file		  = 0;
				path.m_fileLength = 0;
			}

			FsRtlEnterFileSystem();
			ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

			// Remove active Entity, if any
			status = RemoveEntity(&path, (terminal) ? &luid : 0, ~0u, flags | ENTITY_PURGE);

			ExReleaseResourceLite(&m_entitiesResource);
			FsRtlExitFileSystem();

			path.Close();
		}

		ExFreePool(fileNameInfo);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::RemoveEntity(CFilterPath const* path, LUID const* luid, ULONG pos, ULONG flags)
{
	PAGED_CODE();

	// Entities must be locked exclusively

	#if DBG
	{
		if(CFilterControl::IsTerminalServices() && !(flags & ENTITY_ANYWAY))
		{
			ASSERT(luid);
			ASSERT(luid->HighPart || luid->LowPart);
		}
	}
	#endif

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	// Is pos not given?
	if(pos == ~0u)
	{
		ASSERT(path);

		// Search for it
		pos = m_entities.Check(path, true);
	}
				
	if(pos != ~0u)
	{	
		CFilterEntity *const matched = m_entities.GetFromPosition(pos);
		ASSERT(matched);

		status = STATUS_ALERTED;

		// If TS mode and not ANYWAY mode, check LUID
		if(luid && !(flags & ENTITY_ANYWAY))
		{
			// Returns STATUS_ALERTED when last LUID was removed
			status = matched->m_luids.Remove(luid);
		}

		if(STATUS_ALERTED == status)
		{
			status = STATUS_SUCCESS;

			bool remove = true;

			if(flags & (ENTITY_PURGE | ENTITY_DISCARD))
			{
				if(matched->GetType() == TRACK_TYPE_FILE)
				{
					// Single file Entities will be torn down 
					// implicitly. Do not remove them twice
					remove = false;
				}

				ASSERT(matched->m_identifier);

				// Process directories/files related to this Entity
				status = m_context->Purge(matched->m_identifier, flags);
			}

			if(remove)
			{
			ASSERT(matched->m_headerIdentifier);
		
			// Release referenced Header
			m_context->Headers().Release(matched->m_headerIdentifier);

			matched->m_headerIdentifier = 0;
			matched->m_headerBlocksize  = 0;

			// Remove Entity anyway
			m_entities.RemoveRaw(pos, true);
		}
	}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::AddEntity(FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(track);

	PAGED_CODE();

	ASSERT(flags & TRACK_MATCH_EXACT);

	// Entities must be locked exclusively

	bool const terminal = CFilterControl::IsTerminalServices();
	
	if(terminal)
	{
		ASSERT(track->Luid.HighPart || track->Luid.LowPart);
	}

	CFilterHeaderCont &headers = m_context->Headers();

	NTSTATUS status = STATUS_OBJECT_NAME_COLLISION;

	ULONG pos = m_entities.Check(&track->Entity, true);

	// Does Entity already exist?
	if(pos != ~0u)
	{
		headers.LockExclusive();

		CFilterEntity *const entity = m_entities.GetFromPosition(pos);
		ASSERT(entity);
		CFilterHeader *const existing = headers.Get(entity->m_headerIdentifier);
		ASSERT(existing);

		// Exactly same Header?
		bool const equal = existing->Equal(&track->Header);

		if(equal)
		{
			ASSERT(entity->m_identifier);

			track->Entity.m_identifier = entity->m_identifier;

			// Compare EntityKey with active one
			if(existing->m_key.Equal(&track->EntityKey))
			{
				// inform caller that no Entity was created
				status = STATUS_ALERTED;

				// In TS mode, add our LUID to existing Entity's referenced Header
				if(terminal)
				{
					// Add LUID to authenticated list of Header and Entity
					status = existing->m_luids.Add(&track->Luid);

					if(NT_SUCCESS(status))
					{
						status = entity->m_luids.Add(&track->Luid);
					}
				}
			}
			else
			{
				// Hmm, someone is fooling us...
				ASSERT(false);

				status = STATUS_ACCESS_DENIED;
			}

			headers.Unlock();

			return status;
		}

		headers.Unlock();

		status = STATUS_ALERTED;

		// Remove active Entity
		RemoveEntity(0,0, pos, ENTITY_PURGE | ENTITY_ANYWAY);

		// Trigger Entity creation
		pos = ~0u;
	}

	// NOT existing?
	if(pos == ~0u)
	{
		headers.LockExclusive();

		// Matched on existing Header?
		if(track->Entity.m_headerIdentifier)
		{
			ASSERT(track->Entity.m_headerIdentifier != ~0u);

			// Just increment RefCount on referenced Header:
			CFilterHeader *const header = headers.Get(track->Entity.m_headerIdentifier);

			if(header)
			{
				if(terminal)
				{
					// LUID should already be athenticated on Header
					ASSERT(~0u != header->m_luids.Check(&track->Luid));
				}

				track->Entity.m_headerBlocksize = header->m_blockSize;

				header->AddRef();

				status = STATUS_SUCCESS;
			}
			else
			{
				// Bad things have happened...
				ASSERT(false);
			}
		}
		else
		{
			// Add a new Header:
			ASSERT(track->EntityKey.m_size);

			// Set EntityKey temporarily
			CFilterKey fileKey  = track->Header.m_key;
			track->Header.m_key = track->EntityKey;

			// Add Header to List
			status = headers.Add(&track->Header, (terminal) ? &track->Luid : 0);

			// Put its identifier and size into Entity
			track->Entity.m_headerIdentifier = track->Header.m_identifier;
			track->Entity.m_headerBlocksize  = track->Header.m_blockSize;

			// Restore FileKey
			track->Header.m_key = fileKey;
			fileKey.Clear();
		}

		if(NT_SUCCESS(status))
		{
			// make local copy
			CFilterEntity entity = track->Entity;
			
			if(entity.m_file)
			{
				if(flags & TRACK_TYPE_DIRECTORY)
				{
					// transform into directory type
					ASSERT(entity.m_fileLength);

					entity.m_flags &= ~TRACK_TYPE_FILE;
					entity.m_flags |= TRACK_TYPE_DIRECTORY;
					
					entity.m_file	    = 0; 
					entity.m_fileLength = 0;
    			}
			}

			// type should be well known at this point
			ASSERT(entity.m_flags & TRACK_TYPE_RESOLVED);
			ASSERT( !(entity.m_flags & TRACK_CHECK_VOLUME) || (entity.m_flags & TRACK_REDIR));

			// filter out some flags
			entity.m_flags &= TRACK_TYPE_RESOLVED | TRACK_CHECK_VOLUME | TRACK_AUTO_CONFIG | TRACK_APP_LIST | TRACK_REDIR;

			ASSERT(entity.m_flags);
		
			// generate new Entity identifier for this volume
			track->Entity.m_identifier = entity.m_identifier = GenerateEntityIdentifier(); 

			ASSERT(entity.m_identifier);
			ASSERT(entity.m_headerIdentifier);
			ASSERT(entity.m_headerBlocksize);

			if(terminal)
			{
				// LUID should already be athenticated on Header
				ASSERT(NT_SUCCESS(headers.CheckLuid(&track->Luid, entity.m_headerIdentifier)));

				// Add LUID to new Entity
				status = entity.m_luids.Add(&track->Luid);
			}

			if(NT_SUCCESS(status))
			{
				status = m_entities.AddRaw(&entity);
			}
		}

		headers.Unlock();

		if(NT_ERROR(status))
		{
			headers.Release(track->Entity.m_headerIdentifier);

			track->Entity.m_headerIdentifier = 0;
			track->Entity.m_headerBlocksize  = 0;
		}

		if(NT_SUCCESS(status))
		{
			// merge overlapping Entities with same properties, update changed identifier as needed
			ConsolidateEntities(&track->Entity.m_identifier);
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::ManageEntity(FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_context);

	NTSTATUS status = STATUS_SUCCESS;

	bool const terminal = CFilterControl::IsTerminalServices();

	if(terminal)
	{
		status = CFilterBase::GetLuid(&track->Luid);

		if(NT_ERROR(status))
		{
			return status;
		}
	}

	FsRtlEnterFileSystem();

	if(flags & (FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM))
	{
		if(flags & FILFILE_CONTROL_ACTIVE)
		{
			// Negative Entities
			ExAcquireResourceExclusiveLite(&m_negativesResource, true);

			if(flags & FILFILE_CONTROL_REM)
			{
				status = m_negatives.Remove(&track->Entity);
			}
			else
			{
				ASSERT(flags & FILFILE_CONTROL_ADD);

				if(terminal)
				{
					// In TS mode, add owner's LUID to negative Entity to support cleanup
					status = track->Entity.m_luids.Add(&track->Luid);
				}

				if(NT_SUCCESS(status))
				{
					status = m_negatives.Add(&track->Entity);
				}
			}

			ExReleaseResourceLite(&m_negativesResource);
		}
		else
		{
			// Regular Entities
			ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

			if(flags & FILFILE_CONTROL_REM)
			{
				status = RemoveEntity(&track->Entity, (terminal) ? &track->Luid : 0);
			}
			else
			{
				ASSERT(flags & FILFILE_CONTROL_ADD);

				status = AddEntity(track, TRACK_MATCH_EXACT);
			}

			ExReleaseResourceLite(&m_entitiesResource);
		}
	}
	else
	{
		if(flags == FILFILE_CONTROL_BLACKLIST)
		{
			// Check against Blacklist
			if(!m_context->m_blackList.Check(&track->Entity, &track->Luid))
			{
				status = STATUS_OBJECT_NAME_NOT_FOUND;
			}
		}
		else
		{
			// Check against active Entities
			ExAcquireResourceSharedLite(&m_entitiesResource, true);

			if(~0u == m_entities.Check(&track->Entity, false))
			{
				status = STATUS_OBJECT_NAME_NOT_FOUND;
			}

			ExReleaseResourceLite(&m_entitiesResource);
		}
	}

	FsRtlExitFileSystem();
		
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

int CFilterVolume::CheckDirectoryCooked(FILE_OBJECT *file, CFilterDirectory *directory)
{
	ASSERT(m_context);

	int found = 0; 

	if(file && m_context->m_directories.Size())
	{
		FsRtlEnterFileSystem();
		ExAcquireSharedStarveExclusive(&m_context->m_directoriesResource, true);

		ULONG pos = ~0u;

		if(m_context->m_directories.Search(file, &pos))
		{
			ASSERT(pos != ~0u);

			CFilterDirectory *const filterDirectory = m_context->m_directories.Get(pos);
			ASSERT(filterDirectory);

			if(directory)
			{
				// copy content
				*directory = *filterDirectory;
			}

			found = 1;

			// Is corresponding Entity no longer active?
			if(~0u == filterDirectory->m_entityIdentifier)
			{
				DBGPRINT(("CheckDirectoryCooked -INFO: doomed Entity detected\n"));

				found = -1;
			}
		}

		ExReleaseResourceLite(&m_context->m_directoriesResource);
		FsRtlExitFileSystem();
	}

	return found;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::RemoteFileChange(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(file);
	ASSERT(track);
	
	PAGED_CODE();
	
	ASSERT(m_context);
	
	// Should be called on local volumes only
	ASSERT(m_extension->LowerType & FILFILE_DEVICE_VOLUME);

	FsRtlEnterFileSystem();

	// Try to purge corresponding single file Entity, if such exists
	ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

	NTSTATUS status = RemoveEntity(&track->Entity, 0, ~0u, ENTITY_PURGE | ENTITY_ANYWAY);

	ExReleaseResourceLite(&m_entitiesResource);

	// If no such Entity did exist,
	if(NT_ERROR(status))	
	{
		// purge FO directly
		if(CFilterBase::TearDownCache(file, 30, 100))
		{
			status = STATUS_SUCCESS;
		}
	}

	if(NT_SUCCESS(status))	
	{
		if(file->FsContext)
		{
			if(m_context->m_files.Size())
			{
				ExAcquireResourceExclusiveLite(&m_context->m_filesResource, true);

				ULONG pos = ~0u;

				if(m_context->m_files.Check(file, &pos))
				{
					ASSERT(pos != ~0u);

					CFilterFile *const filterFile = m_context->m_files.Get(pos);
					ASSERT(filterFile);

					ASSERT(file->FsContext == filterFile->m_fcb);
					
					// If RefCount is zero and file is not cached, then remove it now
					if(!filterFile->m_refCount && !CFilterBase::IsCached(file))
					{
						DBGPRINT(("RemoteFileChange: FO[0x%p] Remove file\n", file));
					
						m_context->m_files.Remove(pos);
					}
				}

				ExReleaseResourceLite(&m_context->m_filesResource);
			}
		}
	}
	
	// Remove file from header cache
	CFilterControl::Extension()->HeaderCache.Remove(m_extension, file);
	
	FsRtlExitFileSystem();	
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

int CFilterVolume::CheckFileCooked(FILE_OBJECT *file, CFilterContextLink *link)
{
	int found = 0; 

	if(file && file->FsContext)
	{
		ASSERT(m_context);

		if(m_context->m_files.Size())
		{
			FsRtlEnterFileSystem();
			ExAcquireSharedStarveExclusive(&m_context->m_filesResource, true);

			ULONG pos = ~0u;

			if(m_context->m_files.Check(file, &pos))
			{
				ASSERT(pos != ~0u);

				CFilterFile *const filterFile = m_context->m_files.Get(pos);
				ASSERT(filterFile);

				ASSERT(file->FsContext == filterFile->m_fcb);

				if(link)
				{
					// copy content
					*link = filterFile->m_link;
				}

				found = 1;

				// corresponding Entity no longer active ?
				if(~0u == filterFile->m_link.m_entityIdentifier)//判断是否激活，没激活就是-1
				{
					DBGPRINT(("CheckFileCooked -INFO: doomed Entity detected\n"));

					found = -1;
				}
			}

			ExReleaseResourceLite(&m_context->m_filesResource);
			FsRtlExitFileSystem();
		}
	}

	return found;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterVolume::UpdateLink(FILE_OBJECT *file, ULONG flags, bool clear)
{
	ASSERT(file);
	ASSERT(flags);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(file && file->FsContext)
	{
		ASSERT(m_context);

		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_context->m_filesResource, true);

		ULONG pos = ~0u;

		if(m_context->m_files.Check(file, &pos))
		{
			ASSERT(pos != ~0u);

			CFilterFile *const filterFile = m_context->m_files.Get(pos);
			ASSERT(filterFile);

			ASSERT(file->FsContext == filterFile->m_fcb);

			// Use interlocked functions to modify embedded flags value to avoid an
			// exclusive lock on covering structure, it is NetShare's hottest lock.

			if(clear)
			{	
				InterlockedAnd((LONG*) &filterFile->m_link.m_flags, flags);
			}
			else
			{
				InterlockedOr((LONG*) &filterFile->m_link.m_flags, flags);
			}

			status = STATUS_SUCCESS;
		}

		ExReleaseResourceLite(&m_context->m_filesResource);
		FsRtlExitFileSystem();
	}
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::InitNewDirectory(CFilterEntity const *entity, ULONG deepness,FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(entity);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(entity->m_headerIdentifier);
	ASSERT(entity->m_headerIdentifier != ~0u);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	FsRtlEnterFileSystem();

	CFilterHeaderCont &headers = m_context->Headers();
	headers.LockShared();

	CFilterHeader *const header = headers.Get(entity->m_headerIdentifier);

	if(header)
	{
		// use local copy
		CFilterHeader autoConf = *header;
		autoConf.m_deepness    = (deepness == ~0u) ? deepness : deepness - 1;

		headers.Unlock();

		FsRtlExitFileSystem();
	    
		UNICODE_STRING autoConfigPath = {0,0,0};

		// generate AutoConfig path using given path
		status = entity->GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX_DYN);

		if(NT_SUCCESS(status) && track)
		{
			//打开配置文件
			if (!(track->State & TRACK_SHARE_DIRTORY))
			{
				HANDLE fileHandle = 0;
				FILE_OBJECT *file = 0;
				status = CFilterBase::CreateFile(m_extension->Lower,&autoConfigPath,FILE_GENERIC_WRITE,FILE_SHARE_READ,(FILE_CREATE << 24) | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,FILE_ATTRIBUTE_SYSTEM,&file,&fileHandle);
				if(NT_SUCCESS(status))
				{
					ASSERT(file);
					ASSERT(fileHandle);

					status = CFilterCipherManager(m_extension).AutoConfigWrite(file, &autoConf);

					ObDereferenceObject(file);

					ZwClose(fileHandle);
				}
				else
				{
					DBGPRINT(("InitNewDirectory: DirectCreate() failed [0x%08x]\n", status));
				}

				ExFreePool(autoConfigPath.Buffer);
			}
		}
	}
	else
	{
		// should never come here
		ASSERT(false);

		headers.Unlock();

		FsRtlExitFileSystem();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::InitNewFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track, ULONG dispo)
{
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	FsRtlEnterFileSystem();
	
	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));

	CFilterHeader local;
	RtlZeroMemory(&local, sizeof(local));

	NTSTATUS status = STATUS_SUCCESS;

	bool generate = true;

	if(FILE_CREATED != dispo)
	{
		// File was Overwritten/Superseeded
		if(CheckFileCooked(file, &link))
		{
			// If file is already tracked, re-use its Nonce and FileKey
			generate = false;
		}
	}

	if(track->State & TRACK_HAVE_KEY)
	{
		DBGPRINT(("InitNewFile: initialize FO[0x%p] with given Header\n", file));

		// Copy EntityKey
		ASSERT(track->Header.m_key.m_size);
		track->EntityKey = track->Header.m_key;

		// use local copy
		local = track->Header;
		local.m_deepness = 0;
	}
	else
	{
		DBGPRINT(("InitNewFile: initialize FO[0x%p] with Header[0x%x]\n", file, track->Entity.m_headerIdentifier));

		ASSERT(track->Entity.m_headerIdentifier && (track->Entity.m_headerIdentifier != ~0u));

		status = STATUS_OBJECT_NAME_NOT_FOUND;

		CFilterHeaderCont &headers = m_context->Headers();
		headers.LockShared();
		
		CFilterHeader const *header = headers.Get(track->Entity.m_headerIdentifier);

		if(header)
		{
			// Copy EntityKey
			ASSERT(header->m_key.m_size);
			track->EntityKey = header->m_key;

			// Free potentially existing header
			track->Header.Close();

			// Make copy of Payload and have it freed later
			status = header->Copy(&track->Header);
			
			// use local copy
			local = track->Header;
			local.m_deepness = 0;
		}

		headers.Unlock();

		// defaults to re-using
		local.m_nonce = link.m_nonce;
		local.m_key   = link.m_fileKey;
	}

	if(NT_SUCCESS(status))
	{
		if(generate)
		{
			// generate new FileKey with EntityKey's attribs
			local.m_key.m_cipher = track->EntityKey.m_cipher;
			local.m_key.m_size   = track->EntityKey.m_size;
			    		
			status = m_context->GenerateFileKey(&local.m_key);

			// generate new Nonce
			m_context->GenerateNonce(&local.m_nonce);

			DBGPRINT(("InitNewFile: new Key[0x%x] and Nonce[0x%I64x]\n", *((ULONG*) local.m_key.m_key), local.m_nonce));

			#if DBG
			{
				// check new FileKey against active ones to ensure its uniqueness
				ExAcquireResourceSharedLite(&m_context->m_filesResource, true);

				for(ULONG index = 0; index < m_context->m_files.Size(); ++index)
				{
					CFilterFile *const filterFile = m_context->m_files.Get(index);
					ASSERT(filterFile);

					if(filterFile->m_link.m_fileKey.m_size == local.m_key.m_size)
					{
						if(RtlEqualMemory(local.m_key.m_key, filterFile->m_link.m_fileKey.m_key, local.m_key.m_size))
						{
							DBGPRINT(("InitNewFile -WARN: FileKey already used\n"));

							// should never come here ...
							ASSERT(false);
							break;
						}
					}
				}

				ExReleaseResourceLite(&m_context->m_filesResource);
			}
			#endif
		}
		else
		{
			DBGPRINT(("InitNewFile: re-use existing Key[0x%x], Nonce[0x%I64x]\n", *((ULONG*) local.m_key.m_key), local.m_nonce));
		}

		if(NT_SUCCESS(status))
		{
			// Copy some values used for tracking
			track->Header.m_blockSize = local.m_blockSize;
			track->Header.m_nonce	  = local.m_nonce;
			track->Header.m_key		  = local.m_key;

			ASSERT(local.m_key.m_size);
			ASSERT(track->EntityKey.m_size);
			ASSERT(track->EntityKey.m_cipher);

			// Encrypt FileKey using EntityKey 
			m_context->EncodeFileKey(&track->EntityKey, &local.m_key, false);

			// Add Header to file
			status = CFilterCipherManager(m_extension).WriteHeader(file, &local);

			if(NT_SUCCESS(status) && generate)
			{
				// Inject file into HeaderCache to avoid influences
				CFilterControl::Extension()->HeaderCache.Inject(&track->Entity, &local);
			}

			track->State |= TRACK_HAVE_KEY;
		}
	}

	// Be paranoid
	local.m_key.Clear();
	link.m_fileKey.Clear();
	
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::LonelyEntity(FILE_OBJECT *file, ULONG type, ULONG entityIdentifier)
{
	ASSERT(file);

	PAGED_CODE();

	NTSTATUS status	= STATUS_SUCCESS;

	// not given ?
	if(!entityIdentifier)
	{
		if(type & TRACK_TYPE_DIRECTORY)
		{
			CFilterDirectory directory;
			RtlZeroMemory(&directory, sizeof(directory));

			if(CheckDirectoryCooked(file, &directory))
			{
				// Do not check for file type
				type = TRACK_TYPE_DIRECTORY;

				// use only tracked objects that have matched the Entity exactly  
				if(directory.m_flags & TRACK_MATCH_EXACT)
				{
					entityIdentifier = directory.m_entityIdentifier;
				}
			}
		}

		if(type & TRACK_TYPE_FILE)
		{
			CFilterContextLink link;
			RtlZeroMemory(&link, sizeof(link));

			if(CheckFileCooked(file, &link))
			{
				link.m_fileKey.Clear();

				type = TRACK_TYPE_FILE;

				entityIdentifier = link.m_entityIdentifier;
			}
		}
	}

	// Valid identifier?
	if(entityIdentifier && (entityIdentifier != ~0u))
	{
		status = RemoveEntity(entityIdentifier, type, ENTITY_ANYWAY);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::OnDirectoryClose(FILE_OBJECT *directory)
{
	ASSERT(directory);

	PAGED_CODE();

	ASSERT(m_context);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(m_context->m_directories.Size())
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&m_context->m_directoriesResource, true);

		ULONG pos = ~0u;

		// tracked directory ?
		if(m_context->m_directories.Search(directory, &pos))
		{
			ASSERT(pos != ~0u);

			DBGPRINT(("OnDirectoryClose: FO[0x%p] Flags[0x%x]\n", directory, directory->Flags));
	
			ASSERT(pos != ~0u);
			m_context->m_directories.Remove(0, pos);

			status = STATUS_SUCCESS;
		}

		ExReleaseResourceLite(&m_context->m_directoriesResource);
		FsRtlExitFileSystem();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::OnFileCreate(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track, ULONG dispo)
{
	ASSERT(file);
	ASSERT(track);
		
	PAGED_CODE();

	ASSERT(file->FsContext);
	ASSERT(m_context);

	if(CFilterBase::IsStackBased(file))
	{
		DBGPRINT(("OnFileCreate: FO[0x%p] FCB[0x%p] is stack-based, ignore\n", file, file->FsContext));

		return STATUS_SUCCESS;
	}

	FsRtlEnterFileSystem();

	NTSTATUS status = STATUS_SUCCESS;

	// Unknown FileKey?
	if( !(track->State & TRACK_HAVE_KEY))
	{
		// Unknown EntityKey?
		if(!track->EntityKey.m_size)
		{
			CFilterHeaderCont &headers = m_context->Headers();	
			headers.LockShared();

			// Retrieve EntityKey
			ASSERT(track->Entity.m_headerIdentifier);
			CFilterHeader const *header = headers.Get(track->Entity.m_headerIdentifier);

			if(header)
			{
				ASSERT(header->m_key.m_size);
				// Copy by value
				track->EntityKey = header->m_key;
			}

			headers.Unlock();

			if(!header)
			{
				DBGPRINT(("OnFileCreate -ERROR: Cannot find EntityKey\n"));

				FsRtlExitFileSystem();

				return STATUS_ACCESS_DENIED;
			}
		}
	}

	ULONG const hash = track->Entity.Hash(CFilterPath::PATH_FILE);
	ULONG pos   = ~0u;
	bool create = true;

	ExAcquireResourceExclusiveLite(&m_context->m_filesResource, true);

	for(ULONG step = 0; step < 2; ++step)
	{
		// File already tracked?
		if(m_context->m_files.Check(file, &pos))
		{
			CFilterFile *const filterFile = m_context->m_files.Get(pos);
			ASSERT(filterFile);

			ASSERT(file->FsContext == filterFile->m_fcb);
	
			if(filterFile->m_link.m_entityIdentifier != ~0u)
			{
				// So just increment refCount
				filterFile->OnCreate(file, hash);

				DBGPRINT(("OnFileCreate: PID:TID[0x%x:0x%x] Hash[0x%x]\n", PsGetCurrentProcessId(), filterFile->m_threadId, hash));
				DBGPRINT(("OnFileCreate: FO[0x%p] FCB[0x%p] new RefCount[%d]\n", file, file->FsContext, filterFile->m_refCount));

				ExReleaseResourceLite(&m_context->m_filesResource);
				FsRtlExitFileSystem();

				return STATUS_SUCCESS;
			}	
			
			// Resurrect doomed tracked object
			create = false;

			break;
		}

		if(FILE_OPENED != dispo)
		{
			// File was Created/Overwritten/Superseeded, so no need to purge it.
			break;
		}

		// File not cached?
		if(!CFilterBase::IsCached(file))
		{
			break;
		}

		if(step)
		{
			// Hmmm, purging has failed and/or cache is still polluted; the only option left
			// is denying access in the hope that things are more *relaxed* pretty soon.
			DBGPRINT(("OnFileCreate: FO[0x%p] Flush/Purge failed, deny access\n", file));
		
			ExReleaseResourceLite(&m_context->m_filesResource);
			FsRtlExitFileSystem();

			return STATUS_SHARING_VIOLATION;
		}

		DBGPRINT(("OnFileCreate: FO[0x%p] is cached, try Flush/Purge\n", file));

		// Do not hold locks while waiting
		ExReleaseResourceLite(&m_context->m_filesResource);

		// The cache is polluted with unknown data, try to flush/purge. Do this in a loop 
		// to give remote nodes time to react on Oplock breaks - max wait time is ~5 sec.

		CFilterBase::TearDownCache(file, 50, 100);

		ExAcquireResourceExclusiveLite(&m_context->m_filesResource, true);
	}

	ASSERT(pos != ~0u);

	ASSERT(track->Header.m_nonce.QuadPart);
	ASSERT(track->Header.m_blockSize);

	CFilterFile filterFile;
	filterFile.Init();

	filterFile.m_link.m_entityIdentifier = track->Entity.m_identifier;
	filterFile.m_link.m_headerIdentifier = track->Entity.m_headerIdentifier;
	filterFile.m_link.m_nonce			 = track->Header.m_nonce;
	filterFile.m_link.m_headerBlockSize	 = track->Header.m_blockSize;
	
	// Is FileKey encrypted?
	if( !(track->State & TRACK_HAVE_KEY))
	{
		ASSERT(track->EntityKey.m_size);
		ASSERT(track->Header.m_key.m_size);
		// Decrypt FileKey using EntityKey
		m_context->EncodeFileKey(&track->EntityKey, &track->Header.m_key, true);
	}

	// Copy FileKey
	filterFile.m_link.m_fileKey = track->Header.m_key;

	status = filterFile.OnCreate(file, hash);

	if(NT_SUCCESS(status))
	{
		if(create)
		{
			// Add to tracking List
			status = m_context->m_files.Add(&filterFile, pos);
		}
		else
		{
			// Update tracked object
			status = m_context->m_files.Update(&filterFile, pos);
		}

		if(NT_SUCCESS(status))
		{
			DBGPRINT(("OnFileCreate: PID:TID[0x%x:0x%x] Hash[0x%x]\n", PsGetCurrentProcessId(), filterFile.m_threadId, hash));

			DBGPRINT(("OnFileCreate: %s FO[0x%p] FCB[0x%p] Key[0x%x], Nonce[0x%I64x]\n", create ? "Added new" : "Updated existing",
																						 file, 
																						 file->FsContext, 
																						 *((ULONG*) filterFile.m_link.m_fileKey.m_key), 
																						 filterFile.m_link.m_nonce));
		}

		filterFile.Close();
	}

	// Be paranoid
	filterFile.m_link.m_fileKey.Clear();

	ExReleaseResourceLite(&m_context->m_filesResource);
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::OnFileCleanup(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_context);

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(file->FsContext && m_context->m_files.Size())
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_context->m_filesResource, true);

		ULONG pos = ~0u;

		// tracked file ?
		if(m_context->m_files.Check(file, &pos))
		{
			status = STATUS_SUCCESS;

			ASSERT(pos != ~0u);
			CFilterFile* const filterFile = m_context->m_files.Get(pos);
			ASSERT(filterFile);

			// doomed FO (w/o active Entity) ?
			if((~0u == filterFile->m_link.m_entityIdentifier) || !filterFile->m_link.m_entityIdentifier)
			{
				// inform caller
				status = STATUS_ALERTED;
			}
		}

		ExReleaseResourceLite(&m_context->m_filesResource);
		FsRtlExitFileSystem();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::OnFileClose(FILE_OBJECT *file, bool discard)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_context);

	if(CFilterBase::IsStackBased(file))
	{
		DBGPRINT(("OnFileClose: FO[0x%p] FCB[0x%p] is stack-based, ignore\n", file, file->FsContext));

		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if(file->FsContext && m_context->m_files.Size())
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&m_context->m_filesResource, true);

		ULONG entityIdentifier = 0;
		ULONG pos = ~0u;

		if(m_context->m_files.Check(file, &pos))
		{
			ASSERT(pos != ~0u);
			CFilterFile *const filterFile = m_context->m_files.Get(pos);
			ASSERT(filterFile);
			ASSERT(filterFile->m_fcb == file->FsContext);

			bool remove = false;

			// Closed last reference?
			if(filterFile->OnClose(file))
			{
				DBGPRINT(("OnFileClose: FO[0x%p] FCB[0x%p] closed Last\n", file, file->FsContext));

				remove = true;
			}
			else
			{
				if(discard)
				{
					// If RefCount is zero, then remove it now
					if(!filterFile->m_refCount)
					{
						DBGPRINT(("OnFileClose:	FO[0x%p] FCB[0x%p] Discard\n", file, file->FsContext));

						remove = true;
					}
				}
			}

			status = STATUS_ALERTED;

			if(remove)
			{
				// Save Entity identifier
				entityIdentifier = filterFile->m_link.m_entityIdentifier;

				// Only if not doomed
				if(entityIdentifier == ~0u)
				{
					entityIdentifier = 0;
				}

				m_context->m_files.Remove(pos);

				status = STATUS_SUCCESS;
			}
		}

		if(entityIdentifier)
		{
			ExConvertExclusiveToSharedLite(&m_context->m_filesResource);

			// Check whether this file Entity is still referenced
			if(m_context->m_files.CheckIdentifier(entityIdentifier))
			{
				DBGPRINT(("OnFileClose:	FO[0x%p] Entity[0x%x] still referenced\n", file, entityIdentifier));

				// Do not remove it then
				entityIdentifier = 0;
			}
		}

		ExReleaseResourceLite(&m_context->m_filesResource);
		FsRtlExitFileSystem();
		
		// If last FO was closed, check for orphaned single file Entity to be removed
		if(entityIdentifier)
		{
			LonelyEntity(file, TRACK_TYPE_FILE, entityIdentifier);
		}
    }

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::ManageEncryption(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *present, FILFILE_TRACK_CONTEXT *future, ULONG flags)
{
	ASSERT(file);
	ASSERT(flags);

	PAGED_CODE();

	ASSERT(m_extension);

	// Should be adequate size for a couple of ADS infos
	ULONG  const bufferSize = 4096;
	UCHAR *const buffer     = (UCHAR*) ExAllocatePool(PagedPool, bufferSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(buffer, bufferSize);

	if(flags & FILFILE_CONTROL_REM)
	{
		// Remove active file Entity, if any
		RemoveEntity(file, ENTITY_ANYWAY);
	}

	// Process default data stream first
	NTSTATUS status = ManageEncryptionFile(file, present, future, flags);

	if(NT_SUCCESS(status))
	{
		// get ADS info, if any
		if(NT_SUCCESS(CFilterBase::QueryFileInfo(m_extension->Lower, file, FileStreamInformation, buffer, bufferSize)))
		{
			FILE_STREAM_INFORMATION *streamInfo = (FILE_STREAM_INFORMATION*) buffer;

			if(streamInfo->NextEntryOffset)
			{
				FILE_NAME_INFORMATION *fileNameInfo = 0;

				// Retrieve full file path from file system
				status = CFilterBase::QueryFileNameInfo(m_extension->Lower, file, &fileNameInfo);

				if(NT_SUCCESS(status))
				{
					status = STATUS_INSUFFICIENT_RESOURCES;

					ASSERT(fileNameInfo);

					// Estimate some reasonable buffer size
					ULONG  const pathSize = 8 * (m_extension->LowerName.Length + fileNameInfo->FileNameLength);
					UCHAR *const path     = (UCHAR*) ExAllocatePool(PagedPool, pathSize);

					if(path)
					{
						CFilterCipherManager manager(m_extension);

						for(;;)
						{
							streamInfo = (FILE_STREAM_INFORMATION*) ((UCHAR*) streamInfo + streamInfo->NextEntryOffset);

							// check buffer size
							if(pathSize < m_extension->LowerName.Length + fileNameInfo->FileNameLength + streamInfo->StreamNameLength)
							{
								ASSERT(false);

								status = STATUS_UNSUCCESSFUL;
								break;
							}
	                                                						
							// build full stream path
							RtlZeroMemory(path, pathSize);
							RtlCopyMemory(path, m_extension->LowerName.Buffer, m_extension->LowerName.Length);
							ULONG offset = m_extension->LowerName.Length;
							RtlCopyMemory(path + offset, fileNameInfo->FileName, fileNameInfo->FileNameLength);
							offset += fileNameInfo->FileNameLength;
							RtlCopyMemory(path + offset, streamInfo->StreamName, streamInfo->StreamNameLength);

							DBGPRINT(("ManageEncryption: processing ADS[%ws]\n", path));
			                				
							UNICODE_STRING streamPath;
							RtlInitUnicodeString(&streamPath, (LPWSTR) path);

							OBJECT_ATTRIBUTES streamOAs;
							InitializeObjectAttributes(&streamOAs, &streamPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);
							
							HANDLE streamHandle		 = 0;
							IO_STATUS_BLOCK	ioStatus = {0,0};
		
							// open existing stream exclusive
							status = IoCreateFileSpecifyDeviceObjectHint(&streamHandle,
																		 FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
																		 &streamOAs,
																		 &ioStatus,
																		 0,
																		 0,
																		 FILE_SHARE_VALID_FLAGS,
																		 FILE_OPEN, 
																		 FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT,
																		 0,
																		 0,
																		 CreateFileTypeNone,
																		 0,
																		 IO_IGNORE_SHARE_ACCESS_CHECK,
																		 m_extension->Lower);

							if(NT_SUCCESS(status))
							{
								FILE_OBJECT *stream = 0;
									
								status = ObReferenceObjectByHandle(streamHandle, 
																   FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 
																   *IoFileObjectType, 
																   KernelMode, 
																   (void**) &stream, 0);

								if(NT_SUCCESS(status))
								{
									if((flags & FILFILE_CONTROL_REM) || (flags == FILFILE_CONTROL_SET))
									{
										ASSERT(present);
										// stream must have Header, don't propagate error
										if(NT_SUCCESS(manager.RecognizeHeader(stream, &present->Header, TRACK_NO_PAYLOAD)))
										{
											// process this data stream
											status = ManageEncryptionFile(stream, present, future, flags);	
										}

										ASSERT(!present->Header.m_payload);
									}
									else
									{
										ASSERT(flags == FILFILE_CONTROL_ADD);

										// stream must NOT have Header, don't propagate error
										if(NT_ERROR(manager.RecognizeHeader(stream)))
										{
											// process this data stream
											status = ManageEncryptionFile(stream, present, future, flags);
										}
									}	

									ObDereferenceObject(stream);
								}

								ZwClose(streamHandle);
							}
							else
							{	
								DBGPRINT(("ManageEncryption -ERROR: IoCreateFileSpecifyDeviceObjectHint() failed [0x%08x]\n", status));
							}

							manager.Clear();

							// severe error OR finished ?
							if(NT_ERROR(status) || !streamInfo->NextEntryOffset)
							{
								break;
							}
						}
	                    
						ExFreePool(path);
					}

					ExFreePool(fileNameInfo);
				}
			}
		}
	}

	ExFreePool(buffer);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::ManageEncryptionFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *present, FILFILE_TRACK_CONTEXT *future, ULONG flags)
{
	ASSERT(file);
	ASSERT(flags);

	PAGED_CODE();

	ASSERT(m_extension);

	// Actions performed according to flags:
	// FILFILE_CONTROL_SET												Change Header only
	// FILFILE_CONTROL_REM												Decrypt encrypted file		(remove Header)
	// FILFILE_CONTROL_ADD												Encrypt plain file			(add Header)
	// FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM						Re-encrypt encrypted file	(change Header)
	// FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM | FILFILE_CONTROL_SET	Re-encrypt only FileKey		(change Header)

	FsRtlEnterFileSystem();

	// Always check file's cache state
	if(CFilterBase::IsCached(file))
	{
		DBGPRINT(("ManageEncryptionFile: FO[0x%p] Cache is active, Purge\n", file));

		// Is file still cached or tracked?
		if(!CFilterBase::TearDownCache(file, 50, 200) || CheckFileCooked(file))
		{
			DBGPRINT(("ManageEncryptionFile: FO[0x%p] is still cached/tracked, abort\n", file));

			FsRtlExitFileSystem();
            
			// Give up because we cannot guarantee data consistency
			return STATUS_SHARING_VIOLATION;
		}
	}

	NTSTATUS status = STATUS_SUCCESS;

	CFilterCipherManager manager(m_extension);

	// Since we work inplace, save Entity keys
	CFilterKey presentKey;
	presentKey.Clear();
	if(present)
	{
		presentKey = present->EntityKey;
	}

	CFilterKey futureKey;
	futureKey.Clear();
	if(future)
	{
		futureKey = future->EntityKey;
	}

	// Is the plain FileKey needed?
	if(flags & FILFILE_CONTROL_REM)
	{
		ASSERT(present);
		ASSERT(present->EntityKey.m_size);
		ASSERT(present->EntityKey.m_cipher);
		ASSERT(present->Header.m_key.m_size);
		ASSERT(present->Header.m_key.m_cipher);
		// Decrypt FileKey using the EntityKey
		m_context->EncodeFileKey(&present->EntityKey, &present->Header.m_key, true);
	}
	
	if(FILFILE_CONTROL_REM == (flags & (FILFILE_CONTROL_REM | FILFILE_CONTROL_ADD)))
	{
		// Propagate recovery mode, if specified
		manager.SetFlags(flags & FILFILE_CONTROL_RECOVER);

		// Simple DECRYPT
		status = manager.ProcessFile(file, present, 0);
	}
	else if(flags & FILFILE_CONTROL_SET)
	{
		// Simple Header change or REENCRYPT without FileKey change
		ASSERT(future);
		ASSERT(future->Header.m_blockSize);
		ASSERT(present->Header.m_blockSize);

		// Copy plain FileKey and Nonce
		future->Header.m_key   = present->Header.m_key;			
		future->Header.m_nonce = present->Header.m_nonce;			

	#if FILFILE_USE_PADDING
		ASSERT(present->Header.m_key.m_size);

		// Verify Padding to ensure both DEK and FEK are correct
		status = manager.RetrieveTail(file, &present->Header);

		if(NT_ERROR(status))
		{
			DBGPRINT(("ManageEncryptionFile: FO[0x%p] Padding verification failed, abort\n", file));
		}
		else
	#endif
		{
			// Has the Header block size changed?
			if(present->Header.m_blockSize != future->Header.m_blockSize)
			{
				ULONG const keySize = present->Header.m_key.m_size;
				ASSERT(keySize == future->Header.m_key.m_size);

				// Disable encryption logic temporarily
				present->Header.m_key.m_size = 0;
				future->Header.m_key.m_size  = 0;
		        		
				// Move the file data around without changing it
				status = manager.ProcessFile(file, present, future);

				present->Header.m_key.m_size = keySize;
				future->Header.m_key.m_size  = keySize;
			}
		}
	}
	else if(flags & FILFILE_CONTROL_ADD)
	{
		// Initial ENCRYPT or FileKey change
        ASSERT( !(flags & FILFILE_CONTROL_SET));
        		
		ASSERT(future);
		ASSERT(future->EntityKey.m_size);
		ASSERT(future->EntityKey.m_cipher);
		ASSERT(future->Header.m_payloadSize);
		ASSERT(future->Header.m_blockSize);

		// Generate new FileKey with same attribs as EntityKey
		future->Header.m_key.m_cipher = future->EntityKey.m_cipher;
		future->Header.m_key.m_size   = future->EntityKey.m_size;

		status = m_context->GenerateFileKey(&future->Header.m_key);

		// Generate new Nonce value
		m_context->GenerateNonce(&future->Header.m_nonce);

		if(NT_SUCCESS(status))
		{
			DBGPRINT(("ManageEncryptionFile: generated Key[0x%x] and Nonce[0x%I64x]\n", future->Header.m_key.m_size, future->Header.m_nonce));

			// Add Header and encrypt data
			status = manager.ProcessFile(file, present, future);
		}
	}

	if(NT_SUCCESS(status) && future)
	{
		ASSERT(future->Header.m_payloadSize);
		ASSERT(future->Header.m_blockSize);

		if(flags & FILFILE_CONTROL_ADD)
		{
			ASSERT(future->EntityKey.m_size);
			ASSERT(future->EntityKey.m_cipher);
			ASSERT(future->Header.m_key.m_size);
			ASSERT(future->Header.m_key.m_cipher);

			// Encrypt the FileKey using the EntityKey
			m_context->EncodeFileKey(&future->EntityKey, &future->Header.m_key, false);
		}

		// Write new Header
		status = manager.WriteHeader(file, &future->Header);
	}

	// Restore Entity keys
	if(present)
	{
		present->EntityKey = presentKey;
		presentKey.Clear();
	}
	if(future)
	{
		future->EntityKey = futureKey;
		futureKey.Clear();
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::ConsolidateEntities(ULONG *identifier)
{
	ASSERT(identifier);
	ASSERT(*identifier);

	// Entities must be locked exclusively

	PAGED_CODE();

	for(ULONG candidateIndex = 0; candidateIndex < m_entities.Size(); ++candidateIndex)
	{
		CFilterEntity *const candidate = m_entities.GetFromPosition(candidateIndex);
		ASSERT(candidate);

		// check if it matches somewhere
		for(ULONG index = candidateIndex + 1; index < m_entities.Size(); ++index)
		{
			CFilterEntity *const current = m_entities.GetFromPosition(index);
			ASSERT(current);

			// Exact matches must never be happen
			ASSERT(!current->Match(candidate, true));

			// Skip file Entities
			if(current->m_file)
			{
				continue;
			}

			// Check for sub-match
			if(!current->Match(candidate, false))
			{
				continue;
			}
			// Different Header?
			if(current->m_headerIdentifier != candidate->m_headerIdentifier)
			{
				break;
			}

			// For directories, check whether we need to adjust the Deepness indicator
			if(!candidate->m_file && (current->m_deepness != ~0u))
			{
				// Infinite?
				if(candidate->m_deepness == ~0u)
				{
					current->m_deepness = ~0u;
				}
				else
				{
					// Compute new deepness. It's the max of depth plus deepness of both
					ULONG const candidateDeepness = candidate->m_deepness + candidate->m_directoryDepth;

					if(candidateDeepness > current->m_deepness + current->m_directoryDepth)
					{
						current->m_deepness = candidateDeepness - current->m_directoryDepth;
					}
				}
			}

			DBGPRINT(("ConsolidateEntities: [0x%08x] matched with[0x%08x] at[%d]\n", candidate->m_identifier, current->m_identifier, index));

			// In TS mode, merge LUIDs
			if(CFilterControl::IsTerminalServices())
			{
				current->m_luids.Add(candidate->m_luids);
			}

			// Update all objects that reference this Entity
			UpdateEntity(candidate->m_identifier, current->m_identifier);

			// Return updated identifier
			if(candidate->m_identifier == *identifier)
			{
				*identifier = current->m_identifier;
			}

			m_context->Headers().LockExclusive();

			// Release Header reference
			m_context->Headers().Release(candidate->m_headerIdentifier);
			candidate->m_headerIdentifier = 0;
			candidate->m_headerBlocksize  = 0;

			m_context->Headers().Unlock();

			// Remove merged Entity
			m_entities.RemoveRaw(candidateIndex, true);

			// Adjust index since we removed one
			candidateIndex--;

			break;
		}
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::FileCheck(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ASSERT(stack->MajorFunction == IRP_MJ_CREATE);

	// if we have read access using given FO, use it.
	if(stack->FileObject->ReadAccess)
	{
		return CFilterCipherManager(m_extension).RecognizeHeader(stack->FileObject, &track->Header);
	}	

	// otherwise create temporary one to avoid nasty side effects
	FILE_OBJECT *fileStream = 0;

	__try
	{
		if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
		{
			// On redirectors, create intermediate FO directly on device below - otherwise MUP will barf (BSOD) on close
			fileStream = IoCreateStreamFileObjectLite(0, m_extension->Lower);
		}
		else
		{
			fileStream = IoCreateStreamFileObjectLite(stack->FileObject, 0);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		fileStream = 0;
	}

	if(!fileStream)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	fileStream->Flags |= FO_SYNCHRONOUS_IO | FO_NO_INTERMEDIATE_BUFFERING;

	ASSERT(track->Entity.m_directoryLength);
	ASSERT(track->Entity.m_fileLength);

	ACCESS_MASK const access = stack->Parameters.Create.SecurityContext->DesiredAccess;
	ULONG length	  = 0;
	ULONG const flags = (m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR) ? CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE : CFilterPath::PATH_FILE;

	fileStream->FileName.Buffer = track->Entity.CopyTo(flags, &length);

	if(!fileStream->FileName.Buffer)
	{
		ObDereferenceObject(fileStream);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ASSERT(length);

	fileStream->FileName.MaximumLength = (USHORT) (length);
	fileStream->FileName.Length		   = (USHORT) (length - sizeof(WCHAR));

	IO_STATUS_BLOCK const ioStatus	= irp->IoStatus;
	KPROCESSOR_MODE const mode		= irp->RequestorMode;

	irp->RequestorMode = KernelMode;

	IoCopyCurrentIrpStackLocationToNext(irp);

	IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
	ASSERT(next);

	next->Parameters.Create.SecurityContext->DesiredAccess	= FILE_READ_DATA | FILE_READ_ATTRIBUTES;
	next->Parameters.Create.FileAttributes					= 0;
	next->Parameters.Create.ShareAccess						= FILE_SHARE_VALID_FLAGS;
	next->Parameters.Create.Options							= FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | (FILE_OPEN << 24);

	next->Flags		 = 0;
	next->FileObject = fileStream;

	// open file
	NTSTATUS status = CFilterBase::SimpleSend(m_extension->Lower, irp);

	if(STATUS_SUCCESS == status)
	{
		// check for valid Header
		status = CFilterCipherManager(m_extension).RecognizeHeader(fileStream, &track->Header);

		// manually cleanup
		CFilterBase::SendCleanupClose(m_extension->Lower, fileStream, true);
	}
	else if(STATUS_REPARSE == status)
	{
		DBGPRINT(("FileCheck -INFO: STATUS_REPARSE returned\n"));
	}
	else if(NT_ERROR(status))
	{
		DBGPRINT(("FileCheck -ERROR: Open failed [0x%x]\n", status));
	}

	if(stack->Parameters.Create.SecurityContext)
	{
		stack->Parameters.Create.SecurityContext->DesiredAccess = access;
	}

	// restore next stack loc
	IoCopyCurrentIrpStackLocationToNext(irp);
	IoSetCompletionRoutine(irp, 0,0, false, false, false);

	// restore IRP parameters
	irp->RequestorMode	 = mode;
	irp->PendingReturned = false;
	irp->IoStatus		 = ioStatus;
	
	if(!fileStream->Vpb)
	{
		ASSERT(m_extension->Real);

		// HACK: to overcome an OS bug, inject the VPB manually because otherwise the RefCount gets out of sync
		// and thus prevents a dismount. Especially with removable media this becomes an issue. Interestingly, it 
		// seems to be that NTFS already has a workaround against this - whereas FastFat has not.

		if(m_extension->Real->Vpb)
		{
			DBGPRINT(("FileCheck: FO[0x%p] injected VPB[0x%p]\n", stack->FileObject, m_extension->Real->Vpb));

			fileStream->Vpb = m_extension->Real->Vpb;
		}
	}

	// IOManager forgets to free the FileName buffer sometimes, but we'll be charged 
	// for it. This only occurs on FAT drives and not on NTFS or CIFS.
	if(fileStream->FileName.Buffer)
	{
		ExFreePool(fileStream->FileName.Buffer);

		fileStream->FileName.Buffer		   = 0;
		fileStream->FileName.Length		   = 0;
		fileStream->FileName.MaximumLength = 0;
	}

	ObDereferenceObject(fileStream);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::AutoConfigVerify(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	NTSTATUS status = STATUS_SUCCESS;

	CFilterPath path;
	RtlZeroMemory(&path, sizeof(path));

	bool created = false;

	switch(irp->IoStatus.Information)
	{
		case FILE_SUPERSEDED:
		case FILE_CREATED:
		case FILE_OVERWRITTEN:
			created = true;

		default:
		//case FILE_OPENED: 
			break;
	}

	// File or directory created/overwritten/superseded?
	if(created)
	{
		if(flags & TRACK_TYPE_DIRECTORY)
		{
			// Change to parent directory
			status = path.CopyFrom(&track->Entity, CFilterPath::PATH_DIRECTORY);

			if(NT_ERROR(status))
			{
				track->State = TRACK_NO;

				return status;
			}
		}
		else if(flags & TRACK_TYPE_FILE)
		{
			// Change to file's directory
			status = path.CopyFrom(&track->Entity);

			if(NT_ERROR(status))
			{
				track->State = TRACK_NO;

				return status;
			}

			path.m_file		  = 0;
			path.m_fileLength = 0;

			path.SetType(TRACK_TYPE_DIRECTORY);
		}
	}

	// Already read AutoConfig?
	if(track->State & TRACK_AUTO_CONFIG)
	{
		if(flags & TRACK_TYPE_DIRECTORY)
		{
			// Swap in parent's path
			path.Swap(&track->Entity);

			// Create Entity and retreive key as needed
			PostCreateEntity(irp, track, TRACK_TYPE_DIRECTORY);

			// Swap back
			path.Swap(&track->Entity);
		}
	}	
	else
	{
		LPWSTR headerPath = 0;
		ULONG  headerPathLength = 0;

		// Check for valid AutoConfig file
		status = AutoConfigCheck(irp, track, (created) ? 0 : IoGetCurrentIrpStackLocation(irp)->FileObject);

		if(STATUS_SUCCESS == status)
		{
			ULONG const identifier = m_nextIdentifier;

			DBGPRINT(("AutoConfigVerify: FO[0x%p] valid AutoConf\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			if(created)
			{
				// Swap in parent's path
				path.Swap(&track->Entity);

				// Create Entity and retreive key as needed
				PostCreateEntity(irp, track, TRACK_TYPE_DIRECTORY);

				// Swap back
				path.Swap(&track->Entity);

				// Changed Entity?
				if(identifier != m_nextIdentifier)
				{
					headerPath = path.CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_AUTOCONFIG, 
											 &headerPathLength);
				}
			}
			else
			{
				PostCreateEntity(irp, track, TRACK_TYPE_DIRECTORY);

				// Changed Entity?
				if(identifier != m_nextIdentifier)
				{
					headerPath = track->Entity.CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_AUTOCONFIG, 
													  &headerPathLength);
				}
			}

			track->Header.Close();
		}
		else
		{
			if(track->State & TRACK_YES)
			{
				// AutoConfig file is missing, invalid or not yet valid
				DBGPRINT(("AutoConfigVerify: FO[0x%p] missing AutoConf, ignore\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

				ASSERT(track->Entity.m_identifier);

				if(irp->RequestorMode != KernelMode)
				{
					// If the object about to be created has matched exactly, then this
					// must be an explicitly created Entity which should not be removed

					if(track->Entity.m_flags & TRACK_MATCH_EXACT)
					{
						if(!created)
						{
							RemoveEntity(track->Entity.m_identifier, TRACK_TYPE_DIRECTORY, ENTITY_ANYWAY);
		
							headerPath = track->Entity.CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_AUTOCONFIG, 
															  &headerPathLength);

							track->State = TRACK_NO;
						}
					}
					else if(created)
					{
						track->State = TRACK_NO;
					}
				}
				else
				{
					track->State = TRACK_NO;
				}
			}
		}

		// To be removed?
		if(headerPath)
		{
			ASSERT(headerPathLength);

			// Remove from header cache
			CFilterControl::Extension()->HeaderCache.Remove(headerPath, headerPathLength);

			ExFreePool(headerPath);
		}
	}

	path.Close();
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::AutoConfigCheck(IRP *irp, FILFILE_TRACK_CONTEXT *track, FILE_OBJECT *related)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ASSERT(stack->MajorFunction == IRP_MJ_CREATE);

	// HACK: some requests originated in UserMode have KernelMode flag set.
	if(irp->RequestorMode == KernelMode)
	{
		if(!((stack->Parameters.Create.Options & FILE_DIRECTORY_FILE)) && !(stack->Flags & SL_OPEN_TARGET_DIRECTORY))
		{
			DBGPRINT(("AutoConfigCheck: FO[0x%p] Kernel mode request, ignore\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			return STATUS_UNSUCCESSFUL;
		}

		DBGPRINT(("AutoConfigCheck: FO[0x%p] Kernel mode request, but SL_OPEN_TARGET_DIRECTORY\n", IoGetCurrentIrpStackLocation(irp)->FileObject));
	}

	// use temporary stream file object to avoid side effects
	FILE_OBJECT *fileStream = 0;

	__try
	{
		if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
		{
			// On redirectors, create intermediate FO directly on device below - otherwise MUP will barf (BSOD) on close
			fileStream = IoCreateStreamFileObjectLite(0, m_extension->Lower);

			// Ignore relative opens on Redirectors to handle WXP's DFS roots correctly
			related = 0;
		}
		else
		{
			fileStream = IoCreateStreamFileObjectLite(stack->FileObject, 0);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		fileStream = 0;
	}

	if(!fileStream)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	fileStream->Flags |= FO_SYNCHRONOUS_IO;

	NTSTATUS status = STATUS_SUCCESS;

	if(related)
	{
		fileStream->RelatedFileObject = related;

		status = STATUS_INSUFFICIENT_RESOURCES;

		fileStream->FileName.Buffer = (LPWSTR) ExAllocatePool(PagedPool, (g_filFileAutoConfigNameLength + 1) * sizeof(WCHAR));

		if(fileStream->FileName.Buffer)
		{
			fileStream->FileName.Length		   = g_filFileAutoConfigNameLength * sizeof(WCHAR);
			fileStream->FileName.MaximumLength = fileStream->FileName.Length + sizeof(WCHAR);

			RtlCopyMemory(fileStream->FileName.Buffer, g_filFileAutoConfigName, fileStream->FileName.MaximumLength);		

			status = STATUS_SUCCESS;
		}
	}
	else
	{
		ULONG flags = 0;

		// Creative Directory open?
		if((irp->RequestorMode == KernelMode & (stack->Parameters.Create.Options & FILE_DIRECTORY_FILE)) || (stack->Parameters.Create.Options & FILE_DIRECTORY_FILE) && (FILE_CREATE == (stack->Parameters.Create.Options >> 24)))
		{
			DBGPRINT(("AutoConfigCheck: FO[0x%p] Check parent directory\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			flags = CFilterPath::PATH_DIRECTORY;
		}

		// Create path with AutoConfig file
		status = track->Entity.GetAutoConfig(&fileStream->FileName, flags);
	}

	if(NT_SUCCESS(status))
	{
		ACCESS_MASK const access			= stack->Parameters.Create.SecurityContext->DesiredAccess;
		IO_STATUS_BLOCK const ioStatus		= irp->IoStatus;
		KPROCESSOR_MODE const requestorMode = irp->RequestorMode;

		irp->RequestorMode = KernelMode;

		IoCopyCurrentIrpStackLocationToNext(irp);

		IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
		ASSERT(next);

		next->Parameters.Create.SecurityContext->DesiredAccess	= FILE_GENERIC_READ;
		next->Parameters.Create.FileAttributes					= 0;
		next->Parameters.Create.ShareAccess						= FILE_SHARE_VALID_FLAGS;
		next->Parameters.Create.Options							= FILE_NON_DIRECTORY_FILE | (FILE_OPEN << 24);

		next->Flags		 = 0;
		next->FileObject = fileStream;

		// open file, if exists
		status = CFilterBase::SimpleSend(m_extension->Lower, irp);

		if(STATUS_SUCCESS == status)
		{
			// Check for valid AutoConfig file
			status = CFilterCipherManager(m_extension).AutoConfigRead(fileStream, &track->Header);

			// manually cleanup
			CFilterBase::SendCleanupClose(m_extension->Lower, fileStream, true);
		}
		else if(STATUS_REPARSE == status)
		{
			DBGPRINT(("AutoConfigCheck -INFO: STATUS_REPARSE returned\n"));
		}

		if(stack->Parameters.Create.SecurityContext)
		{
			stack->Parameters.Create.SecurityContext->DesiredAccess = access;
		}

		// restore next stack loc
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, 0,0, false, false, false);

		// restore IRP parameters
		irp->RequestorMode	 = requestorMode;
		irp->PendingReturned = false;
		irp->IoStatus		 = ioStatus;
	}
	
	if (NT_ERROR(status))
	{
		if (track->State & TRACK_SHARE_DIRTORY)
		{
			status =  CFilterCipherManager(m_extension).AutoConfigRead(fileStream,&track->Header,0,track);
		}
	}
	
	if(!fileStream->Vpb)
	{
		ASSERT(m_extension->Real);

		// HACK: to overcome an OS bug, inject the VPB manually because otherwise the RefCount gets out of sync
		// and thus prevents a dismount. Especially with removable media this becomes an issue. Interestingly, it 
		// seems to be that NTFS already has a workaround against this - whereas FastFat has not.

		if(m_extension->Real->Vpb)
		{
			DBGPRINT(("AutoConfigCheck: FO[0x%p] injected VPB[0x%p]\n", stack->FileObject, m_extension->Real->Vpb));

			fileStream->Vpb = m_extension->Real->Vpb;
		}
	}

	// IOManager forgets to free the FileName buffer sometimes, but we'll be charged 
	// for it. This only occurs on FAT drives and not on NTFS or CIFS.
	if(fileStream->FileName.Buffer)
	{
		ExFreePool(fileStream->FileName.Buffer);

		fileStream->FileName.Buffer		   = 0;
		fileStream->FileName.Length		   = 0;
		fileStream->FileName.MaximumLength = 0;
	}

	ObDereferenceObject(fileStream);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::AutoConfigCheckGeneric(CFilterPath *path, CFilterHeader *header)
{
	ASSERT(path);
	ASSERT(header);

	PAGED_CODE();

	ASSERT(m_extension);

	UNICODE_STRING autoConfigPath = {0,0,0};
	NTSTATUS status = path->GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX_DYN);

	if(NT_SUCCESS(status))
	{
		FILE_OBJECT *file = 0;
		HANDLE fileHandle = 0;

		status = CFilterBase::CreateFile(m_extension->Lower, 
										 &autoConfigPath,
										 FILE_READ_DATA | FILE_READ_ATTRIBUTES, 
										 FILE_SHARE_VALID_FLAGS,
										 (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 
										 0,
										 &file,
										 &fileHandle);

		//打开成功
		if(NT_SUCCESS(status))
		{
			ASSERT(file);
			ASSERT(fileHandle);

			CFilterHeader autoConfigHeader;
			RtlZeroMemory(&autoConfigHeader, sizeof(autoConfigHeader));

			status = CFilterCipherManager(m_extension).AutoConfigRead(file, &autoConfigHeader, TRACK_NO_PAYLOAD);

			if(NT_SUCCESS(status))
			{
				status = STATUS_UNSUCCESSFUL;

				// verify Header meta data
				if(autoConfigHeader.Equal(header))
				{
					DBGPRINT(("AutoConfigCheckGeneric: matching AutoConfig found, Deepness[0x%x]\n", autoConfigHeader.m_deepness));

					// adjust Deepness indicator
					header->m_deepness = autoConfigHeader.m_deepness;

					status = STATUS_SUCCESS;
				}
				else
				{
					DBGPRINT(("AutoConfigCheckGeneric: valid AutoConfig found, but different Header\n"));
				}

				autoConfigHeader.Close();
			}

			ObDereferenceObject(file);

			ZwClose(fileHandle);
		}
		else
		{
			DBGPRINT(("AutoConfigCheckGeneric -ERROR: DirectOpen() failed [0x%08x]\n", status));
		}

		ExFreePool(autoConfigPath.Buffer);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::CreateEntity(FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(track);
	ASSERT(flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE));

	PAGED_CODE();

	flags &= TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE;
	flags |= TRACK_MATCH_EXACT;

	CFilterEntity *const entity = &track->Entity;

	if( !(track->State & (TRACK_ESCAPE | TRACK_APP_LIST)))
	{
		// File type?
		if((flags & TRACK_TYPE_FILE) && entity->m_file)
		{
			// No matching Entity?
			if(!track->Entity.m_identifier)
			{
				// Check for AutoConfig file with exactly same Header
				if(NT_SUCCESS(AutoConfigCheckGeneric(entity, &track->Header)))
				{
					// Trigger conversion to directory type
					flags |=  TRACK_TYPE_DIRECTORY;
					flags &= ~TRACK_TYPE_FILE;
				}
			}
		}

		// Set Deepness indicator
		entity->m_deepness = track->Header.m_deepness;
	}

	ASSERT((flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE)) != (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE));

	entity->m_flags |= TRACK_AUTO_CONFIG | flags;
	ASSERT(entity->m_flags & TRACK_TYPE_RESOLVED);

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

	NTSTATUS status = AddEntity(track, flags);

	ExReleaseResourceLite(&m_entitiesResource);
	FsRtlExitFileSystem();

	track->State &= ~TRACK_ESCAPE;

	// if an Entity was created ...
	if(STATUS_SUCCESS == status)
	{
		// notify UserMode component
		if(flags & TRACK_TYPE_DIRECTORY)
		{
			//ULONG notifyLength = 0;

			//LPWSTR notify = entity->CopyTo(CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_DEEPNESS,
			 	//				    &notifyLength);

		//	if(notify)
		//	{
				// Function takes ownership
			//	if(NT_ERROR(CFilterControl::Callback().FireNotify(FILFILE_CONTROL_DIRECTORY | FILFILE_CONTROL_ADD, 
							//									  notify, 
						//										  notifyLength)))
				//{
				//	ExFreePool(notify);
				//}
			//}
		}
		else
		{
			// Currently, client is not interested in receiving file Entity notifications
		}
	}

	if(NT_ERROR(status))
	{
		track->State = (STATUS_ACCESS_DENIED == status) ? TRACK_CANCEL : TRACK_NO;
	}
    
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateEntity(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(irp);
	ASSERT(track);
	ASSERT(flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE));

	PAGED_CODE();

	ASSERT(m_extension);

	// Do not trigger on KernelMode requests 
	if(irp->RequestorMode == KernelMode)
	{
		if((!(IoGetCurrentIrpStackLocation(irp)->Parameters.Create.Options & FILE_DIRECTORY_FILE)) & !(IoGetCurrentIrpStackLocation(irp)->Flags & SL_OPEN_TARGET_DIRECTORY))
		{
			DBGPRINT(("PostCreateEntity: Kernel mode request, ignore\n"));

			track->State = TRACK_NO;

			return STATUS_UNSUCCESSFUL;
		}
	}

	// Should be caught before
	ASSERT(!IsRemoteRequest(track, irp));

	FsRtlEnterFileSystem();

	// Check against negative Entities
	if(m_negatives.Size())
	{
		ExAcquireResourceSharedLite(&m_negativesResource, true);

		bool const neg = (m_negatives.Check(&track->Entity) != ~0u);
		
		ExReleaseResourceLite(&m_negativesResource);
		
		if(neg)
		{	
			// Deny access to files within a negative Entity to avoid stale 
			// data and multiple encryption problems. Our management API does
			// not use this code path. Always allow access to directories for
			// enumeration purposes.

			if(track->Entity.GetType() == TRACK_TYPE_FILE)
			{
				DBGPRINT(("PostCreateEntity: matched on Negative, cancel\n"));

				track->State = TRACK_CANCEL;
			}
			else
			{
				DBGPRINT(("PostCreateEntity: matched on Negative, ignore\n"));

				track->State = TRACK_NO;
			}

			FsRtlExitFileSystem();

			return STATUS_UNSUCCESSFUL;
		}
	}

	NTSTATUS status = STATUS_SUCCESS;

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// Check whether Header is already known
	CFilterHeaderCont &headers = m_context->Headers();

	headers.LockShared();
	ULONG const matched = headers.Match(&track->Header);
	headers.Unlock();

	if(matched)
	{
		ASSERT(matched != ~0u);

		// Authenticate against already unlocked Header
		status = PostCreateAuthenticate(irp, track, matched, flags);

		if(NT_SUCCESS(status))
		{
			// Known Header is either different than matched Entity or we have not matched at all
			if(matched != track->Entity.m_headerIdentifier)
			{
				track->Entity.m_headerIdentifier = matched;

				track->State |= TRACK_YES;
				
				CreateEntity(track, flags);
			}
		}

		FsRtlExitFileSystem();

		return status;
	}

	// Call down to UserMode to retrieve key

	// Add function default flags
	track->State &= ~TRACK_YES;
	track->State |= TRACK_CANCEL | TRACK_AUTO_CONFIG;

	// Are we allowed to trigger?
	if(CFilterEngine::s_state & FILFILE_STATE_TRIGGER)
	{
		// Invalidate header identifier as it is different from matched Entity
		track->Entity.m_headerIdentifier = 0;

		ULONG const ctrlFlags = (flags & TRACK_TYPE_DIRECTORY) ? FILFILE_CONTROL_DIRECTORY : FILFILE_CONTROL_NULL;

		// Retrieve Key from UserMode with spinning
		status = CFilterControl::Callback().FireKey(ctrlFlags, track);

		if(NT_SUCCESS(status))
		{
			track->State = TRACK_YES;

			CreateEntity(track, flags);
		}
	}
	else
	{
		if(flags & TRACK_TYPE_DIRECTORY)
		{
			if( !(CFilterEngine::s_state & FILFILE_STATE_ACCESS_DENY_DIR))
			{
				track->State &= ~TRACK_CANCEL;
			}
		}
		else
		{
			if( !(CFilterEngine::s_state & FILFILE_STATE_ACCESS_DENY_FILE))
			{
				track->State &= ~TRACK_CANCEL;
			}
		}

		DBGPRINT(("PostCreateEntity: triggers are deactivated, abort\n"));

		status = STATUS_DEVICE_NOT_CONNECTED;
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PreCreate(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	bool bTrackNetShare=false;

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// valid filename ?
	if(!stack->FileObject || !stack->FileObject->FileName.Buffer || !stack->FileObject->FileName.Length)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DBGPRINT(("PreCreate()--进入\n"));

	ASSERT(stack->MajorFunction == IRP_MJ_CREATE);

	NTSTATUS status = STATUS_SUCCESS;

	if(stack->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
	{
		DBGPRINT(("PreCreate: FILE_OPEN_BY_FILE_ID detected\n"));

		track->State = TRACK_DEFERRED;
	}
	else if(stack->Flags & SL_OPEN_PAGING_FILE)
	{
		// Ignore Paging file
		track->State = TRACK_NO;
	}
	else if(stack->Parameters.Create.Options & (FILE_CREATE_TREE_CONNECTION | FILE_OPEN_FOR_FREE_SPACE_QUERY))
	{
		// Filter out share connects or free space queries
		DBGPRINT(("PreCreate: FO[0x%p] Tree connect or free space query, ignore\n", stack->FileObject));

		track->State = TRACK_NO;
	}
	else
	{
		ULONG flags = TRACK_CHECK_SHORT;

		// Check whether we can give our parser some type hints.
		if(stack->Flags & SL_OPEN_TARGET_DIRECTORY)
		{
			flags |= TRACK_TYPE_FILE;
		}
		else if(FILE_NON_DIRECTORY_FILE == (stack->Parameters.Create.Options & FILE_NON_DIRECTORY_FILE))
		{
			flags |= TRACK_TYPE_FILE;
		}
		else if(FILE_DIRECTORY_FILE == (stack->Parameters.Create.Options & FILE_DIRECTORY_FILE))
		{
			flags |= TRACK_TYPE_DIRECTORY;
		}

		CFilterNormalizer candidate(m_extension, flags);
		status = candidate.NormalizeCreate(irp);

		if(NT_SUCCESS(status))
		{	
			//共享bTrackNetShare
			if (candidate.m_flags & TRACK_SHARE_DIRTORY)
			{
				bTrackNetShare=true;
			}

			// Filter out unsupported devices, like the Novell Redirector or WebDAV for specifc versions
			if( !(candidate.m_flags & TRACK_UNSUPPORTED))
			{
				track->State = TRACK_DEFERRED;

				if(stack->Flags & SL_OPEN_TARGET_DIRECTORY)
				{
					DBGPRINT(("PreCreate: FO[0x%p] SL_OPEN_TARGET_DIRECTORY detected\n", stack->FileObject));

					// Cut off last path component, i.e. the file name
					if(candidate.m_file)
					{
						ASSERT(candidate.m_fileLength);

						RtlZeroMemory(candidate.m_file, candidate.m_fileLength);

						candidate.m_file	   = 0;
						candidate.m_fileLength = 0;

						candidate.m_flags |=  TRACK_TYPE_DIRECTORY;
						candidate.m_flags &= ~TRACK_TYPE_FILE;
					}
				}

				// transfer buffer ownership
				track->Entity.Swap(&candidate, true);

				// If the object type (file/directory) is known at this point, check it now against active
				// Entities, otherwise defer this until the underlying file system is willing to tell.
				//判断当前访问的文件夹或者文件是否之前访问过，如果访问过则则直接复制一些加密相关的信息
				if(track->Entity.m_flags & TRACK_TYPE_RESOLVED)
				{
					FsRtlEnterFileSystem();
					ExAcquireSharedStarveExclusive(&m_entitiesResource, true);

					ULONG const pos = m_entities.Check(&track->Entity);

					if(pos != ~0u)
					{
						track->State = TRACK_YES;

						// copy Identifiers and Flags
						m_entities.CopyInfo(pos, &track->Entity);//复制加解密相关的信息到当前的上下文中
					}

					ExReleaseResourceLite(&m_entitiesResource);
					FsRtlExitFileSystem();
				}
			}
			else
			{
				DBGPRINT(("PreCreate: FO[0x%p] Unsupported device type[0x%x], ignore\n", stack->FileObject, candidate.m_flags));
			}
		}
		else
		{

			//DBGPRINT(("PreCreate: FO[0x%p] 访问网络共享, forbid\n", stack->FileObject, candidate.m_flags));
		}
	}

	if(TRACK_NO != track->State)
	{
		// Check for system directory or IE Cache
		if(IsSpecific(track, TRACK_SYSTEM | TRACK_IE_CACHE))
		{
			track->State = TRACK_NO;
		}
		else
		{
			if(TRACK_DEFERRED == track->State)
			{
				if(!IsRemoteRequest(track, irp))
				{
					// *creative* open request ?
					if (bTrackNetShare)
					{
						track->State |=TRACK_SHARE_DIRTORY;
					}
					else
					{
						ULONG CreateDisposition = (stack->Parameters.Create.Options >> 24) & 0x000000ff;
						if(FILE_OPEN !=CreateDisposition)
						{
							DBGPRINT(("PreCreate: check for AutoConfig file\n"));
							// check for valid AutoConfig file at destination
							if(STATUS_SUCCESS == AutoConfigCheck(irp, track))//如果是目录这读取配置文件头信息
							{
								track->State |= TRACK_AUTO_CONFIG;
							}
						}
					//	else
					//	{
							//
							//	BOOLEAN DirectoryFile=BooleanFlagOn( stack->Parameters.Create.Options, FILE_DIRECTORY_FILE );
							//	BOOLEAN OpenDirectory=(BOOLEAN)(DirectoryFile && ((CreateDisposition == FILE_OPEN) || (CreateDisposition == FILE_OPEN_IF)));
							//	if (OpenDirectory && )
							//{

							//}
						//}
					}
				}
			}
			else if(TRACK_YES == track->State)
			{

				if (bTrackNetShare)
				{
					track->State |=TRACK_SHARE_DIRTORY;
				}

				if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
				{
					// On redirectors, inject read access so that we are able to handle non-aligned write requests correctly
					ULONG const access = stack->Parameters.Create.SecurityContext->DesiredAccess;

					if( !(access & FILE_READ_DATA) && (access & (FILE_WRITE_EA | FILE_WRITE_DATA)) == (FILE_WRITE_EA | FILE_WRITE_DATA))
					{
						DBGPRINT(("PreCreate: FO[0x%p] change Access[0x%x]\n", stack->FileObject, stack->Parameters.Create.SecurityContext->DesiredAccess));
						stack->Parameters.Create.SecurityContext->DesiredAccess |= FILE_READ_DATA;
					}
				}
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreate(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ASSERT(stack->MajorFunction == IRP_MJ_CREATE);
	ASSERT(stack->FileObject);

	DBGPRINT(("PostCreate():文件名[%s]\n", stack->FileObject->FileName.Buffer));

	// filter out non-stream FOs ?
	//直接打开 卷  命名管道 油槽 直接设备打开 则放过
	if((stack->FileObject->Flags & (FO_VOLUME_OPEN | FO_NAMED_PIPE | FO_MAILSLOT | FO_DIRECT_DEVICE_OPEN)) || !stack->FileObject->FsContext)
	{
		DBGPRINT(("PostCreate: FO[0x%p] abstract FileObject, ignore\n", stack->FileObject));
		track->State = TRACK_NO;
		return STATUS_SUCCESS;
	}

	NTSTATUS status	= STATUS_SUCCESS;

	// opened using FILE_OPEN_BY_FILE_ID ?
	if(stack->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
	{
		CFilterNormalizer candidate(m_extension);
		status = candidate.NormalizeFileID(stack->FileObject);

		if(NT_SUCCESS(status))
		{
			status = track->Entity.Swap(&candidate, true);	
		}

		candidate.Close();

		if(NT_ERROR(status) || IsSpecific(track, TRACK_SYSTEM))
		{
			track->State = TRACK_NO;

			return status;
		}
	}

	// Get attributes获得文件属性
	ULONG const attribs = CFilterBase::GetAttributes(m_extension->Lower, stack->FileObject);


	// Check for EFS encrypted files/directories 加密文件
	if((attribs & FILE_ATTRIBUTE_ENCRYPTED) && (attribs != INVALID_FILE_ATTRIBUTES))  
	{
		// Skip them on local volumes
		if(m_extension->LowerType & FILFILE_DEVICE_VOLUME)
		{
			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}
		// Handle them via the redirectors because EFS decryption/encryption is
		// performed on the server! We cannot prohibit this, so deal with it...
	}

	ULONG const ver = CFilterControl::Extension()->SystemVersion;

	// HACK: On CIFS, querying a directory for attribs fails in the context
	// of a rename/move operation.  We imply a directory in this case.
	ULONG const type = (attribs & FILE_ATTRIBUTE_DIRECTORY) ? TRACK_TYPE_DIRECTORY : TRACK_TYPE_FILE;

	// Adjust object type, if different
	track->Entity.SetType(type);
	
	if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
	{
		track->Entity.m_flags &= ~TRACK_REDIR;

		// Estimate underlying network provider. Needed for Vista due to changed redirector model
		ULONG const provider = CFilterBase::GetNetworkProvider(m_extension, stack->FileObject);
		
		switch(provider)
		{
		case FILFILE_DEVICE_REDIRECTOR_CIFS:
			track->Entity.m_flags |= TRACK_CIFS;
			break;
		case FILFILE_DEVICE_REDIRECTOR_WEBDAV:
			track->Entity.m_flags |= TRACK_WEBDAV;
			break;
		case FILFILE_DEVICE_REDIRECTOR_NETWARE:
			track->Entity.m_flags |= TRACK_NETWARE;
			break;
		default:

			DBGPRINT(("PostCreate: FO[0x%p] Unknown network provider, ignore\n", stack->FileObject));

			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}
		
		if(ver & (FILFILE_SYSTEM_WINVISTA | FILFILE_SYSTEM_WIN7))
		{
			// Check whether path has been modified by underlying redirector. This happens with DFS on Vista
			USHORT const post = track->Entity.m_volumeLength + 
								track->Entity.m_directoryLength + 
								track->Entity.m_fileLength - sizeof(WCHAR);

			// Only update with valid path
			if((post > stack->FileObject->FileName.Length) && (stack->FileObject->FileName.Buffer[0] == L'\\'))
			{
				DBGPRINT(("PostCreate: FO[0x%p] Path has been changed\n", stack->FileObject));

				ASSERT(stack->FileObject->FileName.Buffer);
				ASSERT(stack->FileObject->FileName.Length);

				CFilterPath updated;
				status = updated.Init(stack->FileObject->FileName.Buffer,
									  stack->FileObject->FileName.Length,
									  m_extension->LowerType,
									  &m_extension->LowerName);

				if(NT_SUCCESS(status))
				{
					updated.SetType(type);
					// Exchange with existing
					track->Entity.Swap(&updated);
					updated.Close();
				}
			}
		}
	}

	// Deferred Entity check ?
	if(track->State & TRACK_DEFERRED)
	{
		track->State &= ~TRACK_DEFERRED;

		ASSERT( !(track->State & TRACK_YES));

		FsRtlEnterFileSystem();
		ExAcquireSharedStarveExclusive(&m_entitiesResource, true);

		// check against active Entities
		ULONG const pos = m_entities.Check(&track->Entity);

		if(pos != ~0u)
		{
			track->State |= TRACK_YES;

			// copy Identifiers and Flags
			m_entities.CopyInfo(pos, &track->Entity);
		}

		ExReleaseResourceLite(&m_entitiesResource);
		FsRtlExitFileSystem();
	}

	ASSERT(type == track->Entity.GetType());
	ASSERT(type &  TRACK_TYPE_RESOLVED);
	ASSERT(type != (TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY));
	
	ASSERT(track->Entity.m_volume);

	// In TS mode, initialze LUID
	if(ver & FILFILE_SYSTEM_TERMINAL)
	{
		// Should not be set
		ASSERT(!track->Luid.LowPart && !track->Luid.HighPart);

		// Get LUID directly from IRP
		status = CFilterBase::GetLuid(&track->Luid, stack->Parameters.Create.SecurityContext);

		if(NT_ERROR(status))
		{
			return status;
		}

		ASSERT(track->Luid.HighPart || track->Luid.LowPart);
	}

	// Dispatch on object type
	if(TRACK_TYPE_FILE == type)
	{
		PostCreateFile(irp, track);
	}
	else
	{
		ASSERT(TRACK_TYPE_DIRECTORY == type);
	
		PostCreateDirectory(irp, track);
	}

	// request canceled ?
	if(track->State & TRACK_CANCEL)
	{
		// Rollback?
		if(FILE_CREATED == irp->IoStatus.Information)
		{
			DBGPRINT(("PostCreate: delete newly created file\n"));

			FILE_DISPOSITION_INFORMATION dispInfo = {true};

			CFilterBase::SetFileInfo(m_extension->Lower, 
									 stack->FileObject, 
									 FileDispositionInformation, 
									 &dispInfo, 
									 sizeof(dispInfo));
		}

		// Check whether FO comes from MUP. If so, never call IoCancelFileOpen() 
		// on it as it will BSOD. This has been fixed in Vista and later.

		if((m_extension->LowerType & FILFILE_DEVICE_VOLUME) || (ver & (FILFILE_SYSTEM_WINVISTA | FILFILE_SYSTEM_WIN7)))
		{
			IoCancelFileOpen(m_extension->Lower, stack->FileObject);
		}
		else
		{
			DEVICE_OBJECT *target = CFilterBase::GetDeviceObject(stack->FileObject);
			ASSERT(target);
			ASSERT(target->DriverObject);

			// FO related to MUP?  [\FileSystem\MUP]
			if(0x1e == target->DriverObject->DriverName.Length)
			{
				// Manually cleanup to avoid a dangling FO
				CFilterBase::SendCleanupClose(target, stack->FileObject, true);
			}
			else
			{
				IoCancelFileOpen(m_extension->Lower, stack->FileObject);
			}
		}

		// Defaults to Access Denied
		status = STATUS_ACCESS_DENIED;

		if(track->State & TRACK_APP_LIST)
		{
			// Use more specific error
			status = STATUS_SHARING_VIOLATION;
		}

		irp->IoStatus.Status	  = status;
		irp->IoStatus.Information = 0;

		DBGPRINT(("PostCreate: FO[0x%p] cancel with [0x%x]\n", stack->FileObject, irp->IoStatus.Status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateEscape(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags)
{
	ASSERT(irp);
	ASSERT(track);
	ASSERT(flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE));

	PAGED_CODE();

	ULONG depth	= 0;
	ULONG pos	= ~0u;

	if(flags & TRACK_TYPE_DIRECTORY)
	{
		if(!m_context->m_directories.Size())
		{
			return STATUS_SUCCESS;
		}

		// Hash last component only
		ULONG const hash = track->Entity.Hash(CFilterPath::PATH_DIRECTORY | CFilterPath::PATH_TAIL);

		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_context->m_directoriesResource, true);

		// Is exactly same ThreadId, Hash, and within defined time interval as recorded?
		if(m_context->m_directories.SearchSpecial(hash, &pos))
		{
			DBGPRINT(("PostCreateEscape: FO[0x%p] escaped directory detected, catch\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			CFilterDirectory *const directoryFile = m_context->m_directories.Get(pos);
			ASSERT(directoryFile);

			ASSERT(directoryFile->m_entityIdentifier && (directoryFile->m_entityIdentifier != ~0u));
			track->Entity.m_identifier = directoryFile->m_entityIdentifier;

			depth = directoryFile->m_depth;
		}

		ExReleaseResourceLite(&m_context->m_directoriesResource);
		FsRtlExitFileSystem();
	}
	else
	{
		ASSERT(flags & TRACK_TYPE_FILE);

		if(!m_context->m_files.Size())
		{
			return STATUS_SUCCESS;
		}
		
		FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
		ASSERT(file);

		ULONG const hash = track->Entity.Hash(CFilterPath::PATH_FILE);

		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(&m_context->m_filesResource, true);

		// Is exactly same ThreadId, Hash, and within defined time interval as recorded?
		if(m_context->m_files.CheckSpecial(file, &pos, hash))
		{
			DBGPRINT(("PostCreateEscape: FO[0x%p] escaped file detected, catch\n", file));

			CFilterFile *const filterFile = m_context->m_files.Get(pos);
			ASSERT(filterFile);

			ASSERT(filterFile->m_link.m_headerIdentifier);
			track->Entity.m_headerIdentifier = filterFile->m_link.m_headerIdentifier;
		}

		ExReleaseResourceLite(&m_context->m_filesResource);
		FsRtlExitFileSystem();
	}

	NTSTATUS status	= STATUS_SUCCESS;

	// Escaped?
	if(pos != ~0u)
	{
		track->State = TRACK_NO;

		// Check against Blacklist
		if(!m_context->m_blackList.Check(&track->Entity, &track->Luid))
		{
			if(flags & TRACK_TYPE_DIRECTORY)
			{
				CFilterEntity entity;
				RtlZeroMemory(&entity, sizeof(entity));

				status = GetEntityInfo(track->Entity.m_identifier, &entity);

				if(NT_ERROR(status))
				{
					return status;
				}

				if(entity.m_deepness != ~0u)
				{
					// If origin directory a sub of referenced Entity?
					if(depth > entity.m_directoryDepth)
					{
						// Compute new deepness
						entity.m_deepness -= depth - entity.m_directoryDepth;
					}
				}

				track->Entity.m_deepness		 = entity.m_deepness;
				track->Entity.m_headerIdentifier = entity.m_headerIdentifier;
				track->Entity.m_headerBlocksize  = entity.m_headerBlocksize;
			}

			track->State = TRACK_YES | TRACK_ESCAPE;

			// Add a file Entity for this *escaped* object, even on different volumes
			CreateEntity(track, flags);
		}
		else
		{
			DBGPRINT(("PostCreateEscape: FO[0x%p] matched Blacklist, ignore\n", IoGetCurrentIrpStackLocation(irp)->FileObject));
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateDirectoryCreated(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	// Check if process is in bypassed listed
	if(m_context->AppList().Check(irp, FILFILE_APP_BLACK))
	{
		DBGPRINT(("PostCreateDirectoryCreated: FO[0x%p] matched App BLACK\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_SUCCESS;

	if( !(track->State & TRACK_YES))
	{
		// Try to catch a directory escape. That is, a copy (or cross volume move) out of an active Entity
		PostCreateEscape(irp, track, TRACK_TYPE_DIRECTORY);

		if(track->State & TRACK_ESCAPE)
		{
			ASSERT(track->State & TRACK_YES);
			ASSERT(track->Entity.m_headerIdentifier);

			// Create AutoConfig file in newly created directory
			return InitNewDirectory(&track->Entity, track->Entity.m_deepness,track);
		}

		if( !(track->State & TRACK_YES) && (track->State & TRACK_AUTO_CONFIG))
		{
			DBGPRINT(("PostCreateDirectoryCreated: FO[0x%p] Valid AutoConf in parent\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			// Have Entity created for parent directory
			AutoConfigVerify(irp, track, TRACK_TYPE_DIRECTORY);
		}
	}
	else
	{
		// Verify that AutoConf in parent directory is still valid
		AutoConfigVerify(irp, track, TRACK_TYPE_DIRECTORY);
	}

	if( !(track->State & TRACK_YES) || m_context->m_blackList.Check(&track->Entity, &track->Luid))
	{
		if( !(track->State & TRACK_CANCEL))
		{
			track->State = TRACK_NO;
		}

		return STATUS_SUCCESS;
	}

	CFilterEntity entity;
	RtlZeroMemory(&entity, sizeof(entity));

	status = GetEntityInfo(track->Entity.m_identifier, &entity);

	if(NT_SUCCESS(status))
	{
		if(entity.m_deepness != ~0u)
		{
			if(entity.m_directoryDepth + entity.m_deepness < track->Entity.m_directoryDepth)
			{
				DBGPRINT(("PostCreateDirectoryCreated: deepness exceeded, ignore\n"));

				track->State = TRACK_NO;
			}
		}

		if(track->State & TRACK_YES)
		{
			ASSERT(track->Entity.m_headerIdentifier);

			// Create AutoConfig file in new directory
			status = InitNewDirectory(&track->Entity, entity.m_deepness,track);
		}
	}
	else
	{
		track->State = TRACK_NO;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateDirectoryOpened(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ASSERT(file);

	ACCESS_MASK const access = IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess;

	// ignore requests that don't touch the directory content
	if( !(access & (DELETE | FILE_DELETE_CHILD | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE | FILE_LIST_DIRECTORY)))
	{
		DBGPRINT(("PostCreateDirectoryOpened: FO[0x%p] Access[0x%x], ignore\n", file, access));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	// Check if process is in bypassed listed
	if(m_context->AppList().Check(irp, FILFILE_APP_BLACK))
	{
		DBGPRINT(("PostCreateDirectoryOpened: FO[0x%p] matched App BLACK, ignore\n", file));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	// If AutoConf is still valid create Entity as needed
	return AutoConfigVerify(irp, track);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateDirectory(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_context);

	if( !(CFilterEngine::s_state & FILFILE_STATE_DIR))
	{
		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	// Remote request?
	if(IsRemoteRequest(track, irp))
	{
		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_SUCCESS;

	ULONG_PTR const info = irp->IoStatus.Information;

	// If target directory was opened using this special value, the Info 
	// field does not contain the opened flag. Fix this locally
	if(IoGetCurrentIrpStackLocation(irp)->Flags & SL_OPEN_TARGET_DIRECTORY)
	{
		DBGPRINT(("PostCreateDirectory: SL_OPEN_TARGET_DIRECTORY, Info[0x%x]\n", info));

		irp->IoStatus.Information = FILE_OPENED;
	}

	if(!irp->IoStatus.Information)
	{
		if(track->Entity.m_flags & TRACK_WEBDAV)
		{
			DBGPRINT(("PostCreateDirectory(): FO[0x%p] WebDAV, change to open\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			irp->IoStatus.Information = FILE_OPENED;
		}
	}

	switch(irp->IoStatus.Information)
	{
		case FILE_OPENED:

			status = PostCreateDirectoryOpened(irp, track);
			break;
		
		case FILE_SUPERSEDED:
		case FILE_CREATED:
		case FILE_OVERWRITTEN:

			status = PostCreateDirectoryCreated(irp, track);
			break;

		case FILE_EXISTS:
		case FILE_DOES_NOT_EXIST:

		default:
			// just want to know
			ASSERT(false);
			break;
	}

	irp->IoStatus.Information = info;

	if(track->State & TRACK_YES)
	{
		ASSERT( !(track->State & TRACK_CANCEL));

		LARGE_INTEGER tick;
		KeQueryTickCount(&tick);

		DBGPRINT(("PostCreateDirectory(%s): FO[0x%p] track\n", (info == FILE_CREATED) ? "CREATED":"OPENED", IoGetCurrentIrpStackLocation(irp)->FileObject));

		CFilterDirectory directory;

		directory.m_file			 = IoGetCurrentIrpStackLocation(irp)->FileObject;
		directory.m_flags			 = track->Entity.m_flags & (TRACK_MATCH_EXACT | TRACK_AUTO_CONFIG | TRACK_TYPE_RESOLVED);
		directory.m_entityIdentifier = track->Entity.m_identifier;
		directory.m_headerIdentifier = track->Entity.m_headerIdentifier;
		directory.m_depth			 = track->Entity.m_directoryDepth;
		directory.m_hash			 = track->Entity.Hash(CFilterPath::PATH_DIRECTORY | CFilterPath::PATH_TAIL); // Hash last component only
		directory.m_tid				 = (ULONG)(ULONG_PTR) PsGetCurrentThreadId();
		directory.m_tick		     = tick.LowPart;

		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&m_context->m_directoriesResource, true);
		
		// add directory to List
		status = m_context->m_directories.Add(&directory);

		ExReleaseResourceLite(&m_context->m_directoriesResource);
		FsRtlExitFileSystem();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateFile(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(m_context);

	NTSTATUS status = STATUS_SUCCESS;

	ULONG_PTR const info = irp->IoStatus.Information;

	if(!irp->IoStatus.Information)
	{
		if(track->Entity.m_flags & TRACK_WEBDAV)
		{
			DBGPRINT(("PostCreateFile(): FO[0x%p] WebDAV, change to open\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

			irp->IoStatus.Information = FILE_OPENED;
		}
	}

	switch(irp->IoStatus.Information)
	{
		case FILE_OPENED:
		
			status = PostCreateFileOpened(irp, track);
			break;

		case FILE_CREATED:
		case FILE_SUPERSEDED:
		case FILE_OVERWRITTEN:

			status = PostCreateFileCreated(irp, track);
			break;

		//case FILE_EXISTS:
		//case FILE_DOES_NOT_EXIST:
		default:
			// just want to know
			ASSERT(false);
			track->State = TRACK_NO;
			break;
	}

	if(track->State & TRACK_YES)
	{
		ASSERT( !(track->State & TRACK_CANCEL));

		FILE_OBJECT *file = IoGetCurrentIrpStackLocation(irp)->FileObject;
		ASSERT(file);

		// add FO to List
		status = OnFileCreate(file, track, (ULONG) irp->IoStatus.Information);

		if(NT_ERROR(status))
		{
			track->State = TRACK_CANCEL;
		}
	}

	irp->IoStatus.Information = info;

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateAuthenticate(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG headerIdentifier, ULONG flags)
{
	ASSERT(irp);
	ASSERT(track);
	ASSERT(headerIdentifier);
	ASSERT(flags & (TRACK_TYPE_DIRECTORY | TRACK_TYPE_FILE));

	PAGED_CODE();

	ASSERT(m_context);

	// If we are NOT running in TS mode, treat requestor as already authenticated
	if(!CFilterControl::IsTerminalServices())
	{
		DBGPRINT(("PostCreateAuthenticate -INFO: TerminalServices is disabled\n"));

		return STATUS_SUCCESS;
	}

	// Do not trigger on KernelMode requests 
	if(irp->RequestorMode == KernelMode)
	{
		DBGPRINT(("PostCreateAuthenticate: Kernel mode request, ignore\n"));

		return STATUS_SUCCESS;
	}

	// Are we allowed to trigger?
	if( !(CFilterEngine::s_state & FILFILE_STATE_TRIGGER))
	{
		DBGPRINT(("PostCreateAuthenticate: triggers are deactivated, abort\n"));

		return STATUS_DEVICE_NOT_CONNECTED;
	}

	ASSERT(track->Luid.LowPart || track->Luid.HighPart);

	NTSTATUS status = STATUS_SUCCESS;

	CFilterHeaderCont &headers = m_context->Headers();

	headers.LockShared();

	// Check if LUID is already authenticated
	status = headers.CheckLuid(&track->Luid, headerIdentifier);

	if(NT_SUCCESS(status))
	{
		DBGPRINT(("PostCreateAuthenticate: Luid is already authenticated\n"));

		headers.Unlock();

		if(track->Entity.m_identifier && (flags & TRACK_TYPE_FILE))
		{
			ExAcquireResourceSharedLite(&m_entitiesResource, true);
	
			// Check if LUID is already linked to matched file Entity
			CFilterEntity *entity = m_entities.GetFromIdentifier(track->Entity.m_identifier);

			if(entity && (~0u == entity->m_luids.Check(&track->Luid)))
			{
				ExReleaseResourceLite(&m_entitiesResource);

				// Add LUID
				ExAcquireResourceExclusiveLite(&m_entitiesResource, true);

				entity = m_entities.GetFromIdentifier(track->Entity.m_identifier);

				if(entity)
				{
					entity->m_luids.Add(&track->Luid);
				}
			}

			ExReleaseResourceLite(&m_entitiesResource);
		}
	}
	else
	{
		status = STATUS_SUCCESS;

		// If Payload is unknown, make copy from referenced Header
		if(!track->Header.m_payload)
		{
			status = STATUS_UNSUCCESSFUL;

			CFilterHeader const *existing = headers.Get(headerIdentifier);

			if(existing)
			{
				ASSERT(existing->m_payload);
				ASSERT(existing->m_payloadSize);

				status = STATUS_INSUFFICIENT_RESOURCES;

				track->Header.m_payload = (UCHAR*) ExAllocatePool(PagedPool, existing->m_payloadSize);

				if(track->Header.m_payload)
				{
					RtlCopyMemory(track->Header.m_payload, existing->m_payload, existing->m_payloadSize);
				
					track->Header.m_payloadSize = existing->m_payloadSize;
					track->Header.m_payloadCrc  = existing->m_payloadCrc;

					status = STATUS_SUCCESS;

					// Header will be freed by Create handler
				}
			}
			else
			{
				// The referenced Header has been removed meanwhile...
				ASSERT(false);
			}
		}

		headers.Unlock();

		if(NT_SUCCESS(status))
		{
			ASSERT(track->Header.m_payload);
			ASSERT(track->Header.m_payloadSize);

			// Invalidate header identifier that might be different
			track->Entity.m_headerIdentifier = 0;

			ULONG const ctrlFlags = (flags & TRACK_TYPE_DIRECTORY) ? FILFILE_CONTROL_DIRECTORY : FILFILE_CONTROL_NULL;

			status = CFilterControl::Callback().FireKey(ctrlFlags, track);

			// Retrieve Key from UserMode
			if(NT_SUCCESS(status))
			{
				status = STATUS_ACCESS_DENIED;

				headers.LockExclusive();

				CFilterHeader *const existing = headers.Get(headerIdentifier);
				
				if(existing)
				{
					// Compare retrieved EntityKey with active one
					if(existing->m_key.Equal(&track->EntityKey))
					{
						// Add authenticated LUID
						status = existing->m_luids.Add(&track->Luid);

						DBGPRINT(("PostCreateAuthenticate: Add Luid to authenticated\n"));
					}
					else
					{
						// Hmm, someone is fooling us. Just cast an AccessDenied spell back
						ASSERT(false);
					}
				}
				else
				{
					// The referenced Header has been removed meanwhile...
					ASSERT(false);
				}

				headers.Unlock();
			}
		}

		if(NT_ERROR(status))
		{
			track->State &= ~TRACK_YES;
			track->State |= TRACK_CANCEL | TRACK_AUTO_CONFIG;
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateFileOpened(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(m_context);

	// ignore AutoConfig files
	if(IsSpecific(track, TRACK_AUTO_CONFIG))
	{
		DBGPRINT(("PostCreateFileOpened(): FO[0x%p] AutoConfig file, ignore\n", IoGetCurrentIrpStackLocation(irp)->FileObject));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ASSERT(file);

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));

	// already tracked ?
	if(CheckFileCooked(file, &link))
	{
		DBGPRINT(("PostCreateFileOpened: FO[0x%p] FCB[0x%p], already tracked\n", file, file->FsContext));

		FsRtlEnterFileSystem();

		// Check if process is in bypassed listed
		if(m_context->AppList().Check(irp, FILFILE_APP_BLACK))
		{
			// Try to tear down cache
			if(!CFilterBase::TearDownCache(file, 10, 100))
			{
				DBGPRINT(("PostCreateFileOpened: FO[0x%p] tracked and matched App BLACK, cancel\n", file));

				// The file data is still cached and we cannot ensure data
				// consistency, so return SHARING VIOLATION back to caller
				track->State = TRACK_CANCEL | TRACK_APP_LIST;
			}
			else
			{
				// Do not let black-listed FO influence with tracking engine
				m_context->Tracker().Add(file, FILFILE_TRACKER_BYPASS | FILFILE_TRACKER_IGNORE);

				DBGPRINT(("PostCreateFileOpened: FO[0x%p] tracked and matched App BLACK, ignore\n", file));

				track->State = TRACK_NO;
			}

			// Be paranoid
			link.m_fileKey.Clear();

			FsRtlExitFileSystem();

			return STATUS_SUCCESS;
		}

		// Valid Entity?
		if(link.m_entityIdentifier != ~0u)
		{
			ASSERT(link.m_entityIdentifier);

			// Save values in case we have a race with a close operation. We may need them later
			track->Header.m_blockSize		 = link.m_headerBlockSize;
			track->Header.m_nonce			 = link.m_nonce;
			track->Header.m_key				 = link.m_fileKey;

			track->Entity.m_headerIdentifier = link.m_headerIdentifier;

			// Be paranoid
			link.m_fileKey.Clear();

			track->State = TRACK_YES | TRACK_HAVE_KEY;

			// In TS mode, authenticate against already unlocked Header
			PostCreateAuthenticate(irp, track, link.m_headerIdentifier, TRACK_TYPE_FILE);

			FsRtlExitFileSystem();

			return STATUS_SUCCESS;
		}

		// FO is doomed
		DBGPRINT(("PostCreateFileOpened: FO[0x%p] is doomed, resurrect\n", file));

		// Be paranoid
		link.m_fileKey.Clear();

		CFilterBase::TearDownCache(file, 10, 100);

		FsRtlExitFileSystem();
	}
	else
	{
		// Remote request?
		if(IsRemoteRequest(track, irp))
		{
			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}
	}

	if( !(track->Entity.m_flags & TRACK_MATCH_EXACT))
	{
		ACCESS_MASK const access = IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess;

		// HACK: Check for certain size requests issued by McAfee AV 80i. Handle it so they can find their multi-legged animals
		if(access != (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE))
		{
			// ignore requests that won't touch file data
			if(access == (FILE_READ_ATTRIBUTES | DELETE) || !(access & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | DELETE)))
			{
				DBGPRINT(("PostCreateFileOpened: FO[0x%p] defer Header init Access[0x%x], ignore\n", file, access));

				// add this FO to the Ignore List
				m_context->Tracker().Add(file, FILFILE_TRACKER_IGNORE);

				track->State = TRACK_NO;

				return STATUS_SUCCESS;
			}
		}
		else
		{
			DBGPRINT(("PostCreateFileOpened: FO[0x%p] Header init, despite Access[0x%x]\n", file, access));
		}
	}
     
	// if we have an AutoConfig Header from PreCreate ...
	if(track->State & TRACK_AUTO_CONFIG)
	{
		track->State &= ~TRACK_AUTO_CONFIG;
		// ... release it
		track->Header.Close();
	}

	ULONG appList = FILFILE_APP_INVALID;

	// check for valid Header 
	NTSTATUS status = FileCheck(irp, track);

	if(NT_ERROR(status))
	{
		// Invalid header. Check for deferred Header injection scenarios

		// File not zero-sized?
		if(STATUS_MAPPED_FILE_SIZE_ZERO != status)
		{
			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}

		// No write access?
		if(!file->WriteAccess)
		{
			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}

		// Black-listed?
		if(m_context->m_blackList.Check(&track->Entity, &track->Luid))
		{
			DBGPRINT(("PostCreateFileOpened: FO[0x%p] matched Blacklist, ignore\n", file));

			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}
		
		if(track->State & TRACK_YES)
		{
			ASSERT(track->Entity.m_headerIdentifier);

			DBGPRINT(("PostCreateFileOpened: FO[0x%p] lazy Header init\n", file));

			// Add Header to zero-sized file
			if(NT_ERROR(InitNewFile(file, track, FILE_CREATED)))
			{
				track->State = TRACK_NO;
			}

			return STATUS_SUCCESS;
		}

		// Check AppList state
		appList = m_context->AppList().Check(irp, 
											 FILFILE_APP_WHITE | FILFILE_APP_BLACK, 
											 &track->Header,	
											 CFilterControl::IsTerminalServices() ? &track->Luid 
																				  : 0);

		// Opened by White listed process that is not black-listed?
		if((appList & FILFILE_APP_WHITE) != FILFILE_APP_WHITE)
		{
			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}
		
		DBGPRINT(("PostCreateFileOpened: FO[0x%p] lazy Header init\n", file));

		track->State = TRACK_YES | TRACK_APP_LIST | TRACK_HAVE_KEY;

		// Add Header to zero-sized file
		if(NT_SUCCESS(InitNewFile(file, track, FILE_CREATED)))
		{
			CreateEntity(track, TRACK_TYPE_FILE);		
		}
		else
		{
			track->State = TRACK_NO;
		}

		return STATUS_SUCCESS;
	}
	
	// Valid Header. AutoConfig file?
	if(!track->Header.m_key.m_size)
	{
		// We should never come here as both cases should have been filtered out before:
		// 1) regular AutoConfig file
		// 2) AutoConfig file in repositories where its name has been changed

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	// AppList not queried yet?
	if(FILFILE_APP_INVALID == appList)
	{
		appList = m_context->AppList().Check(irp, FILFILE_APP_BLACK);
	}

	// Check if process is black-listed
	if(appList & FILFILE_APP_BLACK)
	{
		// Do not let black-listed FOs influence tracking engine
		m_context->Tracker().Add(file, FILFILE_TRACKER_BYPASS | FILFILE_TRACKER_IGNORE);

		DBGPRINT(("PostCreateFileOpened: FO[0x%p] matched App BLACK, ignore\n", file));

		track->State = TRACK_NO;
	}
	else
	{
		// Create Entity and retreive key as needed
		PostCreateEntity(irp, track, TRACK_TYPE_FILE);
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterVolume::PostCreateFileCreated(IRP *irp, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(irp);
	ASSERT(track);

	PAGED_CODE();

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ASSERT(file);
	
	NTSTATUS status = STATUS_SUCCESS;
	
	bool const autoConfig = IsSpecific(track, TRACK_AUTO_CONFIG);
	bool const terminal   = CFilterControl::IsTerminalServices();
	bool const remote     = IsRemoteRequest(track, irp);

	if(remote)
	{
		bool const tracked = CheckFileCooked(file) ? true : false;

		// Check if file was overwritten/superseeded remotely
		if(FILE_CREATED != irp->IoStatus.Information)
		{
			if(autoConfig)
			{
				// Strip off file name
				track->Entity.m_file	   = 0;
				track->Entity.m_fileLength = 0;
			}
			
			if(tracked)
			{
				DBGPRINT(("PostCreateFileCreated: FO[0x%p] changed remotely, handle\n", file));

				// Deal with this
				RemoteFileChange(file, track);

				track->State = TRACK_NO;
	
				return STATUS_SUCCESS;
			}
		}
		
		if(!autoConfig)
		{
			// Not SRV?
			ASSERT(irp->RequestorMode == KernelMode);
		
			if(!tracked)
			{
				track->State = TRACK_NO;	
			}
		
			DBGPRINT(("PostCreateFileCreated: FO[0x%p] remote and kernel, stop\n", file));
															
			return STATUS_SUCCESS;
		}
	}

	if(autoConfig)
	{
		DBGPRINT(("PostCreateFileCreated: FO[0x%p] AutoConfig file, ignore\n", file));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	if(track->State & (TRACK_AUTO_CONFIG | TRACK_YES))
	{
		// Check against Blacklist
		if(m_context->m_blackList.Check(&track->Entity, &track->Luid))
		{
			DBGPRINT(("PostCreateFileCreated: FO[0x%p] matched Blacklist, ignore\n", file));

			track->State = TRACK_NO;

			return STATUS_SUCCESS;
		}

		// Verify that AutoConf is still valid
		AutoConfigVerify(irp, track, TRACK_TYPE_FILE);
	}

	// Check whether we match on an AppList entry
	ULONG const appList = m_context->AppList().Check(irp, FILFILE_APP_BLACK | FILFILE_APP_WHITE);

	if(appList & FILFILE_APP_BLACK)
	{
		DBGPRINT(("PostCreateFileCreated: FO[0x%p] matched App BLACK, ignore\n", file));

		track->State = TRACK_NO;

		return STATUS_SUCCESS;
	}

	DBGPRINT(("PostCreateFileCreated(%d): FO[0x%p] Requestor[%s] Access[0x%x]\n", irp->IoStatus.Information, file, (irp->RequestorMode == KernelMode) ? "Kernel":"User", IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess));	

	FsRtlEnterFileSystem();

	// Valid AutoConfig from PreCreate()?
	if(track->State & TRACK_AUTO_CONFIG)
	{
		// Create Entity and retreive key as needed
		PostCreateEntity(irp, track, TRACK_TYPE_FILE);
	}
	else if( !(track->State & TRACK_YES))
	{
		// Try to catch a file escape. That is, a copy (or cross volume move) out of an active Entity
		PostCreateEscape(irp, track, TRACK_TYPE_FILE);

		if( !(track->State & TRACK_YES))
		{
			// Matched on white-listed application?
			if(appList & FILFILE_APP_WHITE)
			{
				// Get Payload and EntityKey to be used
				if(m_context->AppList().Check(irp, 
											  FILFILE_APP_WHITE, 
											  &track->Header, 
											  (terminal) ? &track->Luid : 0))
				{
					DBGPRINT(("PostCreateFileCreated: FO[0x%p] matched App WHITE\n", file));

					// If we have write access, write header. Otherwise defer this
					if(file->WriteAccess)
					{
						// Set EntityKey
						track->EntityKey = track->Header.m_key;

						track->State = TRACK_YES | TRACK_APP_LIST | TRACK_HAVE_KEY;
					}
					else
					{
						DBGPRINT(("PostCreateFileCreated: FO[0x%p] No write access[0x%x], defer\n", file, IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess));
					}
				}
			}
		}
	}
        
	if(track->State & TRACK_YES)
	{
		// If we have write access, write header. Otherwise defer this
		if(file->WriteAccess)
		{
			// Add Header to newly created (or over-written) file
			status = InitNewFile(file, track, (ULONG) irp->IoStatus.Information);

			if(NT_SUCCESS(status))
			{
				if(track->State & TRACK_APP_LIST)
				{
					CreateEntity(track, TRACK_TYPE_FILE);
				}
			}
			else
			{
				DBGPRINT(("PostCreateFileCreated: FO[0x%p] InitHeader failed [0x%08x]\n", file, status));

				track->State = TRACK_NO;
			}
		}
		else
		{
			DBGPRINT(("PostCreateFileCreated: FO[0x%p] No write access[0x%x], defer\n", file, IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess));

			track->State = TRACK_NO;
		}
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
