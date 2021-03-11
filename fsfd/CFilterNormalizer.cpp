////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterNormalizer.h: interface for the CFilterNormalizer class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterPath.h"

#include "CFilterNormalizer.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::EnsureCapacity(ULONG size)
{
	PAGED_CODE();

	// Add always a separator and termninating NULL
	size += sizeof(WCHAR) + sizeof(WCHAR);

	if(size > m_capacity)
	{
		// round up
		ULONG const bufferSize = (size + (c_bufferAlign - 1)) & ~(c_bufferAlign - 1);
			
		LPWSTR buffer = (LPWSTR) ExAllocatePool(PagedPool, bufferSize);

		if(!buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(buffer, bufferSize);

		m_capacity = bufferSize;

		if(m_volume)
		{
			size = m_volumeLength;

			// Adjust pointers, if any
			if(m_directory)
			{
				ASSERT(m_directory >= m_volume);
				m_directory = buffer + (m_directory - m_volume);

				size += m_directoryLength; 
			}
			if(m_file)
			{
				ASSERT(m_file >= m_volume);
				m_file = buffer + (m_file - m_volume);

				size += sizeof(WCHAR) + m_fileLength;
			}

			RtlCopyMemory(buffer, m_volume, size);

			ExFreePool(m_volume);
		}

		m_volume = buffer;
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::NormalizeRelative(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(file->FileName.Buffer[0] != L'\\');

	// REL0: RelatedFileObject[\]						file[Dir\file.typ]
	// REL1: RelatedFileObject[\Dir]					file[file.typ]
	// REL2: RelatedFileObject[\Dir1\Dir2]				file[Dir3\file.typ]
	// REL3: RelatedFileObject[\;Z:0\server\share\Dir]	file[file.typ]
	// REL4: RelatedFileObject[\;Z:0\Server\Share\Dir1]	file[Dir2\file.typ]

	FILE_NAME_INFORMATION *fileNameInfo = 0;

	// Query file system for the name as the related FileName field might be invalidated
	NTSTATUS status = CFilterBase::QueryFileNameInfo(m_extension->Lower, file->RelatedFileObject, &fileNameInfo);
		
	if(NT_ERROR(status))
	{
		DBGPRINT(("NormalizeRelative -ERROR: QueryFileNameInfo failed [0x%x]\n", status));

		return status;
	}

	if(m_flags & TRACK_CHECK_VOLUME)
	{
		// At this point, the Session info must be already stripped.
		// Here we have: [\Server\Share\Dir]

		ASSERT(fileNameInfo->FileNameLength >= 2);
		ASSERT(fileNameInfo->FileName[1] != L';');

		m_volumeLength = (USHORT) fileNameInfo->FileNameLength;

		status = EnsureCapacity(m_volumeLength + sizeof(WCHAR) + file->FileName.Length);

		if(NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;

			RtlCopyMemory(m_volume, fileNameInfo->FileName, fileNameInfo->FileNameLength);

			m_volume[m_volumeLength / sizeof(WCHAR)] = L'\\';

			// Here we have something like: [\Server\Share\Dir\file.typ]

			ULONG count = m_volumeLength / sizeof(WCHAR);

			ULONG index;

			for(index = 1; index < count; ++index)
			{
				if(m_volume[index] == L'\\')
				{
					break;
				}
			}

			while(++index < count)
			{
				if(m_volume[index] == L'\\')
				{
					break;
				}
			}

			// Open root directory on connection?
			if(index == count)
			{
				// Add missing backslash
				m_volume[count] = L'\\';

				count++;

				m_volumeLength += sizeof(WCHAR);
			}

			if(index < count)
			{
				m_directory		   = m_volume + index;
				m_directoryLength  = m_volumeLength - (USHORT) (index * sizeof(WCHAR));
				m_volumeLength     = (USHORT) (index * sizeof(WCHAR));

				status = STATUS_SUCCESS;
			}
		}
	}
	else
	{
		status = EnsureCapacity(m_extension->LowerName.Length + file->FileName.Length + sizeof(WCHAR) + fileNameInfo->FileNameLength);

		if(NT_SUCCESS(status))
		{
			ASSERT(m_volume);

			m_volumeLength = m_extension->LowerName.Length;
			
			RtlCopyMemory(m_volume, m_extension->LowerName.Buffer, m_extension->LowerName.Length);

			m_directory		  = m_volume + (m_volumeLength / sizeof(WCHAR));
			m_directoryLength = (USHORT) fileNameInfo->FileNameLength;

			RtlCopyMemory(m_directory, fileNameInfo->FileName, fileNameInfo->FileNameLength);
		}
	}

	if(NT_SUCCESS(status))
	{
		// Root directory?
		if(m_directoryLength != sizeof(WCHAR))
		{
			// Add at least a backslash for it
			m_directory[m_directoryLength / sizeof(WCHAR)] = L'\\';

			m_directoryLength += sizeof(WCHAR);
		}

		RtlCopyMemory((UCHAR*) m_directory + m_directoryLength, file->FileName.Buffer, file->FileName.Length);

		m_directoryLength += file->FileName.Length;
	}

	ExFreePool(fileNameInfo);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::NormalizeAbsolute(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	ASSERT(m_extension);

	ASSERT(file->FileName.Buffer[0] == L'\\');

	// ABS0: RelatedFileObject[]  file[\Dir]
	// ABS1: RelatedFileObject[]  file[\Dir\file.typ]
	// ABS2: RelatedFileObject[]  file[\file.typ]
	// ABS3: RelatedFileObject[]  file[\Server\Share\Dir\file.typ]
	// ABS4: RelatedFileObject[]  file[\;Z:0\Server\Share\Dir\file.typ]

	NTSTATUS status = STATUS_SUCCESS;
	
	// Disk-based path?
	if( !(m_flags & TRACK_CHECK_VOLUME))
	{
		status = EnsureCapacity(m_extension->LowerName.Length + file->FileName.Length);

		if(NT_SUCCESS(status))
		{
			ASSERT(m_volume);

			m_volumeLength = m_extension->LowerName.Length;
			
			RtlCopyMemory(m_volume, m_extension->LowerName.Buffer, m_extension->LowerName.Length);

			m_directory		  = m_volume + (m_volumeLength / sizeof(WCHAR));
			m_directoryLength = file->FileName.Length;

			RtlCopyMemory(m_directory, file->FileName.Buffer, file->FileName.Length);
		}

		return status;
	}

	// Normalize network path

	// 1. [\Server\Share\Dir\file.typ]
	// 2. [\;Z:0\Server\Share\Dir\file.typ]
	// 3. [\Server\Share\Server\Share\Dir\file.typ] - DFS Root
	// 4. [\;LanmanRedirector\;G:0000000000000be9e\Server\Share] - Vista
	// 5. [\DFSClient\;Z:000000000003686b\Server\Share\Dir\file.typ] - DFS drive on Vista

	m_volumeLength = file->FileName.Length;
	
	status = EnsureCapacity(m_volumeLength);

	if(NT_ERROR(status))
	{
		return status;
	}

	status = STATUS_UNSUCCESSFUL;

	RtlCopyMemory(m_volume, file->FileName.Buffer, file->FileName.Length);

	ULONG sessionInfo = 0;
	ULONG index		  = 0; 
	ULONG count		  = m_volumeLength / sizeof(WCHAR);

	// Vista DFS drive style?
	if((count > 13) && (m_volume[11] == L';'))
	{
		// Vista DFS: [\DFSClient\;Z:000000000003686b\Server\Share\Dir\file.typ]

		if(!_wcsnicmp(m_volume, L"\\DFSClient", 10))
		{
			count		   -= 10;
			m_volumeLength -= 10 * sizeof(WCHAR);
			
			RtlMoveMemory(m_volume, m_volume + 10, m_volumeLength);
			RtlZeroMemory(m_volume + count, 10 * sizeof(WCHAR));
		}
	}
	
	// Estimate start of Session info, if any
	if(m_volume[1] == L';')
	{
		// W2K:		[\;Z:0\Server\Share]
		// WXP:		[\;G:0000000000000be9e\Server\Share]
		// Vista:   Lanman:	 [\;LanmanRedirector\;Y:00000000000191d6\Server\Share]
		//			NetWare: [\;NCFSD\NOVELL\SYS\PUBLIC\]

		sessionInfo = 2;

		// Vista?
		if((count >= 20) && !_wcsnicmp(m_volume + 2, L"LanmanRedirector\\;", 18))
		{
			m_flags &= ~TRACK_REDIR;
			m_flags |=  TRACK_CIFS;

			sessionInfo = 20;
		}
		if((count >= 20) && !_wcsnicmp(m_volume + 2, L"WebDavRedirector\\;", 18))
		{
			m_flags &= ~TRACK_REDIR;
			m_flags |=  TRACK_WEBDAV;

			sessionInfo = 20;
		}
		else if((count >= 6) && !_wcsnicmp(m_volume + 2, L"NCFSD\\", 6))
		{
			// Correct flags
			m_flags &= ~TRACK_REDIR;
			m_flags |=  TRACK_NETWARE;

			sessionInfo = 5;
		}

		// Compute Session info length
		for(index = sessionInfo; index < count; ++index)
		{
			if(m_volume[index] == L'\\')
			{
				break;
			}
		}

		if(index < count)
		{
			// Remove it
			count		  -= index;
			m_volumeLength = (USHORT) (count * sizeof(WCHAR));

			RtlMoveMemory(m_volume, m_volume + index, m_volumeLength);
			RtlZeroMemory(m_volume + count, index * sizeof(WCHAR));
		}
	}

	for(index = 1; index < count; ++index)
	{
		if(m_volume[index] == L'\\')
		{
			break;
		}
	}

	while(++index < count)
	{
		if(m_volume[index] == L'\\')
		{
			break;
		}
	}

	// Open root directory on connection?
	if(index == count)
	{
		// Skip tree opens [\Server\IPC$]
		if((count >= 7) && (m_volume[count - 1] == L'$'))
		{
			if(!_wcsnicmp(m_volume + count - 5, L"\\IPC", 4))
			{
				// Trigger ignore
				return STATUS_UNSUCCESSFUL;
			}
		}

		// Add missing backslash
		m_volume[count] = L'\\';

		count++;

		m_volumeLength += sizeof(WCHAR);
	}

	// Here we have something like: [\Server\Share\Dir\file.typ]

	if(index < count)
	{
		m_directoryLength = m_volumeLength - (USHORT) (index * sizeof(WCHAR));
		m_volumeLength   -= m_directoryLength;
		m_directory		  = m_volume + index;

		status = STATUS_SUCCESS;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::NormalizeFileID(FILE_OBJECT *file)
{
	ASSERT(file);

    PAGED_CODE();

	ASSERT(m_extension);

	// Opened using the FILE_ID, so query file system for the name
	FILE_NAME_INFORMATION *fileNameInfo = 0;

	NTSTATUS status = CFilterBase::QueryFileNameInfo(m_extension->Lower, file, &fileNameInfo);
		
	if(NT_SUCCESS(status))
	{
		ASSERT(fileNameInfo);

		status = Init(fileNameInfo->FileName, 
					  fileNameInfo->FileNameLength, 
					  m_extension->LowerType, 
					  &m_extension->LowerName);

		if(NT_SUCCESS(status))
		{
			#if DBG
			{
				DBGPRINT(("NormalizeFileID: FO[0x%p] [", file));
				Print(PATH_VOLUME | PATH_FILE);
				DbgPrint("]\n");
			}
			#endif
		}

		ExFreePool(fileNameInfo);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::NormalizeCreate(IRP *irp)
{
	ASSERT(irp);

    PAGED_CODE();

	ASSERT(m_extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// FileIDs are not supported by this function
	ASSERT( !(stack->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID));

	FILE_OBJECT* const file	= stack->FileObject;
	ASSERT(file);

	// Anyhing to do?
	if(!file->FileName.Length || !file->FileName.Buffer)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
	{
		m_flags |= TRACK_CHECK_VOLUME;

		if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR_CIFS)
		{
			m_flags |= TRACK_CIFS;
		}
		else if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR_WEBDAV)
		{
			m_flags |= TRACK_WEBDAV;
		}
		else if(m_extension->LowerType & FILFILE_DEVICE_REDIRECTOR_NETWARE)
		{
			m_flags |= TRACK_NETWARE;
		}
//如果是网络重定向器  一律 禁止
		DBGPRINT(("网络重定向: NormalizeCreate() 返回 [0x%08x]\n", STATUS_UNSUCCESSFUL));
		//return STATUS_FORBID_SHARE;
		m_flags |= TRACK_YES;
		m_flags |=TRACK_SHARE_DIRTORY;
	}

	NTSTATUS status = STATUS_SUCCESS;

	if(file->RelatedFileObject)
	{
		// Handle relative path
		status = NormalizeRelative(file);
	}
	else
	{
		// Handle absolute path
		status = NormalizeAbsolute(file);
	}

	if(NT_SUCCESS(status))
	{
		ASSERT(m_directory);
		ASSERT(m_directoryLength);

		ASSERT(!m_file);
		ASSERT(!m_fileLength);

		// Common post processing
		status = Parse();

		if(NT_SUCCESS(status))
		{
			// Resolve short components if there are any and we are allowed to do so
			if((m_flags & (TRACK_CHECK_SHORT | TRACK_SHORT_COMPONENT)) == (TRACK_CHECK_SHORT | TRACK_SHORT_COMPONENT))
			{
				status = ShortNameResolver(irp);

				if(NT_SUCCESS(status))
				{
					m_flags &= ~(TRACK_CHECK_SHORT | TRACK_SHORT_COMPONENT);
				}
			}
		}
	}

	if(NT_ERROR(status))
	{
		Close();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterNormalizer::ShortNameResolver(IRP* irp)
{
	PAGED_CODE();

	ASSERT(m_extension);
	ASSERT(m_flags & TRACK_SHORT_COMPONENT);

	if(!irp)
	{
		return STATUS_NOT_IMPLEMENTED;
	}

	// Each path component can have up to 256 chars, so this size should be adequate
	ULONG const longInfoSize = 512 * sizeof(WCHAR);

	FILE_NAMES_INFORMATION* const longInfo = (FILE_NAMES_INFORMATION*) ExAllocatePool(PagedPool, longInfoSize);

	if(!longInfo)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	#if DBG
	{
		/*
		DbgPrint("%sShortNameResolver: ", g_debugHeader);
		Dump(irp);
		*/
	}
	#endif

	NTSTATUS status = STATUS_SUCCESS;

	ASSERT(m_directory);
	ASSERT(m_directoryLength);

	// Directory\File	[Dir1\Dir2\Dir3\file.typ]

	ULONG length = (m_directoryLength + m_fileLength) / sizeof(WCHAR);

	if(m_fileLength)
	{
		// Add path separator
		length++;
	}

	ULONG start	= 1;
	ULONG end	= 1;

	bool resolved = false;

	// For each short component, query parent directory for its
	// long name. Directories itself can be short-named too
	while(start < length)
	{
		bool tilda = false;

		// Search end of component
		while(end < length)
		{
			if(m_directory[end] == L'\\')
			{
				break;
			}
			if(m_directory[end] == L'~')
			{
				tilda = true;
			}	

			end++;
		};

		ASSERT(end >  start);
		ASSERT(end <= length);

		ULONG startAbs = start;

		ULONG const partial = end - start;

		// Valid short name syntax?
		if(tilda && (partial >= 8))
		{
			UNICODE_STRING given;

			given.Length		= (USHORT) (end * sizeof(WCHAR));
			given.MaximumLength = given.Length;
			given.Buffer		= m_directory;

			if(m_flags & TRACK_CHECK_VOLUME)
			{
				ASSERT(m_volume);
				ASSERT(m_volumeLength);
				
				given.Length		+= m_volumeLength;
				given.MaximumLength += m_volumeLength;
				given.Buffer		 = m_volume;

				startAbs += m_volumeLength / sizeof(WCHAR);
			}

			RtlZeroMemory(longInfo, longInfoSize);

			// Retrieve LONG part from handling file system
			status = CFilterBase::GetLongName(m_extension, irp, &given, longInfo, longInfoSize, (USHORT) startAbs);

			if(STATUS_SUCCESS == status)
			{
				LONG const delta = (longInfo->FileNameLength / sizeof(WCHAR)) - (end - start);

				if(delta > 0)
				{
					ULONG const capacity = m_volumeLength + ((length + delta) * sizeof(WCHAR));

					status = EnsureCapacity(capacity);

					if(NT_ERROR(status))
					{
						break;
					}

					resolved = true;

					if(length > end)
					{
						RtlMoveMemory(m_directory + end + delta, m_directory + end, (length - end) * sizeof(WCHAR));
					}

					end    += delta;
					length += delta;
				}

				RtlCopyMemory(m_directory + start, longInfo->FileName, longInfo->FileNameLength);
			}
		}

		start = end + 1;
		end   = start;
	};

	if(resolved)
	{
		ASSERT(end);

		// Re-compute lengths (directory + file) 
		m_directoryLength = (USHORT) ((end - 1) * sizeof(WCHAR));

		if(m_flags & TRACK_TYPE_FILE)
		{
			while(--end)
			{
				if(m_directory[end] == L'\\')
				{
					break;
				}
			}

			ASSERT(end);

			end++;

			m_file			   = m_directory + end;
			m_fileLength	   = m_directoryLength - (USHORT) (end * sizeof(WCHAR));
			m_directoryLength -= (USHORT) (m_fileLength + sizeof(WCHAR));
		}
	}

	ExFreePool(longInfo);

	if(status != STATUS_INSUFFICIENT_RESOURCES)
	{
		status = STATUS_SUCCESS;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if DBG

#pragma PAGEDCODE

void CFilterNormalizer::Dump(IRP* irp, CFilterPath *path)
{
	PAGED_CODE();

	ASSERT(m_extension);

	if(!path)
	{
		path = this;
	}

	ULONG const fullPathSize = m_extension->LowerName.Length + path->m_volumeLength + path->m_directoryLength + path->m_fileLength + (3 * sizeof(WCHAR));

	LPWSTR fullPath = (LPWSTR) ExAllocatePool(PagedPool, fullPathSize);

	if(fullPath)
	{
		RtlZeroMemory(fullPath, fullPathSize);

		ULONG current = 0;
			
		if(path->m_volume && path->m_volumeLength)
		{
			// Usually set on redirectors
			RtlCopyMemory(fullPath, path->m_volume, path->m_volumeLength);

			current += path->m_volumeLength / sizeof(WCHAR);
		}
		else
		{
			// Defaults to current lower device object
			RtlCopyMemory(fullPath, m_extension->LowerName.Buffer, m_extension->LowerName.Length);

			current += m_extension->LowerName.Length / sizeof(WCHAR);
		}

		if(path->m_directory && path->m_directoryLength)
		{
			RtlCopyMemory(fullPath + current, path->m_directory, path->m_directoryLength);

			current += path->m_directoryLength / sizeof(WCHAR);
		}

		if(path->m_file && path->m_fileLength)
		{
			if(fullPath[current - 1] != L'\\')
			{
				fullPath[current] = L'\\';

				current++;
			}

			RtlCopyMemory(fullPath + current, path->m_file, path->m_fileLength);
		}

		bool simple = true;

		if(irp)
		{
			IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
			ASSERT(stack);

			if(stack->MajorFunction == IRP_MJ_CREATE)
			{
				FILE_OBJECT *const file	= stack->FileObject;
				ASSERT(file);

				LPSTR type = "BOTH     ";

				if(stack->Parameters.Create.Options & FILE_DIRECTORY_FILE)
				{
					ASSERT( !(stack->Parameters.Create.Options & FILE_NON_DIRECTORY_FILE));

					type = "DIRECTORY";
				}
				else if(stack->Parameters.Create.Options & FILE_NON_DIRECTORY_FILE)
				{
					ASSERT( !(stack->Parameters.Create.Options & FILE_DIRECTORY_FILE));
						
					type = "FILE     ";
				}

				DbgPrint("%s %s %s [%ws]\n", type, (file->RelatedFileObject) ? "REL":"ABS", (path->m_flags & TRACK_ALTERNATE_STREAM) ? "ADS":"", fullPath);

				simple = false;
			}
		}

		if(simple)
		{
			DbgPrint("[%ws]\n", fullPath);
		}

		ExFreePool(fullPath);
	}
}

#endif // DBG
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////