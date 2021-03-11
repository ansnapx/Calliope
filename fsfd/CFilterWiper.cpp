////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterWiper.cpp: implementation of the CFilterWiper class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CWipePattern.h"

#include "IoControl.h"
#include "CFilterWiper.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterWiper::Close()
{
	PAGED_CODE();

	if(m_cancel)
	{
		ObDereferenceObject(m_cancel);
		m_cancel = 0;
	}

	if(m_progress)
	{
		ObDereferenceObject(m_progress);
		m_progress = 0;
	}

	m_rename   = false;
	m_truncate = false;
	m_delete   = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterWiper::Prepare(ULONG flags, int *patterns, int patternsSize, HANDLE cancel, HANDLE progress)
{
	PAGED_CODE();

	ASSERT(m_random);

	// map flags accordingly
	if(flags & FILFILE_CONTROL_ADD)
	{
		m_rename = true;
	}
	if(flags & FILFILE_CONTROL_SET)
	{
		m_truncate = true;
	}
	if(flags & FILFILE_CONTROL_REM)
	{
		m_delete = true;
	}

	m_patternsCount = 0;

	RtlZeroMemory(m_patterns, sizeof(m_patterns));

	// if no pattern was specified default to just zero'ing file data
	if(patterns)
	{
		ASSERT(patternsSize);

		// ensure bounds
		if(patternsSize > sizeof(m_patterns))
		{
			patternsSize = sizeof(m_patterns);
		}
		
		RtlCopyMemory(m_patterns, patterns, patternsSize);

		m_patternsCount = (char) (patternsSize / sizeof(patterns[0]));
	}

	NTSTATUS status = STATUS_SUCCESS;

	if(cancel)
	{
		// get reference to cancel object, if any
		status = ObReferenceObjectByHandle(cancel, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (void**) &m_cancel, 0);
	}

	if(NT_SUCCESS(status))
	{
		if(progress)
		{
			// get reference to progess object, if any
			status = ObReferenceObjectByHandle(progress, SEMAPHORE_ALL_ACCESS, *ExSemaphoreObjectType, KernelMode, (void**) &m_progress, 0);
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterWiper::WipeStep(LARGE_INTEGER const* offset)
{
	ASSERT(offset);

	PAGED_CODE();

	if(m_cancel)
	{
		// check for cancel
		if(KeReadStateEvent(m_cancel))
		{
			DBGPRINT(("WipeStep: cancelled\n"));
		
			return true;
		}
	}
	
	if(m_progress)
	{
		// ensure the progress value is a multiple of the used IO size
		C_ASSERT(FILFILE_WIPE_PROGRESS_STEP > MM_MAXIMUM_DISK_IO_SIZE);
		C_ASSERT(0 == (FILFILE_WIPE_PROGRESS_STEP % MM_MAXIMUM_DISK_IO_SIZE));

		// offset multiple of progress step value ?
		if(0 == (offset->LowPart & (FILFILE_WIPE_PROGRESS_STEP - 1)))
		{
			DBGPRINT(("WipeStep: progress notification at [0x%I64x]\n", *offset));

			// trigger progress step
			KeReleaseSemaphore(m_progress, SEMAPHORE_INCREMENT, 1, false);	
		}
	}
	
	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterWiper::WipePost(FILE_OBJECT *file, DEVICE_OBJECT *lower)
{
	ASSERT(file);
	ASSERT(lower);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	if(m_rename)
	{
		// Create generic name to overwrite original name with
		LPCWSTR const genericName	 = L"wiped";
		ULONG   const genericNameLen = 5;

		WCHAR name[8] = {0};

		// Check for the impossible ...
		ASSERT(wcslen(genericName) == genericNameLen);
		C_ASSERT(sizeof(name) > (genericNameLen + 2) * sizeof(WCHAR));

		RtlCopyMemory(name, genericName, genericNameLen * sizeof(WCHAR));

		// Loop until we have succeed
		for(USHORT num = 0; num < 16; ++num)
		{
			name[genericNameLen]	 = (num / 10) + L'0';
			name[genericNameLen + 1] = (num % 10) + L'0';
			name[genericNameLen + 2] = UNICODE_NULL;

			status = CFilterBase::SimpleRename(lower, file, name, (genericNameLen + 2) * sizeof(WCHAR), false);

			if(NT_SUCCESS(status) || (status != STATUS_OBJECT_NAME_EXISTS))
			{
				break;
			}
		}
	}

	if(m_truncate)
	{
		// Truncate file to hide its original size
		LARGE_INTEGER eof = {0,0};

		status = CFilterBase::SetFileSize(lower, file, &eof);
	}

	if(m_delete)
	{
		// Finally, delete file
		FILE_DISPOSITION_INFORMATION dispInfo = {true};
			
		status = CFilterBase::SetFileInfo(lower, file, FileDispositionInformation, &dispInfo, sizeof(dispInfo));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterWiper::WipeFile(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();
	
	// Should be adequate for lots of ADS infos
	ULONG  const bufferSize = 4096;
	UCHAR *const buffer     = (UCHAR*) ExAllocatePool(PagedPool, bufferSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(buffer, bufferSize);

	DEVICE_OBJECT *volume = 0;

	// Get corresponding volume device
	NTSTATUS status = CFilterControl::GetVolumeDevice(file, &volume);

	if(NT_ERROR(status))
	{
		DBGPRINT(("WipeFile -ERROR: device not found [0x%08x]\n", status));

		ExFreePool(buffer);

		return status;
	}

	ASSERT(volume);

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
	ASSERT(extension);

	// Get ADS info, if any
	if(NT_SUCCESS(CFilterBase::QueryFileInfo(extension->Lower, file, FileStreamInformation, buffer, bufferSize)))
	{
		FILE_STREAM_INFORMATION *streamInfo = (FILE_STREAM_INFORMATION*) buffer;

		// More than default stream ?
		if(streamInfo->NextEntryOffset)
		{
			FILE_NAME_INFORMATION *fileNameInfo = 0;

			// Retrieve full file path from file system
			status = CFilterBase::QueryFileNameInfo(extension->Lower, file, &fileNameInfo);

			if(NT_SUCCESS(status))
			{
				ASSERT(fileNameInfo);

				status = STATUS_INSUFFICIENT_RESOURCES;

				// Estimate some reasonable buffer size
				ULONG  const pathSize = 8 * (extension->LowerName.Length + fileNameInfo->FileNameLength);
				UCHAR *const path     = (UCHAR*) ExAllocatePool(PagedPool, pathSize);

				if(path)
				{
					for(;;)
					{
						streamInfo = (FILE_STREAM_INFORMATION*) ((UCHAR*) streamInfo + streamInfo->NextEntryOffset);

						// Check our buffer size
						if(pathSize < extension->LowerName.Length + fileNameInfo->FileNameLength + streamInfo->StreamNameLength)
						{
							ASSERT(false);

							status = STATUS_UNSUCCESSFUL;
							break;
						}
                                                						
						// build full stream path
						RtlZeroMemory(path, pathSize);
						RtlCopyMemory(path, extension->LowerName.Buffer, extension->LowerName.Length);
						ULONG offset = extension->LowerName.Length;
						RtlCopyMemory(path + offset, fileNameInfo->FileName, fileNameInfo->FileNameLength);
						offset += fileNameInfo->FileNameLength;
						RtlCopyMemory(path + offset, streamInfo->StreamName, streamInfo->StreamNameLength);

						DBGPRINT(("WipeFile: wiping ADS[%ws]\n", path));
		                				
						UNICODE_STRING streamPath;
						RtlInitUnicodeString(&streamPath, (LPWSTR) path);

						OBJECT_ATTRIBUTES streamOAs;
						InitializeObjectAttributes(&streamOAs, &streamPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

						IO_STATUS_BLOCK	ioStatus = {0,0};
						HANDLE streamHandle		 = 0;

						ULONG const access = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE;
						
						// Open existing stream
						status = IoCreateFileSpecifyDeviceObjectHint(&streamHandle,
																	 access,
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
																	 extension->Lower);

						if(NT_SUCCESS(status))
						{
							FILE_OBJECT *stream = 0;

							status = ObReferenceObjectByHandle(streamHandle, 
															   access, 
															   *IoFileObjectType, 
															   KernelMode, 
															   (void**) &stream, 
															   0);

							if(NT_SUCCESS(status))
							{
								status = WipeData(stream, extension->Lower);

								ObDereferenceObject(stream);
							}

							ZwClose(streamHandle);
						}
						else
						{
							DBGPRINT(("WipeFile -ERROR: IoCreateFileSpecifyDeviceObjectHint() failed [0x%08x]\n", status));
						}

						// Error OR finished ?
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

	ExFreePool(buffer);

	// Wipe default stream
	status = WipeData(file, extension->Lower);

	if(NT_SUCCESS(status))
	{
		// Remove file's Header from cache
		CFilterControl::Extension()->HeaderCache.Remove(extension, file);

		// Perform the post-processing
		WipePost(file, extension->Lower);
	}

	ObDereferenceObject(volume);
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterWiper::WipeData(FILE_OBJECT *file, DEVICE_OBJECT *lower)
{
	ASSERT(file);
	ASSERT(lower);

	PAGED_CODE();

	ASSERT(m_random);

	if(CFilterBase::IsCached(file))
	{
		// Flush dirty pages so that they won't be flushed while/after wiping
		CcFlushCache(file->SectionObjectPointer, 0,0,0);
	}

	LARGE_INTEGER eof = {0,0};

	// Get file size
	NTSTATUS status = CFilterBase::GetFileSize(lower, file, &eof);

	if(NT_SUCCESS(status) && eof.QuadPart)
	{
		// Align on sector boundary
		eof.LowPart = (eof.LowPart + (CFilterBase::c_sectorSize - 1)) & ~((CFilterBase::c_sectorSize - 1));

		FILFILE_READ_WRITE write;
		RtlZeroMemory(&write, sizeof(write));
		
		write.Buffer = (UCHAR*) ExAllocatePool(NonPagedPool, MM_MAXIMUM_DISK_IO_SIZE);

		if(write.Buffer)
		{
			write.Mdl = IoAllocateMdl(write.Buffer, MM_MAXIMUM_DISK_IO_SIZE, false, false, 0);

			if(write.Mdl)
			{
				MmBuildMdlForNonPagedPool(write.Mdl);

				write.Flags = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
				write.Major = IRP_MJ_WRITE;
				write.Wait  = true;
				
				LONG index = 0;

				// Wipe whole file in using each pattern
				do
				{
					DBGPRINT(("WipeData: wiping FO[0x%p] Size[0x%I64x] with Pattern[0x%x]\n", file, eof, m_patterns[index]));

					// Value pattern ?
					if(m_patterns[index] >= 0)
					{
						// Fill buffer with selected pattern
						CWipePattern::Fill(m_patterns[index], write.Buffer, MM_MAXIMUM_DISK_IO_SIZE);
					}

					write.Offset.QuadPart = 0;

					while(write.Offset.QuadPart < eof.QuadPart)
					{
						write.Length = (ULONG) (eof.QuadPart - write.Offset.QuadPart);

						if(!write.Length || (write.Length > MM_MAXIMUM_DISK_IO_SIZE))
						{
							write.Length = MM_MAXIMUM_DISK_IO_SIZE;
						}

						// Random pattern ?
						if(m_patterns[index] < 0)
						{
							// Fill buffer with random data
							m_random->Get(write.Buffer, write.Length);			
						}
						
						status = CFilterBase::ReadWrite(lower, file, &write);

						if(NT_ERROR(status))
						{
							DBGPRINT(("WipeData -ERROR: write failed [0x%08x]\n", status));
							break;
						}

						write.Offset.QuadPart += write.Length;

						// Perform progress step notifications and check for cancelation
						if(WipeStep(&write.Offset))
						{
							status = STATUS_CANCELLED;
							break;
						}
					}
										
					if(NT_ERROR(status))
					{
						break;
					}

					index++;
				}
				while(index < m_patternsCount);

				IoFreeMdl(write.Mdl);
			}

			ExFreePool(write.Buffer);
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
