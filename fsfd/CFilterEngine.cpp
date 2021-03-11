////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterEngine.cpp: implementation of the CFilterEngine class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"
#include "driverMrx.h"

#include "IoControl.h"
#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CFilterContext.h"
#include "CFilterNormalizer.h"
#include "CFilterCipherManager.h"

#include "CFilterEngine.h"

// STATIC ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LONG CFilterEngine::s_state = 0;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterEngine::Init(DRIVER_OBJECT *driver, DEVICE_OBJECT *control, LPCWSTR regPath)
{
	ASSERT(driver);
	ASSERT(control);
	SfLoadDynamicFunctions();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) control->DeviceExtension;
	ASSERT(ctrlExtension);

	// Register this driver to be notified whenever a file system registers itself or
	// removes itself from the registered list.

	//if (ctrlExtension->SystemVersion>FILFILE_SYSTEM_WIN2000)
	//{
	NTSTATUS status = IoRegisterFsRegistrationChange(driver, FileSystemRegister);
	//}	

	if(NT_SUCCESS(status))
	{
		// Register logon session termination
		status = SeRegisterLogonSessionTerminatedRoutine(LogonTermination);

		if(NT_ERROR(status))
		{
			DBGPRINT(("CFilterEngine::Init -ERROR: SeRegisterLogonSessionTerminatedRoutine() failed [0x%08x]\n", status));
		}

		// Reg path given?
		if(regPath)
		{
			ULONG state = FILFILE_STATE_NULL;

			if(NT_SUCCESS(CFilterBase::QueryRegistryLong(regPath, L"Configuration", &state)))
			{
				DBGPRINT(("CFilterEngine::Init: Registry state[0x%x]\n", state));
			}

			s_state = state & FILFILE_STATE_VALID_REG;

			DBGPRINT(("CFilterEngine::Init: Driver state[0x%x]\n", s_state));
		}
	}
	else
	{
		DBGPRINT(("CFilterEngine::Init -ERROR: IoRegisterFsRegistrationChange() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::Close(DRIVER_OBJECT *driver)
{
	ASSERT(driver);

	PAGED_CODE();

	s_state = FILFILE_STATE_NULL;

	FsRtlEnterFileSystem();

	IoUnregisterFsRegistrationChange(driver, FileSystemRegister);

	SeUnregisterLogonSessionTerminatedRoutine(LogonTermination);

	FsRtlExitFileSystem();

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::LogonTermination(LUID *luid)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	LUID temp = {0,0};

	// Called from our termination detection?
	if(luid)
	{
		temp = *luid;

		DBGPRINT(("CFilterEngine::LogonTermination: System invoked [0x%I64x]\n", *luid));
	}
	else
	{
		status = CFilterBase::GetLuid(&temp);

		DBGPRINT(("CFilterEngine::LogonTermination: Internally invoked [0x%I64x]\n", temp));
	}

//	if(NT_SUCCESS(status))
//	{
		// Cleanup terminated LUID 
	//	CFilterControl::Connection(0, &temp);
	//}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterEngine::FileSystemRegister(DEVICE_OBJECT *device, BOOLEAN active)
{
	ASSERT(device);

	PAGED_CODE();

	#if DBG
	{
		LPSTR const action = (active) ? "Register  " : "UnRegister";

		if(FILE_DEVICE_DISK_FILE_SYSTEM == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_DISK_FILE_SYSTEM]\n", action));
		}
		else if(FILE_DEVICE_NETWORK_FILE_SYSTEM == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_NETWORK_FILE_SYSTEM]\n", action));
		}
		else if(FILE_DEVICE_MULTI_UNC_PROVIDER == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_MULTI_UNC_PROVIDER]\n", action));
		}
		else if(FILE_DEVICE_DFS_FILE_SYSTEM == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_DFS_FILE_SYSTEM]\n", action));
		}
		else if(FILE_DEVICE_CD_ROM_FILE_SYSTEM == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_CD_ROM_FILE_SYSTEM]\n", action));
		}
		else if(FILE_DEVICE_TAPE_FILE_SYSTEM == device->DeviceType)
		{
			DBGPRINT(("FileSystemRegister: %s FS [FILE_DEVICE_TAPE_FILE_SYSTEM]\n", action));
		}
		else
		{
			DBGPRINT(("FileSystemRegister: %s FS [UNKNOWN, 0x%x]\n", action, device->DeviceType));
		}
	}
	#endif
	
		
	switch(device->DeviceType)
	{
		case FILE_DEVICE_DISK_FILE_SYSTEM:
		case FILE_DEVICE_NETWORK_FILE_SYSTEM:
			break;

		case FILE_DEVICE_CD_ROM_FILE_SYSTEM:

			if(CFilterControl::s_cdrom)
			{
				break;
			}
		default:
			return;
	}
    if(active)
	{
        // The file system has registered as an active file system. So attach to it.
		DEVICE_OBJECT *filter = device;

		if(!filter)
		{
			DBGPRINT(("FileSystemRegister -WARN: already attached\n"));
			return;
		}

		// Check if we are already attached
		do
		{
			FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;

			if(extension && (FILFILE_FILTER_VOLUME == extension->Common.Type) && (sizeof(FILFILE_VOLUME_EXTENSION) == extension->Common.Size))
			{
				break;
			}

			filter = filter->AttachedDevice;
		}
		while(filter);

		if(filter)
		{
			DBGPRINT(("FileSystemRegister -WARN: already attached\n"));
			return;
		}

		ULONG const objNameInfoSize	= 512;
		OBJECT_NAME_INFORMATION *const objNameInfo = (OBJECT_NAME_INFORMATION*) ExAllocatePool(PagedPool, objNameInfoSize);

		if(objNameInfo)
		{
			RtlZeroMemory(objNameInfo, objNameInfoSize);

			ULONG size = objNameInfoSize;

			
			NTSTATUS status = ObQueryNameString(device->DriverObject, objNameInfo, size, &size);
			
			if(NT_SUCCESS(status))
			{
				// Ignore the MS recognizer, but still attach to other recognizers
				if(!_wcsnicmp(objNameInfo->Name.Buffer, L"\\FileSystem\\Fs_Rec", objNameInfo->Name.Length / sizeof(WCHAR)))
				{
					DBGPRINT(("FileSystemRegister: ignore Recognizer [%ws]\n", objNameInfo->Name.Buffer));

					ExFreePool(objNameInfo);
					return;
				}

				// Ignore the MS Application Virtualization file system driver because 
				// it crashes even on the simplest requests. Weird software..
				if(!_wcsnicmp(objNameInfo->Name.Buffer, L"\\Driver\\sftfs", objNameInfo->Name.Length / sizeof(WCHAR)))
				{
					DBGPRINT(("FileSystemRegister: ignore App Virtual FS [%ws]\n", objNameInfo->Name.Buffer));

					ExFreePool(objNameInfo);
					return;
				}
				
				RtlZeroMemory(objNameInfo, objNameInfoSize);
			}

			size   = objNameInfoSize;
			status = ObQueryNameString(device, objNameInfo, size, &size);

			if(NT_SUCCESS(status))
			{
				// Defaults is FS
				ULONG deviceType = FILFILE_DEVICE_FILE_SYSTEM;

				// Ignore certain file systems like the WebDavRedirector for now
				if(device->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
				{
					// Check if we support this redirector
					deviceType = CFilterBase::GetDeviceType(&objNameInfo->Name);

					switch(deviceType)
					{
						case FILFILE_DEVICE_REDIRECTOR_CIFS:
						case FILFILE_DEVICE_REDIRECTOR_WEBDAV:
							break;

						//case FILFILE_DEVICE_REDIRECTOR_NETWARE:
						default:
							DBGPRINT(("FileSystemRegister: ignore FS [%ws]\n", objNameInfo->Name.Buffer));
							ExFreePool(objNameInfo);
							goto ENUMER_DEVICE;
					}
				}

				status = IoCreateDevice(CFilterControl::Extension()->Driver, sizeof(FILFILE_VOLUME_EXTENSION), 0, device->DeviceType, 0, false, &filter);

				if(NT_SUCCESS(status))
				{
					FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;
					ASSERT(extension);

					RtlZeroMemory(extension, sizeof(FILFILE_VOLUME_EXTENSION));

					//extension->XDiskImageNameType=FILE_XDISK_IMAGE_TYPE;
					extension->Common.Type	 = FILFILE_FILTER_FILE_SYSTEM;
					extension->Common.Size	 = sizeof(FILFILE_VOLUME_EXTENSION);
					extension->Common.Device = filter;

					ASSERT(deviceType);
					extension->LowerType = deviceType;

					DBGPRINT(("FileSystemRegister: try to attach DEVICE [%ws]\n", objNameInfo->Name.Buffer));

					status = STATUS_UNSUCCESSFUL;
					
					extension->Lower = IoAttachDeviceToDeviceStack(filter, device);

					if(extension->Lower)
					{	
						extension->Real	= extension->Lower;

						// Other filter drivers between us and target detected我们的设备和目标设备之间存在别的设备
						if(device != extension->Lower)
						{
							DBGPRINT(("FileSystemRegister -INFO: attached to another Filter\n"));
						}

						status = STATUS_INSUFFICIENT_RESOURCES;
						
						size = objNameInfo->Name.Length + sizeof(WCHAR);

						extension->LowerName.Buffer = (LPWSTR) ExAllocatePool(PagedPool, size);
						
						if(extension->LowerName.Buffer)
						{
							status = STATUS_SUCCESS;

							RtlZeroMemory(extension->LowerName.Buffer, size);
							RtlCopyMemory(extension->LowerName.Buffer, objNameInfo->Name.Buffer, objNameInfo->Name.Length);
													
							extension->LowerName.Length		   = objNameInfo->Name.Length;
							extension->LowerName.MaximumLength = objNameInfo->Name.Length + sizeof(WCHAR);
							
							DBGPRINT(("FileSystemRegister: Attached to [%ws]\n", extension->LowerName.Buffer));
						}

						// If this is a network redirector, add it to our volume List
						if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
						{
							// Redirectors actually behave like volumes
							extension->Common.Type = FILFILE_DEVICE_REDIRECTOR;

							status = CFilterControl::AddVolumeDevice(filter);
						}

						if(NT_SUCCESS(status))
						{
							if(extension->Lower->Flags & DO_DIRECT_IO)
							{
								filter->Flags |= DO_DIRECT_IO;
							}
							else if(extension->Lower->Flags & DO_BUFFERED_IO)
							{
								filter->Flags |= DO_BUFFERED_IO;
							}

							if(extension->Lower->Characteristics & FILE_DEVICE_SECURE_OPEN)
							{
								filter->Characteristics |= FILE_DEVICE_SECURE_OPEN;
							}

							filter->Flags &= ~DO_DEVICE_INITIALIZING;
						}
					}
					else
					{
						DBGPRINT(("FileSystemRegister -ERROR: IoAttachDeviceToDeviceStack() failed\n"));
					}

					if(NT_ERROR(status))
					{
						if(extension->LowerName.Buffer)
						{
							ExFreePool(extension->LowerName.Buffer);
						}	

						IoDeleteDevice(filter);
					}
				}
				else
				{
					DBGPRINT(("FileSystemRegister -ERROR: IoCreateDevice() failed [0x%08x]\n", status));
				}
			}
			else
			{
				DBGPRINT(("FileSystemRegister -ERROR: ObQueryNameString() failed [0x%08x]\n", status));
			}

			ExFreePool(objNameInfo);
		}

ENUMER_DEVICE:

		if (device->DeviceType==FILE_DEVICE_DISK_FILE_SYSTEM)
		{
			SfEnumerateFileSystemVolumes(device);
		}
	}
    else
	{
	    // Search the linked List of drivers attached to this device and check
        // to see whether this driver is attached to it.  If so, remove it.

		DEVICE_OBJECT *filter = device->AttachedDevice;

		while(filter)
		{
	        // This registered file system has someone attached to it.  Scan
	        // until this driver's device object is found and detach it.

			FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;

			if(extension && (extension->Common.Size == sizeof(FILFILE_VOLUME_EXTENSION)))
			{
				ASSERT((FILFILE_FILTER_VOLUME == extension->Common.Type) || (FILFILE_FILTER_FILE_SYSTEM == extension->Common.Type));

				if(extension->LowerName.Buffer)
				{
					DBGPRINT(("FileSystemRegister: Detach from [%ws]\n", extension->LowerName.Buffer));
					
					ExFreePool(extension->LowerName.Buffer);
					extension->LowerName.Buffer = 0;
				}

				extension->LowerName.Length		   = 0;
				extension->LowerName.MaximumLength = 0;

				IoDetachDevice(device);

				// if this a volume device, remove it from our volume List
				if(FILFILE_FILTER_VOLUME == extension->Common.Type)
				{
					CFilterControl::RemoveVolumeDevice(filter);
				}
				
				IoDeleteDevice(filter);
				break;
			}

			device = filter;
			filter = device->AttachedDevice;
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterEngine::SkipCreate(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

    PAGED_CODE();

	ULONG tracker = FILFILE_TRACKER_IGNORE;

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ULONG const access = IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess;

	// Filter out access modes that don't touch the file data
	if((FILE_READ_ATTRIBUTES != access) && ((FILE_READ_ATTRIBUTES | SYNCHRONIZE) != access))
	{
		// Bypass opens issued by SvcHoost.exe which hosts almost
		// all system services. This make CSC work on Vista
		UNICODE_STRING image = RTL_CONSTANT_STRING(L"svchost.exe");

		ASSERT(CFilterControl::Extension());
		CFilterProcess *const process = &CFilterControl::Extension()->Process;
		ASSERT(process);

		if(!process->Match(irp, &image))
		{
			return false;
		}

		tracker = FILFILE_TRACKER_BYPASS;
	}

	//本层不做处理 。复制到下一层处理
	IoCopyCurrentIrpStackLocationToNext(irp);

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	if(STATUS_SUCCESS == CFilterBase::SimpleSend(extension->Lower, irp))
	{
		// Add this FO to the ignore List
		//DBGPRINT(("Skip创建:文件名[%s]  detected, bypass\n", file->FileName.Buffer));
		extension->Volume.m_context->Tracker().Add(file, tracker);
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchCreate(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

    PAGED_CODE();

	// Directed to our CDO?
	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_SUCCESS;
		irp->IoStatus.Information = FILE_OPENED;
		
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_SUCCESS;

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	
	ASSERT(extension);
	
	// If WOD is active, check for DELETE_ON_CLOSE case
	if((s_state & FILFILE_WIPE_ON_DELETE) && (extension->LowerType & FILFILE_DEVICE_VOLUME))
	{
		IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		if(stack->Parameters.Create.Options & FILE_DELETE_ON_CLOSE)
		{
			ASSERT(stack->FileObject);
			DBGPRINT(("DispatchCreate: FO[0x%p] FO_DELETE_ON_CLOSE injected\n", stack->FileObject));
		
			// Hmm, the system never sets this very reasonable value. As it is very helpful 
			// to our needs, set it manually so that our Cleanup handler wipes this too.
			stack->FileObject->Flags |= FO_DELETE_ON_CLOSE;
		}
	}

	// Create path inactive OR lower type NO file system ? 
	if(((s_state & FILFILE_STATE_CREATE) != FILFILE_STATE_CREATE) || !(extension->LowerType & (FILFILE_DEVICE_VOLUME | FILFILE_DEVICE_REDIRECTOR)))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	status = STATUS_SUCCESS;
	if(SkipCreate(device, irp))
	{
		status = irp->IoStatus.Status;

		IoCompleteRequest(irp, IO_DISK_INCREMENT);
		
		return status;
	}

	// Allocate from lookaside list to minimize our stack usage
	C_ASSERT(CFilterContext::c_lookAsideSize >= sizeof(FILFILE_TRACK_CONTEXT));
	FILFILE_TRACK_CONTEXT *const track = (FILFILE_TRACK_CONTEXT*) extension->Volume.m_context->AllocateLookaside();

	if(!track)
	{
		// We should never come here
		ASSERT(false);

		IoSkipCurrentIrpStackLocation(irp);
        
		return IoCallDriver(extension->Lower, irp);
	}

	RtlZeroMemory(track, sizeof(FILFILE_TRACK_CONTEXT));

	// Pre-Create processing
	status = extension->Volume.PreCreate(irp, track);//主要是检查文件路径和读取目录下的配置文件的头信息把文件头放入track->header中

	// Something to do ?
	if(NT_ERROR(status) || (TRACK_NO == track->State))
	{
		bool btrack= (track->State==TRACK_SHARE_DIRTORY);

		track->Entity.Close();
		track->Header.Close();

		extension->Volume.m_context->FreeLookaside(track);

		//if(btrack)
	//	{
			//irp->IoStatus.Status=STATUS_ACCESS_DENIED;
			//irp->IoStatus.Information=0;
		//	IoCompleteRequest(irp, IO_NO_INCREMENT);

			//return irp->IoStatus.Status;
	//	}
	//	else
	//	{
			IoSkipCurrentIrpStackLocation(irp);

			return IoCallDriver(extension->Lower, irp);
	//	}

		
	}

	//DBGPRINT(("DispatchCreate: Stack[0x%x]\n", IoGetRemainingStackSize()));

	if(track->State & TRACK_YES)
	{
		//if(irp->)
		//{
		//if (CFilterControl::Extension()->bReadOnly)
		//{
		//	track->State|=TRACK_READ_ONLY;
		//}
/*
		if (!CFilterControl::Extension()->Process.IsTrustProcess(irp))
		{
			track->Entity.Close();
			track->Header.Close();

			extension->Volume.m_context->FreeLookaside(track);

			irp->IoStatus.Status=STATUS_ACCESS_DENIED;
			irp->IoStatus.Information=0;
			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_ACCESS_DENIED;
		}
		*/
		//	}
		if((track->Entity.m_flags & (TRACK_WEBDAV | TRACK_TYPE_DIRECTORY)) == (TRACK_WEBDAV | TRACK_TYPE_DIRECTORY))
		{
			ULONG const options = IoGetCurrentIrpStackLocation(irp)->Parameters.Create.Options;
			ULONG const access  = IoGetCurrentIrpStackLocation(irp)->Parameters.Create.SecurityContext->DesiredAccess;

			if(((DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES) == access) && (options & FILE_DIRECTORY_FILE))
			{
				#if DBG
				{
					DbgPrint("%sDispatchCreate(): FO[0x%p] Access[0x%x, 0x%x] WebDAV directory delete [", g_debugHeader, 
																										  IoGetCurrentIrpStackLocation(irp)->FileObject,
																										  access,
																										  options & 0x00ffffff);
					track->Entity.Print(CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE);
					DbgPrint("]\n");
				}
				#endif

				// Have potential AutoConfig file deleted
				Delete(extension, track);
			}
		}
	}
	
	// Copy parameters to next location
	IoCopyCurrentIrpStackLocationToNext(irp);

	// Let the call proceed
	status = CFilterBase::SimpleSend(extension->Lower, irp);
	
	if(STATUS_SUCCESS == status)
	{
		status=extension->Volume.PostCreate(irp, track);
	}

	track->Header.Close();
	track->Entity.Close();
	track->EntityKey.Clear();

	extension->Volume.m_context->FreeLookaside(track);

	if (status==STATUS_UNSUCCESSFUL)
	{
		status = irp->IoStatus.Status=STATUS_ACCESS_DENIED;
		irp->IoStatus.Information=0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
	
	status = irp->IoStatus.Status;
	IoCompleteRequest(irp, IO_DISK_INCREMENT);
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchDeviceControl(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		return CFilterControl::Dispatch(device, irp);
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// CIFS redirector on Vista or later?
	if((extension->LowerType & FILFILE_DEVICE_REDIRECTOR_CIFS) && CFilterControl::IsWindowsVistaOrLater())
	{
		IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		switch(stack->Parameters.DeviceIoControl.IoControlCode)
		{
			case 0x140414:

				// Check for this special network request that Vista uses with W2kX SRV prior to
				// perform the special network copy below. Failing it causes the same behavior,
				// including cases where the target is not tracked occuring when copy and rename
				// are combined in one operation.

				// Fall through is intentional

			case 0x144418:

				// Check for this special network request that Vista uses with W2kX SRV in cases
				// where the source and destination of a copy operation are located on the same
				// server. This causes the copying to be performed entirely on/by the server, and
				// so no write requestes are issued against the file on the client what leads
				// to all sorts of data corruptions.

				// Tracked FO?
				if(extension->Volume.CheckFileCooked(stack->FileObject))
				{
					DBGPRINT(("DispatchDeviceControl: FO[0x%p] Abort request[0x%x]\n", stack->FileObject, stack->Parameters.DeviceIoControl.IoControlCode));

					// Failing this request triggers a fallback to standard behavior
					irp->IoStatus.Status	  = STATUS_UNSUCCESSFUL;
					irp->IoStatus.Information = 0;

					IoCompleteRequest(irp, IO_NO_INCREMENT);

					return STATUS_UNSUCCESSFUL;
				}

				break;

			default:
				break;
		}
	}

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::FsUserRequest(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	FILE_NAME_INFORMATION *path = 0;

	bool check	  = false;
	bool complete = false;
	bool allow    = false;

	switch(stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case FSCTL_MOVE_FILE:
		{
			MOVE_FILE_DATA *const move = (MOVE_FILE_DATA*) irp->AssociatedIrp.SystemBuffer;
			ASSERT(move);

			if(move->FileHandle)
			{
				FILE_OBJECT *file = 0;

				// get a pointer to the FO
				NTSTATUS status = ObReferenceObjectByHandle(move->FileHandle, READ_CONTROL, *IoFileObjectType, KernelMode, (void**) &file, 0);

				if(NT_SUCCESS(status))
				{
					ASSERT(file);

					// defrag of tracked file ?
					if(extension->Volume.CheckFileCooked(file))
					{
						DBGPRINT(("DispatchFsControl: IRP_MN_USER_FS_REQUEST [FSCTL_MOVE_FILE], complete\n"));

						complete = true;
					}
					else
					{
						#ifdef FILFILE_WDE_CARETAKER
						{
							// Get file name
							CFilterBase::QueryFileNameInfo(extension->Lower, file, &path);

							// Allow defrag for write access
							allow = file->WriteAccess ? true : false;	
						}
						#endif
					}

					ObDereferenceObject(file);
				}
			}

			break;
		}
		case FSCTL_SET_COMPRESSION: 
		{
			ASSERT(irp->AssociatedIrp.SystemBuffer);

			// Prohibit compression, but always allow decompression
			if(COMPRESSION_FORMAT_NONE != *((USHORT*) irp->AssociatedIrp.SystemBuffer))
			{
				check = true;
			}
			break;
		}
		case FSCTL_SET_ENCRYPTION:
		{
			ASSERT(stack->Parameters.DeviceIoControl.Type3InputBuffer);

			ENCRYPTION_BUFFER const* enc = (ENCRYPTION_BUFFER*) stack->Parameters.DeviceIoControl.Type3InputBuffer;

			// Prohibit EFS encryption, but always allow EFS decryption
			if((FILE_SET_ENCRYPTION   == enc->EncryptionOperation) ||
			   (STREAM_SET_ENCRYPTION == enc->EncryptionOperation))
			{
				check = true;
			}
			break;
		}

		default:
		{
			break;
		}
	}

	if(check)
	{
		ASSERT(!complete);
		ASSERT(!allow);

		ASSERT((stack->Parameters.DeviceIoControl.IoControlCode == FSCTL_SET_COMPRESSION) ||
			   (stack->Parameters.DeviceIoControl.IoControlCode == FSCTL_SET_ENCRYPTION));
		ASSERT(stack->FileObject);

		// Tracked file or directory?
		if(extension->Volume.CheckFileCooked(stack->FileObject) || 
		   extension->Volume.CheckDirectoryCooked(stack->FileObject))
		{
			DBGPRINT(("DispatchFsControl: FSCTL_SET_ENCRYPTION or COMPRESSION, complete\n"));

			complete = true;
		}
		else
		{
			#ifdef FILFILE_WDE_CARETAKER
			{
				if(extension->LowerType & FILFILE_DEVICE_VOLUME)
				{
					// Get file name
					CFilterBase::QueryFileNameInfo(extension->Lower, stack->FileObject, &path);
				}
			}
			#endif
		}
	}

#ifdef FILFILE_WDE_CARETAKER
	if(path)
	{
		ASSERT(!complete);
		ASSERT(extension->LowerType & FILFILE_DEVICE_VOLUME);

		if(!allow && (path->FileNameLength == sizeof(c_wdeMetaPath) - sizeof(WCHAR)))
		{
			if(!_wcsnicmp(path->FileName, c_wdeMetaPath, (sizeof(c_wdeMetaPath) / sizeof(WCHAR)) - 1))
			{
				DBGPRINT(("DispatchFsControl: Targeting WDE meta data file, complete\n"));

				// Trigger completion
				complete = true;
			}
		}

		ExFreePool(path);
	}
#endif //FILFILE_WDE_CARETAKER

	if(complete)
	{
		// Fail request
		irp->IoStatus.Status	  = STATUS_ACCESS_DENIED;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_ACCESS_DENIED;
	}

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::FsMountVolume(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// Allocate intermediate buffer for name queries
	ULONG const bufferSize = 512;
	LPWSTR buffer		   = (LPWSTR) ExAllocatePool(PagedPool, bufferSize);	

	if(!buffer)
	{
		irp->IoStatus.Status	  = STATUS_INSUFFICIENT_RESOURCES;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(buffer, bufferSize);

	// Save real storage device as some underlying driver may invalidate it. This happens sometimes on Vista
	ASSERT(IoGetCurrentIrpStackLocation(irp)->Parameters.MountVolume.Vpb);
	DEVICE_OBJECT *const realDevice = IoGetCurrentIrpStackLocation(irp)->Parameters.MountVolume.Vpb->RealDevice;
	ASSERT(realDevice);

	ULONG size = 0;

	// Check if we simply can ignore this object
	NTSTATUS status = ObQueryNameString(realDevice->DriverObject, (OBJECT_NAME_INFORMATION*) buffer, bufferSize, &size);

	if(NT_SUCCESS(status))
	{
		OBJECT_NAME_INFORMATION *const objNameInfo = (OBJECT_NAME_INFORMATION*) buffer;

		// See if device belongs to the VolumeShadowCopy driver
		if((objNameInfo->Name.Length >= 15 * sizeof(WCHAR)) && !_wcsnicmp(objNameInfo->Name.Buffer, L"\\Driver\\VolSnap", 15))
		{
			ExFreePool(buffer);

			DBGPRINT(("FsMountVolume -INFO: Ignore device\n"));

			IoSkipCurrentIrpStackLocation(irp);

			return IoCallDriver(extension->Lower, irp);
		}
	}
	else
	{
		DBGPRINT(("FsMountVolume -ERROR: ObQueryNameString() failed [0x%x]\n", status));
	}

	DBGPRINT(("FsMountVolume: IRP_MN_MOUNT_VOLUME on DO(dev,real)[0x%p, 0x%p]\n", extension->Lower, realDevice));

	DEVICE_OBJECT *filter = 0;

	status = IoCreateDevice(CFilterControl::Extension()->Driver, 
							sizeof(FILFILE_VOLUME_EXTENSION), 
							0, 
							device->DeviceType, 
							0, 
							false, 
							&filter);

	if(NT_SUCCESS(status))
	{
		ASSERT(filter);

		FILFILE_VOLUME_EXTENSION *const filterExtension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;
		ASSERT(filterExtension);

		RtlZeroMemory(filterExtension, sizeof(FILFILE_VOLUME_EXTENSION));

		IoCopyCurrentIrpStackLocationToNext(irp);

		// Let mount request procceed
		status = CFilterBase::SimpleSend(extension->Lower, irp);

		if(NT_SUCCESS(status))
		{
			// Get potentially changed VPB
			VPB *const realVpb = realDevice->Vpb;
			ASSERT(realVpb);

			if(realVpb != IoGetCurrentIrpStackLocation(irp)->Parameters.MountVolume.Vpb)
			{
				DBGPRINT(("FsMountVolume -INFO: VPB has been changed\n"));
			}

//			filterExtension->XDiskImageNameType=FILE_XDISK_IMAGE_TYPE;
			filterExtension->Common.Type	= FILFILE_FILTER_VOLUME;
			filterExtension->Common.Size	= sizeof(FILFILE_VOLUME_EXTENSION);
			filterExtension->Common.Device	= filter;
			filterExtension->Real			= realVpb->RealDevice;
			filterExtension->LowerType		= FILFILE_DEVICE_VOLUME;
			
			RtlZeroMemory(buffer, bufferSize);

			#if DBG
			{
				// Print what has been mounted
				if(realVpb->VolumeLabelLength)
				{
					ASSERT(realVpb->VolumeLabelLength < bufferSize);

					RtlCopyMemory(buffer, realVpb->VolumeLabel, realVpb->VolumeLabelLength);

					DBGPRINT(("FsMountVolume: Mount volume on [%ws]\n", buffer));

					RtlZeroMemory(buffer, bufferSize);
				}
			}
			#endif
			
			size = 0;

			// Query for name of the real device
			status = ObQueryNameString(realVpb->RealDevice, (OBJECT_NAME_INFORMATION*) buffer, bufferSize, &size);

			if(NT_SUCCESS(status))
			{
				OBJECT_NAME_INFORMATION *const objNameInfo = (OBJECT_NAME_INFORMATION*) buffer;

				// Allocate buffer for device name of exact length
				filterExtension->LowerName.Length		  = (USHORT) objNameInfo->Name.Length;
				filterExtension->LowerName.MaximumLength  = (USHORT) objNameInfo->Name.Length + sizeof(WCHAR);
				filterExtension->LowerName.Buffer		  = (LPWSTR) ExAllocatePool(PagedPool, filterExtension->LowerName.MaximumLength);
				
				if(filterExtension->LowerName.Buffer)
				{
					RtlZeroMemory(filterExtension->LowerName.Buffer, filterExtension->LowerName.MaximumLength);
					RtlCopyMemory(filterExtension->LowerName.Buffer, objNameInfo->Name.Buffer, filterExtension->LowerName.Length);

					DBGPRINT(("FsMountVolume: Attached to [%wZ]\n", &filterExtension->LowerName));
				}
			}

			// Init and add to our internal volume list
			status = CFilterControl::AddVolumeDevice(filter);

			if(NT_SUCCESS(status))
			{
				DEVICE_OBJECT *const lower = IoAttachDeviceToDeviceStack(filter, realVpb->DeviceObject);

				if(lower)
				{
					filterExtension->Lower = lower; 

					if(lower != realVpb->DeviceObject)
					{
						DBGPRINT(("FsMountVolume -INFO: Lower[0x%p] differs from Target[0x%p]\n", lower, realVpb->DeviceObject));
					}

					if(lower->Flags & DO_DIRECT_IO)
					{
						filter->Flags |= DO_DIRECT_IO;
					}
					else if(lower->Flags & DO_BUFFERED_IO)
					{
						filter->Flags |= DO_BUFFERED_IO;
					}

					filter->Flags &= ~DO_DEVICE_INITIALIZING;
				}
				else
				{
					DBGPRINT(("FsMountVolume -ERROR: IoAttachDeviceToDeviceStack() failed\n"));
					
					// Cleanup
					CFilterControl::RemoveVolumeDevice(filter);

					status = STATUS_UNSUCCESSFUL;
				}
			}
		}
		else
		{
			DBGPRINT(("FsMountVolume: Mount request for DO[0x%08x] failed [0x%08x]\n", device, irp->IoStatus.Status));
		}

		if(NT_ERROR(status))
		{
			if(filterExtension->LowerName.Buffer)
			{
				ExFreePool(filterExtension->LowerName.Buffer);
				filterExtension->LowerName.Buffer = 0;
			}

			IoDeleteDevice(filter);
		}

		// Don't propagate errors at this stage since the volume is already mounted
		status = irp->IoStatus.Status;
	}
	else
	{
		DBGPRINT(("FsMountVolume -ERROR: IoCreateDevice() failed [0x%08x]\n", status));
	}

	// Free intermediate buffer
	ExFreePool(buffer);

	irp->IoStatus.Status = status;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::FsLoadFileSystem(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	DBGPRINT(("FsLoadFileSystem: IRP_MN_LOAD_FILE_SYSTEM, detach from [%wZ]\n", &extension->LowerName));

	IoCopyCurrentIrpStackLocationToNext(irp);
	
	// Detach from lower device
	IoDetachDevice(extension->Lower);

	// Let request proceed
	NTSTATUS status = CFilterBase::SimpleSend(extension->Lower, irp);

	// successfully ?
	if(NT_ERROR(status) && (STATUS_IMAGE_ALREADY_LOADED != status))
	{
		// The load was not successful. Simply reattach to the recognizer
		// driver in case it ever figures out how to get the driver loaded
		// on a subsequent call.

		DBGPRINT(("FsLoadFileSystem -ERROR: Request failed [0x%08x], re-attach to [%wZ]\n", irp->IoStatus.Status, &extension->LowerName));

		DEVICE_OBJECT *const previous = IoAttachDeviceToDeviceStack(extension->Common.Device, extension->Lower);

		if(!previous)
		{
			DBGPRINT(("FsLoadFileSystem -ERROR: IoAttachDeviceToDeviceStack() failed\n"));
		}
	}
    else
	{
		// Load was successful, so perform cleanup
		if(extension->LowerName.Buffer)
		{
			ExFreePool(extension->LowerName.Buffer);
			extension->LowerName.Buffer = 0;
		}
	
		IoDeleteDevice(extension->Common.Device);
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchFsControl(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;
		
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	switch(IoGetCurrentIrpStackLocation(irp)->MinorFunction)
	{
		case IRP_MN_USER_FS_REQUEST:	
			return FsUserRequest(device, irp);

		case IRP_MN_MOUNT_VOLUME:	
			return FsMountVolume(device, irp);

		case IRP_MN_LOAD_FILE_SYSTEM:	
			return FsLoadFileSystem(device, irp);

		default:
			break;
	}

	IoSkipCurrentIrpStackLocation(irp);

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

bool CFilterEngine::EstimateCaching(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, FILE_OBJECT *file, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(file);
	ASSERT(link);

	if(irp->Flags & IRP_NOCACHE)
	{
		return false;
	}

	if(IoGetCurrentIrpStackLocation(irp)->Flags & SL_WRITE_THROUGH)//通写标志
	{
		DBGPRINT(("EstimateCaching: SL_WRITE_THROUGH detected\n"));
	}

	// Disk-based volume?//如果是磁盘卷类型,则直接返回TRUE
	if(extension->LowerType & FILFILE_DEVICE_VOLUME)
	{
		return true;
	}

	// Redirector path:重定向器类型路径

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;//文件对象的FsContext是FCB结构
	ASSERT(fcb);

	ExAcquireResourceSharedLite(fcb->Resource, true);

	DBGPRINT(("EstimateCaching: FOFlags[0x%x] FCBFlags[0x%x,0x%x] Ver[0x%x], ", file->Flags, fcb->Flags, fcb->Flags2, fcb->Reserved));

	ULONG const ver = CFilterControl::Extension()->SystemVersion;

	ULONG mrxState = 0;

	// Everything but Windows 2000?
	if( !(ver & FILFILE_SYSTEM_WIN2000))
	{
		ASSERT(fcb->Flags & FSRTL_FLAG_ADVANCED_HEADER);

		// Check if this is a Vista FCB where the upper 4 bits are used as version info.
		if((fcb->Reserved & 0xf0) > 1)
		{
			// Advanced Header v2: Vista, Win7
			MRX_FCB_ADVANCED_VISTA *const mrxFcbAdv = (MRX_FCB_ADVANCED_VISTA*) fcb;

			mrxState = mrxFcbAdv->FcbState;
		}
		else
		{
			// Advanced Header v1: WXP, W2K3
			MRX_FCB_ADVANCED *const mrxFcbAdv = (MRX_FCB_ADVANCED*) fcb;

			mrxState = mrxFcbAdv->FcbState;
		}

		DBGPRINT_N(("MRX_FCB_ADVANCED state[0x%x]", mrxState));
	}
	else
	{
		ASSERT(ver & FILFILE_SYSTEM_WIN2000);

		// Common Header: W2K, NT4
		MRX_FCB *const mrxFcb = (MRX_FCB*) fcb;

		mrxState = mrxFcb->FcbState;

		DBGPRINT_N(("MRX_FCB state[0x%x]", mrxState));
	}

	bool serverOpen		= false;
	bool cachingAllowed = true;

	// Check if caching is enabled for this request
	if(IRP_MJ_READ == stack->MajorFunction)
	{
		if( !(mrxState & FCB_STATE_READCACHEING_ENABLED))
		{
			cachingAllowed = false;
		}
	}
	else
	{
		ASSERT(IRP_MJ_WRITE == stack->MajorFunction);

		if( !(mrxState & FCB_STATE_WRITECACHEING_ENABLED))
		{
			cachingAllowed = false;
		}
	}

	// Post processing for distinct systems:

	if(ver & (FILFILE_SYSTEM_WINVISTA | FILFILE_SYSTEM_WIN7))
	{
		// Vista SP1 has introduced additional flag values
		if(mrxState & FCB_STATE_DISABLE_LOCAL_BUFFERING)
		{
			cachingAllowed = false;
		}

		// Windows 7 (RTM, 7600) has changed the behavior again
		if(ver & FILFILE_SYSTEM_WIN7)
		{
			if( !(mrxState & FCB_STATE_COLLAPSING_ENABLED))
			{
				cachingAllowed = true;
			}
		}
	}
	else if(ver & FILFILE_SYSTEM_WIN2000)
	{
		// If the flags value is completly zeroed, assume caching. 
		// This is needed for W2k Hotfix(885250)
		if(!mrxState)
		{
			ASSERT( !(irp->Flags & IRP_PAGING_IO));
			ASSERT( !(irp->MdlAddress));

			cachingAllowed = true;

			if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR_CIFS)
			{
				// Another W2k weirdness, we really have a SRVOPEN here even
				// if the flag is missing. I love those folks in Redmond...
				serverOpen = true;
			}
		}
	}

	// Is caching still allowed?
	if(cachingAllowed)
	{
		if((mrxState & (FCB_STATE_SRVOPEN_USED | FCB_STATE_FOBX_USED)) == (FCB_STATE_SRVOPEN_USED | FCB_STATE_FOBX_USED))
		{
			serverOpen = true;
		}

		// Check deeper...
		if(serverOpen)
		{
			MRX_FOBX *const mrxFobx		   = (MRX_FOBX*) file->FsContext2;
			MRX_SRV_OPEN *const mrxSrvOpen = mrxFobx->pSrvOpen;

			if(mrxSrvOpen)
			{
				ASSERT(mrxSrvOpen->nodeHeader.NodeTypeCode == NODE_TYPE_SRVOPEN);

				// Is caching for this request explicitly disabled?
				if(IRP_MJ_READ == stack->MajorFunction)
				{
					if(mrxSrvOpen->Flags & SRVOPEN_FLAG_DONTUSE_READ_CACHEING)
					{
						cachingAllowed = false;
					}
				}
				else
				{
					ASSERT(IRP_MJ_WRITE == stack->MajorFunction);

					if(mrxSrvOpen->Flags & SRVOPEN_FLAG_DONTUSE_WRITE_CACHEING)
					{
						cachingAllowed = false;
					}
				}

				DBGPRINT_N((", MRX_SRV_OPEN Flags[0x%x]", mrxSrvOpen->Flags));
			}
			else
			{
				// Hmm, the flags value states that the we have a valid SRVOPEN... 
				DBGPRINT_N((", MRX_SRV_OPEN is NULL"));
			}
		}
	}

	#if DBG
	{
		if(!cachingAllowed)
		{
			DbgPrint(", NOCACHE");
		}

		DbgPrint("\n");
	}
	#endif
	
	ExReleaseResourceLite(fcb->Resource);

	if(link->m_flags & TRACK_USE_CACHE)
	{
		ASSERT(IRP_MJ_WRITE == stack->MajorFunction);

		// Clear out cache hint left
		extension->Volume.UpdateLink(file, ~TRACK_USE_CACHE, true);
	}

	return cachingAllowed;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionReadCached(DEVICE_OBJECT *device, IRP *irp, void *context)
{
	ASSERT(irp);

	UNREFERENCED_PARAMETER(device);

	NTSTATUS status = irp->IoStatus.Status;

	if(NT_SUCCESS(status))
	{
		// Actually, completion routines can be called at DISPATCH_LEVEL, but this has never happen in the cached path yet.
		ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

		IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) stack->FileObject->FsContext;
		ASSERT(fcb);

		FsRtlEnterFileSystem();
		ExAcquireResourceSharedLite(fcb->Resource, true);

		// overlapped read ?
		if(context)
		{
			// the Dispatch routine has placed this value here
			ULONG const metaSize = (ULONG)(ULONG_PTR) context;

			ASSERT(fcb->FileSize.QuadPart > stack->Parameters.Read.ByteOffset.QuadPart + metaSize);

			// adjust it
			irp->IoStatus.Information = (ULONG) (fcb->FileSize.QuadPart - (stack->Parameters.Read.ByteOffset.QuadPart + metaSize));

			DBGPRINT(("CompletionReadCached: adjusted Info[0x%x]\n", irp->IoStatus.Information));

			FILE_OBJECT *const file = stack->FileObject;

			// synchronous IO ?
			if( !(irp->Flags & IRP_PAGING_IO) && (file->Flags & FO_SYNCHRONOUS_IO))
			{
				// adjust current byte offset
				file->CurrentByteOffset.QuadPart = stack->Parameters.Read.ByteOffset.QuadPart + irp->IoStatus.Information;

				ASSERT(fcb->FileSize.QuadPart > file->CurrentByteOffset.QuadPart);

				DBGPRINT(("CompletionReadCached: adjusted Curr[0x%I64x]\n", file->CurrentByteOffset));
			}
		}

		ExReleaseResourceLite(fcb->Resource);
		FsRtlExitFileSystem();
	}
	else
	{
		DBGPRINT(("CompletionReadCached -ERROR: request failed [0x%08x]\n", status));
	}
	
    if(irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if FILFILE_USE_PADDING

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionReadNonAligned(DEVICE_OBJECT *device, IRP *irp, void *context)
{
	READ_WRITE_CONTEXT *const readWrite = (READ_WRITE_CONTEXT*) context;
	ASSERT(readWrite);

	ASSERT(readWrite->RequestUserBuffer);		// Original request UserBuffer
	ASSERT(readWrite->RequestUserBufferMdl);	// Mdl covering locked UserBuffer
	ASSERT(readWrite->Buffer);					// Crypt context

	FILFILE_CRYPT_CONTEXT *const crypt = (FILFILE_CRYPT_CONTEXT*) readWrite->Buffer;
	ASSERT(crypt);

	if(NT_SUCCESS(irp->IoStatus.Status) && irp->IoStatus.Information)
	{
		// get our intermediate buffer
		UCHAR *source = (UCHAR*) MmGetMdlVirtualAddress(irp->MdlAddress);
		ASSERT(source);

		// get target UserBuffer
		UCHAR *const target = (UCHAR*) MmGetSystemAddressForMdlSafe(readWrite->RequestUserBufferMdl, NormalPagePriority);
		ASSERT(target);

		if(target)
		{
			// decode buffer inplace
			CFilterContext::Decode(source, (ULONG) irp->IoStatus.Information, crypt);

			IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
			ASSERT(stack);

			source += stack->Parameters.Read.ByteOffset.LowPart & (CFilterBase::c_sectorSize - 1);
			
			// copy decrypted data into user's buffer
			ASSERT(irp->IoStatus.Information > crypt->Value);
			ULONG valid = (ULONG) irp->IoStatus.Information - crypt->Value;

			if(valid > stack->Parameters.Read.Length)
			{
				valid = stack->Parameters.Read.Length;
			}

			RtlCopyMemory(target, source, valid);

			if( !(irp->Flags & IRP_PAGING_IO))
			{
				irp->IoStatus.Information = valid;

				FILE_OBJECT *const file = stack->FileObject;

				// synchronous IO ?
				if(file->Flags & FO_SYNCHRONOUS_IO)
				{
					// adjust current byte offset
					file->CurrentByteOffset.QuadPart = stack->Parameters.Read.ByteOffset.QuadPart + irp->IoStatus.Information;

					ASSERT(((FSRTL_COMMON_FCB_HEADER*) file->FsContext)->FileSize.QuadPart > file->CurrentByteOffset.QuadPart);

					DBGPRINT(("CompletionReadNonAligned: adjusted Curr[0x%I64x]\n", file->CurrentByteOffset));
				}
			}
		}
	}
	else
	{
		DBGPRINT(("CompletionReadNonAligned -ERROR: request failed or zero [0x%08x]\n", irp->IoStatus.Status));
	}

	// Unlock locked UserBuffer
	MmUnlockPages(readWrite->RequestUserBufferMdl);
	// Free Mdl covering locked UserBuffer	
	IoFreeMdl(readWrite->RequestUserBufferMdl);

	// Free intermediate buffer and restore changed parameters
	IoFreeMdl(irp->MdlAddress);	
	irp->MdlAddress = 0;

	ExFreePool(irp->UserBuffer);
	irp->UserBuffer = readWrite->RequestUserBuffer;

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// be paranoid
	RtlZeroMemory(crypt, sizeof(FILFILE_CRYPT_CONTEXT));

	extension->Volume.m_context->FreeLookaside(crypt);

	extension->Volume.m_context->FreeLookaside(readWrite);
		
    if(irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

#endif //FILFILE_USE_PADDING
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if FILFILE_USE_PADDING

#pragma PAGEDCODE

NTSTATUS CFilterEngine::ReadNonAligned(FILFILE_VOLUME_EXTENSION* extension, IRP *irp, LONGLONG vdl, FILFILE_CRYPT_CONTEXT* crypt)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(crypt);

	PAGED_CODE();

	ASSERT(!irp->MdlAddress);
	ASSERT(irp->UserBuffer);

	// Handle misalignment of offset/size requests on redirectors
	ASSERT(extension->LowerType & (FILFILE_DEVICE_REDIRECTOR_CIFS | FILFILE_DEVICE_REDIRECTOR_WEBDAV));

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	C_ASSERT(CFilterContext::c_lookAsideSize >= sizeof(READ_WRITE_CONTEXT));
	READ_WRITE_CONTEXT *const readWrite = (READ_WRITE_CONTEXT*) extension->Volume.m_context->AllocateLookaside();

	if(readWrite)
	{
		RtlZeroMemory(readWrite, sizeof(READ_WRITE_CONTEXT));

		IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
		ASSERT(next);

		LONGLONG targetOffset = next->Parameters.Read.ByteOffset.QuadPart;
		LONG	 targetSize	  = next->Parameters.Read.Length;

		DBGPRINT(("ReadNonAligned: FO[0x%p] Requested: Size[0x%x] Offset[0x%I64x]\n", next->FileObject, targetSize, targetOffset));
		
		// Allocate Mdl to cover UserBuffer
		readWrite->RequestUserBufferMdl = IoAllocateMdl(irp->UserBuffer, targetSize, false, false, 0);

		if(readWrite->RequestUserBufferMdl)
		{
			// Probe/Lock UserBuffer so that it cannot go away
			__try 
			{
				MmProbeAndLockPages(readWrite->RequestUserBufferMdl, irp->RequestorMode, IoWriteAccess);

				status = STATUS_SUCCESS;
			}
			__except(EXCEPTION_EXECUTE_HANDLER) 
			{
				status = STATUS_INVALID_USER_BUFFER;
			}

			if(NT_SUCCESS(status))
			{
				status = STATUS_INSUFFICIENT_RESOURCES;

				// Compute how much to read additionally around given request. That is, before and/or after.
				ULONG const deltaOffset = (ULONG) targetOffset & (CFilterBase::c_sectorSize - 1);

				if(deltaOffset)
				{
					ASSERT(crypt->Offset.QuadPart >= deltaOffset);
					crypt->Offset.QuadPart -= deltaOffset;

					ASSERT(targetOffset >= deltaOffset);
					targetOffset -= deltaOffset;
					targetSize   += deltaOffset;
				}

				ULONG deltaSize = (-targetSize) & (CFilterBase::c_sectorSize - 1);

				targetSize += deltaSize;

				// Overlap with VDL ?
				if(targetOffset + targetSize >= vdl)
				{
					// cut off size
					targetSize = (ULONG) (vdl - targetOffset);

					deltaSize = CFilterContext::ComputePadding(targetSize);

					targetSize += deltaSize;
				}

				// Set size of additional bytes
				crypt->Value = deltaOffset + deltaSize;

				ASSERT(crypt->Value < (ULONG) targetSize);

				ASSERT(0 == (targetSize   % CFilterContext::c_blockSize));
				ASSERT(0 == (targetOffset % CFilterBase::c_sectorSize));
								
				// save original UserBuffer
				readWrite->RequestUserBuffer = irp->UserBuffer;
				// store Crypt context
				readWrite->Buffer = (UCHAR*) crypt;

				// Allocate intermediate buffer for request processing
				irp->UserBuffer = ExAllocatePool(NonPagedPool, targetSize);

				if(irp->UserBuffer)
				{
					irp->MdlAddress = IoAllocateMdl(irp->UserBuffer, targetSize, false, false, 0);

					if(irp->MdlAddress)
					{
						MmBuildMdlForNonPagedPool(irp->MdlAddress);

						ASSERT(readWrite->RequestUserBuffer);
						ASSERT(readWrite->RequestUserBufferMdl);
						ASSERT(readWrite->Buffer);

						DBGPRINT(("ReadNonAligned: FO[0x%p] Performed: Size[0x%x] Offset[0x%I64x]\n", next->FileObject, targetSize, targetOffset));

						// Update parameters in next location
						next->Parameters.Read.ByteOffset.QuadPart = targetOffset;
						next->Parameters.Read.Length			  = targetSize;
						
						IoSetCompletionRoutine(irp, CompletionReadNonAligned, readWrite, true, true, true);

						return STATUS_SUCCESS;
					}

					// Error path:
					ExFreePool(irp->UserBuffer);

					MmUnlockPages(readWrite->RequestUserBufferMdl);
				}

				irp->UserBuffer = readWrite->RequestUserBuffer;
			}

			IoFreeMdl(readWrite->RequestUserBufferMdl);
		}

		extension->Volume.m_context->FreeLookaside(readWrite);
	}

	return status;
}

#endif //FILFILE_USE_PADDING
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionRead(DEVICE_OBJECT *device, IRP *irp, void *context)
{
	ASSERT(irp);
	ASSERT(context);
	ASSERT(device);

	// get crypt context
	FILFILE_CRYPT_CONTEXT *const crypt = (FILFILE_CRYPT_CONTEXT*) context;
		
	if(NT_SUCCESS(irp->IoStatus.Status))
	{
		IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		ULONG const bufferSize = (ULONG) irp->IoStatus.Information;

		if(bufferSize)
		{
			UCHAR* buffer = (UCHAR*) irp->UserBuffer;
			
			if(irp->MdlAddress)
			{
				buffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
			}

			ASSERT(buffer);

			if(buffer)
			{
				// decode buffer
				CFilterContext::Decode(buffer, bufferSize, crypt);

				// substract Tail bytes, if any
				ASSERT(irp->IoStatus.Information >= crypt->Value);
				irp->IoStatus.Information -= crypt->Value;

				if( !(irp->Flags & IRP_PAGING_IO))
				{
					FILE_OBJECT *const file = stack->FileObject;
					ASSERT(file);

					// synchronous IO ?
					if(file->Flags & FO_SYNCHRONOUS_IO)
					{
						// adjust current byte offset
						file->CurrentByteOffset.QuadPart = stack->Parameters.Read.ByteOffset.QuadPart + irp->IoStatus.Information;

						ASSERT(((FSRTL_COMMON_FCB_HEADER*) file->FsContext)->FileSize.QuadPart > file->CurrentByteOffset.QuadPart);

						DBGPRINT(("CompletionRead: adjusted Curr[0x%I64x]\n", file->CurrentByteOffset));
					}
				}
			}
		}
	}
	else
	{
		DBGPRINT(("CompletionRead -ERROR: request failed [0x%08x]\n", irp->IoStatus.Status));
	}

	// be paranoid
	RtlZeroMemory(crypt, sizeof(FILFILE_CRYPT_CONTEXT));

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	extension->Volume.m_context->FreeLookaside(crypt);
	
    if(irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::ReadBypass(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);
	
	ASSERT(irp->UserBuffer);
	ASSERT( !(irp->Flags & IRP_NOCACHE));
	
	irp->IoStatus.Information = 0;
	
	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);
	
	FILE_OBJECT *const file = stack->FileObject;
	ASSERT(file);
	
	NTSTATUS status = STATUS_SUCCESS;
	
	MDL *mdl = irp->MdlAddress;
			
	if(!mdl)
	{
		ASSERT(0 == (stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE)));
	
		// Lock down user buffer
		mdl = IoAllocateMdl(irp->UserBuffer, stack->Parameters.Read.Length, false, false, 0);
		
		if(!mdl)
		{
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		__try 
		{
			MmProbeAndLockPages(mdl, irp->RequestorMode, IoReadAccess);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			
			irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
		
			return STATUS_INVALID_USER_BUFFER;
		}
	}
	
	FsRtlEnterFileSystem();					 
	
	// Cached or mem-mapped?
	if(CFilterBase::IsCached(file))
	{
		DBGPRINT(("ReadBypass: FO[0x%p] Flush\n", file));
	
		// Flush potentially stale data to disk we are going to read. Flush 
		// entire file because CC stumbles when we do this in exact chunks.
		CcFlushCache(file->SectionObjectPointer, 0,0, &irp->IoStatus);
					 
		irp->IoStatus.Information = 0;
	}
	
	FILFILE_READ_WRITE readWrite;
	
	readWrite.Buffer = (UCHAR*) irp->UserBuffer;
	readWrite.Mdl	 = mdl;	
	readWrite.Offset = stack->Parameters.Read.ByteOffset;
	readWrite.Length = stack->Parameters.Read.Length;
	readWrite.Flags	 = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;	
	readWrite.Major	 = IRP_MJ_READ;
	readWrite.Wait	 = true;
	
	bool truncated = false;
	bool beyondEOF = false;	
						   	
	FSRTL_COMMON_FCB_HEADER* const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
	ASSERT(fcb);
	
	ExAcquireResourceSharedLite(fcb->Resource, true);
	
	// Check some conditions regarding EOF
	if(readWrite.Offset.QuadPart >= fcb->FileSize.QuadPart)
	{
		beyondEOF = true;	
	}
	else if(readWrite.Length >= fcb->FileSize.QuadPart - readWrite.Offset.QuadPart)
	{
		// Truncate Length we are going to read. Do not take it into account for alignment checks
		readWrite.Length = (ULONG) (fcb->FileSize.QuadPart - readWrite.Offset.QuadPart);
		
		truncated = true;
	}
	
	ExReleaseResourceLite(fcb->Resource);	
	
	status = STATUS_END_OF_FILE;
	
	if(!beyondEOF)
	{
		DBGPRINT(("ReadBypass: FO[0x%p] Read Size[0x%x] Offset[0x%I64x]\n", file, readWrite.Length, readWrite.Offset));
		
		// Read data from disk including Header and Tail, if requested
		if((readWrite.Offset.LowPart & (CFilterBase::c_sectorSize - 1)) || 
		   (!truncated && (readWrite.Length & (CFilterBase::c_sectorSize - 1))))
		{
			status = CFilterBase::ReadNonAligned(extension->Lower, file, &readWrite);
		}
		else
		{	
			status = CFilterBase::ReadWrite(extension->Lower, file, &readWrite);
		}	
		
		if(NT_SUCCESS(status))
		{		
			irp->IoStatus.Information = readWrite.Length;
	
			// For synchronous FOs, advance position
			if(file->Flags & FO_SYNCHRONOUS_IO)
			{
				file->CurrentByteOffset.QuadPart = readWrite.Offset.QuadPart + readWrite.Length;
			}
		}
	}
	
	// Allocated MDL?
	if(mdl != irp->MdlAddress)
	{
		MmUnlockPages(mdl);
	
		IoFreeMdl(mdl);
	}
	
	FsRtlExitFileSystem();	
	
	irp->IoStatus.Status = status;
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::ReadMdl(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);
	
	NTSTATUS status = STATUS_SUCCESS;

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);
	
	UCHAR* buffer = 0;

	if(stack->MinorFunction & IRP_MN_COMPLETE)
	{
		ASSERT(irp->MdlAddress);
		ASSERT(!irp->MdlAddress->Next);

		DBGPRINT(("ReadMdl: FO[0x%p] IRP_MN_COMPLETE\n", stack->FileObject));

		// Free resources allocated below
		buffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
		ASSERT(buffer);
		
		IoFreeMdl(irp->MdlAddress);
		irp->MdlAddress = 0;
	}
	else if(stack->MinorFunction & IRP_MN_MDL)
	{
		ASSERT(!irp->MdlAddress);
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		
		// Save UserBuffer用户缓冲区
		void* const saved = irp->UserBuffer;
		
		ULONG const bufferSize = stack->Parameters.Read.Length;

		DBGPRINT(("ReadMdl: FO[0x%p] IRP_MN_MDL Size[0x%x] Offset[0x%I64x]\n", stack->FileObject, bufferSize, stack->Parameters.Read.ByteOffset));

		// Allocate underlying buffer for MDL we are going to create
		buffer = (UCHAR*) ExAllocatePool(NonPagedPool, bufferSize);

		if(buffer)
		{
			// Create dedicated MDL分配MDL
			irp->MdlAddress = IoAllocateMdl(buffer, bufferSize, false, false, 0);
			
			if(irp->MdlAddress)
			{
				MmBuildMdlForNonPagedPool(irp->MdlAddress);
				
				irp->UserBuffer = buffer;//返回给用户层的缓冲区
				
				FILE_OBJECT *const file = stack->FileObject;//获得文件对象
				ASSERT(file);
				
				if(!file->PrivateCacheMap)
				{
					FILFILE_READ_WRITE readWrite;
					
					readWrite.Buffer = buffer;
					readWrite.Mdl	 = irp->MdlAddress;	
					
					readWrite.Length = stack->Parameters.Read.Length;

					// Use minimum			
					if(readWrite.Length > CFilterBase::c_sectorSize)
					{
						readWrite.Length = CFilterBase::c_sectorSize;
					}
								
					readWrite.Offset = stack->Parameters.Read.ByteOffset;
					readWrite.Flags	 = IRP_SYNCHRONOUS_API | IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;	
					readWrite.Major	 = IRP_MJ_READ;
					readWrite.Wait	 = true;		
					
					DBGPRINT(("ReadMdl: FO[0x%p] Init cache\n", file));
					
					// Have lower driver initiate caching初始化缓存
					CFilterBase::ReadWrite(extension->Lower, file, &readWrite);
					
					// Zero out decrypted data
					RtlZeroMemory(readWrite.Buffer, readWrite.Length);			
					
					if(file->PrivateCacheMap)
					{
						// Disable read-ahead and write-behind
						CcSetAdditionalCacheAttributes(file, true, true);
					}				
				}
					
				// Read the data directly from disk bypassing system cache
				status = ReadBypass(extension, irp, link);
				
	 			if(NT_SUCCESS(status))
	 			{
	 				buffer = 0;
	 			}
	 			else
				{
					IoFreeMdl(irp->MdlAddress);
					irp->MdlAddress = 0;	
				}
			}
				
			// Restore UserBuffer			
			irp->UserBuffer = saved;
		}		
	}
	
	if(buffer)
	{
		ExFreePool(buffer);	
	}
	
	irp->IoStatus.Status = status;
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::DispatchRead(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	// directed to CDO ?
	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// Skip some request types
	if( !(s_state & FILFILE_STATE_FILE) || !stack->Parameters.Read.Length)
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	FILE_OBJECT *const file = stack->FileObject;
	ASSERT(file);

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));
	int const state = extension->Volume.CheckFileCooked(file, &link);


	FILFILE_CONTROL_EXTENSION* externtion=(FILFILE_CONTROL_EXTENSION*)CFilterControl::Extension();
	
	if(!state)
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	bool bypass = false;

	// See if this request comes from SRV
	if(file->Flags & FO_REMOTE_ORIGIN)
	{
		if(stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE))
		{
			// be paranoid
			link.m_fileKey.Clear();
		
			// Usually this request comes from SRV trying to access the cached data directly
			NTSTATUS const status = ReadMdl(extension, irp, &link);

			IoCompleteRequest(irp, IO_DISK_INCREMENT);
			
			return status;		
		}

		ULONG_PTR const top = (ULONG_PTR) IoGetTopLevelIrp();
		
		// Handle case where other components (like CC) use this remote FO
		if(!top || (top > FSRTL_MAX_TOP_LEVEL_IRP_FLAG))
		{
			DBGPRINT(("DispatchRead: FO[0x%p] remote request, bypass\n", file));
			
			bypass = true;
		}
		else
		{
			DBGPRINT(("DispatchRead: FO[0x%p] remote request, TopLevel[0x%x] handle\n", file, top));
		}
	}

	// Bypass request?放过请求
	if(bypass || (extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS))
	{
		DBGPRINT(("DispatchRead: FO[0x%p] File is bypassed\n", file));
		
		// be paranoid
		link.m_fileKey.Clear();
			
		if(irp->Flags & IRP_NOCACHE)
		{
			IoSkipCurrentIrpStackLocation(irp);

			return IoCallDriver(extension->Lower, irp);		
		}
	
		NTSTATUS const status = ReadBypass(extension, irp, &link);
		
		IoCompleteRequest(irp, IO_DISK_INCREMENT);
		
		return status;
	}
	        
	// Is this a doomed FO whose crypto context was torn down?
	if(state == -1)
	{
		DBGPRINT(("DispatchRead: FO[0x%p] is doomed, cancel\n", file));

		// be paranoid
		link.m_fileKey.Clear();

		irp->IoStatus.Status	  = STATUS_FILE_CLOSED;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_FILE_CLOSED;
	}
	
	if(stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE))
	{
		// Local MDL request, have lower driver handle it
		DBGPRINT(("DispatchRead: FO[0x%p] local MDL[%d] request\n", file, stack->MinorFunction));
	
		// be paranoid
		link.m_fileKey.Clear();

		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	FsRtlEnterFileSystem();

	IoCopyCurrentIrpStackLocationToNext(irp);//转发IRP

	ASSERT(link.m_nonce.QuadPart);
	ASSERT(link.m_headerBlockSize);

	FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
	ASSERT(fcb);

	BOOLEAN locked = false;
            
	// Check whether this lock is already held
	if(!IoGetTopLevelIrp())
	{
		locked = ExAcquireResourceSharedLite(fcb->Resource, true);
		ASSERT(locked);
	}
	
	LONGLONG const fileSize	= (fcb->FileSize.QuadPart) ? fcb->FileSize.QuadPart - CFilterContext::c_tail : fcb->FileSize.QuadPart;	
	LONGLONG const vdl		= (fcb->ValidDataLength.QuadPart) ? fcb->ValidDataLength.QuadPart - CFilterContext::c_tail : fcb->ValidDataLength.QuadPart;
	LONGLONG targetOffset	= stack->Parameters.Read.ByteOffset.QuadPart + link.m_headerBlockSize;
	ULONG    targetSize		= stack->Parameters.Read.Length;
	
	ASSERT(fileSize >= 0);
	ASSERT(vdl >= 0);

	if(locked)
	{
        ExReleaseResourceLite(fcb->Resource);
	}

	// Beyond EOF ?读取到文件结尾
	if(targetOffset >= fileSize)
	{
		DBGPRINT(("DispatchRead: start beyond EOF, complete\n"));

		// be paranoid
		link.m_fileKey.Clear();

		FsRtlExitFileSystem();
        
		// just complete
		irp->IoStatus.Status	  = STATUS_END_OF_FILE;
		irp->IoStatus.Information = 0;
		
		IoCompleteRequest(irp, IO_NO_INCREMENT);
        
		return STATUS_END_OF_FILE;
	}

	// Estimate cache state, especially for redirectors
	if(!EstimateCaching(extension, irp, file, &link))
	{
		//
		// NON CACHED path
		//

		link.m_flags |= TRACK_NOCACHE;

		DBGPRINT(("DispatchRead: Stack[0x%x], Toplevel[0x%x]\n", IoGetRemainingStackSize(), IoGetTopLevelIrp()));

		if(irp->MdlAddress)
		{
			DBGPRINT(("DispatchRead: MDL  FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x]\n", file, file->FsContext, irp->Flags, file->Flags, stack->Parameters.Read.Length, stack->Parameters.Read.ByteOffset));
        }
		else if(irp->UserBuffer)
		{
			DBGPRINT(("DispatchRead: USER FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x]\n", file, file->FsContext, irp->Flags, file->Flags, stack->Parameters.Read.Length, stack->Parameters.Read.ByteOffset));
		}
		else
		{
			// We should never come here
			ASSERT(false);
		}

		// Read beyond VDL?读取的大小是否大于等于VDL(有数据长度)
		if(targetOffset >= vdl)
		{
//大于等于VDL,如果没有读取到文件结尾但是有大于了有效数据长度,就产生一个错误的读取
			DBGPRINT(("DispatchRead: beyond VDL[0x%I64x], handled\n", vdl));

			// be paranoid
			link.m_fileKey.Clear();

			FsRtlExitFileSystem();
    
			irp->IoStatus.Status	  = STATUS_SUCCESS;
			irp->IoStatus.Information = targetSize;

			// Read overlap EOF?
			if(targetOffset + targetSize >= fileSize)
			{
				ASSERT(fileSize >= targetOffset);
				irp->IoStatus.Information = (ULONG) (fileSize - targetOffset);					
			}

			UCHAR *buffer = (UCHAR*) irp->UserBuffer;
			
			if(irp->MdlAddress)
			{
				buffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
			}

			ASSERT(buffer);
                			
			if(buffer)
			{
				// zero out request buffer
				RtlZeroMemory(buffer, irp->IoStatus.Information);
			}

			IoCompleteRequest(irp, IO_DISK_INCREMENT);

			return STATUS_SUCCESS;
		}

		C_ASSERT(CFilterContext::c_lookAsideSize >= sizeof(FILFILE_CRYPT_CONTEXT));
		FILFILE_CRYPT_CONTEXT *const crypt = (FILFILE_CRYPT_CONTEXT*) extension->Volume.m_context->AllocateLookaside();
//分配一个解密结构上下文
		if(crypt)
		{
			RtlZeroMemory(crypt, sizeof(FILFILE_CRYPT_CONTEXT));

			// copy crypt parameters by value
			crypt->Offset	= stack->Parameters.Read.ByteOffset;//解密文件的被读取的大小
			crypt->Nonce	= link.m_nonce;
			crypt->Key		= link.m_fileKey;//解密key

			IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
			ASSERT(next);

			// skip Header in next location跳过文件头
			next->Parameters.Read.ByteOffset.QuadPart = targetOffset;

		#if FILFILE_USE_PADDING
			// Check Offset and Size for non-alignment
			if(((ULONG) targetOffset | targetSize) & (CFilterBase::c_sectorSize - 1))
			{
				// Handle it
				NTSTATUS const status = ReadNonAligned(extension, irp, vdl, crypt);

				if(NT_ERROR(status))
				{
					// be paranoid
					link.m_fileKey.Clear();
					RtlZeroMemory(crypt, sizeof(FILFILE_CRYPT_CONTEXT));

					FsRtlExitFileSystem();

					extension->Volume.m_context->FreeLookaside(crypt);
		            
					// just complete
					irp->IoStatus.Status	  = status;
					irp->IoStatus.Information = 0;

					IoCompleteRequest(irp, IO_NO_INCREMENT);

					return status;
				}
			}
			else
		#endif //FILFILE_USE_PADDING
			{
				// overlap with cooked VDL ?
				if(targetOffset + targetSize > vdl)
				{
					// also read Padding, ignore Filler
					crypt->Value = CFilterContext::ComputePadding((ULONG) vdl);

    				next->Parameters.Read.Length = (ULONG) ((vdl + crypt->Value) - targetOffset);

					DBGPRINT(("DispatchRead: adjusted Length[0x%x], Padding[0x%x]\n", next->Parameters.Read.Length, crypt->Value));
				}

				// Never read more than requested - it might not fit into provided buffer...
				ASSERT(stack->Parameters.Read.Length >= next->Parameters.Read.Length);

			#if FILFILE_USE_PADDING
				ASSERT(0 == (next->Parameters.Read.Length % CFilterContext::c_blockSize));
				ASSERT(0 == (next->Parameters.Read.ByteOffset.LowPart % CFilterBase::c_sectorSize));
			#endif

				IoSetCompletionRoutine(irp, CompletionRead, crypt, true, true, true);
			}
	   	}
	}
	else
	{
		//
		// CACHED path读取缓存里的数据
		//

		DBGPRINT(("DispatchRead: CACHED FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x]\n", file, file->FsContext, irp->Flags, stack->FileObject->Flags, stack->Parameters.Read.Length, stack->Parameters.Read.ByteOffset));

		// Check if the request overlaps with EOF, if so the file system below 
		// will adjust the byte size returned. So we need to adjust it too.
		if(targetOffset + stack->Parameters.Read.Length > fileSize)
		{
			DBGPRINT(("DispatchRead: CACHED read overlaps EOF, trigger adjust\n"));

			IoSetCompletionRoutine(irp, CompletionReadCached, (void*)(ULONG_PTR)(link.m_headerBlockSize + CFilterContext::c_tail), true, true, true);
		}
		else
		{
			#if DBG
			{
				IoSetCompletionRoutine(irp, CompletionReadCached, 0, true, true, true);
			}
			#endif
		}
	}

	// be paranoid
	link.m_fileKey.Clear();

	FsRtlExitFileSystem();

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::WritePreparePaging(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);

	ASSERT(irp->MdlAddress);
	ASSERT(irp->Flags & IRP_PAGING_IO);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ASSERT(stack->FileObject);
	FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) stack->FileObject->FsContext;
	ASSERT(fcb);

	BOOLEAN locked = false;
            
	// Lock already held?
	if(!IoGetTopLevelIrp())
	{
		locked = ExAcquireResourceSharedLite(fcb->Resource, true);
		ASSERT(locked);
	}

	DBGPRINT(("WritePreparePaging: FO[0x%p] FCB(ALC[0x%I64x] EOF[0x%I64x] VDL[0x%I64x]) PCM[0x%x]\n", stack->FileObject, fcb->AllocationSize, fcb->FileSize, fcb->ValidDataLength, stack->FileObject->PrivateCacheMap));

	LONGLONG const fileSize = fcb->FileSize.QuadPart;

	if(locked)
	{
		ExReleaseResourceLite(fcb->Resource);
	}

	// Compute native offset
	LONGLONG const nativeOffset = stack->Parameters.Write.ByteOffset.QuadPart + link->m_headerBlockSize;
	// compute request size
	LONGLONG const requestSize = nativeOffset + stack->Parameters.Write.Length;

	// Start beyond EOF?
	if(nativeOffset >= fileSize)
	{
		DBGPRINT(("WritePreparePaging: start beyond EOF\n"));

		// inform caller about this
		link->m_flags |= TRACK_BEYOND_EOF;

		return STATUS_SUCCESS;
	}

#if FILFILE_USE_PADDING
	// Check if this write needs Padding
	if(requestSize >= (fileSize - (CFilterContext::c_tail + CFilterContext::ComputeFiller((ULONG) fileSize))))
	{
		IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
		ASSERT(next);

		// Truncate length
		ASSERT(nativeOffset < fileSize);
		next->Parameters.Write.Length = (ULONG) (fileSize - nativeOffset);

		link->m_flags |= TRACK_PADDING;
		
		DBGPRINT(("WritePreparePaging: overlap EOF, truncated Length[0x%x]\n", next->Parameters.Write.Length));
	}
#else
	// Check if this overlap with EOF (in case we use no Padding at all)?
	if(requestSize > fileSize)
	{
		IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
		ASSERT(next);

		// Truncate length
		ASSERT(nativeOffset < fileSize);
		next->Parameters.Write.Length = (ULONG) (fileSize - nativeOffset);

		DBGPRINT(("WritePreparePaging: overlap EOF, truncated Length[0x%x]\n", next->Parameters.Write.Length));
	}
#endif

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::WritePrepare(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ASSERT(stack->FileObject);
	FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) stack->FileObject->FsContext;
	ASSERT(fcb);

	ExAcquireResourceSharedLite(fcb->Resource, true);

	DBGPRINT(("WritePrepare: FO[0x%p] FCB(ALC[0x%I64x] EOF[0x%I64x] VDL[0x%I64x]) PCM[0x%x]\n", stack->FileObject, fcb->AllocationSize, fcb->FileSize, fcb->ValidDataLength, stack->FileObject->PrivateCacheMap));

	LONGLONG vdl			= fcb->ValidDataLength.QuadPart;
	LONGLONG const fileSize = fcb->FileSize.QuadPart;

	ExReleaseResourceLite(fcb->Resource);

	// Compute final EOF
	LONGLONG requestSize = stack->Parameters.Write.ByteOffset.QuadPart + stack->Parameters.Write.Length + link->m_headerBlockSize;
 
#if FILFILE_USE_PADDING
	// Check if this write needs Padding
	if(requestSize >= (fileSize - (CFilterContext::c_tail + CFilterContext::ComputeFiller((ULONG) fileSize))))
	{
		requestSize += CFilterContext::c_tail;

		link->m_flags |= TRACK_PADDING;

		if(link->m_flags & TRACK_NOCACHE)
		{
			// increase write length by Tail
			IoGetNextIrpStackLocation(irp)->Parameters.Write.Length += CFilterContext::c_tail;
		}
	}

	if(link->m_flags & TRACK_NOCACHE)
	{
		// check request alignment
		if(stack->Parameters.Write.ByteOffset.LowPart & (CFilterBase::c_sectorSize - 1))
		{
			ASSERT(!irp->MdlAddress);

			link->m_flags |=  TRACK_ALIGNMENT;
			link->m_flags &= ~TRACK_PADDING;
		}
		else if(stack->Parameters.Write.Length & (CFilterBase::c_sectorSize - 1))
		{
			if( !(link->m_flags & TRACK_PADDING))
			{
				link->m_flags |=  TRACK_ALIGNMENT;
				link->m_flags &= ~TRACK_PADDING;
			}
		}
	}
#endif //FILFILE_USE_PADDING
	    
	// extend EOF ?
	if(requestSize > fileSize)
	{
		DBGPRINT(("WritePrepare: extending EOF[0x%I64x]\n", requestSize));

		status = CFilterBase::SetFileSize(extension->Lower, stack->FileObject, (LARGE_INTEGER*) &requestSize);

		if(NT_ERROR(status))
		{
			return status;
		}

	#if FILFILE_USE_PADDING
		if(link->m_flags & TRACK_ALIGNMENT)
		{
			ASSERT(link->m_flags & TRACK_NOCACHE);

			link->m_flags |= TRACK_PADDING;

			LONGLONG const eof = fileSize - (link->m_headerBlockSize + CFilterContext::c_tail);

			// Beyond EOF ?
			if(stack->Parameters.Write.ByteOffset.QuadPart > eof)
			{
				// Adjust params in next stack to have our Write handler zero out the gap.
				IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
				ASSERT(next);

				ASSERT(next->Parameters.Write.ByteOffset.QuadPart > eof);
				next->Parameters.Write.Length			   += (ULONG) (next->Parameters.Write.ByteOffset.QuadPart - eof);
				next->Parameters.Write.ByteOffset.QuadPart  = eof;

				link->m_flags |= TRACK_BEYOND_EOF;

				DBGPRINT(("WritePrepare: non-aligned and beyond EOF\n"));
			}
		}
	#endif //FILFILE_USE_PADDING
	}
   
	// Skip VDL handling on redirectors. They don't support persistent VDL
	if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
	{
		DBGPRINT(("WritePrepare: Redirector detected, leave\n"));

		return STATUS_SUCCESS;
	}
    
	if(!vdl)
	{
		return STATUS_SUCCESS;
	}

	BOOLEAN locked = false;
    
	// Is Offset beyond VDL? Then we have to zero out the data in between.
	if(vdl < (stack->Parameters.Write.ByteOffset.QuadPart + link->m_headerBlockSize))
	{
		DBGPRINT(("WritePrepare: write beyond VDL[0x%I64x]\n", vdl));

		// Check if we should trigger a cache init, if not already done
		if(!stack->FileObject->PrivateCacheMap && !(irp->Flags & IRP_NOCACHE))
		{
			DBGPRINT(("WritePrepare: Cache is not initialized yet\n"));

			FILFILE_READ_WRITE readWrite;
			RtlZeroMemory(&readWrite, sizeof(readWrite));

			readWrite.Buffer = (UCHAR*) ExAllocatePool(NonPagedPool, CFilterBase::c_sectorSize);

			if(readWrite.Buffer)
			{
				RtlZeroMemory(readWrite.Buffer, CFilterBase::c_sectorSize);

				// Use cooked offset
				if(vdl >= link->m_headerBlockSize)
				{
					vdl -= link->m_headerBlockSize;

					readWrite.Offset.QuadPart = vdl;
					readWrite.Flags			  = IRP_SYNCHRONOUS_API | IRP_WRITE_OPERATION | IRP_DEFER_IO_COMPLETION;
					readWrite.Major			  = IRP_MJ_WRITE;
					readWrite.Wait			  = true;
					readWrite.Mdl			  = IoAllocateMdl(readWrite.Buffer, CFilterBase::c_sectorSize, false, false, 0);

					if(readWrite.Mdl)
					{
						MmBuildMdlForNonPagedPool(readWrite.Mdl);

						ASSERT(stack->Parameters.Write.ByteOffset.QuadPart > vdl);
						readWrite.Length = (ULONG) (stack->Parameters.Write.ByteOffset.QuadPart - vdl);

						if(readWrite.Length > CFilterBase::c_sectorSize)
						{
							readWrite.Length = CFilterBase::c_sectorSize;
						}

						DBGPRINT(("WritePrepare: trigger Cache init, Size[0x%x] Offset[0x%I64x]\n", readWrite.Length, readWrite.Offset));

						// Fill gap with zeros and initialize cache
						status = CFilterBase::ReadWrite(extension->Lower, stack->FileObject, &readWrite);

						if(NT_ERROR(status))
						{
							DBGPRINT(("WritePrepare -ERROR: ReadWrite() failed [0x%08x]\n", status));
						}

						IoFreeMdl(readWrite.Mdl);
					}
				}

				ExFreePool(readWrite.Buffer);
			}
		}

		locked = ExAcquireResourceExclusiveLite(fcb->Resource, true);

		// Get current VDL, cooked
		if(fcb->ValidDataLength.QuadPart >= link->m_headerBlockSize)
		{
			vdl	= fcb->ValidDataLength.QuadPart - link->m_headerBlockSize;

			// still beyond VDL ?
			if(stack->Parameters.Write.ByteOffset.QuadPart > vdl)
			{
				// NOTE: On non-cached writes disk-based FSs only support sector aligned offset/size pairs
								
				// CcZeroData could raise an exception, so guard the call
				__try
				{
					DBGPRINT(("WritePrepare: Use CcZeroData(s,e)[0x%I64x,0x%I64x]\n", vdl, stack->Parameters.Write.ByteOffset));					
									 
					// Zero out gap, use cooked offsets
					if(!CcZeroData(stack->FileObject, (LARGE_INTEGER*) &vdl, (LARGE_INTEGER*) &stack->Parameters.Write.ByteOffset, true))
					{
						DBGPRINT(("WritePrepare: CcZeroData() returned FALSE\n"));
					}
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					status = GetExceptionCode();

					DBGPRINT(("WritePrepare: CcZeroData() raised an exception [0x%08x]\n", status));
				}
			}
		}
	}

	// VDL to be extended?
	if(requestSize > vdl)
	{
		if(!locked)
		{
			locked = ExAcquireResourceExclusiveLite(fcb->Resource, true);
		}

		ASSERT(fcb->ValidDataLength.QuadPart < requestSize);
		DBGPRINT(("WritePrepare: extend VDL[0x%I64x]\n", requestSize));
		
		// Extend it directly
		fcb->ValidDataLength.QuadPart = requestSize;

		if(CcIsFileCached(stack->FileObject))		
		{
			DBGPRINT(("WritePrepare: call CcSetFileSizes()\n"));

			// Let CC know about
			CcSetFileSizes(stack->FileObject, (CC_FILE_SIZES*) &fcb->AllocationSize);
		}
	}

	if(locked)
	{
		ExReleaseResourceLite(fcb->Resource);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if FILFILE_USE_PADDING

#pragma PAGEDCODE

NTSTATUS CFilterEngine::WriteNonAligned(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);

	PAGED_CODE();

	ASSERT(irp->UserBuffer);
	ASSERT(!irp->MdlAddress);

	// Handle misalignment of offset/size requests on redirectors
	ASSERT(extension->LowerType & (FILFILE_DEVICE_REDIRECTOR_CIFS | FILFILE_DEVICE_REDIRECTOR_WEBDAV));

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	LONGLONG targetOffset = stack->Parameters.Write.ByteOffset.QuadPart;
	LONG	 targetSize   = stack->Parameters.Write.Length;

	IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
	ASSERT(next);

	// Beyond EOF ?
	if(link->m_flags & TRACK_BEYOND_EOF)
	{
		DBGPRINT(("WriteNonAligned: FO[0x%p] write beyond EOF, Size[0x%x] Offset[0x%I64x]\n", stack->FileObject, targetSize, targetOffset));

		targetOffset = next->Parameters.Write.ByteOffset.QuadPart;
		targetSize   = next->Parameters.Write.Length;
	}
	else
	{
		DBGPRINT(("WriteNonAligned: FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", stack->FileObject, targetSize, targetOffset));
	}

	// Compute how much to read around given request prior to process the actual write.
	LONG deltaOffset = (ULONG) targetOffset & (CFilterBase::c_sectorSize - 1);

	if(deltaOffset)
	{
		ASSERT(targetOffset >= deltaOffset);
		targetOffset -= deltaOffset;
		targetSize   += deltaOffset;
	}

	LONG const deltaSize = (-targetSize) & (CFilterBase::c_sectorSize - 1);

	if(deltaSize)
	{
		targetSize += deltaSize;
	}

	ASSERT(deltaOffset || deltaSize);
	ASSERT(0 == (targetOffset % CFilterBase::c_sectorSize));
	ASSERT(0 == (targetSize   % CFilterBase::c_sectorSize));
	
	// Allocate intermediate buffer
	LONG   const bufferSize = targetSize + CFilterContext::c_tail;
	UCHAR *const buffer	    = (UCHAR*) ExAllocatePool(NonPagedPool, bufferSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// ReadWrite
	FILFILE_READ_WRITE readWrite;
	RtlZeroMemory(&readWrite, sizeof(readWrite));

	readWrite.Mdl = IoAllocateMdl(buffer, bufferSize, false, false, 0);

	if(!readWrite.Mdl)
	{
		ExFreePool(buffer);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	MmBuildMdlForNonPagedPool(readWrite.Mdl);

	readWrite.Buffer = buffer;
	readWrite.Length = CFilterBase::c_sectorSize;
	readWrite.Flags  = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	readWrite.Major  = IRP_MJ_READ;
	readWrite.Wait   = true;

	// Crypt
	FILFILE_CRYPT_CONTEXT crypt;
	RtlZeroMemory(&crypt, sizeof(crypt));
    
	crypt.Nonce = link->m_nonce;
	crypt.Key	= link->m_fileKey;

	NTSTATUS status = STATUS_SUCCESS;

	// Read LHS sector, if any
	if(deltaOffset)
	{
		crypt.Offset.QuadPart	  = targetOffset;
		readWrite.Offset.QuadPart = targetOffset + link->m_headerBlockSize;

		DBGPRINT(("WriteNonAligned: FO[0x%p] fetch LHS at [0x%I64x]\n", stack->FileObject, readWrite.Offset));
		
		status = CFilterBase::ReadWrite(extension->Lower, stack->FileObject, &readWrite);

		if(NT_SUCCESS(status))
		{
			// Decrypt LHS sector
			CFilterContext::Decode(buffer, CFilterBase::c_sectorSize, &crypt);
		}
	}

	if(NT_SUCCESS(status))
	{
		if(link->m_flags & TRACK_BEYOND_EOF)
		{
			// Fill gap with zeros
			ASSERT(bufferSize > deltaOffset);
			RtlZeroMemory(buffer + deltaOffset, bufferSize - deltaOffset);

			ASSERT(stack->Parameters.Write.ByteOffset.QuadPart > next->Parameters.Write.ByteOffset.QuadPart);
			deltaOffset += (ULONG) (stack->Parameters.Write.ByteOffset.QuadPart - next->Parameters.Write.ByteOffset.QuadPart);
		}
		else if(deltaSize && ((targetSize > CFilterBase::c_sectorSize) || !deltaOffset))
		{
			// Read RHS sector, if not already done
			ASSERT(targetSize >= CFilterBase::c_sectorSize);
			LONG const rhs = targetSize - CFilterBase::c_sectorSize;

			crypt.Offset.QuadPart	  = targetOffset + rhs;
			readWrite.Offset.QuadPart = crypt.Offset.QuadPart + link->m_headerBlockSize;
			readWrite.Buffer		  = buffer + rhs;
			
			MmPrepareMdlForReuse(readWrite.Mdl);
			MmInitializeMdl(readWrite.Mdl, readWrite.Buffer, CFilterBase::c_sectorSize);
			MmBuildMdlForNonPagedPool(readWrite.Mdl);

			DBGPRINT(("WriteNonAligned: FO[0x%p] fetch RHS at [0x%I64x]\n", stack->FileObject, readWrite.Offset));
			
			status = CFilterBase::ReadWrite(extension->Lower, stack->FileObject, &readWrite);

			if(NT_SUCCESS(status))
			{
				// Decrypt RHS sector
				CFilterContext::Decode(readWrite.Buffer, CFilterBase::c_sectorSize, &crypt);
			}
		}

		if(NT_SUCCESS(status))
		{
			LONG const sourceSize = stack->Parameters.Write.Length;

			__try
			{
				// Probe UserBuffer and copy user's data into intermediate buffer
				ProbeForRead(irp->UserBuffer, sourceSize, sizeof(UCHAR));

				ASSERT(deltaOffset + sourceSize <= targetSize);
				RtlCopyMemory(buffer + deltaOffset, (UCHAR*) irp->UserBuffer, sourceSize);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				status = STATUS_INVALID_USER_BUFFER;
			}

			if(NT_SUCCESS(status))
			{
				status = STATUS_INSUFFICIENT_RESOURCES;

				C_ASSERT(CFilterContext::c_lookAsideSize >= sizeof(READ_WRITE_CONTEXT));
				READ_WRITE_CONTEXT *const readWriteCtx = (READ_WRITE_CONTEXT*) extension->Volume.m_context->AllocateLookaside();

				if(readWriteCtx)
				{
					RtlZeroMemory(readWriteCtx, sizeof(READ_WRITE_CONTEXT));

					status = STATUS_SUCCESS;

					MmPrepareMdlForReuse(readWrite.Mdl);
					MmInitializeMdl(readWrite.Mdl, buffer, bufferSize);
					MmBuildMdlForNonPagedPool(readWrite.Mdl);

					readWriteCtx->RequestMdl = readWrite.Mdl;

					crypt.Offset.QuadPart = targetOffset;
		
					next->Parameters.Write.ByteOffset.QuadPart = targetOffset + link->m_headerBlockSize;

					// Align on Block boundary to avoid increasing EOF
					targetSize = ((deltaOffset + sourceSize) + (CFilterContext::c_blockSize - 1)) & ~(CFilterContext::c_blockSize - 1);
					next->Parameters.Write.Length = targetSize;

					readWriteCtx->Buffer	 = buffer;
					readWriteCtx->BufferSize = bufferSize;

					// Need to update Padding?
					if(link->m_flags & TRACK_PADDING)
					{
						ASSERT(bufferSize >= deltaOffset + sourceSize + CFilterContext::c_tail);

						next->Parameters.Write.Length = deltaOffset + sourceSize + CFilterContext::c_tail;
						
						ULONG const padded = extension->Volume.m_context->AddPaddingFiller(buffer, 
																						   deltaOffset + sourceSize);
						// Encrypt whole block of Padding too
						if(padded == CFilterContext::c_tail)
						{
							targetSize += padded;
						}
					}

					// Encode intermediate buffer
					ASSERT(0 == (targetSize % CFilterContext::c_blockSize));
					CFilterContext::Encode(buffer, targetSize, &crypt);

					// Save original request parameters
					readWriteCtx->RequestUserBufferMdl = 0;
					readWriteCtx->RequestUserBuffer    = irp->UserBuffer;
										
					// Change request parameters
					irp->UserBuffer = buffer;
					irp->MdlAddress = readWrite.Mdl;
					
					IoSetCompletionRoutine(irp, CompletionWrite, readWriteCtx, true, true, true);					

					DBGPRINT(("WriteNonAligned: FO[0x%p] writing Size[0x%x] Offset[0x%I64x]\n", next->FileObject, next->Parameters.Write.Length, next->Parameters.Write.ByteOffset));
				}
			}
		}
	}

	// be paranoid
	RtlZeroMemory(&crypt, sizeof(crypt));

	if(NT_ERROR(status))
	{
		IoFreeMdl(readWrite.Mdl);

		ExFreePool(buffer);
	}

	return status;
}

#endif //FILFILE_USE_PADDING
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::Write(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);

#if FILFILE_USE_PADDING
	if(link->m_flags & TRACK_ALIGNMENT)
	{
		// handle non-aligned write request
		return WriteNonAligned(extension, irp, link);
	}
#endif

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	C_ASSERT(CFilterContext::c_lookAsideSize >= sizeof(READ_WRITE_CONTEXT));
	READ_WRITE_CONTEXT *const readWrite = (READ_WRITE_CONTEXT*) extension->Volume.m_context->AllocateLookaside();

	if(readWrite)
	{
		RtlZeroMemory(readWrite, sizeof(READ_WRITE_CONTEXT));
		
		IO_STACK_LOCATION *const next = IoGetNextIrpStackLocation(irp);
		ASSERT(next);

		ULONG targetSize = next->Parameters.Write.Length;
		ULONG sourceSize = IoGetCurrentIrpStackLocation(irp)->Parameters.Write.Length;

		// truncated write request ?
		if(sourceSize > targetSize)
		{
			sourceSize = targetSize;
		}

		ASSERT(sourceSize);
		ASSERT(targetSize >= sourceSize);

		#if FILFILE_USE_PADDING
		 ASSERT(0 == (next->Parameters.Write.Length % CFilterBase::c_sectorSize) || (link->m_flags & TRACK_PADDING));
		 ASSERT(0 == (next->Parameters.Write.ByteOffset.QuadPart % CFilterBase::c_sectorSize));
		#endif

		// align size of temporary buffer on sector boundary
		readWrite->BufferSize = (targetSize + (CFilterBase::c_sectorSize - 1)) & ~(CFilterBase::c_sectorSize - 1);
		readWrite->Buffer	  = (UCHAR*) ExAllocatePool(NonPagedPool, readWrite->BufferSize);

		if(readWrite->Buffer)
		{
			// zero out unused bytes, if any
			if(readWrite->BufferSize > targetSize)
			{
				RtlZeroMemory(readWrite->Buffer + targetSize, readWrite->BufferSize - targetSize);
			}

			readWrite->RequestMdl = IoAllocateMdl(readWrite->Buffer, readWrite->BufferSize, false, false, 0);

			if(readWrite->RequestMdl)
			{
				MmBuildMdlForNonPagedPool(readWrite->RequestMdl);

				FILFILE_CRYPT_CONTEXT crypt;
				RtlZeroMemory(&crypt, sizeof(crypt));

				// set crypt parameters, by value
				crypt.Offset = next->Parameters.Write.ByteOffset;
				crypt.Nonce  = link->m_nonce;
				crypt.Key    = link->m_fileKey;

				// skip our Header, adjust offset
				next->Parameters.Write.ByteOffset.QuadPart += link->m_headerBlockSize;

				if(irp->MdlAddress)
				{
					// usually PAGING_IO
					UCHAR *const source = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
					ASSERT(source);

					if(source)
					{
						RtlCopyMemory(readWrite->Buffer, source, sourceSize);

						status = STATUS_SUCCESS;
					}
				}
				else
				{
					ASSERT(irp->UserBuffer);

					__try
					{
						// User request
						ProbeForRead(irp->UserBuffer, sourceSize, sizeof(UCHAR));

						RtlCopyMemory(readWrite->Buffer, (UCHAR*) irp->UserBuffer, sourceSize);

						status = STATUS_SUCCESS;
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						status = STATUS_INVALID_USER_BUFFER;
					}
				}

				if(NT_SUCCESS(status))
				{
					#if FILFILE_USE_PADDING
					{
						// Padding needed?
						if(link->m_flags & TRACK_PADDING)
						{
							ASSERT(targetSize >= CFilterContext::c_tail);
							targetSize -= CFilterContext::c_tail;

							// Adjust cooked bytes transferred in current stack if request was truncated
							IoGetCurrentIrpStackLocation(irp)->Parameters.Write.Length = targetSize;

							ULONG const padded = extension->Volume.m_context->AddPaddingFiller(readWrite->Buffer, 
																							   targetSize);
							ASSERT(padded <= CFilterContext::c_tail);

							targetSize += padded;
						}
					}
					#endif

					// encode inplace
					CFilterContext::Encode(readWrite->Buffer, targetSize, &crypt);

					// save original request parameters
					readWrite->RequestUserBuffer    = irp->UserBuffer;
					readWrite->RequestUserBufferMdl = irp->MdlAddress;

					// change request parameters
					irp->MdlAddress = readWrite->RequestMdl;
					irp->UserBuffer = MmGetMdlVirtualAddress(irp->MdlAddress);

					DBGPRINT(("Write: FO[0x%p] FCB[0x%p] Size[0x%x] Offset[0x%I64x]\n", next->FileObject, next->FileObject->FsContext, next->Parameters.Write.Length, next->Parameters.Write.ByteOffset));

					IoSetCompletionRoutine(irp, CompletionWrite, readWrite, true, true, true);
				}

  				// be paranoid
				RtlZeroMemory(&crypt, sizeof(crypt));
			}
		}

		if(NT_ERROR(status))
		{
			if(readWrite->RequestMdl)
			{
				IoFreeMdl(readWrite->RequestMdl);
			}
			if(readWrite->Buffer)
			{
				ExFreePool(readWrite->Buffer);
			}

			extension->Volume.m_context->FreeLookaside(readWrite);
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::WriteBypass(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);
	
	ASSERT(irp->UserBuffer);	
	ASSERT( !(irp->Flags & IRP_NOCACHE));

	irp->IoStatus.Information = 0;
	
	NTSTATUS status = STATUS_SUCCESS;

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	FILE_OBJECT *const file = stack->FileObject;
	ASSERT(file);
	
	if(stack->Parameters.Write.ByteOffset.QuadPart < link->m_headerBlockSize)
	{
		DBGPRINT(("WriteBypass -WARN: FO[0x%p] Modify existing header\n", file));
	}

	MDL *mdl = irp->MdlAddress;
			
	if(!mdl)
	{
		ASSERT(0 == (stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE)));
	
		// Lock down user buffer
		mdl = IoAllocateMdl(irp->UserBuffer, stack->Parameters.Write.Length, false, false, 0);
		
		if(!mdl)
		{
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		__try 
		{
			MmProbeAndLockPages(mdl, irp->RequestorMode, IoWriteAccess);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			
			irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
		
			return STATUS_INVALID_USER_BUFFER;
		}
	}
	
	FsRtlEnterFileSystem();			 
	
	FILFILE_READ_WRITE readWrite;

	readWrite.Buffer = (UCHAR*) irp->UserBuffer;
	readWrite.Mdl	 = mdl;	
	readWrite.Offset = stack->Parameters.Write.ByteOffset;
	readWrite.Length = stack->Parameters.Write.Length;
	readWrite.Flags	 = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	readWrite.Major	 = IRP_MJ_WRITE;
	readWrite.Wait	 = true;	
	
	bool endsAtEOF = false;
	bool extendEOF = false;
	bool beyondEOF = false;
	bool beyondVDL = false;
	
	LARGE_INTEGER requestSize;
	requestSize.QuadPart = readWrite.Offset.QuadPart + readWrite.Length;
	
	// Check some conditions regarding EOF
	FSRTL_COMMON_FCB_HEADER* const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
	ASSERT(fcb);
					 
	// As we're now wearing CC's hat, we are responsible for proper locking/synchronization
	BOOLEAN locked = ExAcquireResourceExclusiveLite(fcb->PagingIoResource, true);
	
	LARGE_INTEGER vdl;
	vdl.QuadPart = fcb->ValidDataLength.QuadPart;
	
	if(readWrite.Offset.QuadPart > fcb->FileSize.QuadPart)
	{
		beyondEOF = true;
		extendEOF = true;
	}
	else
	{
		if(requestSize.QuadPart > fcb->FileSize.QuadPart)
		{
			extendEOF = true;
		}
		else if(requestSize.QuadPart == fcb->FileSize.QuadPart)
		{
			endsAtEOF = true;
		}
	}
	if(readWrite.Offset.QuadPart > vdl.QuadPart)
	{
		beyondVDL = true;
	}

	// Cached or mem-mapped?
	if(!beyondEOF && !beyondVDL && CFilterBase::IsCached(file))
	{
		// Compute cooked offsets for purging
		LARGE_INTEGER ccOffset = stack->Parameters.Write.ByteOffset;
		LONG ccLength		   = stack->Parameters.Write.Length;

		if(ccOffset.QuadPart >= link->m_headerBlockSize)
		{
			ccOffset.QuadPart -= link->m_headerBlockSize;
		}
		else
		{
			ccLength -= link->m_headerBlockSize;
			
			ccOffset.QuadPart = 0;
		}
		
		if(ccLength > 0)
		{
			ASSERT(locked);

			DBGPRINT(("WriteBypass: FO[0x%p] Purge Size[0x%x] Offset[0x%I64x]\n", file, ccLength, ccOffset));

			ASSERT(file->SectionObjectPointer);
			
			// Purge data from cache we are going to overwrite on disk
			if(!CcPurgeCacheSection(file->SectionObjectPointer, &ccOffset, ccLength, false))
			{
				DBGPRINT(("WriteBypass: FO[0x%p] Purge has failed\n", file));
			}
		}			
	}
	
	if(extendEOF)
	{
		if(locked)
		{
			// Don't hold the lock while extending EOF
			ExReleaseResourceLite(fcb->PagingIoResource);

			locked = false;
		}

		DBGPRINT(("WriteBypass: extend EOF[0x%I64x]\n", requestSize));

		status = CFilterBase::SetFileSize(extension->Lower, file, &requestSize);
	}

	if(NT_SUCCESS(status))
	{
		if(!locked)
		{
			locked = ExAcquireResourceExclusiveLite(fcb->PagingIoResource, true);
		}

		if(beyondVDL)
		{
			// Update VDL
			vdl.QuadPart = fcb->ValidDataLength.QuadPart;

			// Still beyond VDL?
			if(readWrite.Offset.QuadPart > vdl.QuadPart)
			{
				DBGPRINT(("WriteBypass: beyond VDL[0x%I64x], zero gap\n", vdl));

				// Zero gap directly on disk bypassing cache. Well, this is the job
				// of the underlying file system, but sometimes that causes a BSOD
				// when SRV is aggressively triming it writes and so the underlying
				// FS (NTFS) calls at high IRQL into CC. This is not a good idea and 
				// they should actually know better...

				ASSERT(vdl.QuadPart < stack->Parameters.Write.ByteOffset.QuadPart);
				status = CFilterBase::ZeroData(extension->Lower, file, &vdl, &stack->Parameters.Write.ByteOffset);
			}
		}

		if(NT_SUCCESS(status))
		{
			DBGPRINT(("WriteBypass: FO[0x%p] Write Size[0x%x] Offset[0x%I64x]\n", file, readWrite.Length, readWrite.Offset));
			
			// Write data to disk
			if((readWrite.Offset.LowPart & (CFilterBase::c_sectorSize - 1)) || 
			   (!endsAtEOF && !extendEOF && (readWrite.Length & (CFilterBase::c_sectorSize - 1)) ))
			{
				status = CFilterBase::WriteNonAligned(extension->Lower, file, &readWrite);
			}
			else
			{	
				status = CFilterBase::ReadWrite(extension->Lower, file, &readWrite);
			}
			
			if(NT_SUCCESS(status))
			{
				irp->IoStatus.Information = readWrite.Length;
			
				// For synchronous FOs, advance position
				if(file->Flags & FO_SYNCHRONOUS_IO)
				{
					file->CurrentByteOffset = requestSize;
				}
			}	 	
		}
	}

	if(locked)
	{
		ExReleaseResourceLite(fcb->PagingIoResource);
	}
	
	// Allocated MDL?
	if(mdl != irp->MdlAddress)
	{
		MmUnlockPages(mdl);
	
		IoFreeMdl(mdl);
	}
	
	FsRtlExitFileSystem();			 
	
	irp->IoStatus.Status = status;
				
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::WriteMdl(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link)
{
	ASSERT(extension);
	ASSERT(irp);
	ASSERT(link);
	
	NTSTATUS status = STATUS_SUCCESS;

	UCHAR* buffer = 0;
	MDL * mdl	  = 0;

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	FILE_OBJECT *const file = stack->FileObject;
	ASSERT(file);
		
	if(stack->MinorFunction & IRP_MN_COMPLETE)//如果是IRP_MN_COMPLETE,写请求完成
	{
		ASSERT(irp->MdlAddress);
	
		DBGPRINT(("WriteMdl: FO[0x%p] IRP_MN_COMPLETE Offset[0x%I64x]\n", file, stack->Parameters.Write.ByteOffset));
		
		buffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
		ASSERT(buffer);

		ASSERT(irp->MdlAddress);
		ASSERT(!irp->MdlAddress->Next);
		
		void* const saved = irp->UserBuffer;
		irp->UserBuffer = buffer;
		
		// Write data directly to disk bypassing cache. Handle alignment and cache coherency
		status = WriteBypass(extension, irp, link);		

		irp->UserBuffer = saved;

		// Free resources allocated below
		mdl = irp->MdlAddress;
		irp->MdlAddress = 0;
	}
	else if(stack->MinorFunction & IRP_MN_MDL)//如果是IRP_MN_MDL，则分配MDL,数据写入MDL
	{
		ASSERT(!irp->MdlAddress);

		status = STATUS_INSUFFICIENT_RESOURCES;

		ULONG const bufferSize = stack->Parameters.Write.Length;

		DBGPRINT(("WriteMdl: FO[0x%p] IRP_MN_MDL Size[0x%x] Offset[0x%I64x]\n", file, bufferSize, stack->Parameters.Read.ByteOffset));

		// Allocate underlying buffer for MDL we are going to create
		buffer = (UCHAR*) ExAllocatePool(NonPagedPool, bufferSize);

		if(buffer)
		{
			mdl = IoAllocateMdl(buffer, bufferSize, false, false, 0);
			
			if(mdl)
			{
				MmBuildMdlForNonPagedPool(mdl);
				
				FILFILE_READ_WRITE readWrite;

				readWrite.Buffer  = buffer;
				readWrite.Mdl	  = mdl;	
				readWrite.Offset  = stack->Parameters.Write.ByteOffset;
				readWrite.Length  = (bufferSize > CFilterBase::c_sectorSize) ? CFilterBase::c_sectorSize : bufferSize;
				readWrite.Flags	  = IRP_SYNCHRONOUS_API | IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
				readWrite.Major	  = IRP_MJ_READ;
				readWrite.Wait	  = true;
				
				status = STATUS_SUCCESS;

				// Has cache been initialized for this FO yet?
				if(!file->PrivateCacheMap)
				{
					DBGPRINT(("WriteMdl: FO[0x%p] Init cache\n", file));
				
					// Have lower driver initiate caching. Otherwise we don't ever
					// see an IRP_MN_COMPLETE what causes the buffer to be leaked
					status = CFilterBase::ReadWrite(extension->Lower, file, &readWrite);
					
					// Zero out decrypted data
					RtlZeroMemory(readWrite.Buffer, readWrite.Length);
					
					if(file->PrivateCacheMap)
					{
						// Disable read-ahead and write-behind
						CcSetAdditionalCacheAttributes(file, true, true);
					}
				}

				if(NT_SUCCESS(status))
				{
					irp->IoStatus.Status	  = STATUS_SUCCESS;
					irp->IoStatus.Information = bufferSize;

					irp->MdlAddress = mdl;

					mdl	   = 0;
					buffer = 0;
				}
				else
				{
					irp->IoStatus.Status	  = status;
					irp->IoStatus.Information = 0;
				}
			}
		}		
	}
	
	if(mdl)
	{
		IoFreeMdl(mdl);
	}

	if(buffer)
	{
		ExFreePool(buffer);	
	}
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionWrite(DEVICE_OBJECT *device, IRP *irp, void *context)
{
	ASSERT(irp);
	ASSERT(context);
	ASSERT(device);

	if(NT_SUCCESS(irp->IoStatus.Status))
	{
		IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		FILE_OBJECT *const file = stack->FileObject;
		ASSERT(file);
            
		// use minimum of both
		if(stack->Parameters.Write.Length < irp->IoStatus.Information)
		{
			irp->IoStatus.Information = stack->Parameters.Write.Length;
		}

		if( !(irp->Flags & IRP_PAGING_IO))
		{
			// synchronous IO ?
			if(file->Flags & FO_SYNCHRONOUS_IO)
			{
				// adjust current byte offset
				file->CurrentByteOffset.QuadPart = stack->Parameters.Write.ByteOffset.QuadPart + irp->IoStatus.Information;

				ASSERT(((FSRTL_COMMON_FCB_HEADER*) file->FsContext)->FileSize.QuadPart > file->CurrentByteOffset.QuadPart);

				DBGPRINT(("CompletionWrite: adjusted Curr[0x%I64x]\n", file->CurrentByteOffset));
			}
		}
	}
	else
	{
		DBGPRINT(("CompletionWrite -ERROR: request failed [0x%08x]\n", irp->IoStatus.Status));
	}

	READ_WRITE_CONTEXT *const readWrite = (READ_WRITE_CONTEXT*) context;
	ASSERT(readWrite);

	// restore original parameters
	irp->MdlAddress = readWrite->RequestUserBufferMdl;
	irp->UserBuffer = readWrite->RequestUserBuffer;

	if(readWrite->RequestMdl)
	{
		IoFreeMdl(readWrite->RequestMdl);
	}
	if(readWrite->Buffer)
	{
		ExFreePool(readWrite->Buffer);
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	extension->Volume.m_context->FreeLookaside(readWrite);
		
    if(irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if DBG	 // only used for logging purposes

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionWriteCached(DEVICE_OBJECT *device, IRP *irp, void *context)
{
	UNREFERENCED_PARAMETER(device);
	ASSERT(irp);

	if(NT_SUCCESS(irp->IoStatus.Status))
	{
		// Completion functions could be called at DISPATCH_LEVEL, but this never happens in the cached path.
		ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

		FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;

		if(file)
		{
			FSRTL_COMMON_FCB_HEADER* const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;

			if(fcb)
			{
				LARGE_INTEGER uli		  = {0,0};
				LARGE_INTEGER* ccFileSize = &uli;

				if(CcIsFileCached(file))
				{
					ccFileSize = CcGetFileSizePointer(file);
					ASSERT(ccFileSize);
				}

				FsRtlEnterFileSystem();
				ExAcquireResourceSharedLite(fcb->Resource, true);

				DBGPRINT(("CompletionWriteCached: FO[0x%p] FCB(ALC[0x%I64x] EOF[0x%I64x] VDL[0x%I64x]\n", file, fcb->AllocationSize, fcb->FileSize, fcb->ValidDataLength));
				DBGPRINT(("CompletionWriteCached: CC[0x%I64x] PCM[0x%x] Curr[0x%x] Info[0x%x]\n", *ccFileSize, file->PrivateCacheMap, file->CurrentByteOffset, irp->IoStatus.Information));

				ExReleaseResourceLite(fcb->Resource);
				FsRtlExitFileSystem();
			}
		}
	}
	else
	{
		DBGPRINT(("CompletionWriteCached -ERROR: request failed [0x%08x]\n", irp->IoStatus.Status));
	}
	
    if(irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

#endif // DBG
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::WriteAlreadyEncrypted(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp)
{
	ASSERT(extension);
	ASSERT(irp);

	//if (CFilterControl::Extension()->bReadOnly)
	//{
		//return STATUS_MEDIA_WRITE_PROTECTED;
	//}

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// Buffer too small to hold Header Block or not Zero offset?
	if((stack->Parameters.Write.Length < sizeof(FILFILE_HEADER_BLOCK)) || stack->Parameters.Write.ByteOffset.QuadPart)
	{
		return STATUS_SUCCESS;
	}

	ASSERT(stack->FileObject);
	FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) stack->FileObject->FsContext;
	ASSERT(fcb);

	// Ensure no other write requests have been issued to this FO
	ExAcquireResourceSharedLite(fcb->Resource, true);

	LONGLONG const vdl = fcb->ValidDataLength.QuadPart;

	ExReleaseResourceLite(fcb->Resource);

	// VDL invalid or not multiple of Header size?
	if(!vdl || (vdl % CFilterHeader::c_align))
	{
		return STATUS_SUCCESS;
	}

	NTSTATUS status = STATUS_SUCCESS;

	UCHAR const* buffer = 0;

	// Get buffer being written for header recognition
	if(irp->MdlAddress)
	{
		buffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, HighPagePriority);
		ASSERT(buffer);
	}
	else
	{
		ASSERT(irp->UserBuffer);

		__try
		{
			ProbeForRead(irp->UserBuffer, stack->Parameters.Write.Length, sizeof(UCHAR));

			buffer = (UCHAR*) irp->UserBuffer;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			buffer = 0;					
		}
	}
	
	if(buffer)
	{
		FILFILE_HEADER_BLOCK const*const block = (FILFILE_HEADER_BLOCK*) buffer;

		// Verify Header block
		if((FILF_POOL_TAG == block->Magic) &&
		   !(block->BlockSize % CFilterHeader::c_align) && 
		   (block->BlockSize >= sizeof(FILFILE_HEADER_BLOCK) + block->PayloadSize))
		{
			bool tearDown = true;

			// Check Payload's CRC, if contained entirely in available buffer
			if(stack->Parameters.Write.Length >= sizeof(FILFILE_HEADER_BLOCK) + block->PayloadSize)
			{
				ULONG const crc = CFilterBase::Crc32(buffer + sizeof(FILFILE_HEADER_BLOCK), block->PayloadSize);

				if(crc != block->PayloadCrc)							
				{
					tearDown = false;
				}
			}

			if(tearDown)
			{
				DBGPRINT(("WriteAlreadyEncrypted: FO[0x%p] Already encrypted, tear down\n", stack->FileObject));

				// Tear down tracked FO, and discard CC's references
				if(STATUS_ALERTED != extension->Volume.OnFileClose(stack->FileObject, true))
				{
					// Remove file's Header from cache
					CFilterControl::Extension()->HeaderCache.Remove(extension, stack->FileObject);

					status = STATUS_UNSUCCESSFUL;
				}
				else
				{
					DBGPRINT(("WriteAlreadyEncrypted: Still tracked\n"));

					status = STATUS_ACCESS_DENIED;
				}
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::DispatchWrite(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	// directed to CDO ?
	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// ignore some type of requests忽略一些请求
	if( !(s_state & FILFILE_STATE_FILE) || !stack->Parameters.Write.Length)
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	FILE_OBJECT *const file = stack->FileObject;
	ASSERT(file);

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));

	int const state = extension->Volume.CheckFileCooked(file, &link);//检查文件对象cooked中是否存在

	if(!state)
	{
		//不存在直接忽略
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}
	
	bool bypass = false;

	// See if this request comes from SRV
	if(file->Flags & FO_REMOTE_ORIGIN)//如果来自远程的请求
	{
		if(stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE))
		{
			//如果FO_REMOTE_ORIGIN直接访问缓存,忽略不加密
			// be paranoid
			link.m_fileKey.Clear();
		
			// Usually this request comes from SRV trying to access the cached data directly
			NTSTATUS const status = WriteMdl(extension, irp, &link);

			IoCompleteRequest(irp, IO_DISK_INCREMENT);

			return status;		
		}

		ULONG_PTR const top = (ULONG_PTR) IoGetTopLevelIrp();
		
		// Handle case where other components (like CC) use this remote FO
		if(!top || (top > FSRTL_MAX_TOP_LEVEL_IRP_FLAG))
		{
			DBGPRINT(("DispatchWrite: FO[0x%p] remote request, bypass\n", file));
			
			bypass = true;
		}
		else
		{	
			DBGPRINT(("DispatchWrite: FO[0x%p] remote request, TopLevel[0x%x] handle\n", file, top));
		}
	}

	// Bypass request?
	if(bypass || (extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS))
	{
		DBGPRINT(("DispatchWrite: FO[0x%p] File is bypassed\n", file));

		// be paranoid
		link.m_fileKey.Clear();

		if(irp->Flags & IRP_NOCACHE)
		{
			IoSkipCurrentIrpStackLocation(irp);

			return IoCallDriver(extension->Lower, irp);		
		}
		
		NTSTATUS const status = WriteBypass(extension, irp, &link);
		
		IoCompleteRequest(irp, IO_DISK_INCREMENT);		
		
		return status;
	}

	// doomed FO, whose crypto context has been torn down ?
	if(state == -1)
	{
		DBGPRINT(("DispatchWrite: FO[0x%p] is doomed, cancel\n", file));

		// be paranoid
		link.m_fileKey.Clear();

		irp->IoStatus.Status	  = STATUS_FILE_CLOSED;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_FILE_CLOSED;
	}
	
	if(stack->MinorFunction & (IRP_MN_MDL | IRP_MN_COMPLETE))
	{
		// Usually this request comes from SRV trying to access the cached data directly
		DBGPRINT(("DispatchWrite: FO[0x%p] local MDL[%d] request\n", file, stack->MinorFunction));

		// be paranoid
		link.m_fileKey.Clear();

		IoSkipCurrentIrpStackLocation(irp);
	
		return IoCallDriver(extension->Lower, irp);
	}

	FsRtlEnterFileSystem();

	// Check whether file is already encrypted by inspecting at the very first write
	NTSTATUS status = WriteAlreadyEncrypted(extension, irp);

	if(NT_ERROR(status))
	{
		// be paranoid
		link.m_fileKey.Clear();

		FsRtlExitFileSystem();

		if(STATUS_ACCESS_DENIED == status)
		{
			DBGPRINT(("DispatchWrite: FO[0x%p] Already encrypted, abort\n", file));

			irp->IoStatus.Status	  = STATUS_ACCESS_DENIED;
			irp->IoStatus.Information = 0;

			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_ACCESS_DENIED;
		}
		else if (STATUS_MEDIA_WRITE_PROTECTED  == status)
		{
			DBGPRINT(("DispatchWrite: FO[0x%p] forbid write STATUS_INVALID_DEVICE_REQUEST, abort\n", file));

			irp->IoStatus.Status	  = STATUS_MEDIA_WRITE_PROTECTED ;
			irp->IoStatus.Information = 0;

			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_MEDIA_WRITE_PROTECTED;
		}

		DBGPRINT(("DispatchWrite: FO[0x%p] Already encrypted, bypass\n", file));

		IoSkipCurrentIrpStackLocation(irp);
	
		return IoCallDriver(extension->Lower, irp);
	}

	IoCopyCurrentIrpStackLocationToNext(irp);

	BOOLEAN complete = false;

	ASSERT(link.m_nonce.QuadPart);
	ASSERT(link.m_headerBlockSize);
        	
	// estimate cache state, especially on redirectors
	if(EstimateCaching(extension, irp, file, &link))
	{
		//
		// CACHED path
		//

		DBGPRINT(("DispatchWrite: CACHED FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x] PCM[0x%x]\n", file, file->FsContext, irp->Flags, file->Flags, stack->Parameters.Write.Length, stack->Parameters.Write.ByteOffset, file->PrivateCacheMap));
		
		status = WritePrepare(extension, irp, &link);

		#if DBG
		 IoSetCompletionRoutine(irp, CompletionWriteCached, 0, true, true, true);
		#endif
	}
	else
	{
		//
		// NON CACHED path
		//

		link.m_flags |= TRACK_NOCACHE;

		DBGPRINT(("DispatchWrite: Stack[0x%x], Toplevel[0x%x]\n", IoGetRemainingStackSize(), IoGetTopLevelIrp()));

		if(irp->MdlAddress)
		{
			DBGPRINT(("DispatchWrite: MDL  FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x]\n", file, file->FsContext, irp->Flags, file->Flags, stack->Parameters.Write.Length, stack->Parameters.Write.ByteOffset));
		
			if(irp->Flags & IRP_PAGING_IO)
			{
           		WritePreparePaging(extension, irp, &link);

				if(link.m_flags & TRACK_BEYOND_EOF)
				{
					DBGPRINT(("DispatchWrite: beyond EOF, complete\n"));

					complete = true;
				}
			}
			else
			{
				// This kind of request is usually related to CSC
				DBGPRINT(("DispatchWrite: MDL  FO[0x%p] w/o IRP_PAGING_IO, maybe CSC\n", file));				

				status = WritePrepare(extension, irp, &link);
			}
		}
		else if(irp->UserBuffer)
		{
			DBGPRINT(("DispatchWrite: USER FO[0x%p] FCB[0x%p] Flags(I,F)[0x%x,0x%x] Size[0x%x] Offset[0x%I64x]\n", file, file->FsContext, irp->Flags, file->Flags, stack->Parameters.Write.Length, stack->Parameters.Write.ByteOffset));

			status = WritePrepare(extension, irp, &link);
		}
		else
		{
			// We should never come here
			ASSERT(false);
		}

		if(NT_SUCCESS(status) && !complete)
		{
			// Perform the actual encoding
			status = Write(extension, irp, &link);
		}
	}

	// be paranoid
	link.m_fileKey.Clear();

	FsRtlExitFileSystem();

	if(NT_ERROR(status) || complete)
	{
		DBGPRINT(("DispatchWrite: complete with [0x%08x]\n", status));

		irp->IoStatus.Status	  = status;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchQueryInformation(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// inactive ? 
	if( !(s_state & FILFILE_STATE_FILE))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);
	
	switch(stack->Parameters.QueryFile.FileInformationClass)
	{
		case FileStandardInformation:
		case FileAllInformation:
		case FileNetworkOpenInformation:
		case FileStreamInformation:
			break;

		default:
		{
			IoSkipCurrentIrpStackLocation(irp);

        	return IoCallDriver(extension->Lower, irp);
		}
	}

	ASSERT(stack->FileObject);

	// ignore SRV's requests
	if(stack->FileObject->Flags & FO_REMOTE_ORIGIN)
	{
		DBGPRINT(("DispatchQueryInformation: FO[0x%p] Class[0x%x] remote request, ignore\n", stack->FileObject, stack->Parameters.QueryFile.FileInformationClass));

		IoSkipCurrentIrpStackLocation(irp);

        return IoCallDriver(extension->Lower, irp);
	}

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));
	
	// of interest ?
	if(!extension->Volume.CheckFileCooked(stack->FileObject, &link))
	{
		IoSkipCurrentIrpStackLocation(irp);

        return IoCallDriver(extension->Lower, irp);
	}

	// be paranoid
	link.m_fileKey.Clear();

	IoCopyCurrentIrpStackLocationToNext(irp);

	NTSTATUS status = CFilterBase::SimpleSend(extension->Lower, irp);

	// Note: STATUS_BUFFER_OVERFLOW is not an error condition
	if(NT_SUCCESS(status) || (STATUS_BUFFER_OVERFLOW == status))
	{
		DBGPRINT(("DispatchQueryInformation: FO[0x%p] Flags(I,F)[0x%x,0x%x] [", stack->FileObject, irp->Flags, stack->FileObject->Flags));

		if(FileStreamInformation == stack->Parameters.QueryFile.FileInformationClass)
		{		
			// ensure valid buffer size
			if(irp->IoStatus.Information >= sizeof(FILE_STREAM_INFORMATION))
			{
				FILE_STREAM_INFORMATION *info = (FILE_STREAM_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
				ASSERT(info);

				// Adjust each entry's sizes accordingly
				for(;;)
				{
					// Header sizes of each stream are equal
					ULONG metaSize = link.m_headerBlockSize;

					// Substract Tail, if there is one
					if(info->StreamSize.QuadPart > metaSize)
					{
						metaSize += CFilterContext::c_tail;
					}

					if(info->StreamSize.QuadPart >= metaSize)
					{
						info->StreamSize.QuadPart -= metaSize;
					}

					if(info->StreamAllocationSize.QuadPart >= metaSize)
					{
						info->StreamAllocationSize.QuadPart -= metaSize;
					}

					if(!info->NextEntryOffset)
					{
						break;
					}
                    
					info = (FILE_STREAM_INFORMATION*) ((UCHAR*) info + info->NextEntryOffset);
					ASSERT(((UCHAR*) info + sizeof(FILE_STREAM_INFORMATION)) < ((UCHAR*) irp->AssociatedIrp.SystemBuffer + irp->IoStatus.Information));			
				}

				DBGPRINT_N(("FileStreamInformation] Adjusted\n"));
			}
		}
		else
		{
			LARGE_INTEGER *fileSize  = 0;
			LARGE_INTEGER *allocSize = 0;

			if(FileAllInformation == stack->Parameters.QueryFile.FileInformationClass)
			{
				// ensure valid buffer size
				if(irp->IoStatus.Information >= sizeof(FILE_ALL_INFORMATION))
				{
					FILE_ALL_INFORMATION *const info = (FILE_ALL_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
					ASSERT(info);

					fileSize  = &info->StandardInformation.EndOfFile;
					allocSize = &info->StandardInformation.AllocationSize;

					DBGPRINT_N(("FileAllInformation Curr:0x%I64x ", info->PositionInformation.CurrentByteOffset));
				}
			}
			else if(FileStandardInformation == stack->Parameters.QueryFile.FileInformationClass)
			{
				// ensure valid buffer size
				if(irp->IoStatus.Information >= sizeof(FILE_STANDARD_INFORMATION))
				{
					FILE_STANDARD_INFORMATION *const info = (FILE_STANDARD_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
					ASSERT(info);

					fileSize  = &info->EndOfFile;
					allocSize = &info->AllocationSize;

					DBGPRINT_N(("FileStandardInformation "));
				}
			}
			else
			{
				ASSERT(FileNetworkOpenInformation == stack->Parameters.QueryFile.FileInformationClass);

				// ensure valid buffer size
				if(irp->IoStatus.Information >= sizeof(FILE_NETWORK_OPEN_INFORMATION))
				{
					FILE_NETWORK_OPEN_INFORMATION *const info = (FILE_NETWORK_OPEN_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
					ASSERT(info);

					fileSize  = &info->EndOfFile;
					allocSize = &info->AllocationSize;

					DBGPRINT_N(("FileNetworkOpenInformation["));
				}
			}
	        
			ULONG metaSize = link.m_headerBlockSize;

			if(fileSize)
			{
				// Substract Tail, if there is one
				if(fileSize->QuadPart > metaSize)
				{
					metaSize += CFilterContext::c_tail;
				}

				if(fileSize->QuadPart >= metaSize)
				{
					fileSize->QuadPart -= metaSize;
				}
			}

			if(allocSize && (allocSize->QuadPart >= metaSize))
			{
				allocSize->QuadPart -= metaSize;
			}

			if(allocSize && fileSize)
			{
				DBGPRINT_N(("ALC:0x%I64x EOF:0x%I64x]\n", *allocSize, *fileSize));
			}                                                                       		
		}
	}
	else
	{
		DBGPRINT(("DispatchQueryInformation -ERROR: request failed [0x%08x]\n", status));
	}

	IoCompleteRequest(irp, IO_DISK_INCREMENT);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterEngine::CompletionSetInformation(DEVICE_OBJECT *device, IRP *irp, void* context)
{
	ASSERT(irp);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// Restore request values to avoid side effects
	if(FileEndOfFileInformation == stack->Parameters.SetFile.FileInformationClass)
	{
		FILE_END_OF_FILE_INFORMATION *const fileInfo = (FILE_END_OF_FILE_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
		ASSERT(fileInfo);

		ULONG const metaSize = (ULONG) (ULONG_PTR) context;
		ASSERT(metaSize);

		ASSERT(fileInfo->EndOfFile.QuadPart >= metaSize);
		fileInfo->EndOfFile.QuadPart -= metaSize;
	}
	else
	{
		ASSERT(FileAllocationInformation == stack->Parameters.SetFile.FileInformationClass);

		FILE_ALLOCATION_INFORMATION *const fileInfo = (FILE_ALLOCATION_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
		ASSERT(fileInfo);

		ULONG const metaSize = (ULONG) (ULONG_PTR) context;
		ASSERT(metaSize);
    
		ASSERT(fileInfo->AllocationSize.QuadPart >= metaSize);
		fileInfo->AllocationSize.QuadPart -= metaSize;
	}

	// Do not propagate pending flag when called directly
    if(device && irp->PendingReturned)
	{
        IoMarkIrpPending(irp);
    }

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::Rename(FILFILE_VOLUME_EXTENSION *extension, IRP *irp)
{
	ASSERT(extension);
	ASSERT(irp);

	PAGED_CODE();
	
	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	if(!stack->Parameters.SetFile.FileObject)
	{	
		// SIMPLE, check path at fileInfo->FileName. Have never appeared w/o SRV.

		ASSERT(false);

		return STATUS_SUCCESS;
	}

	// RELATIVE/QUALIFIED, extract filename from fileInfo->FileName (like [\??\d:\FilFile\test.txt])
	// Note:	RELATIVE renames issued by SRV have RootDirectory parameter set

	NTSTATUS status = STATUS_SUCCESS;

	CFilterPath targetPath;
	RtlZeroMemory(&targetPath, sizeof(targetPath));
	 
	CFilterDirectory target;
	RtlZeroMemory(&target, sizeof(target));

	CFilterDirectory source;
	RtlZeroMemory(&source, sizeof(source));

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));

	bool blacklisted = false;

	// See if source is a tracked file or directory
	if(!extension->Volume.CheckFileCooked(stack->FileObject, &link))
	{
		extension->Volume.CheckDirectoryCooked(stack->FileObject, &source);
	}

	// See if target is a tracked directory
	extension->Volume.CheckDirectoryCooked(stack->Parameters.SetFile.FileObject, &target);
	
	// Did one of the above occur?
	if(target.m_headerIdentifier || link.m_headerIdentifier || source.m_headerIdentifier)
	{
		// Built target path
		if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
		{
			// Use FO to avoid strange resolving issues with DFS
			FILE_OBJECT *const file = stack->Parameters.SetFile.FileObject;
			ASSERT(file);
			
			status = targetPath.Init(file->FileName.Buffer, 
									 file->FileName.Length,		
									 extension->LowerType, 
									 &extension->LowerName);
		}
		else
		{
			// Use parameter info because local file systems change the target
			// FO's name, each differently. Skip drive letter '\??\x:'
			FILE_RENAME_INFORMATION *const info = (FILE_RENAME_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
			ASSERT(info);

			ASSERT(info->FileName);
			ASSERT(info->FileNameLength >= (6 * sizeof(WCHAR)));

			status = targetPath.Init(info->FileName + 6, 
									 info->FileNameLength - (6 * sizeof(WCHAR)), 
									 extension->LowerType, 
									 &extension->LowerName);
		}

		if(NT_ERROR(status))
		{
			// be paranoid
			link.m_fileKey.Clear();

			return status;
		}

		ASSERT(targetPath.GetType());

		LUID luid = {0,0};

		if(CFilterControl::IsTerminalServices())
		{
			CFilterBase::GetLuid(&luid);
		}

		// Check target against Blacklist
		if(extension->Volume.m_context->BlackList().Check(&targetPath, &luid))
		{
			DBGPRINT(("Rename: Target matches Blacklist\n"));

			blacklisted = true;
		}
	}

	// Is target a tracked directory?
	if(target.m_headerIdentifier)
	{
		ASSERT(targetPath.GetType());

		// Defaults to copy/delete semantics
		status = STATUS_NOT_SAME_DEVICE;

		// Is source a tracked file?
		if(link.m_headerIdentifier)
		{
			targetPath.SetType(TRACK_TYPE_FILE);

			// Not blacklisted?
			if(!blacklisted)
			{
				// Exactly same Payload?
				if(link.m_headerIdentifier == target.m_headerIdentifier)
				{
					ASSERT(target.m_headerIdentifier && (target.m_headerIdentifier != ~0u));

					DBGPRINT(("Rename: FO[0x%p] file already encrypted, ignore\n", stack->FileObject));

					status = STATUS_SUCCESS;
				}
				else
				{
					// Check whether source and target directory are the same. If so, don't 
					// trigger re-encryption. This is neccessary to handle the ReplaceFile() 
					// API call that doesn't support copy/delete semantics.
					FILE_NAME_INFORMATION *fileNameInfo = 0;

					// Retrieve source file path from file system
					if(NT_SUCCESS(CFilterBase::QueryFileNameInfo(extension->Lower, 
																 stack->FileObject, 
																 &fileNameInfo)))
					{
						ASSERT(fileNameInfo);

						CFilterPath sourcePath;
						RtlZeroMemory(&sourcePath, sizeof(sourcePath));

						sourcePath.Init(fileNameInfo->FileName, 
										fileNameInfo->FileNameLength, 
										extension->LowerType,
										&extension->LowerName);

						if(sourcePath.GetType())
						{
							sourcePath.SetType(TRACK_TYPE_FILE);

							// Compare only directories
							sourcePath.m_file		= 0;
							sourcePath.m_fileLength = 0;

							targetPath.m_file		= 0;
							targetPath.m_fileLength = 0;

							// Same directory?
							if(sourcePath.Match(&targetPath, true))
							{
								DBGPRINT(("Rename: FO[0x%p] Rename within directory, ignore\n", stack->FileObject));

								status = STATUS_SUCCESS;
							}
						}

						sourcePath.Close();

						ExFreePool(fileNameInfo);
					}
				}
			}

			// Check if there is an Entity related to this FO, if so remove it
			extension->Volume.LonelyEntity(stack->FileObject, TRACK_TYPE_FILE);
		}
		else
		{
			// Is source a tracked directory?
			if(source.m_headerIdentifier)
			{
				ASSERT(targetPath.GetType());

				targetPath.SetType(TRACK_TYPE_DIRECTORY);

				// Not blacklisted?
				if(!blacklisted)
				{
					// Exactly same Payload?
					if(source.m_headerIdentifier == target.m_headerIdentifier)
					{
						ASSERT(target.m_headerIdentifier && (target.m_headerIdentifier != ~0u));

						DBGPRINT(("Rename: FO[0x%p] directory already encrypted, ignore\n", stack->FileObject));

						status = STATUS_SUCCESS;
					}
				}

				// Check if there is an Entity related to this FO, if so remove it
				extension->Volume.LonelyEntity(stack->FileObject, TRACK_TYPE_DIRECTORY);
			}
			else if(blacklisted)
			{	
				// Source is not tracked and target is blacklisted, so just ignore it
				status = STATUS_SUCCESS;
			}
		}
	}
	else if(link.m_headerIdentifier || source.m_headerIdentifier)
	{
		ASSERT(targetPath.GetType());

		// Source is a tracked file or directory
		ULONG type		 = TRACK_TYPE_FILE;
		ULONG identifier = link.m_entityIdentifier;

		if(source.m_headerIdentifier)
		{
			identifier = source.m_entityIdentifier;
			type       = TRACK_TYPE_DIRECTORY;
		}

		ASSERT(type);
		ASSERT(identifier);

		// Ensure correct type
		targetPath.SetType(type);

		if(blacklisted)
		{
			// Tear down top Entity, if such
			extension->Volume.LonelyEntity(stack->FileObject, type);

			// Trigger decryption
			status = STATUS_NOT_SAME_DEVICE;
		}
		else
		{
			// Update file Entity with new name
			extension->Volume.UpdateEntity(identifier, &targetPath);
		}
	}

	targetPath.Close();

	// be paranoid
	link.m_fileKey.Clear();

	// Trigger copy/delete semantics?
	if(STATUS_NOT_SAME_DEVICE == status)
	{
		DBGPRINT(("Rename: FO[0x%p] force copy/delete semantics\n", stack->FileObject));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::Delete(FILFILE_VOLUME_EXTENSION *extension, IRP *irp)
{
	ASSERT(extension);
	ASSERT(irp);

	PAGED_CODE();

	FILE_DISPOSITION_INFORMATION *const info = (FILE_DISPOSITION_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
	ASSERT(info);

	// Really delete the file?
	if(!info->DeleteFile)
	{
		return STATUS_SUCCESS;
	}

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ASSERT(file);

	CFilterDirectory directory;
	RtlZeroMemory(&directory, sizeof(directory));

	// Tracked directory?
	if(!extension->Volume.CheckDirectoryCooked(file, &directory))
	{
		return STATUS_SUCCESS;
	}

	// We have to delete our AutoConfig file first so that the directory 
	// can be deleted. So retrieve directory path from file system

	FILE_NAME_INFORMATION *fileNameInfo = 0;
	NTSTATUS status = CFilterBase::QueryFileNameInfo(extension->Lower, file, &fileNameInfo);

	if(NT_ERROR(status))
	{
		return status;
	}

	ASSERT(fileNameInfo);

	// Build full qualified path
	LPCWSTR source	   = fileNameInfo->FileName;
	ULONG sourceLength = fileNameInfo->FileNameLength;

	if((extension->LowerType & FILFILE_DEVICE_REDIRECTOR) && CFilterControl::IsWindowsVistaOrLater())
	{
		// Hmm, querying for the name gives us a strange formated path
		// with DFS on Vista. So use the updated path in the FO instead
		if(fileNameInfo->FileNameLength > file->FileName.Length)
		{
			DBGPRINT(("Delete(I): FO[0x%p] Path has been changed\n", file));

			ASSERT(file->FileName.Buffer);
			ASSERT(file->FileName.Length);

			// Use updated path
			source	     = file->FileName.Buffer;
			sourceLength = file->FileName.Length;
		}
	}

	CFilterPath path;
	status = path.Init(source, sourceLength, extension->LowerType, &extension->LowerName);

	if(NT_SUCCESS(status))
	{
		// Ensure it's a directory
		path.SetType(TRACK_TYPE_DIRECTORY);

		// Append AutoConfig name. Use dynamic redirector prefix as Mup fails to route this request
		// properly on Vista with DFS and CSC enabled. CSC sometimes claims such requests but fails
		// to handle them properly. This change forces a full parsing resulting in proper routing.

		UNICODE_STRING autoConfigPath = {0,0,0};
		status = path.GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX_DYN);

		if(NT_SUCCESS(status))
		{
			status = CFilterBase::CreateFile(extension->Lower, 
											 &autoConfigPath,
											 DELETE | FILE_READ_ATTRIBUTES,
											 FILE_SHARE_READ | FILE_SHARE_WRITE,
											 (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE); 

			if(NT_SUCCESS(status))
			{
				DBGPRINT(("Delete(I): Deleted AutoConf file\n"));

				if((extension->LowerType & FILFILE_DEVICE_REDIRECTOR) && CFilterControl::IsWindowsVistaOrLater())
				{
					// Still use static redirector prefix with HeaderCache
					ExFreePool(autoConfigPath.Buffer);
					RtlZeroMemory(&autoConfigPath, sizeof(autoConfigPath));

					path.GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX);
				}

				if(autoConfigPath.Buffer)
				{
					ASSERT(autoConfigPath.Length);

					CFilterControl::Extension()->HeaderCache.Remove(autoConfigPath.Buffer, 
																	autoConfigPath.Length);
				}
			}
			else
			{
				DBGPRINT(("Delete(I): Error [0x%x] deleting AutoConf[%wZ]\n", status, &autoConfigPath));
			}

			if(autoConfigPath.Buffer)
			{
				ExFreePool(autoConfigPath.Buffer);
			}
		}

		path.Close();
	}

	// Check for loneliness only if we had an exact match
	if(directory.m_flags & TRACK_MATCH_EXACT)
	{
		// Check whether the deleted directory corresponds to an active AutoConfig Entity
		extension->Volume.LonelyEntity(file, TRACK_TYPE_DIRECTORY, directory.m_entityIdentifier);
	}

	ExFreePool(fileNameInfo);
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::Delete(FILFILE_VOLUME_EXTENSION *extension, FILFILE_TRACK_CONTEXT *track)
{
	ASSERT(extension);
	ASSERT(track);

	PAGED_CODE();

	// Ensure we have already matched
	ASSERT(track->State & TRACK_YES);

	UNICODE_STRING autoConfigPath = {0,0,0};
	NTSTATUS status = track->Entity.GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX_DYN);

	if(NT_SUCCESS(status))
	{
		status = CFilterBase::CreateFile(extension->Lower, 
										 &autoConfigPath,
										 DELETE | FILE_READ_ATTRIBUTES,
										 FILE_SHARE_READ | FILE_SHARE_WRITE,
										 (FILE_OPEN << 24) | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);
		if(NT_SUCCESS(status))
		{
			DBGPRINT(("Delete(T): Deleted AutoConf file\n"));

			if((extension->LowerType & FILFILE_DEVICE_REDIRECTOR) && CFilterControl::IsWindowsVistaOrLater())
			{
				// Still use static redirector prefix with HeaderCache
				ExFreePool(autoConfigPath.Buffer);
				RtlZeroMemory(&autoConfigPath, sizeof(autoConfigPath));

				track->Entity.GetAutoConfig(&autoConfigPath, CFilterPath::PATH_VOLUME | CFilterPath::PATH_PREFIX);
			}

			if(autoConfigPath.Buffer)
			{
				ASSERT(autoConfigPath.Length);

				CFilterControl::Extension()->HeaderCache.Remove(autoConfigPath.Buffer, 
																autoConfigPath.Length);
			}
		}
		else
		{
			DBGPRINT(("Delete(T): Error [0x%x] deleting AutoConf[%wZ]\n", status, &autoConfigPath));
		}

		if(autoConfigPath.Buffer)
		{
			ExFreePool(autoConfigPath.Buffer);
		}
	}

	// If we had an exact match, remove the Entity
	if(track->Entity.m_flags & TRACK_MATCH_EXACT)
	{
		extension->Volume.RemoveEntity(track->Entity.m_identifier, TRACK_TYPE_DIRECTORY);
	}
	
	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchSetInformation(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	// directed to CDO ?
	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	ULONG const infoType = stack->Parameters.SetFile.FileInformationClass;

	if((FileDispositionInformation == infoType) || (FileRenameInformation == infoType))
	{
		// Remove file's Header from cache
		CFilterControl::Extension()->HeaderCache.Remove(extension, stack->FileObject);
	}

	// inactive ? 
	if( !(s_state & FILFILE_STATE_FILE))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	ASSERT(stack->FileObject);

	// If this request really comes from SRV, simply ignore it
	if((stack->FileObject->Flags & FO_REMOTE_ORIGIN) && !IoGetTopLevelIrp())
	{
		DBGPRINT(("DispatchSetInformation: FO[0x%p] remote request, ignore\n", stack->FileObject));

		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	// Delete operation?
	if(FileDispositionInformation == infoType)
	{
		Delete(extension, irp);

		IoSkipCurrentIrpStackLocation(irp);
			
		return IoCallDriver(extension->Lower, irp);
	}

	// Rename operation?
	if(FileRenameInformation == infoType)
	{
		if(STATUS_NOT_SAME_DEVICE == Rename(extension, irp))
		{
			// Fail request with specific error code to force copy/delete semantics
			irp->IoStatus.Status	  = STATUS_NOT_SAME_DEVICE;
			irp->IoStatus.Information = 0;

			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_NOT_SAME_DEVICE;
		}

		// As we do not really need our stack location here, let the next driver use ours. This also avoids
		// a BSOD (IO_NO_MORE_STACK_LOCATIONS) occuring with a Symantec AV update using an esoteric layering
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	ASSERT(stack->FileObject);

	if((FileEndOfFileInformation != infoType) && (FileAllocationInformation != infoType))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	CFilterContextLink link;
	RtlZeroMemory(&link, sizeof(link));

	int const state = extension->Volume.CheckFileCooked(stack->FileObject, &link);

	if(!state)
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	// doomed FO, whose crypto context was torn down?
	if(state == -1)
	{
		// Let Lazy Writer's size changes pass
		if((FileEndOfFileInformation != infoType) || !stack->Parameters.SetFile.AdvanceOnly)
		{
			DBGPRINT(("DispatchSetInformation: FO[0x%p] is doomed, cancel\n", stack->FileObject));

			// be paranoid
			link.m_fileKey.Clear();

			irp->IoStatus.Status	  = STATUS_FILE_CLOSED;
			irp->IoStatus.Information = 0;

			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_FILE_CLOSED;
		}

		DBGPRINT(("DispatchSetInformation: FO[0x%p] is doomed, handle\n", stack->FileObject));
	}

	FsRtlEnterFileSystem();

	IoCopyCurrentIrpStackLocationToNext(irp);

	LARGE_INTEGER fileSize = {0,0};
	ULONG metaSize		   = link.m_headerBlockSize;

	bool truncate = false;
	
	if(FileEndOfFileInformation == infoType)
	{
		FILE_END_OF_FILE_INFORMATION *const fileInfo = (FILE_END_OF_FILE_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
		ASSERT(fileInfo);

		DBGPRINT(("DispatchSetInformation: FO[0x%p] Flags(I,F)[0x%x,0x%x] [FileEndOfFileInformation] [0x%I64x]", stack->FileObject, irp->Flags, stack->FileObject->Flags, fileInfo->EndOfFile));

		// add Tail if this is neither the LazyWriter nor a truncation to zero
		if(!stack->Parameters.SetFile.AdvanceOnly && fileInfo->EndOfFile.QuadPart)
		{
			metaSize += CFilterContext::c_tail;

			fileSize.QuadPart = fileInfo->EndOfFile.QuadPart + metaSize;

			// check for truncation
			FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) stack->FileObject->FsContext;
			ASSERT(fcb);
						
			ExAcquireResourceSharedLite(fcb->Resource, true);

			if(fileSize.QuadPart < fcb->ValidDataLength.QuadPart)
			{
				// trigger Tail update
				truncate = true;
			}

 			ExReleaseResourceLite(fcb->Resource);

			fileInfo->EndOfFile = fileSize;
		}
		else
		{
			fileInfo->EndOfFile.QuadPart += metaSize;
		}

		if(stack->Parameters.SetFile.AdvanceOnly)
		{
			DBGPRINT_N((" adjusted to [0x%I64x] AdvanceOnly\n", fileInfo->EndOfFile));
		}
		else
		{
			DBGPRINT_N((" adjusted to [0x%I64x]\n", fileInfo->EndOfFile));
		}
	}
	else
	{
		ASSERT(FileAllocationInformation == infoType);

		FILE_ALLOCATION_INFORMATION *const fileInfo = (FILE_ALLOCATION_INFORMATION*) irp->AssociatedIrp.SystemBuffer;
		ASSERT(fileInfo);

		DBGPRINT(("DispatchSetInformation: FO[0x%p] Flags(I,F)[0x%x,0x%x] [FileAllocationInformation][0x%I64x]", stack->FileObject, irp->Flags, stack->FileObject->Flags, fileInfo->AllocationSize));
	        
		if(fileInfo->AllocationSize.QuadPart)
		{
			metaSize += CFilterContext::c_tail;
		}
            		
		fileInfo->AllocationSize.QuadPart += metaSize;

		DBGPRINT_N((" adjusted to [0x%I64x]\n", fileInfo->AllocationSize));
	}

	NTSTATUS status = STATUS_SUCCESS;

	if(truncate)
	{
		ASSERT(fileSize.QuadPart);
		ASSERT(fileSize.QuadPart > link.m_headerBlockSize);

		// Should not be doomed
		ASSERT(state != -1);

		DBGPRINT(("DispatchSetInformation: FO[0x%p] truncate to [0x%I64x]\n", stack->FileObject, fileSize.QuadPart));

		// let request proceed
		status = CFilterBase::SimpleSend(extension->Lower, irp);
	
		if(NT_SUCCESS(status))
		{
		#if FILFILE_USE_PADDING
			// update cut off Tail
			status = CFilterCipherManager(extension).UpdateTail(stack->FileObject, &link, &fileSize);
		#endif
		}

		// restore changed value directly
		CompletionSetInformation(0, irp, (void*)(ULONG_PTR) metaSize);

		status = irp->IoStatus.Status;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
	else
	{
		// restore value at completion
		IoSetCompletionRoutine(irp, CompletionSetInformation, (void*)(ULONG_PTR) metaSize, true, true, true);

		status = IoCallDriver(extension->Lower, irp);
	}

	// be paranoid
	link.m_fileKey.Clear();

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchCleanup(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
	ASSERT(file);

	// Check whether WipeOnDelete should be performed
	if((s_state & FILFILE_WIPE_ON_DELETE) && (extension->LowerType & FILFILE_DEVICE_VOLUME))
	{
		// Ongoing delete operation?
		if(file->DeletePending || (file->Flags & FO_DELETE_ON_CLOSE))
		{
			// Skip directories
			if( !(CFilterBase::GetAttributes(extension->Lower, file) & FILE_ATTRIBUTE_DIRECTORY))
			{
				DBGPRINT(("DispatchCleanup: FO[0x%p] Wipe on delete\n", file));

				// Wipe only files on local volumes
				CFilterControl::Extension()->Wiper.WipeFile(file);
			}
		}
	}

	if((s_state & FILFILE_STATE_FILE) && (extension->LowerType & (FILFILE_DEVICE_VOLUME | FILFILE_DEVICE_REDIRECTOR)))
	{
		NTSTATUS status = extension->Volume.OnFileCleanup(file);

		// lonely FO detected (w/o active Entity) ?
		if(STATUS_ALERTED == status)
		{
			DBGPRINT(("DispatchCleanup: lonely FO detected, FlushPurge\n"));

			IoCopyCurrentIrpStackLocationToNext(irp);

			// let proceed
			status = CFilterBase::SimpleSend(extension->Lower, irp);

			FsRtlEnterFileSystem();
			CFilterBase::FlushAndPurgeCache(file);
			FsRtlExitFileSystem();

			IoCompleteRequest(irp, IO_DISK_INCREMENT);

			return status;
		}
	}

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchClose(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// Lower type a file system?
	if((s_state & FILFILE_STATE_FILE) && (extension->LowerType & (FILFILE_DEVICE_VOLUME | FILFILE_DEVICE_REDIRECTOR)))
	{
		FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
		ASSERT(file);

		// Check if this FO is tracked and if it should be ignored
		ULONG const state = extension->Volume.m_context->Tracker().Remove(file);

		if(!file->Vpb && !file->FsContext)
		{
			// Since no file system below hasn't added specific data to this FO, just complete
			// it here. This is a known bug in MUP on Vista, which will BSOD otherwise

			// Additional note: With Novell NetWare on Vista, the FsContext2 is sometimes set.
			// I have no idea what those guys put in there, but we cannot let MUP proceed with
			// this FO since it will BSOD. I hope they cleanup their stuff elsewhere...

			DBGPRINT(("DispatchClose -WARN: FO[0x%p] is empty, complete\n", file));

			irp->IoStatus.Status	  = STATUS_SUCCESS;
			irp->IoStatus.Information = 0;

			IoCompleteRequest(irp, IO_NO_INCREMENT);

			return STATUS_SUCCESS;
		}

		// Do not let this FO influencing with tracking engine
		if(0 == (state & FILFILE_TRACKER_IGNORE))
		{
			// First check Directories
			NTSTATUS const status = extension->Volume.OnDirectoryClose(file);

			// No directory match, then check files
			if(STATUS_SUCCESS != status)
			{
				extension->Volume.OnFileClose(file);
			}
		}
	}

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DirectoryQuerySizes(void *entry, ULONG entryType, ULONG headerSize)
{
	ASSERT(entry);
	ASSERT(entryType);
	ASSERT(headerSize);

	PAGED_CODE();

	LARGE_INTEGER *eof   = 0;
	LARGE_INTEGER *alloc = 0;

	switch(entryType)
	{
		case FileBothDirectoryInformation:
		{
			FILE_BOTH_DIR_INFORMATION *const dirInfo = (FILE_BOTH_DIR_INFORMATION*) entry;

			eof   = &dirInfo->EndOfFile;
			alloc = &dirInfo->AllocationSize;
			break;
		}
		case FileDirectoryInformation:
		{
			FILE_DIRECTORY_INFORMATION *const dirInfo = (FILE_DIRECTORY_INFORMATION*) entry;

			eof   = &dirInfo->EndOfFile;
			alloc = &dirInfo->AllocationSize;
			break;
		}
		case FileFullDirectoryInformation:
		{
			FILE_FULL_DIR_INFORMATION *const dirInfo = (FILE_FULL_DIR_INFORMATION*) entry;

			eof   = &dirInfo->EndOfFile;
			alloc = &dirInfo->AllocationSize;
			break;
		}
		case FileIdBothDirectoryInformation:
		{
			FILE_ID_BOTH_DIR_INFORMATION *const dirInfo = (_FILE_ID_BOTH_DIR_INFORMATION*) entry;

			eof   = &dirInfo->EndOfFile;
			alloc = &dirInfo->AllocationSize;
			break;
		}
		case FileIdFullDirectoryInformation:
		{
			FILE_ID_FULL_DIR_INFORMATION *const dirInfo = (FILE_ID_FULL_DIR_INFORMATION*) entry;

			eof   = &dirInfo->EndOfFile;
			alloc = &dirInfo->AllocationSize;
			break;
		}
		default:
			ASSERT(false);
			break;
	}

	ULONG metaSize = headerSize;

	if(eof)
	{
		// substract Tail only if there is one
		if(eof->QuadPart > headerSize)
		{
			metaSize += CFilterContext::c_tail;
		}

		if(eof->QuadPart >= metaSize)
		{
			eof->QuadPart -= metaSize;
		}
	}

	if(alloc)
	{
		if(alloc->QuadPart >= metaSize)
		{
			alloc->QuadPart -= metaSize;
		}
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterEngine::DirectoryQueryNames(UCHAR *buffer, ULONG bufferSize, void *entry, ULONG entryType)
{
	ASSERT(buffer);
	ASSERT(entry);
	ASSERT(entryType);

	PAGED_CODE();
	
	ULONG  entrySize	   = 0;
	ULONG  fileNameLength  = 0; 
	LPWSTR fileName		   = 0;

	switch(entryType)
	{
		case FileBothDirectoryInformation:
		{
			FILE_BOTH_DIR_INFORMATION *const dirInfo = (FILE_BOTH_DIR_INFORMATION*) entry;

			entrySize	   = sizeof(FILE_BOTH_DIR_INFORMATION);
			fileNameLength = dirInfo->FileNameLength;
			fileName	   = dirInfo->FileName;
			break;
		}
		case FileDirectoryInformation:
		{
			FILE_DIRECTORY_INFORMATION *const dirInfo = (FILE_DIRECTORY_INFORMATION*) entry;

			entrySize	   = sizeof(FILE_DIRECTORY_INFORMATION);
			fileNameLength = dirInfo->FileNameLength;
			fileName	   = dirInfo->FileName;
			break;
		}
		case FileFullDirectoryInformation:
		{
			FILE_FULL_DIR_INFORMATION *const dirInfo = (FILE_FULL_DIR_INFORMATION*) entry;

			entrySize	   = sizeof(FILE_FULL_DIR_INFORMATION);
			fileNameLength = dirInfo->FileNameLength;
			fileName	   = dirInfo->FileName;
			break;
		}
		case FileIdBothDirectoryInformation:
		{
			FILE_ID_BOTH_DIR_INFORMATION *const dirInfo = (_FILE_ID_BOTH_DIR_INFORMATION*) entry;

			entrySize	   = sizeof(FILE_ID_BOTH_DIR_INFORMATION);
			fileNameLength = dirInfo->FileNameLength;
			fileName	   = dirInfo->FileName;
			break;
		}
		case FileIdFullDirectoryInformation:
		{
			FILE_ID_FULL_DIR_INFORMATION *const dirInfo = (FILE_ID_FULL_DIR_INFORMATION*) entry;

			entrySize	   = sizeof(FILE_ID_FULL_DIR_INFORMATION);
			fileNameLength = dirInfo->FileNameLength;
			fileName	   = dirInfo->FileName;
			break;
		}
		default:
			ASSERT(false);
			break;
	}

	// compute exact size of this entry including the FileName, but w/o alignment
	entrySize += fileNameLength - sizeof(WCHAR);
	
	// Are we just queried for the entry size?
	if(!bufferSize)
	{
		return entrySize;
	}

	ASSERT(fileName);

	// check FileName
	if(fileNameLength != (g_filFileAutoConfigNameLength * sizeof(WCHAR)))
	{
		// Off by one? Seen on WXP with WebDAV which counts the terminating zero
		if(fileNameLength - sizeof(WCHAR) != (g_filFileAutoConfigNameLength * sizeof(WCHAR)))
		{
			return 0;
		}
	}
	
	ASSERT(RtlUpcaseUnicodeChar(g_filFileAutoConfigName[0]) == g_filFileAutoConfigName[0]);
	
	// at least the first character of AutoConfig name must be upcase
	if(RtlUpcaseUnicodeChar(fileName[0]) != g_filFileAutoConfigName[0])
	{
		return 0;
	}
	
	if(_wcsnicmp(fileName, g_filFileAutoConfigName, g_filFileAutoConfigNameLength))
	{
		return 0;
	}

	// NextEntryOffset is always the first value in all handled structs
	ULONG const nextOffset = *((ULONG*) entry);
	
	// not last entry ?
	if(nextOffset)
	{
		entrySize = nextOffset;

		UCHAR *const next = (UCHAR*) entry + nextOffset;
		UCHAR *const end  = buffer + bufferSize;
													
		// remove AutoConfig entry
		ASSERT(end > next);
		RtlMoveMemory(entry, next, end - next);

		entry = end - entrySize;
	}

	// clear AutoConfig entry/unused space
	RtlZeroMemory(entry, entrySize);

	DBGPRINT(("DirectoryQueryNames: removed AutoConfig entry from type[%d]\n", entryType));

	ASSERT(entrySize);

	return entrySize;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DirectoryQuery(IRP *irp, ULONG headerSize)
{
	ASSERT(irp);

	PAGED_CODE();

	ASSERT(irp->UserBuffer);

	// a couple of compile time checks to ensure 1) NextEntryOffset is the very first value, and
	C_ASSERT(0 == offsetof(FILE_DIRECTORY_INFORMATION,	 NextEntryOffset));
	C_ASSERT(0 == offsetof(FILE_FULL_DIR_INFORMATION,	 NextEntryOffset));
	C_ASSERT(0 == offsetof(FILE_BOTH_DIR_INFORMATION,	 NextEntryOffset));
	C_ASSERT(0 == offsetof(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset));
	C_ASSERT(0 == offsetof(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset));
	// 2) FileAttributes value is always at same offset in all structs handled.
	C_ASSERT(offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) == offsetof(FILE_FULL_DIR_INFORMATION,    FileAttributes));
	C_ASSERT(offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) == offsetof(FILE_BOTH_DIR_INFORMATION,    FileAttributes));
	C_ASSERT(offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) == offsetof(FILE_ID_BOTH_DIR_INFORMATION, FileAttributes));
	C_ASSERT(offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) == offsetof(FILE_ID_FULL_DIR_INFORMATION, FileAttributes));
	
	ULONG const infoClass = IoGetCurrentIrpStackLocation(irp)->Parameters.QueryDirectory.FileInformationClass;
	ULONG *info			  = (ULONG*) irp->UserBuffer;
	UCHAR *const buffer   = (UCHAR*) irp->UserBuffer;
	ULONG bufferSize	  = 0;
		
	// HACK: Compute buffer size manually because FastFat sometimes returns a wrong value
	for(;;)
	{
		// Very last entry?
		if(!*info)
		{
			// get only exact size
			bufferSize += DirectoryQueryNames(buffer, 0, info, infoClass);

			break;
		}

		// Just use NextEntryOffset
		bufferSize += *info;

		info = (ULONG*) ((UCHAR*) info + *info);
	}

	// We should not exceed caller's buffer
	ASSERT(bufferSize <= IoGetCurrentIrpStackLocation(irp)->Parameters.QueryDirectory.Length);

	ULONG *infoLast	= info = (ULONG*) buffer;
	ULONG autoConfigSize = 0;

	for(;;)
	{
		ASSERT(info < (ULONG*) (buffer + bufferSize));

		// Ensure FileAttributes' offset is a multiple of 4.
		C_ASSERT(0 == (offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) % sizeof(ULONG)));

		// Skip directory entries
		if( !(*(info + offsetof(FILE_DIRECTORY_INFORMATION, FileAttributes) / sizeof(ULONG)) & FILE_ATTRIBUTE_DIRECTORY))
		{
			// Remove only once
			if(!autoConfigSize)
			{
				bool const veryLast = !*info;

				// Remove AutoConfig entry, if any
				autoConfigSize = DirectoryQueryNames(buffer, bufferSize, info, infoClass);
				
				if(autoConfigSize)
				{
					if(veryLast)
					{
						// Cut off link to just removed AutoConfig entry
						*infoLast = 0;

						break;
					}
				}
			}

			if(headerSize)
			{
				// Adjust contained file sizes accordingly, if any
				DirectoryQuerySizes(info, infoClass, headerSize);
			}
		}

		if(!*info)
		{
			break;
		}

		infoLast = info;
		info	 = (ULONG*) ((UCHAR*) info + *info);
	}

	ASSERT(bufferSize >= autoConfigSize);
	bufferSize -= autoConfigSize;

	// Set returned buffer size always to computed value
	irp->IoStatus.Information = bufferSize;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchDirectoryControl(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// active ? 
	if( !(s_state & FILFILE_STATE_DIR))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	IO_STACK_LOCATION const*const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	if(IRP_MN_QUERY_DIRECTORY != stack->MinorFunction)
	{
		ASSERT(IRP_MN_NOTIFY_CHANGE_DIRECTORY == stack->MinorFunction);

		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	// interesting type ?
	switch(stack->Parameters.QueryDirectory.FileInformationClass)
	{
		case FileDirectoryInformation:
		case FileFullDirectoryInformation:
		case FileBothDirectoryInformation:
		case FileIdBothDirectoryInformation:
		case FileIdFullDirectoryInformation:
			break;

		default:
			
			IoSkipCurrentIrpStackLocation(irp);

			return IoCallDriver(extension->Lower, irp);
	}

	CFilterDirectory directory;
	RtlZeroMemory(&directory, sizeof(directory));

	if(!extension->Volume.CheckDirectoryCooked(stack->FileObject, &directory))
	{
		IoSkipCurrentIrpStackLocation(irp);

		return IoCallDriver(extension->Lower, irp);
	}

	// doomed directory ?
	if(~0u == directory.m_entityIdentifier)
	{
		irp->IoStatus.Status	  = STATUS_ACCESS_DENIED;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_ACCESS_DENIED;
	}

	IoCopyCurrentIrpStackLocationToNext(irp);

	NTSTATUS status = CFilterBase::SimpleSend(extension->Lower, irp);	

	if(NT_SUCCESS(status))
	{
		__try
		{
			// valid Entity?
			if(directory.m_entityIdentifier)
			{
				CFilterEntity entity;
				RtlZeroMemory(&entity, sizeof(entity));

				// get Header block size for the matched Entity
				if(NT_SUCCESS(extension->Volume.GetEntityInfo(directory.m_entityIdentifier, &entity)))
				{
					ASSERT(entity.m_headerBlocksize);

					// search returned buffer for interesting entries and handle these accordingly
					DirectoryQuery(irp, entity.m_headerBlocksize);
				}
			}
			else
			{
				// just remove AutoConfig entry
				DirectoryQuery(irp, 0);
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			irp->IoStatus.Status	  = STATUS_INVALID_USER_BUFFER;
			irp->IoStatus.Information = 0;
			
			status = STATUS_INVALID_USER_BUFFER;
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchShutdown(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		if(CFilterEngine::s_state)
		{
			CFilterEngine::s_state = FILFILE_STATE_FILE;

			DBGPRINT(("DispatchShutdown: Shutdown on DO[0x%p], deactivate driver\n", device));
		}

		irp->IoStatus.Status	  = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);
	
	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterEngine::DispatchPass(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	if(device == CFilterControl::s_control)
	{
		irp->IoStatus.Status	  = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	#if DBG
	{
		FILE_OBJECT *const file = IoGetCurrentIrpStackLocation(irp)->FileObject;
			
		if(extension->Volume.CheckFileCooked(file))
		{
			ULONG const major = IoGetCurrentIrpStackLocation(irp)->MajorFunction;

			switch(major)
			{
				case IRP_MJ_QUERY_EA:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_QUERY_EA\n", file));
					break;
				case IRP_MJ_SET_EA:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_SET_EA\n", file));
					break;
				case IRP_MJ_FLUSH_BUFFERS:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_FLUSH_BUFFERS\n", file));
					break;
				case IRP_MJ_QUERY_VOLUME_INFORMATION:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_QUERY_VOLUME_INFORMATION\n", file));
					break;
				case IRP_MJ_SET_VOLUME_INFORMATION:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_SET_VOLUME_INFORMATION\n", file));
					break;
				case IRP_MJ_DIRECTORY_CONTROL:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_DIRECTORY_CONTROL\n", file));
					break;
				case IRP_MJ_INTERNAL_DEVICE_CONTROL:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_INTERNAL_DEVICE_CONTROL\n", file));
					break;
				case IRP_MJ_SHUTDOWN:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_SHUTDOWN\n", file));
					break;
				case IRP_MJ_LOCK_CONTROL:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_LOCK_CONTROL\n", file));
					break;
				case IRP_MJ_CREATE_MAILSLOT:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_CREATE_MAILSLOT\n", file));
					break;
				case IRP_MJ_QUERY_SECURITY:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_QUERY_SECURITY\n", file));
					break;
				case IRP_MJ_SET_SECURITY:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_SET_SECURITY\n", file));
					break;
				case IRP_MJ_CREATE_NAMED_PIPE:
					DBGPRINT(("DispatchPass: FO[0x%p] IRP_MJ_CREATE_NAMED_PIPE\n", file));
					break;

				default:
					DBGPRINT(("DispatchPass: FO[0x%p] UNKNOWN major func [0x%08x]\n", file, major));
					break;
			}
		}
	}
	#endif // DBG

	IoSkipCurrentIrpStackLocation(irp);

	return IoCallDriver(extension->Lower, irp);
}

SF_DYNAMIC_FUNCTION_POINTERS g_SfDynamicFunctions;

void  CFilterEngine::SfLoadDynamicFunctions ()
						/*++

						Routine Description:

						This routine tries to load the function pointers for the routines that
						are not supported on all versions of the OS.  These function pointers are
						then stored in the global structure SpyDynamicFunctions.

						This support allows for one driver to be built that will run on all
						versions of the OS Windows 2000 and greater.  Note that on Windows 2000,
						the functionality may be limited.

						Arguments:

						None.

						Return Value:

						None.

						--*/
{
	UNICODE_STRING functionName;

	RtlZeroMemory( &g_SfDynamicFunctions, sizeof( g_SfDynamicFunctions ) );

	//
	//  For each routine that we would want to use, lookup its address in the
	//  kernel or HAL.  If it is not present, that field in our global
	//  SpyDynamicFunctions structure will be set to NULL.
	//

	RtlInitUnicodeString( &functionName, L"FsRtlRegisterFileSystemFilterCallbacks" );
	g_SfDynamicFunctions.RegisterFileSystemFilterCallbacks = (PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS)MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoAttachDeviceToDeviceStackSafe" );
	g_SfDynamicFunctions.AttachDeviceToDeviceStackSafe = (PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE)MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoEnumerateDeviceObjectList" );
	g_SfDynamicFunctions.EnumerateDeviceObjectList =(PSF_ENUMERATE_DEVICE_OBJECT_LIST) MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoGetLowerDeviceObject" );
	g_SfDynamicFunctions.GetLowerDeviceObject =(PSF_GET_LOWER_DEVICE_OBJECT) MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoGetDeviceAttachmentBaseRef" );
	g_SfDynamicFunctions.GetDeviceAttachmentBaseRef = (PSF_GET_DEVICE_ATTACHMENT_BASE_REF)MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoGetDiskDeviceObject" );
	g_SfDynamicFunctions.GetDiskDeviceObject = (PSF_GET_DISK_DEVICE_OBJECT)MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"IoGetAttachedDeviceReference" );
	g_SfDynamicFunctions.GetAttachedDeviceReference = (PSF_GET_ATTACHED_DEVICE_REFERENCE)MmGetSystemRoutineAddress( &functionName );

	RtlInitUnicodeString( &functionName, L"RtlGetVersion" );
	g_SfDynamicFunctions.GetVersion = (PSF_GET_VERSION)MmGetSystemRoutineAddress( &functionName );

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



NTSTATUS CFilterEngine::SfEnumerateFileSystemVolumes (IN DEVICE_OBJECT *device)
{

	ASSERT(device);
	PAGED_CODE();

	NTSTATUS status=STATUS_SUCCESS;

//	PDEVICE_OBJECT newDeviceObject;
//	PDEVCTRL_DEVICE_EXTENSION newDevExt;
	PDEVICE_OBJECT *devList;
	//PDEVICE_OBJECT storageStackDeviceObject;
	ULONG numDevices;
	ULONG i;
//	BOOLEAN isShadowCopyVolume;
	BOOLEAN hasLock = FALSE;
	//
	//  Find out how big of an array we need to allocate for the  mounted device list.
	//
	status = (g_SfDynamicFunctions.EnumerateDeviceObjectList)	(device->DriverObject,NULL,0,&numDevices );
	//
	//  We only need to get this list of there are devices.  If we don't get an error there are no devices so go on.
	//
	if ( NT_SUCCESS( status ) ) {

		return status;
	}

	ASSERT( STATUS_BUFFER_TOO_SMALL == status );
	//
	//  Allocate memory for the list of known devices
	//
	numDevices += 8;		//grab a few extra slots

	devList = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool,(numDevices * sizeof(PDEVICE_OBJECT )));
	if ( NULL == devList ) {

		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//
	//  Now get the list of devices.  If we get an error again
	//  something is wrong, so just fail.
	//
	ASSERT( NULL != g_SfDynamicFunctions.EnumerateDeviceObjectList );

	status = ( g_SfDynamicFunctions.EnumerateDeviceObjectList )(device->DriverObject,devList,( numDevices * sizeof( PDEVICE_OBJECT ) ),&numDevices );

	if ( !NT_SUCCESS( status ) )  {
		ExFreePool(devList);
		return status;
	}

	//
	//  Allocate the name control structure.  We'll use this same name  buffer each time through the for loop.
	//
	BOOLEAN active=true;
	//status = NLAllocateNameControl( &devName, &g_Data.NameBufferLookasideList );
	//如果枚举失败
	if ( !NT_SUCCESS( status ) ) {
		//
		//  If we couldn't get it then we can not process any of the  entries, release all of the device objects and return.
		//
		for ( i=0; i<numDevices; i++ ) {
			ObDereferenceObject( devList[i] );
		}
		ExFreePool(devList);
		goto SkipAttach;
	}

	//
	//  Walk the given list of devices and attach to them if we should.
	//
	for ( i=0; i < numDevices; i++ ) {

		//
		//  Initialize state so it will look like a clean name each time
		//
	//	devName->Name.Length = 0;

		__try {
			//
			//  Do not attach if:
			//	  - This is the control device object ( the one passed in )
			//	  - The device type does not match
			//	  - We are already attached to it.
			//
			if(active)
			{
				// The file system has registered as an active file system. So attach to it.
				DEVICE_OBJECT *filter = devList[i];

				// //检查是否已经Attach
				do
				{
					if (!filter)
					{
						break;
					}

					FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;

					if(extension && (FILFILE_FILTER_VOLUME == extension->Common.Type) && (sizeof(FILFILE_VOLUME_EXTENSION) == extension->Common.Size))
					{
						break;
					}

					filter = filter->AttachedDevice;
				}
				while(filter);

				if(filter)
				{
					DBGPRINT(("FileSystemRegister -WARN: already attached\n"));
					__leave;
				}

				ULONG const objNameInfoSize	= 512;
				OBJECT_NAME_INFORMATION *const objNameInfo = (OBJECT_NAME_INFORMATION*) ExAllocatePool(PagedPool, objNameInfoSize);

				if(objNameInfo)
				{
					RtlZeroMemory(objNameInfo, objNameInfoSize);

					ULONG size = objNameInfoSize;

					NTSTATUS status = ObQueryNameString(devList[i]->DriverObject, objNameInfo, size, &size);

					if(NT_SUCCESS(status))
					{
						// Ignore the MS recognizer, but still attach to other recognizers
						if(!_wcsnicmp(objNameInfo->Name.Buffer, L"\\FileSystem\\Fs_Rec", objNameInfo->Name.Length / sizeof(WCHAR)))
						{
							DBGPRINT(("FileSystemRegister: ignore Recognizer [%ws]\n", objNameInfo->Name.Buffer));

							ExFreePool(objNameInfo);
							goto SkipAttach;
						}

						// Ignore the MS Application Virtualization file system driver because 
						// it crashes even on the simplest requests. Weird software..
						if(!_wcsnicmp(objNameInfo->Name.Buffer, L"\\Driver\\sftfs", objNameInfo->Name.Length / sizeof(WCHAR)))
						{
							DBGPRINT(("FileSystemRegister: ignore App Virtual FS [%ws]\n", objNameInfo->Name.Buffer));

							ExFreePool(objNameInfo);
							goto SkipAttach;
						}

						RtlZeroMemory(objNameInfo, objNameInfoSize);
					}

					size   = objNameInfoSize;
					status = ObQueryNameString(devList[i], objNameInfo, size, &size);

					if(NT_SUCCESS(status))
					{
						// Defaults is FS
											// Ignore certain file systems like the WebDavRedirector for now
						status = IoCreateDevice(CFilterControl::Extension()->Driver, sizeof(FILFILE_VOLUME_EXTENSION), 0, devList[i]->DeviceType, 0, false, &filter);

						if(NT_SUCCESS(status))
						{
							FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) filter->DeviceExtension;
							ASSERT(extension);

							RtlZeroMemory(extension, sizeof(FILFILE_VOLUME_EXTENSION));

//							extension->XDiskImageNameType=FILE_XDISK_IMAGE_TYPE;
							extension->Common.Type	 = FILFILE_FILTER_FILE_SYSTEM;
							extension->Common.Size	 = sizeof(FILFILE_VOLUME_EXTENSION);
							extension->Common.Device = filter;

							DBGPRINT(("FileSystemRegister: try to attach DEVICE [%ws]\n", objNameInfo->Name.Buffer));

							status = STATUS_SUCCESS;
							if (active)
							{
								//询问设备名称
								RtlZeroMemory(objNameInfo, size);
								UNICODE_STRING  DosName={0};
								UNICODE_STRING  linklName={0};
								PDEVICE_OBJECT storageStackDeviceObject=NULL;
								status = ( g_SfDynamicFunctions.GetDiskDeviceObject )( devList[i],&storageStackDeviceObject);

								if (storageStackDeviceObject && NT_SUCCESS(status))
								{
									status = RtlVolumeDeviceToDosName(storageStackDeviceObject,&DosName);
								}
								else
								{
									status=STATUS_UNSUCCESSFUL;
								}

								if (NT_SUCCESS(status))
								{
									UNICODE_STRING driveLetterName={0},driveName={0}; 
									WCHAR TempLetterName[] = L"\\??\\";

									RtlInitUnicodeString( &driveLetterName, TempLetterName );

									driveName.Buffer  =  (PWSTR)ExAllocatePool(PagedPool,256);//1024*2   
									driveName.MaximumLength =  256;

									RtlCopyUnicodeString(&driveName,&driveLetterName);

									RtlAppendUnicodeStringToString(&driveName,&DosName);
									status=CFilterBase::ResolveSymbolicLink(&driveName,&linklName);

									if (DosName.Buffer)
									{
										ExFreePool(DosName.Buffer);
									}

									if (NT_SUCCESS(status))
									{

										UNICODE_STRING SystemPath={0};
										UNICODE_STRING deviceName = {0,0,0};

										NTSTATUS status = CFilterBase::GetSystemPath(&SystemPath);

										if(NT_SUCCESS(status))
										{
											status = CFilterBase::ParseDeviceName(SystemPath.Buffer,SystemPath.Length,&deviceName);

											if (NT_SUCCESS(status))
											{
												if(_wcsnicmp(linklName.Buffer,deviceName.Buffer, deviceName.Length / sizeof(WCHAR)))
												{
													status=STATUS_UNSUCCESSFUL;
												}
												else
												{
													status=STATUS_SUCCESS;
												}
											}
											else
											{
												if(_wcsnicmp(linklName.Buffer, L"\\Device\\HarddiskVolume1", linklName.Length / sizeof(WCHAR)))
												{
													status=STATUS_UNSUCCESSFUL;
												}
												else
												{
													status=STATUS_SUCCESS;
												}
											}
 
										}
										else
										{
											if(_wcsnicmp(linklName.Buffer, L"\\Device\\HarddiskVolume1", linklName.Length / sizeof(WCHAR)))
											{
												status=STATUS_UNSUCCESSFUL;
											}
											else
											{
												status=STATUS_SUCCESS;
											}

										}										
									}

									if (NT_SUCCESS(status))
									{
										size = linklName.Length + sizeof(WCHAR);

										extension->LowerName.Buffer = (LPWSTR) ExAllocatePool(PagedPool, size);

										RtlZeroMemory(extension->LowerName.Buffer, size);
										RtlCopyMemory(extension->LowerName.Buffer, linklName.Buffer, linklName.Length);

										extension->LowerName.Length		   = linklName.Length;
										extension->LowerName.MaximumLength =linklName.Length + sizeof(WCHAR);

										DBGPRINT(("FileSystemRegister: Attached to [%ws]\n", extension->LowerName.Buffer));
									}

									if (driveName.Buffer)
									{
										ExFreePool(driveName.Buffer);
									}

									if (storageStackDeviceObject)
									{
										ObDereferenceObject(storageStackDeviceObject);
									}
								}
							}

							// If this is a network redirector, add it to our volume List
							if(NT_SUCCESS(status))
							{
								// Redirectors actually behave like volumes

								extension->Common.Type = FILFILE_FILTER_VOLUME;
								extension->Common.Size	= sizeof(FILFILE_VOLUME_EXTENSION);
								extension->Common.Device	= filter;
								extension->LowerType		= FILFILE_DEVICE_VOLUME;
							}

							if(NT_SUCCESS(status))
							{
								DEVICE_OBJECT *const lower = IoAttachDeviceToDeviceStack(filter, devList[i]);

								if(lower)
								{
									extension->Lower = lower;
									extension->Real	= extension->Lower;

									if(lower !=device)
									{
										DBGPRINT(("FsMountVolume -INFO: Lower[0x%p] differs from Target[0x%p]\n", lower, extension->Real));
									}

									if(lower->Flags & DO_DIRECT_IO)
									{
										filter->Flags |= DO_DIRECT_IO;
									}
									else if(lower->Flags & DO_BUFFERED_IO)
									{
										filter->Flags |= DO_BUFFERED_IO;
									}

									filter->Flags &= ~DO_DEVICE_INITIALIZING;

									status = CFilterControl::AddVolumeDevice(filter);

									if(NT_ERROR(status))
									{
										CFilterControl::RemoveVolumeDevice(filter);
									}
								}
								else
								{
									DBGPRINT(("FsMountVolume -ERROR: IoAttachDeviceToDeviceStack() failed\n"));

									// Cleanup
									status = STATUS_UNSUCCESSFUL;
								}
							}
/*
							if(NT_SUCCESS(status))
							{
								if(extension->Lower->Flags & DO_DIRECT_IO)
								{
									filter->Flags |= DO_DIRECT_IO;
								}
								else if(extension->Lower->Flags & DO_BUFFERED_IO)
								{
									filter->Flags |= DO_BUFFERED_IO;
								}

								if(extension->Lower->Characteristics & FILE_DEVICE_SECURE_OPEN)
								{
									filter->Characteristics |= FILE_DEVICE_SECURE_OPEN;
								}

								filter->Flags &= ~DO_DEVICE_INITIALIZING;
							}

							if (NT_SUCCESS(status))
							{
								extension->Lower = IoAttachDeviceToDeviceStack(filter, devList[i]);

								if(extension->Lower)
								{	
									extension->Real	= extension->Lower;

									// Other filter drivers between us and target detected
									if(device != extension->Lower)
									{
										DBGPRINT(("FileSystemRegister -INFO: attached to another Filter\n"));
									}
								}

							}

*/

						//			}
							////			else
							//		{
							//		DBGPRINT(("FileSystemRegister -ERROR: IoAttachDeviceToDeviceStack() failed\n"));
							//	}

							if(NT_ERROR(status))
							{
								if(extension->LowerName.Buffer)
								{
									ExFreePool(extension->LowerName.Buffer);
								}	

								IoDeleteDevice(filter);
							}
						}
						else
						{
							DBGPRINT(("FileSystemRegister -ERROR: IoCreateDevice() failed [0x%08x]\n", status));
						}
					}
					else
					{
						DBGPRINT(("FileSystemRegister -ERROR: ObQueryNameString() failed [0x%08x]\n", status));
					}

					ExFreePool(objNameInfo);
				}
			}

			//  Get the real ( disk/storage stack ) device object associated
			//  with this file system device object.  Only try to attach
			//  if we have a disk/storage stack device object.
			//

			

			////
			////  Determine if this is a shadow copy volume.  If so don't
			////  attach to it.
			////  NOTE:  There is no reason sfilter shouldn't attach to these
			////		 volumes, this is simply a sample of how to not
			////		 attach if you don't want to
			////
			//
			//  Allocate a new device object to attach with
			//

		

			//
			//  See if we are already attached, if so don't attach again
			//
		} 
		__finally{

			//  Remove reference added by IoGetDiskDeviceObject.
			//  We only need to hold this reference until we are
			//  successfully attached to the current volume.  Once
			//  we are successfully attached to devList[i], the
			//  IO Manager will make sure that the underlying
			//  storageStackDeviceObject will not go away until
			//  the file system stack is torn down.
			//

		//	if ( storageStackDeviceObject != NULL ) {

			///	ObDereferenceObject( storageStackDeviceObject );
		//	}
///
			//
			//  Cleanup the device object if still defined
			//

			ObDereferenceObject( devList[i] );
		}
	}

SkipAttach:

	//
	//  We are going to ignore any errors received while attaching.  We
	//  simply won't be attached to those volumes if we get an error
	//

	status = STATUS_SUCCESS;

	//
	//  Free the memory we allocated for the list.
	//

	ExFreePool(devList);

	return status;
}