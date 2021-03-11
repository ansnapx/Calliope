////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterControl.cpp: implementation of the CFilterControl class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "IoControl.h"

#include "CFilterBase.h"
#include "CFilterEngine.h"
#include "CFilterCipherManager.h"

#include "CFilterControl.h"

// STATICS //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DEVICE_OBJECT*	CFilterControl::s_control		= 0;
LPCWSTR			CFilterControl::s_deviceNameDos	= L"\\DosDevices\\XAzFileCrypt";
ULONG			CFilterControl::s_cdrom			= 0;

#ifdef FILFILE_SUPPORT_WEBDAV
 ULONG			CFilterControl::s_transIEcache	= 0;
#else
 ULONG			CFilterControl::s_transIEcache	= 1;
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterControl::Init(DRIVER_OBJECT *driver, UNICODE_STRING *regPath, DEVICE_OBJECT *control)
{
	ASSERT(driver);
	ASSERT(control);

	// init static variable
	s_control = control;

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) control->DeviceExtension;
	ASSERT(ctrlExtension);
	RtlZeroMemory(ctrlExtension, sizeof(FILFILE_CONTROL_EXTENSION));

	ctrlExtension->Common.Type	 = FILFILE_FILTER_CONTROL;
	ctrlExtension->Common.Size	 = sizeof(FILFILE_CONTROL_EXTENSION);
	ctrlExtension->Common.Device = control;
	ctrlExtension->bReadOnly=0;

	ctrlExtension->Driver		 = driver;
	ctrlExtension->SystemProcess = PsGetCurrentProcess();

	// Get system version
	ULONG major = 0, minor = 0, build = 0;
	PsGetVersion(&major, &minor, &build, 0);

	DBGPRINT(("Running on Major/Minor[%d,%d] Build[%d]\n", major, minor, build)); 

	switch(major)
	{
		case 5:
			switch(minor)
			{
				case 0:
					ctrlExtension->SystemVersion = FILFILE_SYSTEM_WIN2000;
					break;
				case 1:
					ctrlExtension->SystemVersion = FILFILE_SYSTEM_WINXP;
					break;
				case 2:
					ctrlExtension->SystemVersion = FILFILE_SYSTEM_WIN2003;
					break;
				default:
					ASSERT(false);
					break;
			}
			break;
		case 6:
			switch(minor)
			{
				case 0:
					ctrlExtension->SystemVersion = FILFILE_SYSTEM_WINVISTA;
					break;
				case 1:
					ctrlExtension->SystemVersion = FILFILE_SYSTEM_WIN7;
					break;
				default:
					ASSERT(false);
					break;
			}
			break;
		default:
			ASSERT(false);
			break;
	}

	NTSTATUS status = ExInitializeResourceLite(&ctrlExtension->Lock);

	if(NT_ERROR(status))
	{
		return status;
	}

	InitializeListHead(&ctrlExtension->Volumes);
	
	if(regPath)
	{
		ULONG const pathSize = regPath->Length + (11 * sizeof(WCHAR)) + sizeof(WCHAR);
		LPWSTR path			 = (LPWSTR) ExAllocatePool(PagedPool, pathSize);

		if(path)
		{
			// save registry path to parameters, if any
			RtlZeroMemory(path, pathSize);
			RtlCopyMemory(path, regPath->Buffer, regPath->Length);
			RtlCopyMemory((UCHAR*) path + regPath->Length, L"\\Parameters", 11 * sizeof(WCHAR));

			ctrlExtension->RegistryPath	= path;
		}
	}

	// Init Context
	status = ctrlExtension->Context.Init();

	if(NT_SUCCESS(status))
	{
		// Configured to attach to CDROM and DVD drives?
		CFilterBase::QueryRegistryLong(ctrlExtension->RegistryPath, L"CDROM", &s_cdrom);

		if(s_cdrom)
		{
			DBGPRINT(("CDROM support enabled\n"));
		}

		// Configured to handle IE Cache tranparently?
		CFilterBase::QueryRegistryLong(ctrlExtension->RegistryPath, L"TransIEcache", &s_transIEcache);

		if(s_transIEcache)
		{
			DBGPRINT(("IE Cache is handled transparently\n"));
		}
		 
		// Init Engine
		status = CFilterEngine::Init(driver, control, ctrlExtension->RegistryPath);

		if(NT_SUCCESS(status))
		{
			// Init Process tracker
			ctrlExtension->Process.Init();

			// Init Callback
			ctrlExtension->Callback.Init(ctrlExtension);

			// Init WiperOnDelete handler
			ctrlExtension->Wiper.Init(&ctrlExtension->Context.m_randomizerLow);
	
			// Init Header cache
			ctrlExtension->HeaderCache.Init(ctrlExtension->RegistryPath);

			// Register CDO for shutdown notifications
			IoRegisterShutdownNotification(control);

			control->Flags |=  DO_DIRECT_IO;
			control->Flags &= ~DO_DEVICE_INITIALIZING;
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::InitDeferred()
{
	PAGED_CODE();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	// Query system path we are booted from
	NTSTATUS status = CFilterBase::GetSystemPath(&ctrlExtension->SystemPath);

	if(NT_SUCCESS(status))
	{
		ASSERT(ctrlExtension->SystemPath.Buffer);
		ASSERT(ctrlExtension->SystemPath.Length);

		UNICODE_STRING deviceName = {0,0,0};

		status = CFilterBase::ParseDeviceName(ctrlExtension->SystemPath.Buffer, 
											  ctrlExtension->SystemPath.Length, 
											  &deviceName);
		if(NT_SUCCESS(status))
		{
			// Get device system we booted from
			DEVICE_OBJECT *volume = 0;
			status = GetVolumeDevice(&deviceName, &volume);
			
			if(NT_SUCCESS(status))
			{
				ASSERT(volume);

				FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
				ASSERT(volExtension);

				// Tag it as such
				volExtension->System = true;

				ObDereferenceObject(volume);
			}
		}
	}

	ULONG terminal = 0;

	// TerminalServices mode override in registry?
	status = CFilterBase::QueryRegistryLong(ctrlExtension->RegistryPath, L"Terminal", &terminal);

	// Missing or Auto specified?
	if(NT_ERROR(status) || (terminal >= 2))
	{
		// Query registry to see if we are running in TS mode. Works (including FUS) an all version till Vista/Longhorn, 
		status = CFilterBase::QueryRegistryLong(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
												L"AllowMultipleTSSessions",
												&terminal);
		if(NT_ERROR(status))
		{
			// Dynamically link to RtlGetVersion() because it is not available on Windows 2000
			typedef NTSTATUS (NTAPI* f_getVersion)(PRTL_OSVERSIONINFOW);

			UNICODE_STRING func = RTL_CONSTANT_STRING(L"RtlGetVersion");

			f_getVersion getVersion = (f_getVersion) MmGetSystemRoutineAddress(&func);

			if(getVersion)
			{
				// Get system type
				RTL_OSVERSIONINFOEXW osInfo;
				RtlZeroMemory(&osInfo, sizeof(osInfo));
				osInfo.dwOSVersionInfoSize = sizeof(osInfo);

				status = getVersion((RTL_OSVERSIONINFOW*) &osInfo);

				DBGPRINT(("Initdeferred: Running on Suite[0x%x] Product[0x%x]\n", osInfo.wSuiteMask, 
																				  osInfo.wProductType));

				if(osInfo.wSuiteMask & VER_SUITE_TERMINAL)
				{
					if( !(osInfo.wSuiteMask & VER_SUITE_SINGLEUSERTS))
					{
 						terminal = 1;
					}
				}
			}
			else
			{
				DBGPRINT(("Initdeferred: Failed to retrieve address of RtlGetVersion\n")); 
			}
		}
	}

	if(terminal == 1)
	{
		ctrlExtension->SystemVersion |= FILFILE_SYSTEM_TERMINAL;

		DBGPRINT(("Initdeferred -INFO: TerminalServices mode is enabled\n"));

		ASSERT(IsTerminalServices());
	}

	ctrlExtension->Context.InitDeferred(ctrlExtension->RegistryPath);

	// Init Randomizer(low) here to avoid delays on very first random request
	ULONG rand;
	ctrlExtension->Context.Randomize((UCHAR*) &rand, sizeof(rand));

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

//Ð¶ÔØÇý¶¯µÄÊ±ºò 
NTSTATUS CFilterControl::Close(DRIVER_OBJECT *driver)
{
	ASSERT(driver);

	PAGED_CODE();
	
	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	// Unregister
	IoUnregisterShutdownNotification(s_control);

	// Shutdown engine
	NTSTATUS status = CFilterEngine::Close(driver);

	// Shutdown Process tracker
	ctrlExtension->Process.Close(true);
	// Shutdown WipeOnDelete handler
	ctrlExtension->Wiper.Close();
	// Shutdown Callback stuff
	ctrlExtension->Callback.Close();
	// Shutdown Header cache
	ctrlExtension->HeaderCache.Close();

	LARGE_INTEGER delay;
	delay.QuadPart = RELATIVE(MILLISECONDS(200)); 
	// wait ~200 ms
	KeDelayExecutionThread(KernelMode, false, &delay);

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

	while(!IsListEmpty(&ctrlExtension->Volumes))
	{
		LIST_ENTRY *const entry = RemoveHeadList(&ctrlExtension->Volumes);
		ASSERT(entry);

		FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
		ASSERT(volExtension);

		//ASSERT(volExtension->Common.Type == FILFILE_FILTER_VOLUME);

		if(volExtension->LowerName.Buffer)
		{
			DBGPRINT(("CFilterControl::Close - Detach and delete VOLUME for [%wZ]\n", &volExtension->LowerName));

			ExFreePool(volExtension->LowerName.Buffer);
			volExtension->LowerName.Buffer = 0;
		}

		volExtension->LowerName.Length		  = 0;
		volExtension->LowerName.MaximumLength = 0;

		ctrlExtension->VolumesCount--;

		IoDetachDevice(volExtension->Lower);

		// close engine volume object, delete resource
		volExtension->Volume.Close();
		
		IoDeleteDevice(volExtension->Common.Device);
	};

	ctrlExtension->Context.Close();
	
	ExReleaseResourceLite(&ctrlExtension->Lock);
	ExDeleteResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	// loop through device objects and delete each
	DEVICE_OBJECT* device = driver->DeviceObject;

    while(device)
	{
		FILFILE_COMMON_EXTENSION *const common = (FILFILE_COMMON_EXTENSION*) device->DeviceExtension;
		ASSERT(common);

		if((FILFILE_FILTER_VOLUME == common->Type) || (FILFILE_FILTER_FILE_SYSTEM == common->Type))
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) common;
			ASSERT(volExtension);

			if(volExtension->LowerName.Buffer)
			{
				DBGPRINT(("CFilterControl::Close - Detach and delete FILTER for [%wZ]\n", &volExtension->LowerName));

				ExFreePool(volExtension->LowerName.Buffer);
				volExtension->LowerName.Buffer = 0;
			}

			volExtension->LowerName.Length		  = 0;
			volExtension->LowerName.MaximumLength = 0;

			IoDetachDevice(volExtension->Lower);
		}
		else if(FILFILE_FILTER_CONTROL == common->Type)
		{
			DBGPRINT(("CFilterControl::Close - Delete CONTROL device\n"));
		}
		else
		{
			DBGPRINT(("CFilterControl::Close - Delete UNKNOWN device\n"));
		}

		DEVICE_OBJECT *const next = device->NextDevice;

		IoDeleteDevice(device);

		device = next;
	}

	if(ctrlExtension->RegistryPath)
	{
		ExFreePool(ctrlExtension->RegistryPath);
		ctrlExtension->RegistryPath = 0;
	}

	if(ctrlExtension->SystemPath.Buffer)
	{
		ExFreePool(ctrlExtension->SystemPath.Buffer);

		ctrlExtension->SystemPath.Buffer		= 0;
		ctrlExtension->SystemPath.Length		= 0;
		ctrlExtension->SystemPath.MaximumLength = 0;
	}

	s_control = 0;

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::AddVolumeDevice(DEVICE_OBJECT *device)
{
	ASSERT(device);

	PAGED_CODE();

	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(volExtension);

	// ensure volume object
	//ASSERT(volExtension->Common.Type == FILFILE_FILTER_VOLUME);

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

	for(;;)
	{
		// increment Volume identifier
		ULONG candidate = ctrlExtension->VolumeNextIdentifier + 1;
	
		// Use only 8 bit, because it is used as highest 8 bit for composite 
		// identifiers; 0xfd and 0xfe are reserved and have special meaning.  
		if(candidate >= 0xfd)
		{
			candidate = 1;
		}

		ctrlExtension->VolumeNextIdentifier = candidate;

		// Loop through existing volumes to ensure the choosen identifier is unique
		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);

			if(volExtension->Volume.m_nextIdentifier == candidate)
			{
				// finish
				candidate = 0;
				break;
			}
		}

		// finished ?
		if(candidate)
		{
			break;
		}
	}

	// initialize engine volume object
	NTSTATUS status = volExtension->Volume.Init(volExtension, ctrlExtension->VolumeNextIdentifier);

	if(NT_SUCCESS(status))
	{
		// should be empty
		ASSERT(!volExtension->Volume.m_entities.Size());

		ULONG const redirectorType = volExtension->LowerType & FILFILE_DEVICE_REDIRECTOR;

		// inject appropriate Entities, if any
		for(ULONG index = 0; index < ctrlExtension->Entities.Size(); ++index)
		{
			CFilterEntity *const entity = ctrlExtension->Entities.GetFromPosition(index);
			ASSERT(entity);

			ASSERT(entity->m_volume);
			ASSERT(entity->m_volumeLength);

			bool add = false;

			if(redirectorType)
			{
				// same Redirector ?
				if(redirectorType == (entity->m_flags & FILFILE_DEVICE_REDIRECTOR))
				{
					add = true;
				}
			}
			else
			{
				USHORT const length = (entity->m_volumeLength > volExtension->LowerName.Length) ? volExtension->LowerName.Length : entity->m_volumeLength;

				// same device ?
				if(!_wcsnicmp(entity->m_volume, volExtension->LowerName.Buffer, entity->m_volumeLength / sizeof(WCHAR)))
				{
					add = true;
				}		
			}

			if(add)
			{
				// switch off volume (compare) mode, usually on disk-based volumes
				if(!redirectorType)
				{
					entity->m_flags &= ~TRACK_CHECK_VOLUME;
				}

				#if DBG
				{
					DbgPrint("%sAddVolumeDevice - dispatch Entity [", g_debugHeader);
					entity->Print(CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE | CFilterPath::PATH_DEEPNESS);
					DbgPrint("]\n");
				}
				#endif

				// generate new Entity identifier for this Volume
				entity->m_identifier = volExtension->Volume.GenerateEntityIdentifier();

				// add to volume object
				status = volExtension->Volume.m_entities.Add(entity);

				if(NT_ERROR(status))
				{
					DBGPRINT(("AddVolumeDevice -ERROR: add Entity[0x%08x] failed [0x%08x]\n", entity, status));
					break;
				}

				// remove from control object, transfer ownership
				ctrlExtension->Entities.RemoveRaw(index, false);

				index--;
			}
		}

		if(NT_SUCCESS(status))
		{
			// add to list of active volumes
			InsertTailList(&ctrlExtension->Volumes, &volExtension->Link);

			ctrlExtension->VolumesCount++;

			DBGPRINT(("AddVolumeDevice - new count[%d], volumeIdentifier[0x%02x]\n", ctrlExtension->VolumesCount, ctrlExtension->VolumeNextIdentifier));
		}
	}
	else
	{
		DBGPRINT(("RemoveVolumeDevice -ERROR: initializing of CFilterVolume failed [0x%08x]\n", status));
	}

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::RemoveVolumeDevice(DEVICE_OBJECT *device)
{
	ASSERT(device);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	FsRtlEnterFileSystem();
	ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

	FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(volExtension);

	// ensure volume object
	ASSERT(volExtension->Common.Type == FILFILE_FILTER_VOLUME);
	
	ExAcquireResourceExclusiveLite(&volExtension->Volume.m_entitiesResource, true);

	DBGPRINT(("RemoveVolumeDevice: volumeIdentifier[0x%02x]\n", volExtension->Volume.m_nextIdentifier >> 24));

	// remove appropriate Entities and add back to control object
	for(ULONG index = 0; index < volExtension->Volume.m_entities.Size(); ++index)
	{
		CFilterEntity *entity = volExtension->Volume.m_entities.GetFromPosition(index);
		ASSERT(entity);

		// ignore AutoConfig AND Lanman Entities
		if( !(entity->m_flags & (TRACK_AUTO_CONFIG | TRACK_CHECK_VOLUME)))
		{
			// switch back to volume mode 
			entity->m_flags |= TRACK_CHECK_VOLUME;

			#if DBG
			{
				DbgPrint("%sRemoveVolumeDevice - dispatch back Entity [", g_debugHeader);
				entity->Print(CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE | CFilterPath::PATH_DEEPNESS);
				DbgPrint("]\n");
			}
			#endif

			// invalidate Entity identifier
			entity->m_identifier = 0;

			status = ctrlExtension->Entities.Add(entity);

			if(NT_SUCCESS(status))
			{
				// Note: there is no need to adjust references back to Entities because we are already detached.
				volExtension->Volume.m_entities.RemoveRaw(index, false);

				index--;
			}
		}
	}

	ExReleaseResourceLite(&volExtension->Volume.m_entitiesResource);

	// close engine volume object, free remaining Entities
	status = volExtension->Volume.Close();

	RemoveEntryList(&volExtension->Link);

	ctrlExtension->VolumesCount--;

	DBGPRINT(("RemoveVolumeDevice - new count[%d]\n", ctrlExtension->VolumesCount));

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::GetVolumeDevice(FILE_OBJECT *file, DEVICE_OBJECT **device)
{
	ASSERT(file);
	ASSERT(device);

	PAGED_CODE();

	NTSTATUS status = STATUS_NO_SUCH_DEVICE;

	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

	// get lowest device object
	DEVICE_OBJECT *lowest = CFilterBase::GetDeviceObject(file);

	// walk through the attached device list until we have found our object
	while(lowest)
	{
		FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) lowest->DeviceExtension;

		if(volExtension && (FILFILE_FILTER_VOLUME == volExtension->Common.Type) && (sizeof(FILFILE_VOLUME_EXTENSION) == volExtension->Common.Size))
		{
			*device = volExtension->Common.Device;

			ObReferenceObject(*device);

			status = STATUS_SUCCESS;
			break;
		}

		lowest = lowest->AttachedDevice;
	}

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	ASSERT(NT_ERROR(status) || *device);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::GetVolumeDevice(ULONG identifier, DEVICE_OBJECT **device)
{
	ASSERT(identifier);
	ASSERT(device);

	PAGED_CODE();

	NTSTATUS status = STATUS_NO_SUCH_DEVICE;

	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

	for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
	{
		FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
		ASSERT(volExtension);

		if((volExtension->Volume.m_nextIdentifier & 0xff000000) == (identifier & 0xff000000))
		{
			*device = volExtension->Common.Device;

			ObReferenceObject(*device);

			status = STATUS_SUCCESS;
			break;
		}
	}

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	ASSERT(NT_ERROR(status) || *device);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::GetVolumeDevice(UNICODE_STRING *deviceName, DEVICE_OBJECT **device)
{
	ASSERT(deviceName);
	ASSERT(device);

	PAGED_CODE();

	ASSERT(deviceName->Buffer);
	ASSERT(deviceName->Length);

	NTSTATUS status = STATUS_NO_SUCH_DEVICE;

	UNICODE_STRING lookup = *deviceName;

	ASSERT(s_control);
	FILFILE_CONTROL_EXTENSION *const ctrlExtension = (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
	ASSERT(ctrlExtension);

	FsRtlEnterFileSystem();

	for(ULONG step = 0; step < 2; ++step)
	{
		ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);
			//ASSERT(FILFILE_FILTER_VOLUME == volExtension->Common.Type);

			if(!_wcsnicmp(lookup.Buffer, volExtension->LowerName.Buffer, volExtension->LowerName.Length / sizeof(WCHAR)))
			{
				*device = volExtension->Common.Device;

				ObReferenceObject(*device);

				status = STATUS_SUCCESS;
				break;
			}
		}

		ExReleaseResourceLite(&ctrlExtension->Lock);
		
		// Found device?
		if(NT_SUCCESS(status))
		{
			break;
		}

		// Try to resolve a potentially symbolic link and then check again
		if(NT_ERROR(CFilterBase::ResolveSymbolicLink(deviceName, &lookup)))
		{
			break;
		}
	}

	if(deviceName->Buffer != lookup.Buffer)
	{
		ExFreePool(lookup.Buffer);
	}

	FsRtlExitFileSystem();

	ASSERT(NT_ERROR(status) || *device);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::DispatchValidate(IRP *irp)
{
	ASSERT(irp);

	PAGED_CODE();
	
	if(!irp->AssociatedIrp.SystemBuffer)
	{
		return STATUS_INVALID_PARAMETER;
	}

	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
	ASSERT(stack);

	// Verify input sizes
	if(stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(FILFILE_CONTROL))
	{
		return STATUS_INVALID_PARAMETER;
	}

	FILFILE_CONTROL const*const control = (FILFILE_CONTROL*) irp->AssociatedIrp.SystemBuffer;

	// Check the magic value
	if(control->Magic != FILFILE_CONTROL_MAGIC)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Check version. We only accept the exact same version
	if(control->Version != FILFILE_CONTROL_VERSION)
	{
		DBGPRINT(("DispatchValidate -ERROR: Client uses incompatilble version[%d]\n", control->Version));

		return STATUS_INVALID_PARAMETER;
	}

	ULONG const totalSize = sizeof(FILFILE_CONTROL) + control->PathLength + control->CryptoSize + control->PayloadSize + control->DataSize;

	// Valid Sizes?
	if(totalSize > stack->Parameters.DeviceIoControl.InputBufferLength)
	{
		return STATUS_INVALID_PARAMETER;
	}
	// Valid Bounds?
	if((ULONG) control->PayloadOffset + control->PayloadSize > totalSize)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if((ULONG) control->CryptoOffset + control->CryptoSize > totalSize)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if((ULONG) control->DataOffset + control->DataSize > totalSize)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Check for path properties, if any
	if(control->PathOffset && control->PathLength)
	{
		if((ULONG) control->PathOffset + control->PathLength > totalSize)
		{
			return STATUS_INVALID_PARAMETER;
		}

		LPCWSTR const path = (LPWSTR)((UCHAR*) control + control->PathOffset);

		// Should always be a multiple of two
		if(control->PathLength & 1)
		{
			return STATUS_INVALID_PARAMETER;
		}

		// Check for proper termination
		ULONG pathLen = control->PathLength / sizeof(WCHAR);
		
		while(--pathLen)
		{
			if(!path[pathLen])
			{
				break;
			}
		}
		
		if(!pathLen)
		{
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Passed
	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::Dispatch(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	PAGED_CODE();

	ASSERT(s_control);

#ifdef _AMD64_
	if(IoIs32bitProcess(irp))
	{
		DBGPRINT(("DispatchControl: Called from 32-bit user-mode process\n"));
	}
	else
	{
		DBGPRINT(("DispatchControl: Called from 64-bit user-mode process\n"));
	}
#endif

	ULONG statusInfo = 0;

	// Validate input buffer
	NTSTATUS status = DispatchValidate(irp);
	
	if(NT_SUCCESS(status))
	{
		IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
		ASSERT(stack);

		FILFILE_CONTROL *const control = (FILFILE_CONTROL*) irp->AssociatedIrp.SystemBuffer;
		ULONG const controlSize		   = stack->Parameters.DeviceIoControl.InputBufferLength;

		switch(stack->Parameters.DeviceIoControl.IoControlCode)
		{	
			case IOCTL_FILFILE_GET_STATE:			// STATE

				DBGPRINT(("Control: IOCTL_FIFILE_GET_STATE, current state [0x%x]\n", CFilterEngine::s_state));

				status = STATUS_INVALID_PARAMETER;

				if(irp->MdlAddress)
				{
					UCHAR *userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;

					status = State(control, userBuffer, &statusInfo);
				}
				break;
			
			case IOCTL_FILFILE_SET_STATE:

				status = State(control);

				DBGPRINT(("Control: IOCTL_FILFILE_SET_STATE, new state [0x%x]\n", CFilterEngine::s_state));
				break;

			case IOCTL_FILFILE_GET_HEADER:			// HEADER
			{				
				DBGPRINT(("Control: IOCTL_FILFILE_GET_HEADER\n"));

				UCHAR *userBuffer = 0;
				
				if(irp->MdlAddress)
				{
					userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;
				}

				status = GetHeader(control, userBuffer, &statusInfo);
				break;
			}
			case IOCTL_FILFILE_SET_HEADER:

				DBGPRINT(("Control: IOCTL_FILFILE_SET_HEADER\n"));

				status = SetHeader(control);
				break;

			case IOCTL_FILFILE_ENTITY:				// ENTITY

				DBGPRINT(("Control: IOCTL_FILFILE_ENTITY\n"));

				status = ManageEntity(control);
				break;
												
			case IOCTL_FILFILE_ENUM_ENTITIES:
			{
				DBGPRINT(("Control: IOCTL_FILFILE_ENUM_ENTITIES\n"));

				UCHAR *userBuffer = 0;

				if(irp->MdlAddress)
				{
					userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;
				}

				status = EnumEntities(control, userBuffer, &statusInfo);

				break;
			}
			case IOCTL_FILFILE_ENCRYPTION:			// ENCRYPTION

				DBGPRINT(("Control: IOCTL_FILFILE_ENCRYPTION\n"));
						
				status = ManageEncryption(control);
				break;

			case IOCTL_FILFILE_CALLBACK_CONNECTION:	// CALLBACK
			{
				DBGPRINT(("Control: IOCTL_FILFILE_CALLBACK_CONNECTION\n"));

				status = Connection(control);
				break;
			}
			case IOCTL_FILFILE_ADD_CREDIBLE_PROCESS:
			{
				DBGPRINT(("Control: IOCTL_FILFILE_ADD_CREDIBLE_PROCESS\n"));
				status = AddCredibleProcess(control);
				break;
			}
			case IOCTL_FILFILE_SET_READONLY:
				{
					status=SetControlReadOnly(control);
					break;
				}
			case IOCTL_FILFILE_CALLBACK_REQUEST:
			{
				DBGPRINT(("Control: IOCTL_FILFILE_CALLBACK_REQUEST\n"));

				status = STATUS_INVALID_PARAMETER;

				if(irp->MdlAddress)
				{
					UCHAR *userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;

					status = Extension()->Callback.Request(control->Flags, (FILFILE_CONTROL_OUT*) userBuffer, &statusInfo);
				}
				break;
			}
			case IOCTL_FILFILE_CALLBACK_RESPONSE:
			{
				DBGPRINT(("Control: IOCTL_FILFILE_CALLBACK_RESPONSE\n"));

				if(control->CryptoOffset && control->CryptoSize)
				{
					status = Extension()->Callback.Response((ULONG) control->Value1, 
															  (UCHAR*) control + control->CryptoOffset, 
															  control->CryptoSize);
				}
				else
				{
					// Cancel
					status = Extension()->Callback.Response((ULONG) control->Value1, 0,0);
				}
				break;
			}
			case IOCTL_FILFILE_CALLBACK_RESPONSE_HEADER:
				{
					DBGPRINT(("Control: IOCTL_FILFILE_CALLBACK_RESPONSE\n"));

					if(control->CryptoOffset && control->CryptoSize)
					{
						status = Extension()->Callback.ResponseHeader((UCHAR*) control + control->CryptoOffset,control->CryptoSize);
					}
				}
				break;
			case IOCTL_FILFILE_OPEN_FILE:			// OPEN

				DBGPRINT(("Control: IOCTL_FILFILE_OPEN_FILE\n"));

				status = STATUS_INVALID_PARAMETER;

				if(irp->MdlAddress)
				{
					UCHAR* userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;

					status = OpenFile(control, userBuffer, &statusInfo);
				}
				break;
													
			case IOCTL_FILFILE_GET_BLACKLIST:		// BLACKLIST

				DBGPRINT(("Control: IOCTL_FILFILE_GET_BLACKLIST\n"));
				
				status = STATUS_INVALID_PARAMETER;

				if(irp->MdlAddress)
				{
					UCHAR* userBuffer = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					statusInfo = stack->Parameters.DeviceIoControl.OutputBufferLength;

					status = Blacklist(control, userBuffer, &statusInfo);
				}
				break;

			case IOCTL_FILFILE_SET_BLACKLIST:

				DBGPRINT(("Control: IOCTL_FILFILE_SET_BLACKLIST\n"));

				status = Blacklist(control);
				break;

			case IOCTL_FILFILE_WIPER:			// WIPER

				DBGPRINT(("Control: IOCTL_FILFILE_WIPER\n"));

				status = Wiper(control);
				break;
				//case 

			default:
				DBGPRINT(("Control: -ERROR: unsupported ControlCode [0x%08x]\n", stack->Parameters.DeviceIoControl.IoControlCode));

				status = STATUS_INVALID_PARAMETER;
				break;
		}

		if(NT_ERROR(status))
		{
			statusInfo = 0;
		}

		// Zero everything because IO Manager could have copied sensitive data temporarily
		RtlZeroMemory(control, controlSize);
	}
	else
	{
		DBGPRINT(("Control: -ERROR: invalid input parameters\n"));
	}

	irp->IoStatus.Status	  = status;
	irp->IoStatus.Information = statusInfo;
	
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::State(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize)
{
	ASSERT(control);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	// Change state?
	if(control->Flags & FILFILE_CONTROL_SET)
	{
		if(control->Flags & FILFILE_CONTROL_ADD)
		{
			// Very first activation?
			if(!CFilterEngine::s_state)
			{
				InitDeferred();
			}

			// Set fully active
			InterlockedOr(&CFilterEngine::s_state, FILFILE_STATE_VALID_USER);
		}
		else
		{
			// If TerminalServices is active, void deactivation requests. In this case,
			// deactivation is then done implicitely when very last client disconnects.
			if(!IsTerminalServices())
			{
				// Set passive, only file path remains active
				InterlockedAnd(&CFilterEngine::s_state, ~(FILFILE_STATE_DIR | FILFILE_STATE_ACCESS_DENY | FILFILE_STATE_TRIGGER));

				// Clear Header cache
				Extension()->HeaderCache.Clear();
			}
		}
	}
	else
	{
		// Query current state:
		status = STATUS_INVALID_PARAMETER;

		if(userBuffer && userBufferSize)
		{
			status = STATUS_BUFFER_TOO_SMALL;

			if(*userBufferSize >= sizeof(FILFILE_CONTROL_OUT))
			{
				status = STATUS_SUCCESS;

				__try
				{
					RtlZeroMemory(userBuffer, sizeof(FILFILE_CONTROL_OUT));

					FILFILE_CONTROL_OUT *const out = (FILFILE_CONTROL_OUT*) userBuffer; 

					out->Flags = FILFILE_CONTROL_NULL;

					// set flags according internal state
					if((CFilterEngine::s_state & FILFILE_STATE_CREATE) == FILFILE_STATE_CREATE)
					{
						out->Flags = FILFILE_CONTROL_ACTIVE;
					}

					// provide full state value too
					out->Value = CFilterEngine::s_state;

					*userBufferSize = sizeof(FILFILE_CONTROL_OUT);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					status = STATUS_INVALID_USER_BUFFER;
				}
			}
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::EnumEntitiesBool(FILFILE_CONTROL *control)
{
	ASSERT(control);

	PAGED_CODE();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	CFilterHeaderCont &headers = ctrlExtension->Context.Headers();

	NTSTATUS status		= STATUS_SUCCESS;
	ULONG entitiesCount = 0;
	LUID luid			= {0,0};

	bool const neg		= (control->Flags & FILFILE_CONTROL_ACTIVE) ? true : false;
	bool const terminal = IsTerminalServices();

	if(terminal)
	{
		status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

	headers.LockShared();

	// Get number of currently unowned Entities
	if(!neg)
	{
		if(terminal)
		{
			ULONG const count = ctrlExtension->Entities.Size();

			for(ULONG index = 0; index < count; ++index)
			{
				CFilterEntity *entity = ctrlExtension->Entities.GetFromPosition(index);
				ASSERT(entity);

				if(~0u != entity->m_luids.Check(&luid))
				{
					entitiesCount++;
				}
			}
		}
		else
		{
			entitiesCount += ctrlExtension->Entities.Size();
		}
	}

	if(!entitiesCount)
	{
		// Add active Entities, owned by Volumes
		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);

			if(neg)
			{
				// Negative Entities
				entitiesCount += volExtension->Volume.m_negatives.Size();
			}
			else
			{
				// Regular Entities
				if(terminal)
				{
					if(volExtension->Volume.m_entities.Size())
					{
						ExAcquireResourceSharedLite(&volExtension->Volume.m_entitiesResource, true);

						ULONG const count = volExtension->Volume.m_entities.Size();

						for(ULONG pos = 0; pos < count; ++pos)
						{
							CFilterEntity *entity = volExtension->Volume.m_entities.GetFromPosition(pos);
							ASSERT(entity);

							if(~0u != entity->m_luids.Check(&luid))
							{
								entitiesCount++;

								break;
							}
						}
						
						ExReleaseResourceLite(&volExtension->Volume.m_entitiesResource);
					}
				}
				else
				{
					entitiesCount += volExtension->Volume.m_entities.Size();
				}
			}

			// Stop if at least one entry was found as this is a boolean query
			if(entitiesCount)
			{
				break;
			}
		}
	}

	headers.Unlock();

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	return (entitiesCount) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::EnumEntities(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize)
{
	ASSERT(control);

	PAGED_CODE();

	// Simple Boolean query?
	if(!userBuffer)
	{
		return EnumEntitiesBool(control);
	}

	ASSERT(userBufferSize);

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	CFilterHeaderCont &headers = ctrlExtension->Context.Headers();

	NTSTATUS status = STATUS_SUCCESS;
	ULONG current   = 0;
	LUID luid		= {0,0};

	bool const neg		= (control->Flags & FILFILE_CONTROL_ACTIVE) ? true : false;
	bool const terminal = IsTerminalServices();

	if(terminal)
	{
		status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}
	}

	FsRtlEnterFileSystem();
	ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);
	
	headers.LockShared();
	
	__try
	{
		RtlZeroMemory(userBuffer, *userBufferSize);

		LPWSTR buffer	  = (LPWSTR) userBuffer;
		ULONG  bufferSize = *userBufferSize;

		ULONG const flags = CFilterPath::PATH_PREFIX | CFilterPath::PATH_VOLUME | CFilterPath::PATH_FILE | CFilterPath::PATH_DEEPNESS;

		if(!neg)
		{
			ULONG const count = ctrlExtension->Entities.Size();

			// Passive regular Entities, owned by CDO
			for(ULONG pos = 0; pos < count; ++pos)
			{
				CFilterEntity *entity = ctrlExtension->Entities.GetFromPosition(pos);
				ASSERT(entity);

				if(!terminal || (~0u != entity->m_luids.Check(&luid)))
				{
					ULONG const written = entity->Write(buffer + current, 
														bufferSize - (current * sizeof(WCHAR)), 
														flags);
					if(!written)
					{
						status = STATUS_BUFFER_TOO_SMALL;
						break;
					}

					current += written / sizeof(WCHAR);
				}
			}
		}

		// active Entities, owned by Volumes
		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);

			if(neg)
			{
				// Negative Entities
				ExAcquireResourceSharedLite(&volExtension->Volume.m_negativesResource, true);

				ULONG const count = volExtension->Volume.m_negatives.Size();

				for(ULONG pos = 0; pos < count; ++pos)
				{
					CFilterEntity *entity = volExtension->Volume.m_negatives.GetFromPosition(pos);
					ASSERT(entity);

					if(!terminal || (~0u != entity->m_luids.Check(&luid)))
					{
						ULONG const written = entity->Write(buffer + current, 
														    bufferSize - (current * sizeof(WCHAR)), 
															flags);
						if(!written)
						{
							status = STATUS_BUFFER_TOO_SMALL;
							break;
						}

						current += written / sizeof(WCHAR);
					}
				}
				
				ExReleaseResourceLite(&volExtension->Volume.m_negativesResource);
			}
			else
			{
				// Regular Entities
				ExAcquireResourceSharedLite(&volExtension->Volume.m_entitiesResource, true);

				ULONG const count = volExtension->Volume.m_entities.Size();

				for(ULONG pos = 0; pos < count; ++pos)
				{
					CFilterEntity *entity = volExtension->Volume.m_entities.GetFromPosition(pos);
					ASSERT(entity);

					if(!terminal || (~0u != entity->m_luids.Check(&luid)))
					{
						ULONG const written = entity->Write(buffer + current, 
															bufferSize - (current * sizeof(WCHAR)), 
															flags);
						if(!written)
						{
							status = STATUS_BUFFER_TOO_SMALL;
							break;
						}

						current += written / sizeof(WCHAR);
					}
				}
				
				ExReleaseResourceLite(&volExtension->Volume.m_entitiesResource);
			}
		}

		if(current && ((current + 1) * sizeof(WCHAR) < bufferSize))
		{
			// teminate entire buffer
			buffer[current++] = UNICODE_NULL;
		}

		*userBufferSize = current * sizeof(WCHAR);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = STATUS_INVALID_USER_BUFFER;
	}

	headers.Unlock();

	ExReleaseResourceLite(&ctrlExtension->Lock);
	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::RemoveEntities(ULONG flags)
{
	PAGED_CODE();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	LUID luid = {0,0};

	bool const terminal = IsTerminalServices();

	if(terminal)
	{
		NTSTATUS status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}

		ASSERT(luid.HighPart || luid.LowPart);
	}

	FsRtlEnterFileSystem();

	if(flags & ENTITY_NEGATIVE)
	{
		DBGPRINT(("RemoveEntities: removing negatives\n"));
		
		ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

		// Remove Volume Entities
		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);

			volExtension->Volume.RemoveEntities(ENTITY_NEGATIVE, (terminal) ? &luid : 0);
		}

		ExReleaseResourceLite(&ctrlExtension->Lock);
	}

	if(flags & ENTITY_REGULAR)
	{
		DBGPRINT(("RemoveEntities: removing regulars\n"));

		CFilterContext *const context = &ctrlExtension->Context;

		ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

		if(ctrlExtension->Entities.Size())
		{
			ULONG const count = ctrlExtension->Entities.Size();

			// remove CDO Entities
			for(ULONG pos = 0; pos < count; ++pos)
			{
				CFilterEntity *entity = ctrlExtension->Entities.GetFromPosition(pos);
				ASSERT(entity);

				if(entity)
				{
					// Release Header referenced by this Entity
					context->Headers().Release(entity->m_headerIdentifier);

					entity->m_headerIdentifier = 0;
					entity->m_headerBlocksize  = 0;

					ctrlExtension->Entities.RemoveRaw(pos, true);
				}
			}
		}

		// remove Volume Entities
		for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
		{
			FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
			ASSERT(volExtension);

			volExtension->Volume.RemoveEntities(ENTITY_REGULAR | ENTITY_PURGE, (terminal) ? &luid : 0);
		}

		ExReleaseResourceLite(&ctrlExtension->Lock);

		if(terminal)
		{
			// Remove LUID from Headers
			CFilterHeaderCont &headers = context->Headers();

			headers.LockExclusive();
			headers.RemoveLuid(&luid);
			headers.Unlock();
		}
	}

	FsRtlExitFileSystem();

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::Wiper(FILFILE_CONTROL *control)
{
	ASSERT(control);

	PAGED_CODE();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	NTSTATUS status = STATUS_SUCCESS;

	int *patterns     = 0;
	int  patternsSize = 0;

	// Valid pattern vector?
	if(control->PayloadOffset)
	{
		if(!control->PayloadSize)
		{
			return STATUS_INVALID_PARAMETER;
		}

		patterns     = (int*) ((UCHAR*) control + control->PayloadOffset);
		patternsSize = control->PayloadSize;
	}

	if(control->Flags & FILFILE_CONTROL_WIPE_ON_DELETE)
	{
		DBGPRINT(("WipeOnDelete: Flags[0x%x] Patterns[%d]\n", control->Flags, patternsSize/sizeof(int)));

		if(control->Flags & FILFILE_CONTROL_ACTIVE)
		{
			// Very first activation ?
			if(!CFilterEngine::s_state)
			{
				// Init Randomizer(low) here to avoid delays on very first wipe
				ULONG rand;
				ctrlExtension->Context.Randomize((UCHAR*) &rand, sizeof(rand));
			}

			// Set/overwrite pattern vector, if any
			ctrlExtension->Wiper.Prepare(0, patterns, patternsSize);

			// Activate WOD
			InterlockedOr(&CFilterEngine::s_state, FILFILE_WIPE_ON_DELETE);
		}
		else
		{
			// Deactivate WOD
			InterlockedAnd(&CFilterEngine::s_state, ~FILFILE_WIPE_ON_DELETE);
		}
	}
	else
	{
		// Valid file handle?
		if(!control->Value1)
		{
			return STATUS_INVALID_PARAMETER;
		}

		DBGPRINT(("WipeFile: Flags[0x%x] Patterns[%d] Cancel[0x%x] Progress[0x%x]\n", control->Flags, 
																					  patternsSize/sizeof(int), 
																					  control->Value2, 
																					  control->Value3));

		// Use stack-based instance to support multiple wipe operations simultaneously
		CFilterWiper wiper;

		status = wiper.Init(&ctrlExtension->Context.m_randomizerLow);

		if(NT_SUCCESS(status))
		{
			status = wiper.Prepare(control->Flags, 
								   patterns, 
								   patternsSize, 
								   (HANDLE)(ULONG_PTR) control->Value2, 
								   (HANDLE)(ULONG_PTR) control->Value3);

			if(NT_SUCCESS(status))
			{
				FILE_OBJECT *file = 0;

				status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR) control->Value1, 
												   FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 
												   *IoFileObjectType, 
												   UserMode, 
												   (void**) &file, 
												   0);

				if(NT_SUCCESS(status))
				{
					ASSERT(file);

					status = wiper.WipeFile(file);

					ObDereferenceObject(file);
				}
				else
				{
					DBGPRINT(("Wiper -ERROR: ObReferenceObjectByHandle() failed [0x%08x]\n", status));
				}
			}

			wiper.Close();
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::OpenFile(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize)
{
	ASSERT(control);

	PAGED_CODE();

	if(!control->PathOffset || !control->PathLength)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if(!userBuffer || !userBufferSize)
	{
		return STATUS_INVALID_PARAMETER;
	}
	if(*userBufferSize < sizeof(FILFILE_CONTROL_OUT))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	LPWSTR const userPath = (LPWSTR) ((UCHAR*) control + control->PathOffset);
	
	DBGPRINT(("OpenFile: [%ws]\n", userPath));

	ULONG deviceType = FILFILE_DEVICE_NULL;
	UNICODE_STRING deviceName = {0,0,0};

	// Get device name from path
	NTSTATUS status = CFilterBase::ParseDeviceName(userPath, control->PathLength, &deviceName, &deviceType);

	if(NT_ERROR(status))
	{
		return status;
	}

	DEVICE_OBJECT *volume = 0;
	status = GetVolumeDevice(&deviceName, &volume);
	
	if(NT_SUCCESS(status))
	{
		ASSERT(volume);

		// Targeting redirector on Vista or later?
		if((deviceType & FILFILE_DEVICE_REDIRECTOR) && IsWindowsVistaOrLater())
		{
			// Use Mup as device prefix to avoid strange behaviors with CSC which
			// sometimes claims requests but fails to handle them correctly
			RtlCopyMemory(userPath, L"\\Device\\Mup", 11 * sizeof(WCHAR));
			RtlMoveMemory(userPath + 11, userPath + 24, control->PathLength - (24 * sizeof(WCHAR)));
			RtlZeroMemory((UCHAR*) userPath + control->PathLength - ((24 - 12) * sizeof(WCHAR)), (24 - 12) * sizeof(WCHAR));
		}

		UNICODE_STRING filePath;
		RtlInitUnicodeString(&filePath, userPath);

		OBJECT_ATTRIBUTES fileOAs;
		InitializeObjectAttributes(&fileOAs, &filePath, OBJ_CASE_INSENSITIVE, 0,0);

		HANDLE fileHandle		 = 0;
		IO_STATUS_BLOCK	ioStatus = {0,0};

		// Default parameters:
		ULONG fileAttribs		= FILE_ATTRIBUTE_NORMAL;
		ULONG fileDisposition	= FILE_OPEN;
		ULONG fileShare			= 0; // Exclusive access
		ULONG fileAccess		= FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
		ULONG fileOptions		= FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT;
		
		// AutoConfig file?
		if(control->Flags & FILFILE_CONTROL_AUTOCONF)		
		{
			fileOptions &= ~FILE_NO_INTERMEDIATE_BUFFERING;			
			
			if(control->Flags & FILFILE_CONTROL_ADD)
			{
				fileAttribs	= FILE_ATTRIBUTE_SYSTEM;

				fileDisposition = FILE_OPEN_IF;
			}
			else
			{
				// Use lowest permissions set needed
				fileAccess = DELETE | FILE_READ_ATTRIBUTES;
			}
		}

		// Shared access?
		if(control->Flags & FILFILE_CONTROL_SHARED)
		{
			fileAccess = FILE_GENERIC_READ;
			fileShare  = FILE_SHARE_VALID_FLAGS;
		}
		
		FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
		ASSERT(volExtension);

		// Open file without re-entering the file system stack
		status = IoCreateFileSpecifyDeviceObjectHint(&fileHandle,
													 fileAccess,
													 &fileOAs,
													 &ioStatus,
													 0,
													 fileAttribs,
													 fileShare,
													 fileDisposition, 
													 fileOptions,
													 0,
													 0,
													 CreateFileTypeNone,
													 0,
													 IO_FORCE_ACCESS_CHECK,
													 volExtension->Lower);

		if(NT_SUCCESS(status))
		{
			__try
			{
				RtlZeroMemory(userBuffer, sizeof(FILFILE_CONTROL_OUT));

				FILFILE_CONTROL_OUT *out = (FILFILE_CONTROL_OUT*) userBuffer; 

				out->Flags  = FILFILE_CONTROL_HANDLE;
				out->Value  = (ULONG_PTR) fileHandle;

				*userBufferSize = sizeof(FILFILE_CONTROL_OUT);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				ZwClose(fileHandle);

				status = STATUS_INVALID_USER_BUFFER;
			}
		}
		else
		{
			DBGPRINT(("OpenFile -ERROR: IoCreateFileSpecifyDeviceObjectHint() failed [0x%08x]\n", status));
		}

		ObDereferenceObject(volume);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::AppLists(FILFILE_CONTROL *control, ULONG cipher)
{
	ASSERT(control);

	PAGED_CODE();

	ASSERT(control->PathOffset);
	ASSERT(control->PathLength);

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	LPCWSTR userPath	 = (LPCWSTR) ((UCHAR*) control + control->PathOffset);
	ULONG userPathLength = control->PathLength;

	// Transform to char count
	userPathLength /= sizeof(WCHAR);

	// Strip trailing zeros
	while(userPathLength > 1)
	{
		if(userPath[userPathLength - 1])
		{
			break;
		}

		userPathLength--;
	}
	
	userPathLength *= sizeof(WCHAR);

	DBGPRINT(("AppLists: [%ws] Header[0x%x] Flags[0x%x]\n", userPath, 
														    control->PayloadSize, 
															control->Flags));

	NTSTATUS status = STATUS_SUCCESS;

	LUID luid = {0,0};

	if(IsTerminalServices())
	{
		status = CFilterBase::GetLuid(&luid);

		if(NT_ERROR(status))
		{
			return status;
		}

		ASSERT(luid.HighPart || luid.LowPart);
	}

	CFilterAppList &appList = ctrlExtension->Context.AppList();

	if(control->Flags & FILFILE_CONTROL_ADD)
	{
		if(control->Flags & FILFILE_CONTROL_BLACKLIST)
		{
			// Application Blacklist
			status = appList.Add(userPath, userPathLength, FILFILE_APP_BLACK);
		}
		else
		{
			// Application Whitelist
			if( !(cipher & (FILFILE_CIPHER_SYM_AES128 | FILFILE_CIPHER_SYM_AES192 | FILFILE_CIPHER_SYM_AES256)))
			{
				return STATUS_INVALID_PARAMETER;
			}

			ASSERT(control->PayloadOffset);
			ASSERT(control->PayloadSize);
			ASSERT(control->CryptoOffset);
			ASSERT(control->CryptoSize);
		
			CFilterHeader header;

			status = header.Init((UCHAR*) control + control->PayloadOffset, 
								 control->PayloadSize);

			if(NT_SUCCESS(status))
			{
				header.m_luid = luid;

				header.m_key.Init(cipher,
								  (UCHAR*) control + control->CryptoOffset, 
								  control->CryptoSize);

				status = appList.Add(userPath, 
									 userPathLength,
									 FILFILE_APP_WHITE,
									 &header);
				header.Close();
			}
		}
	}
	else
	{
		ASSERT(control->Flags & FILFILE_CONTROL_REM);

		// Either Application list
		status = appList.Remove(userPath, 
								userPathLength,
								IsTerminalServices() ? &luid : 0);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::ManageEntity(FILFILE_CONTROL *control)
{
	ASSERT(control);

	PAGED_CODE();

	// ALL Entities to be removed?
	if((control->Flags & (FILFILE_CONTROL_SET | FILFILE_CONTROL_REM)) == (FILFILE_CONTROL_SET | FILFILE_CONTROL_REM))
	{
		return RemoveEntities((control->Flags & FILFILE_CONTROL_ACTIVE) ? ENTITY_NEGATIVE : ENTITY_REGULAR);
	}

	// Verify some input parameters
	if(!control->PathOffset || !control->PathLength)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Cipher algo and mode used for encryption
	ULONG cipher = FILFILE_CIPHER_MODE_DEFAULT;

	// Skip params check for negative Entities and Application Blacklists 
	if((control->Flags & FILFILE_CONTROL_ADD) && !(control->Flags & (FILFILE_CONTROL_ACTIVE | FILFILE_CONTROL_BLACKLIST)))
	{
		if(!control->PayloadOffset || !control->PayloadSize)
		{
			return STATUS_INVALID_PARAMETER;
		}

		if(control->CryptoSize)
		{
			switch(control->CryptoSize)
			{
				case 128 / 8:
					cipher |= FILFILE_CIPHER_SYM_AES128;
					break;
				case 192 / 8:
					cipher |= FILFILE_CIPHER_SYM_AES192;
					break;
				case 256 / 8:
					cipher |= FILFILE_CIPHER_SYM_AES256;
					break;

				default:
					return STATUS_INVALID_PARAMETER;
			}

			if(!control->CryptoOffset)
			{
				return STATUS_INVALID_PARAMETER;
			}
		}
	}

	// Application Black or White list?
	if(control->Flags & FILFILE_CONTROL_APPLICATION)
	{
		return AppLists(control, cipher);
	}

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	LPCWSTR userPath = (LPCWSTR) ((UCHAR*) control + control->PathOffset);

	DBGPRINT(("ManageEntity: [%ws] Header[0x%x] Flags[0x%x]\n", userPath, control->PayloadSize, control->Flags));

	ULONG deviceType = FILFILE_DEVICE_NULL;
	UNICODE_STRING deviceName = {0,0,0};

	// Get device name from path
	NTSTATUS status = CFilterBase::ParseDeviceName(userPath, control->PathLength, &deviceName, &deviceType);

	if(NT_ERROR(status))
	{
		return status;
	}

	FsRtlEnterFileSystem();

	DEVICE_OBJECT *volume = 0;
	status = GetVolumeDevice(&deviceName, &volume);
	
	if(NT_SUCCESS(status))
	{
		ASSERT(volume);

		FILFILE_TRACK_CONTEXT track;
		RtlZeroMemory(&track, sizeof(track));

		if(control->PayloadSize)
		{
			ASSERT(control->PayloadOffset);

			// Init Header
			status = track.Header.Init((UCHAR*) control + control->PayloadOffset, control->PayloadSize);

			if(NT_SUCCESS(status))
			{
				status = STATUS_INVALID_PARAMETER;

				if(control->CryptoSize)
				{
					ASSERT(control->CryptoOffset);

					// Init Entity Key
					track.EntityKey.Init(cipher,
										(UCHAR*) control + control->CryptoOffset, 
										 control->CryptoSize);

					status = STATUS_SUCCESS;
				}
				else if((control->Flags & FILFILE_CONTROL_ADD) == FILFILE_CONTROL_ADD)
				{
					CFilterHeaderCont &headers = ctrlExtension->Context.Headers();

					headers.LockShared();

					// Find Entity Key for exactly same Payload
					CFilterHeader const* existing = headers.Search(&track.Header);
					
					if(existing)
					{
						// Copy Entity Key
						track.EntityKey.Init(&existing->m_key);

						status = STATUS_SUCCESS;
					}

					headers.Unlock();
				}
			}
		}

		if(NT_SUCCESS(status))
		{
			// init Entity
			status = track.Entity.InitClient(userPath, control->PathLength, CFilterPath::PATH_DEEPNESS);

			if(NT_SUCCESS(status))
			{
				FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
				ASSERT(volExtension);

				// set Entity type
				track.Entity.m_flags |= (track.Entity.m_file) ? TRACK_TYPE_FILE : TRACK_TYPE_DIRECTORY;

				// add to target Volume
				status = volExtension->Volume.ManageEntity(&track, control->Flags);

				if(STATUS_SUCCESS != status)
				{
					DBGPRINT(("ManageEntity -ERROR: ManageEntity() returned [0x%08x]\n", status));
				}
			}
			else
			{
				DBGPRINT(("ManageEntity -ERROR: CFilterEntity.Init() failed [0x%08x]\n", status));
			}
		}
		
		track.Header.Close();
		track.Entity.Close();
		track.EntityKey.Clear();
        
		ObDereferenceObject(volume);
	}
	else
	{
		DBGPRINT(("ManageEntity -INFO: device not active\n"));

		status = STATUS_NO_SUCH_DEVICE;

		// remove from CDO, e.g. if volume is removed
		if(control->Flags & FILFILE_CONTROL_REM)
		{
			CFilterPath path;

			status = path.InitClient(userPath, control->PathLength, CFilterPath::PATH_DEEPNESS);

			if(NT_SUCCESS(status))
			{
				status = STATUS_NO_SUCH_DEVICE;
				
				ExAcquireResourceExclusiveLite(&ctrlExtension->Lock, true);

				// set Entity type
				path.m_flags = TRACK_CHECK_VOLUME | TRACK_TYPE_DIRECTORY;

				if(path.m_file)
				{
					path.m_flags = TRACK_CHECK_VOLUME | TRACK_TYPE_FILE;
				}

				ULONG const pos = ctrlExtension->Entities.Check(&path, true);

				if(pos != ~0u)
				{
					CFilterEntity *const entity = ctrlExtension->Entities.GetFromPosition(pos);
					ASSERT(entity);

					if(entity)
					{
						CFilterContext *const context = &ctrlExtension->Context;

						// release Header referenced by this Entity
						context->Headers().Release(entity->m_headerIdentifier);

						entity->m_headerIdentifier = 0;
						entity->m_headerBlocksize  = 0;

						status = ctrlExtension->Entities.RemoveRaw(pos, true);
					}
				}
				else
				{
					DBGPRINT(("ManageEntity -INFO: Entity not found in CDO\n"));
				}

				ExReleaseResourceLite(&ctrlExtension->Lock);
				
				path.Close();
			}
		}
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::GetHeader(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize)
{
	ASSERT(control);

	PAGED_CODE();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);
        
	CFilterHeader header;
	RtlZeroMemory(&header, sizeof(header));

	NTSTATUS status = STATUS_SUCCESS;

	bool alreadyCached = false;

	// Use Header cache?
	if(control->PathOffset)
	{
		LPWSTR const path = (LPWSTR) ((UCHAR*) control + control->PathOffset);

		// Query cache, by reference
		if(NT_SUCCESS(ctrlExtension->HeaderCache.Query(path, control->PathLength, &header)))
		{
			alreadyCached = true;

			// Positive match?
			if(!header.m_payloadSize)
			{
				// Indicate negative match
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}
		}
	}

	if(!alreadyCached)
	{
		// Verify input parameters
		if(!control->Value1 || !(control->Flags & FILFILE_CONTROL_HANDLE))
		{
			return STATUS_INVALID_PARAMETER;
		}

		HANDLE fileHandle = (HANDLE)(ULONG_PTR) control->Value1;
		FILE_OBJECT *file = 0;

		// Get FO
		status = ObReferenceObjectByHandle(fileHandle, FILE_GENERIC_READ, *IoFileObjectType, UserMode, (void**) &file, 0);

		if(NT_SUCCESS(status))
		{
			ASSERT(file);

			DEVICE_OBJECT *volume = 0;

			status = GetVolumeDevice(file, &volume);
			
			if(NT_SUCCESS(status))
			{
				ASSERT(volume);

				status = STATUS_UNSUCCESSFUL;

				FILFILE_VOLUME_EXTENSION *const volExtension = ((FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension);
				ASSERT(volExtension);

				// Check if the corresponding file is tracked, if so get header from there w/o taking file path
				if( !(control->Flags & FILFILE_CONTROL_AUTOCONF))
				{
					CFilterContextLink link;
					RtlZeroMemory(&link, sizeof(link));

					if(volExtension->Volume.CheckFileCooked(file, &link))
					{
						ASSERT(link.m_headerIdentifier);
						ASSERT(link.m_headerIdentifier != ~0u);

						DBGPRINT(("GetHeader: tracked Header found [0x%x]\n", link.m_headerIdentifier));

						status = STATUS_SUCCESS;

						// Header DATA requested ?
						if(userBuffer)
						{
							FsRtlEnterFileSystem();

							CFilterHeaderCont &headers = ctrlExtension->Context.Headers();
							headers.LockShared();

							CFilterHeader const*const tracked = headers.Get(link.m_headerIdentifier);
							ASSERT(tracked);

							if(tracked)
							{
								status = header.Init(tracked->m_payload, tracked->m_payloadSize);
							}

							headers.Unlock();

							FsRtlExitFileSystem();
						}

						// be paranoid
						RtlZeroMemory(&link, sizeof(link));
					}
				}

				if(NT_ERROR(status))
				{
					ASSERT(!header.m_payload);
					ASSERT(!header.m_payloadSize);

					CFilterCipherManager manager(volExtension);

					if(control->Flags & FILFILE_CONTROL_AUTOCONF)
					{
						// get AutoConfig file
						status = manager.AutoConfigRead(file, &header);
					}
					else
					{
						// get tracked Header
						status = manager.RecognizeHeader(file, &header);
					}

					if(NT_ERROR(status))
					{
						DBGPRINT(("GetHeader: no valid Header found\n"));
					}
				}

				ObDereferenceObject(volume);
			}
			else
			{
				DBGPRINT(("GetHeader -ERROR: device not found [0x%08x]\n", status));
			}

			ObDereferenceObject(file);
		}
		else
		{
			DBGPRINT(("GetHeader -ERROR: ObReferenceObjectByHandle() failed [0x%08x]\n", status));
		}
	}

	if(NT_SUCCESS(status))
	{
		// Header DATA requested ?
		if(userBuffer)
		{
			ASSERT(header.m_payload);
			ASSERT(header.m_payloadSize);

			ASSERT(userBufferSize);

			status = STATUS_BUFFER_TOO_SMALL;

			ULONG const bufferSize = sizeof(FILFILE_CONTROL_OUT) + header.m_payloadSize;

			if(*userBufferSize >= bufferSize)
			{
				__try
				{
					RtlZeroMemory(userBuffer, bufferSize);

					FILFILE_CONTROL_OUT *const out = (FILFILE_CONTROL_OUT*) userBuffer;

					out->Flags		 = (control->Flags & FILFILE_CONTROL_AUTOCONF);
					out->PayloadSize = header.m_payloadSize;

					// copy Payload
					RtlCopyMemory(userBuffer + sizeof(FILFILE_CONTROL_OUT), header.m_payload, header.m_payloadSize);
                                					
					*userBufferSize = bufferSize;

					status = STATUS_SUCCESS;
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					status = STATUS_INVALID_USER_BUFFER;
				}
			}
		}
	}

	// Add to cache?
	if(!alreadyCached)
	{   	
		if(control->PathOffset)
		{
			// Add negative entry if we have really failed and a positive if we have the Payload
			if(NT_ERROR(status) || header.m_payload)
			{
				LPWSTR path = (LPWSTR) ExAllocatePool(PagedPool, control->PathLength);

				if(path)
				{
					RtlCopyMemory(path, (UCHAR*) control + control->PathOffset, control->PathLength);

					// Add to Header cache
					if(NT_SUCCESS(ctrlExtension->HeaderCache.Add(path, control->PathLength, &header)))
					{
						// Take buffer ownership
						header.m_payload	 = 0;
						header.m_payloadSize = 0;
					}
					else
					{
						ExFreePool(path);
					}
				}
			}
		}

		header.Close();
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::SetHeader(FILFILE_CONTROL *control)
{
	ASSERT(control);

	PAGED_CODE();

	// verify input parameters
	if(!control->Value1 || !(control->Flags & FILFILE_CONTROL_HANDLE))
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG fileAccess = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;

	if(control->Flags & FILFILE_CONTROL_AUTOCONF)
	{
		// Delete AutoConfig?
		if( !(control->PayloadSize))
		{
			// Use only lowest set of permissions needed
			fileAccess = DELETE | FILE_READ_ATTRIBUTES;
		}
	}
	else
	{
		// valid Header Payload ?
		if(!control->PayloadOffset || !control->PayloadSize)
		{
			return STATUS_INVALID_PARAMETER;
		}
	}

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);
	
	HANDLE fileHandle = (HANDLE)(ULONG_PTR) control->Value1;
	FILE_OBJECT *file = 0;
		
	// get a pointer to FileObject
	NTSTATUS status = ObReferenceObjectByHandle(fileHandle, fileAccess, *IoFileObjectType, UserMode, (void**) &file, 0);

	if(NT_SUCCESS(status))
	{
		ASSERT(file);

		DEVICE_OBJECT *volume = 0;

		status = GetVolumeDevice(file, &volume);

		if(NT_SUCCESS(status))
		{
			ASSERT(volume);

			FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
			ASSERT(volExtension);

			CFilterCipherManager manager(volExtension);

			// AutoConfig file ?
			if(control->Flags & FILFILE_CONTROL_AUTOCONF)
			{
				// Remove directory Entity, if any
				 volExtension->Volume.RemoveEntity(file, ENTITY_AUTO_CONFIG | ENTITY_ANYWAY);

				CFilterHeader header;
				RtlZeroMemory(&header, sizeof(header));

				header.m_payload	  = (UCHAR*) control + control->PayloadOffset;
				header.m_payloadSize  = control->PayloadSize;
				header.m_deepness	  = (ULONG) control->Value2;

				// write Header, otherwise delete it
				status = manager.AutoConfigWrite(file, &header);
			}
			else
			{
				// Remove file Entity, if any
				volExtension->Volume.RemoveEntity(file, ENTITY_ANYWAY);

				// normal file Header
				FILFILE_TRACK_CONTEXT present;
				RtlZeroMemory(&present, sizeof(present));
    
				// check Header, retrieve only its meta data
				status = manager.RecognizeHeader(file, &present.Header, TRACK_NO_PAYLOAD);

				if(NT_SUCCESS(status))
				{
					ASSERT(control->PayloadOffset);
					ASSERT(control->PayloadSize);

					FILFILE_TRACK_CONTEXT future;
					RtlZeroMemory(&future, sizeof(future));

					// set new Payload
					future.Header.m_payload		= (UCHAR*) control + control->PayloadOffset;
					future.Header.m_payloadSize	= control->PayloadSize;
					future.Header.m_blockSize	= (sizeof(FILFILE_HEADER_BLOCK) + control->PayloadSize + (CFilterHeader::c_align - 1)) & ~(CFilterHeader::c_align - 1);
					
					status = volExtension->Volume.ManageEncryption(file, &present, &future, FILFILE_CONTROL_SET);
				}

				ASSERT(!present.Header.m_payload);
			}

			// Remove current Header from cache
			ctrlExtension->HeaderCache.Remove(volExtension, file);

			ObDereferenceObject(volume);
		}
		else
		{
			DBGPRINT(("SetHeader -ERROR: device not found [0x%08x]\n", status));
		}

		ObDereferenceObject(file);
	}
	else
	{
		DBGPRINT(("SetHeader -ERROR: ObReferenceObjectByHandle() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma  PAGEDCODE
NTSTATUS CFilterControl::AddCredibleProcess(FILFILE_CONTROL* control)
{
	ASSERT(control);

	PAGED_CODE();
	ULONG const pid = (ULONG)(ULONG_PTR) PsGetCurrentProcessId();

	NTSTATUS status = STATUS_SUCCESS;
	if(control)
	{

		if(!control->Value1 || !(control->Flags & FILFILE_CONTROL_HANDLE))
		{
			status=STATUS_INVALID_PARAMETER;
		}

		if(control->Flags & FILFILE_CONTROL_ADD)
		{
			FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
			ctrlExtension->Process.s_ulParentPid=control->Value1;
			ctrlExtension->Process.Add(pid,NULL);
		}
	}
	return status;
}

#pragma  PAGEDCODE
NTSTATUS  CFilterControl::SetControlReadOnly(FILFILE_CONTROL* control)
{
	ASSERT(control);

	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	if(control)
	{

		if(!control->Value1 || !(control->Flags & FILFILE_CONTROL_HANDLE))
		{
			status=STATUS_INVALID_PARAMETER;
		}

		if(control->Flags & FILFILE_CONTROL_ADD)
		{
			FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
			ctrlExtension->bReadOnly=(bool)control->PathLength;
		}
	}
	return status;
}


#pragma PAGEDCODE

NTSTATUS CFilterControl::Connection(FILFILE_CONTROL *control, LUID const* luid)
{
	ASSERT(control || luid);

	PAGED_CODE();

	ULONG const pid = (ULONG)(ULONG_PTR) PsGetCurrentProcessId();

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	NTSTATUS status = STATUS_SUCCESS;

	// Simple connection behavior?
	if(!IsTerminalServices())
	{
		FsRtlEnterFileSystem();

		if(control)
		{
			if(control->Flags & FILFILE_CONTROL_ADD)
			{
				//ctrlExtension->Process.s_ulParentPid=control->DataOffset;
				status = ctrlExtension->Callback.Connect((HANDLE)(ULONG_PTR) control->Value1, 
														 (HANDLE)(ULONG_PTR) control->Value2, 
														 (HANDLE)(ULONG_PTR) control->Value3);

				if(NT_SUCCESS(status))
				{
					// Use our termination detection because MSFT's is not reliable
					ctrlExtension->Process.MarkForTermination(pid, true);
				}
			}
			else
			{
				ctrlExtension->Callback.Disconnect();

				// Cleanup AppList entries
				ctrlExtension->Context.AppList().Remove();

				// Cleanup Blacklist entries
				ctrlExtension->Context.BlackList().Clear();

				ctrlExtension->Process.MarkForTermination(pid, false);
			}
		}
		else
		{
			ctrlExtension->Callback.Disconnect();

			// Cleanup AppList entries
			ctrlExtension->Context.AppList().Remove();

			// Cleanup Blacklist entries
			ctrlExtension->Context.BlackList().Clear();

			ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

			// Remove Entities, owned by Volumes
			for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
			{
				FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
				ASSERT(volExtension);

				volExtension->Volume.RemoveEntities(ENTITY_NEGATIVE | ENTITY_REGULAR | ENTITY_PURGE);
			}

			ExReleaseResourceLite(&ctrlExtension->Lock);
		}

		FsRtlExitFileSystem();

		return status;
	}

	// We operate in TS mode

	LUID luidVal = {0,0};

	// Called from UserMode? 
	if(control)
	{
		// Connecting?
		if(control->Flags & FILFILE_CONTROL_ADD)
		{
			status = ctrlExtension->Callback.Connect((HANDLE)(ULONG_PTR) control->Value1, 
													 (HANDLE)(ULONG_PTR) control->Value2, 
													 (HANDLE)(ULONG_PTR) control->Value3);

			if(NT_SUCCESS(status))
			{
				// Use our termination detection because MSFT's is not reliable
				ctrlExtension->Process.MarkForTermination(pid, true);
			}


			return status;
		}

		// Disconnecting:

		status = CFilterBase::GetLuid(&luidVal);

		if(NT_ERROR(status))
		{
			return status;
		}

		ASSERT(luidVal.HighPart || luidVal.LowPart);

		luid = &luidVal;

		// Unmark our termination detection
		ctrlExtension->Process.MarkForTermination(pid, false);
	}
	else
	{
		// System initated cleanup
	}

	ASSERT(luid);

	status = ctrlExtension->Callback.Disconnect(luid);

	FsRtlEnterFileSystem();

	// Cleanup AppList entries with client's LUID
	ctrlExtension->Context.AppList().Remove(luid);

	// Cleanup Blacklist entries with client's LUID
	ctrlExtension->Context.BlackList().Remove(luid);

	// Remove LUID from Entities
	ExAcquireResourceSharedLite(&ctrlExtension->Lock, true);

	// Add active Entities, owned by Volumes
	for(LIST_ENTRY *entry = ctrlExtension->Volumes.Flink; entry != &ctrlExtension->Volumes; entry = entry->Flink)
	{
		FILFILE_VOLUME_EXTENSION *const volExtension = CONTAINING_RECORD(entry, FILFILE_VOLUME_EXTENSION, Link);          
		ASSERT(volExtension);

		// Since we are in TS mode, remove LUID from each Entity. 
		// If last LUID was removed, tear down Entity itself
		volExtension->Volume.RemoveEntities(ENTITY_NEGATIVE | ENTITY_REGULAR | ENTITY_PURGE, luid);
	}

	ExReleaseResourceLite(&ctrlExtension->Lock);

	// Remove LUID from Headers
	CFilterHeaderCont &headers = ctrlExtension->Context.Headers();

	headers.LockExclusive();
	headers.RemoveLuid(luid);
	headers.Unlock();

	// If last client has disconnected, disable driver
	if(STATUS_ALERTED == status)
	{
		DBGPRINT(("Connection: Last has client disconnected, going passive\n"));

		// Set passive, only file path remains active
		InterlockedAnd(&CFilterEngine::s_state,
					   ~(FILFILE_STATE_DIR | FILFILE_STATE_ACCESS_DENY | FILFILE_STATE_TRIGGER));
	}

	FsRtlExitFileSystem();

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::ManageEncryption(FILFILE_CONTROL *control)
{
	ASSERT(control);

	PAGED_CODE();

	// verify input parameters
	if(!control->Value1)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Filter unused flags
	control->Flags &= FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM | FILFILE_CONTROL_SET | FILFILE_CONTROL_RECOVER;

	if(!control->Flags)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if(control->Flags & FILFILE_CONTROL_ADD)
	{
		// Filter incompatible flags
		control->Flags &= ~FILFILE_CONTROL_RECOVER;
	}

	if(control->Flags & FILFILE_CONTROL_RECOVER)
	{
		DBGPRINT(("ManageEncryption -WARN: Recovery mode specified\n"));
	}

	if(!control->CryptoOffset)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Cipher algo and mode used for encryption
	ULONG cipher = FILFILE_CIPHER_MODE_DEFAULT;

	switch(control->CryptoSize)
	{
		case 128 / 8:
			cipher |= FILFILE_CIPHER_SYM_AES128;
			break;
		case 192 / 8:
			cipher |= FILFILE_CIPHER_SYM_AES192;
			break;
		case 256 / 8:
			cipher |= FILFILE_CIPHER_SYM_AES256;
			break;

		default:
			return STATUS_INVALID_PARAMETER;
	}

	FILFILE_CONTROL_EXTENSION *const ctrlExtension = Extension();
	ASSERT(ctrlExtension);

	if(control->Flags & FILFILE_CONTROL_ADD)
	{
		if(!control->PayloadOffset || !control->PayloadSize)
		{
			return STATUS_INVALID_PARAMETER;
		}

		if(control->Flags & (FILFILE_CONTROL_REM | FILFILE_CONTROL_SET))
		{
			// valid current Session Key ?
			if(!control->DataOffset)
			{
				return STATUS_INVALID_PARAMETER;
			}

			switch(control->DataSize)
			{
				case 128 / 8:
				case 192 / 8:
				case 256 / 8:
					break;

				default:
					return STATUS_INVALID_PARAMETER;
			}
		}
	}

	HANDLE fileHandle = (HANDLE)(ULONG_PTR) control->Value1;
	FILE_OBJECT *file = 0;
		
	// get a pointer to FileObject
	NTSTATUS status = ObReferenceObjectByHandle(fileHandle, 
												FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
												*IoFileObjectType, 
												UserMode, 
												(void**) &file, 
												0);

	if(NT_SUCCESS(status))
	{
		ASSERT(file);

		status = STATUS_NO_SUCH_DEVICE;

		DEVICE_OBJECT *volume = 0;
			
		// get corresponding volume device
		status = GetVolumeDevice(file, &volume);

		if(NT_SUCCESS(status))
		{
			ASSERT(volume);

			FILFILE_VOLUME_EXTENSION *const volExtension = (FILFILE_VOLUME_EXTENSION*) volume->DeviceExtension;
			ASSERT(volExtension);

			// Simple DECRYPT ?
			if(FILFILE_CONTROL_REM == (control->Flags & (FILFILE_CONTROL_REM | FILFILE_CONTROL_ADD)))
			{
				DBGPRINT(("ManageEncryption: Decrypt Flags[0x%x]\n", control->Flags));

				FILFILE_TRACK_CONTEXT track;
				RtlZeroMemory(&track, sizeof(track));

				// ensure file has a valid Header, get meta data only
				status = CFilterCipherManager(volExtension).RecognizeHeader(file, &track.Header, TRACK_NO_PAYLOAD);

				if(NT_SUCCESS(status))
				{
					// init Entity Key
					track.EntityKey.Init(track.Header.m_key.m_cipher,
										 (UCHAR*) control + control->CryptoOffset, 
										 control->CryptoSize);

					// decrypt file data
					status = volExtension->Volume.ManageEncryption(file, &track, 0, control->Flags);
				}
				else
				{
					status = STATUS_UNSUCCESSFUL;

					DBGPRINT(("ManageEncryption -ERROR: no valid Header\n"));
				}

				ASSERT(!track.Header.m_payload);

				track.EntityKey.Clear();
			}
			else if(FILFILE_CONTROL_ADD == control->Flags)
			{
				DBGPRINT(("ManageEncryption: Encrypt Flags[0x%x]\n", control->Flags));

				// Simple ENCRYPT
				status = CFilterCipherManager(volExtension).RecognizeHeader(file);
				
				// Ensure file is currently NOT encrypted, i.e. has an invalid Header
				if((STATUS_UNSUCCESSFUL == status) || (STATUS_MAPPED_FILE_SIZE_ZERO == status))
				{
					FILFILE_TRACK_CONTEXT track;
					RtlZeroMemory(&track, sizeof(track));

					// Reference Header
					track.Header.m_payload		= (UCHAR*) control + control->PayloadOffset;
					track.Header.m_payloadSize	= control->PayloadSize;
					track.Header.m_blockSize	= (sizeof(FILFILE_HEADER_BLOCK) + control->PayloadSize + (CFilterHeader::c_align - 1)) & ~(CFilterHeader::c_align - 1);
                    
					// Init Entity Key
					track.EntityKey.Init(cipher,
										 (UCHAR*) control + control->CryptoOffset, 
										 control->CryptoSize);

					// Add Header and encrypt file data
					status = volExtension->Volume.ManageEncryption(file, 0, &track, control->Flags);

					track.EntityKey.Clear();
				}
				else if(NT_SUCCESS(status))
				{
					status = STATUS_UNSUCCESSFUL;

					DBGPRINT(("ManageEncryption -ERROR: Header already present\n"));
				}
			}
			else
			{
				ASSERT(control->DataSize);
				ASSERT(control->DataOffset);

				DBGPRINT(("ManageEncryption: ReEncrypt Flags[0x%x]\n", control->Flags));
				
				// Change EntityKey. If FILFILE_CONTROL_SET is specified just re-encrypt the FileKey only
				ASSERT((control->Flags & (FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM)) == (FILFILE_CONTROL_ADD | FILFILE_CONTROL_REM));

				FILFILE_TRACK_CONTEXT present;
				RtlZeroMemory(&present, sizeof(present));

				// Ensure file has a valid Header, get meta data only
				status = CFilterCipherManager(volExtension).RecognizeHeader(file, &present.Header, TRACK_NO_PAYLOAD);
				
				if(NT_SUCCESS(status))
				{
					// Init current EntityKey
					present.EntityKey.Init(present.Header.m_key.m_cipher,
										   (UCHAR*) control + control->DataOffset, 
										   control->DataSize);

					FILFILE_TRACK_CONTEXT future;
					RtlZeroMemory(&future, sizeof(future));

					// Reference new Header
					future.Header.m_payload		= (UCHAR*) control + control->PayloadOffset;
					future.Header.m_payloadSize = control->PayloadSize;
					future.Header.m_blockSize	= (sizeof(FILFILE_HEADER_BLOCK) + control->PayloadSize + (CFilterHeader::c_align - 1)) & ~(CFilterHeader::c_align - 1);

					// Init new EntityKey
					future.EntityKey.Init(present.Header.m_key.m_cipher,
										  (UCHAR*) control + control->CryptoOffset, 
										  control->CryptoSize);

					// Add Header and encrypt file data	as specified
					status = volExtension->Volume.ManageEncryption(file, &present, &future, control->Flags);

					future.EntityKey.Clear();
					present.EntityKey.Clear();
				}
				else 
				{
					DBGPRINT(("ManageEncryption -ERROR: no valid Header\n"));
				}

				ASSERT(!present.Header.m_payload);
			}

			// Remove current Header from cache anyway
			ctrlExtension->HeaderCache.Remove(volExtension, file);

			ObDereferenceObject(volume);
		}
		else
		{
			DBGPRINT(("ManageEncryption -ERROR: device not found [0x%08x]\n", status));
		}

		ObDereferenceObject(file);
	}
	else
	{
		DBGPRINT(("ManageEncryption -ERROR: ObReferenceObjectByHandle() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterControl::Blacklist(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize)
{
	ASSERT(control);

	PAGED_CODE();

	// Verify input parameters
	if( !(control->Flags & FILFILE_CONTROL_BLACKLIST))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if(control->Flags & FILFILE_CONTROL_ADD)
	{
		if(control->Value1)
		{
			if(!control->PathOffset || !control->PathLength)
			{
				return STATUS_INVALID_PARAMETER;
			}
		}
	}
	else
	{
		if(!userBuffer || !userBufferSize || !*userBufferSize)
		{
			return STATUS_INVALID_PARAMETER;
		}
	}

	NTSTATUS status = STATUS_SUCCESS;

	CFilterBlackListDisp &blacklist = Extension()->Context.BlackList();

	if(control->Flags & FILFILE_CONTROL_ADD)
	{
		if(control->Value1)
		{
			ASSERT(control->PathOffset);
			ASSERT(control->PathLength);

			// Add entries
			status = blacklist.Set((LPWSTR)((UCHAR*) control + control->PathOffset),	
								   control->PathLength, 
								   control->Flags);
		}
		else
		{
			// Clear all entries
			status = blacklist.Set();
		}
	}
	else
	{
		ASSERT(userBuffer);
		ASSERT(userBufferSize);
		ASSERT(*userBufferSize);

		// Retrieve Blacklist
		RtlZeroMemory(userBuffer, *userBufferSize);

		status = blacklist.Get((LPWSTR) userBuffer, userBufferSize);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
