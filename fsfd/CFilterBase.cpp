////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterBase.cpp: implementation of the CFilterBase class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"
#include "driverMrx.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "IoControl.h"

#include <ntddndis.h>		// for MAC address query

// STATICS ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

ULONG  CFilterBase::s_timeoutKeyRequest    = FILFILE_KEY_REQUEST_TIMEOUT;
ULONG  CFilterBase::s_timeoutRandomRequest = FILFILE_RANDOM_REQUEST_TIMEOUT;

CFilterBase::f_mupProvider CFilterBase::s_mupGetProviderInfo = 0;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void CompileTimeChecks()
{
	// No function, just a conmon place for compile time checks

	C_ASSERT(sizeof(LUID) == sizeof(ULONGLONG));

	C_ASSERT(FILFILE_HEADER_META_SIZE == sizeof(FILFILE_HEADER_BLOCK));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

bool CFilterBase::IsCached(FILE_OBJECT *file)
{
	if(file)
	{
		if(file->SectionObjectPointer)
		{
			if(file->SectionObjectPointer->DataSectionObject || file->SectionObjectPointer->ImageSectionObject)
			{
				return true;
			}
		}
	}
 
	return false; 
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::GetLuid(LUID *luid, IO_SECURITY_CONTEXT *ioSecurity)
{ 
	ASSERT(luid);

	PAGED_CODE();

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if(ioSecurity)
	{
		ASSERT(ioSecurity->AccessState);

		if(ioSecurity->AccessState->SubjectSecurityContext.ClientToken)
		{
			status = SeQueryAuthenticationIdToken(ioSecurity->AccessState->SubjectSecurityContext.ClientToken,luid);
		}
		else
		{
			status = SeQueryAuthenticationIdToken(ioSecurity->AccessState->SubjectSecurityContext.PrimaryToken,luid);
		}

		if(NT_ERROR(status))
		{
			DBGPRINT(("GetLuid(I): from IO_SECURITY_CONTEXT failed [0x%x]\n", status));
		}
	}
	else
	{
		SECURITY_SUBJECT_CONTEXT secSub;

		SeCaptureSubjectContext(&secSub);
		SeLockSubjectContext(&secSub);

		// Use W2k compatible way to get primary token
		PACCESS_TOKEN token = SeQuerySubjectContextToken(&secSub);

		if(token)
		{
			status = SeQueryAuthenticationIdToken(token, luid);
		}

		SeUnlockSubjectContext(&secSub);

		/*
		// Use on WXP and above
		PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());

		if(token)
		{
			status = SeQueryAuthenticationIdToken(token, authId);

			PsDereferencePrimaryToken(token);
		}
		*/

		if(NT_ERROR(status))
		{
			DBGPRINT(("GetLuid(II): from SUBJECT_CONTEXT failed [0x%x]\n", status));
		}
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

DEVICE_OBJECT* CFilterBase::AttachSafe(DEVICE_OBJECT* device, DEVICE_OBJECT* target)
{
	ASSERT(device);

	PAGED_CODE();

	// are we already attached ?
	while(target)
	{
		FILFILE_VOLUME_EXTENSION* extension = (FILFILE_VOLUME_EXTENSION*) target->DeviceExtension;

		if(extension && (FILFILE_FILTER_VOLUME == extension->Common.Type) && (sizeof(FILFILE_VOLUME_EXTENSION) == extension->Common.Size))
		{
			break;
		}

		target = target->AttachedDevice;
	};

	if(target)
	{
		DBGPRINT(("AttachSafe: already attached\n"));

		return 0;
	}

	return IoAttachDeviceToDeviceStack(device, target);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

DEVICE_OBJECT* CFilterBase::GetDeviceObject(FILE_OBJECT *file)
{
	ASSERT(file);
	
	PAGED_CODE();

	if(file->Vpb && file->Vpb->DeviceObject)
	{
		return file->Vpb->DeviceObject;
	}
	else if( !(file->Flags & FO_DIRECT_DEVICE_OPEN) && file->DeviceObject->Vpb && file->DeviceObject->Vpb->DeviceObject)
	{
		return file->DeviceObject->Vpb->DeviceObject;
	}

	return file->DeviceObject;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterBase::GetDeviceType(UNICODE_STRING *deviceName)
{
	ASSERT(deviceName);
	
	PAGED_CODE();

	ASSERT(deviceName->Length);
	ASSERT(deviceName->MaximumLength);
	ASSERT(deviceName->Buffer);

	LPCWSTR deviceStart   = deviceName->Buffer + 8;
	ULONG const deviceLen = (deviceName->Length / sizeof(WCHAR)) - 8;

	if(deviceLen >= 3)
	{
		if(!_wcsnicmp(deviceStart, L"Mup", 3))
		{
			return FILFILE_DEVICE_REDIRECTOR_CIFS;
		}
		  
		if(CFilterControl::s_cdrom)
		{
			if(deviceLen >= 5)
			{
				if(!_wcsnicmp(deviceStart, L"CdRom", 5))
				{
					return FILFILE_DEVICE_VOLUME;
				}
			}
		}

		if(deviceLen >= 8)
		{
			if(!_wcsnicmp(deviceStart, L"Harddisk", 8))
			{
				return FILFILE_DEVICE_VOLUME;
			}

			if(deviceLen >= 16)
			{
				if(!_wcsnicmp(deviceStart, L"LanmanRedirector", 16))
				{
					return FILFILE_DEVICE_REDIRECTOR_CIFS;
				}

			#ifdef FILFILE_SUPPORT_WEBDAV
				if(!_wcsnicmp(deviceStart, L"WebDavRedirector", 16))
				{
					 return FILFILE_DEVICE_REDIRECTOR_WEBDAV;
				}
			#else
				#pragma message("*** WebDAV support is disabled ***")
			#endif
	
				if(deviceLen >= 17)
				{
					if(!_wcsnicmp(deviceStart, L"PGPdisks", 8))				
					{
						return FILFILE_DEVICE_VOLUME;
					}

					if(!_wcsnicmp(deviceStart, L"NetWareRedirector", 17))				
					{
						return FILFILE_DEVICE_REDIRECTOR_NETWARE;
					}
				}
			}
		}
	}

	return FILFILE_DEVICE_NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterBase::GetNetworkProvider(FILFILE_VOLUME_EXTENSION *extension, FILE_OBJECT *file)
{
	ASSERT(extension);
	ASSERT(file);

	PAGED_CODE();

	ULONG type = extension->LowerType & FILFILE_DEVICE_REDIRECTOR;
	ASSERT(type);
	
	if(CFilterControl::IsWindowsVistaOrLater())
	{
		// Not yet initialized?
		if(!s_mupGetProviderInfo)
		{
			UNICODE_STRING name = RTL_CONSTANT_STRING(L"FsRtlMupGetProviderInfoFromFileObject");

			// Link lazily because function is not available on earlier versions
			s_mupGetProviderInfo = (f_mupProvider) MmGetSystemRoutineAddress(&name);
		}

		if(s_mupGetProviderInfo)
		{
			UCHAR buffer[sizeof(FSRTL_MUP_PROVIDER_INFO_LEVEL_2) + (32 * sizeof(WCHAR))] = {0};
			ULONG bufferSize = sizeof(buffer);

			NTSTATUS status = s_mupGetProviderInfo(file, 2, buffer, &bufferSize);

			if(NT_SUCCESS(status))
			{
				FSRTL_MUP_PROVIDER_INFO_LEVEL_2 *const level2 = (FSRTL_MUP_PROVIDER_INFO_LEVEL_2*) buffer;

				type = GetDeviceType(&level2->ProviderName);
			}
		}
	}

	return type;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

ULONG CFilterBase::Hash(LPCWSTR path, ULONG pathLength)
{
	PAGED_CODE();

	ULONG hash = 0;

	if(path && pathLength)
	{
		pathLength /= sizeof(WCHAR);
		
		for(ULONG index = 0; index < pathLength; ++index) 
		{
			// transform char to upcase
			WCHAR upcase = path[index];

			if(upcase >= 'a')
			{
				if(upcase <= 'z')
				{
					upcase -= ('a' - 'A');
				}
				else
				{
					upcase = RtlUpcaseUnicodeChar(upcase);
				}
			}

			hash = (hash << 6) - hash + upcase;
		}
	}
	else
	{
		ASSERT(false);
	}

	return hash;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::GetSystemPath(UNICODE_STRING *systemPath)
{
	ASSERT(systemPath);

	PAGED_CODE();

	UNICODE_STRING partition = {0,0,0};
	UNICODE_STRING volume    = {0,0,0};

	UNICODE_STRING systemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot");

	// Resolve 
	NTSTATUS status = CFilterBase::ResolveSymbolicLink(&systemRoot, &partition);

	if(NT_SUCCESS(status))
	{
		ASSERT(partition.Buffer);

		USHORT index = partition.Length / sizeof(WCHAR);
		ASSERT(index);

		// Strip last component
		while(--index)
		{
			if(partition.Buffer[index] == L'\\')
			{
				break;
			}
		}

		USHORT const saved = partition.Length;

		partition.Length = index * sizeof(WCHAR);

		// Resolve partition to corresponding volume
		status = CFilterBase::ResolveSymbolicLink(&partition, &volume);

		if(NT_SUCCESS(status))
		{
			status = STATUS_INSUFFICIENT_RESOURCES;

			USHORT const pathSize = volume.Length + (saved - partition.Length) + sizeof(WCHAR) + sizeof(WCHAR);
			LPWSTR path = (LPWSTR) ExAllocatePool(PagedPool, pathSize);

			if(path)
			{
				RtlZeroMemory(path, pathSize);

				// Build full path
				RtlCopyMemory(path, volume.Buffer, volume.Length);
				RtlCopyMemory((UCHAR*) path + volume.Length, partition.Buffer + index, saved - partition.Length);
				// Add trailing backslash
				path[(pathSize / sizeof(WCHAR)) - 2] = L'\\';

				systemPath->MaximumLength = pathSize;
				systemPath->Length		  = pathSize - sizeof(WCHAR);
				systemPath->Buffer		  = path;

				DBGPRINT(("GetSystemPath: SystemPath [%wZ]\n", systemPath));
				
				status = STATUS_SUCCESS;
			}

			ExFreePool(volume.Buffer);
		}

		ExFreePool(partition.Buffer);
	}

	return status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::ResolveSymbolicLink(UNICODE_STRING *linkSource, UNICODE_STRING *linkTarget)
{
	ASSERT(linkSource);
	ASSERT(linkTarget);

	PAGED_CODE();

	ASSERT(linkSource->Length);
	ASSERT(linkSource->MaximumLength);
	ASSERT(linkSource->Buffer);
	
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, linkSource, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

	HANDLE link		= 0;
	NTSTATUS status = ZwOpenSymbolicLinkObject(&link, GENERIC_READ, &oa);

	if(NT_SUCCESS(status))
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		ULONG const targetSize = 2048;

		UNICODE_STRING target;
		target.Length		  = 0;
		target.MaximumLength  = targetSize;
		target.Buffer		  = (WCHAR*) ExAllocatePool(PagedPool, targetSize);

		if(target.Buffer)
		{
			RtlZeroMemory(target.Buffer, targetSize);

			status = ZwQuerySymbolicLinkObject(link, &target, 0);

			if(NT_SUCCESS(status))
			{
				*linkTarget = target;
			}
			else
			{
				ExFreePool(target.Buffer);
			}
		}

		ZwClose(link);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma PAGEDCODE

NTSTATUS CFilterBase::ParseDeviceName(LPCWSTR path, ULONG pathLength, UNICODE_STRING *deviceName, ULONG *deviceType)
{
	ASSERT(path);
	ASSERT(pathLength);

	PAGED_CODE();

	// 1. [\Device\HarddiskVolume1]
	// 2. [\Device\Harddisk2\DP(1)0-0+8]; USBSTOR
	// 3. [\Device\LanmanRedirector\]
	// 4. [\Device\HarddiskDmVolumes\XXXXXXDg0\Volume1]; Dynamic Disk
	// 5. [\Device\HarddiskDmVolumes\PhysicalDmVolumes\BlockVolume1]; Physical Dynamic Disk

	ULONG const len	= pathLength / sizeof(WCHAR);
	ULONG index		= len;

	if((len >= 22) && !_wcsnicmp(path, L"\\Device\\HarddiskVolume", 22))
	{
		index = 23;
	}
	else if((len >= 26) && !_wcsnicmp(path, L"\\Device\\HarddiskDmVolumes\\", 26))
	{
		index = 26;

		while(index < len)
		{
			if(path[index] == L'\\')
			{
				break;
			}

			index++;
		}

		index++;
	}
	else if((len >= 16) && !_wcsnicmp(path, L"\\Device\\Harddisk", 16))
	{
		index = 17;

		while(index < len)
		{
			if(path[index] == L'\\')
			{
				break;
			}

			index++;
		}

		index++;
	}
	else if((len >= 17) && !_wcsnicmp(path, L"\\Device\\PGPdisks\\", 17))
	{
		index = 17;

		while(index < len)
		{
			if(path[index] == L'\\')
			{
				break;
			}

			index++;
		}
	}
	else if((len >= 8) && !_wcsnicmp(path, L"\\Device\\", 8))
	{
		index = 8;
	}

	// separate device component
	while(index < len)
	{
		if(path[index] == L'\\')
		{
			break;
		}

		index++;
	}

	// found ?
	if(index < len)
	{
		UNICODE_STRING name = {(USHORT) (index * sizeof(WCHAR)), 
							   (USHORT) (index * sizeof(WCHAR)),
							   (PWSTR) path};
		if(deviceName)
		{
			*deviceName = name;
		}

		if(deviceType)
		{
			*deviceType = GetDeviceType(&name);

			// Supported device type?
			if(FILFILE_DEVICE_NULL == *deviceType)
			{
				return STATUS_NOT_SUPPORTED;
			}
		}

		return STATUS_SUCCESS;
	}

	return STATUS_INVALID_PARAMETER;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

ULONG CFilterBase::Crc32(UCHAR const* buffer, ULONG bufferSize)
{
	// this table comes from Dr. Dobbs Journal, May 1992

	static ULONG const table[256] = 
	{
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
		0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
		0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
		0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
		0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
		0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
		0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
		0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
		0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
		0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
		0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
		0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
		0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
		0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
		0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
		0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
		0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
		0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
		0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
		0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
		0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
		0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
		0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
		0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
		0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
		0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
		0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
		0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
		0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
		0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
		0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
		0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
		0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
		0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
		0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
		0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
		0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
		0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
		0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
		0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
		0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D 
	};

	ULONG crc = 0;

	if(buffer && bufferSize)
	{
		/*
		while(bufferSize--)
		{
			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
		}
		*/

		// instead use 'Duff's Device'
		ULONG count = (bufferSize + 7) / 8;
			
		switch(bufferSize % 8)
		{
			case 0:	do	{	crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 7:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 6:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 5:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 4:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 3:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 2:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
			case 1:			crc = (crc >> 8) ^ table[(unsigned char)(crc ^ *buffer++)];
					} 
					while(--count);
		}
	}

	return crc;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::SimpleSend(DEVICE_OBJECT *device, IRP *irp)
{
	ASSERT(device);
	ASSERT(irp);

	KEVENT event;
	KeInitializeEvent(&event, NotificationEvent, false);

	IoSetCompletionRoutine(irp, SimpleCompletion, &event, true, true, true);

	NTSTATUS status = IoCallDriver(device, irp);

	if(STATUS_PENDING == status)
	{
		KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);	

		status = irp->IoStatus.Status;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::SimpleCompletion(DEVICE_OBJECT *device, IRP *irp, void* context)
{
	ASSERT(irp);

	UNREFERENCED_PARAMETER(device);

	if(irp->PendingReturned)
	{
		ASSERT(context);
		KeSetEvent((KEVENT*) context, 0, false);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::SimpleCompletionFree(DEVICE_OBJECT *device, IRP *irp, void* context)
{
	UNREFERENCED_PARAMETER(device);
	ASSERT(irp);

	*irp->UserIosb = irp->IoStatus;

	if(irp->PendingReturned)
	{
		ASSERT(context);
		KeSetEvent((KEVENT*) context, 0, false);
	}

	IoFreeIrp(irp);	

	return STATUS_MORE_PROCESSING_REQUIRED;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::SendCleanupClose(DEVICE_OBJECT *device, FILE_OBJECT *file, bool cleanupOnly)
{
	ASSERT(device);
	ASSERT(file);

	PAGED_CODE();

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	IRP *const irp = IoAllocateIrp(device->StackSize, false);

	if(irp)
	{
		IO_STATUS_BLOCK ioStatus = {0,0};

		irp->UserIosb			 = &ioStatus;
		irp->RequestorMode		 = KernelMode;
		irp->Tail.Overlay.Thread = PsGetCurrentThread();
		irp->Flags				 = IRP_SYNCHRONOUS_API | IRP_CLOSE_OPERATION;

		// manually send CLEANUP
		IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
		ASSERT(stack);

		stack->MajorFunction = IRP_MJ_CLEANUP;
		stack->MinorFunction = IRP_MN_NORMAL;
		stack->DeviceObject	 = device;
		stack->FileObject	 = file;

		KEVENT event;
		KeInitializeEvent(&event, NotificationEvent, false);

		IoSetCompletionRoutine(irp, SimpleCompletion, &event, true, true, true);

		status = IoCallDriver(device, irp);

		if(STATUS_PENDING == status)
		{
			KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);

			status = ioStatus.Status;
		}

		if(NT_ERROR(status))
		{
			DBGPRINT(("SendCleanupClose -ERROR: IRP_MJ_CLEANUP failed [0x%08x]\n", status));
		}

		if(!cleanupOnly)
		{
			IoReuseIrp(irp, STATUS_SUCCESS);

			ioStatus.Status		 = 0;
			ioStatus.Information = 0;

			irp->UserIosb			 = &ioStatus;
			irp->RequestorMode		 = KernelMode;
			irp->Tail.Overlay.Thread = PsGetCurrentThread();
			irp->Flags				 = IRP_SYNCHRONOUS_API | IRP_CLOSE_OPERATION;

			stack = IoGetNextIrpStackLocation(irp);
			ASSERT(stack);
			
			stack->MajorFunction = IRP_MJ_CLOSE;
			stack->MinorFunction = IRP_MN_NORMAL;
			stack->DeviceObject	 = device;
			stack->FileObject	 = file;

			KeClearEvent(&event);

			IoSetCompletionRoutine(irp, SimpleCompletion, &event, true, true, true);

			// manually send CLOSE
			status = IoCallDriver(device, irp);

			if(STATUS_PENDING == status)
			{
				KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);

				status = ioStatus.Status;
			}

			if(NT_ERROR(status))
			{
				DBGPRINT(("SendCleanupClose -ERROR: IRP_MJ_CLOSE failed [0x%08x]\n", status));
			}
		}

		IoFreeIrp(irp);
	}
	else
	{
		DBGPRINT(("SendCleanupClose -ERROR: IoAllocateIrp() failed\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::SimpleRename(DEVICE_OBJECT *device, FILE_OBJECT *file, LPCWSTR fileName, ULONG fileNameLength, BOOLEAN replace)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(fileName);
	ASSERT(fileNameLength);

	PAGED_CODE();

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	ULONG const renameInfoSize				  = sizeof(FILE_RENAME_INFORMATION) + fileNameLength + sizeof(WCHAR);
	FILE_RENAME_INFORMATION *const renameInfo = (FILE_RENAME_INFORMATION*) ExAllocatePool(PagedPool, renameInfoSize);

	if(renameInfo)
	{
		RtlZeroMemory(renameInfo, renameInfoSize);

		renameInfo->ReplaceIfExists = false;
		renameInfo->RootDirectory	= 0;
		renameInfo->FileNameLength  = fileNameLength;

		RtlCopyMemory(renameInfo->FileName, fileName, fileNameLength);

		IRP *const irp = IoAllocateIrp(device->StackSize, false);

		if(irp)
		{
			IO_STATUS_BLOCK ioStatus = {0,0};

			irp->UserIosb			  = &ioStatus;
			irp->RequestorMode		  = KernelMode;
			irp->Tail.Overlay.Thread  = PsGetCurrentThread();
			irp->Flags				 |= IRP_SYNCHRONOUS_API;

			irp->AssociatedIrp.SystemBuffer	= renameInfo;
			
			IO_STACK_LOCATION *const stack = IoGetNextIrpStackLocation(irp);
			ASSERT(stack);

			stack->MajorFunction = IRP_MJ_SET_INFORMATION;
			stack->MinorFunction = IRP_MN_NORMAL;
			stack->DeviceObject	 = device;
			stack->FileObject	 = file;

			stack->Parameters.SetFile.FileObject			= 0;
			stack->Parameters.SetFile.Length				= renameInfoSize;
			stack->Parameters.SetFile.FileInformationClass	= FileRenameInformation;
			stack->Parameters.SetFile.ReplaceIfExists		= replace;

			status = SimpleSend(device, irp);

			if(NT_ERROR(status))
			{
				DBGPRINT(("SimpleRename -ERROR: IRP_MJ_SET_INFORMATION [0x%08x]\n", status));
			}

			IoFreeIrp(irp);
		}
		else
		{
			DBGPRINT(("SimpleRename -ERROR: IoAllocateIrp() failed\n"));
		}

		ExFreePool(renameInfo);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::GetLongName(FILFILE_VOLUME_EXTENSION *extension, IRP *createIrp, UNICODE_STRING *path, void *buffer, ULONG bufferSize, USHORT shortNameStart)
{
	ASSERT(extension);
	ASSERT(path);
	ASSERT(buffer);
	ASSERT(bufferSize);

	ASSERT(shortNameStart);

	PAGED_CODE();

	if(!createIrp)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// we are within the create path 
	IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(createIrp);
	ASSERT(stack);

	ASSERT(stack->MajorFunction == IRP_MJ_CREATE);
	ASSERT(stack->FileObject);

	FILE_OBJECT *fileStream = 0;

	__try
	{
		if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
		{
			// On redirectors create intermediate FO directly on Lower - otherwise MUP will barf (BSOD) on close
			fileStream = IoCreateStreamFileObjectLite(0, extension->Lower);
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

	//DBGPRINT(("GetLongName: FO[0x%p] Flags[0x%08x]\n", fileStream, fileStream->Flags));

	fileStream->Flags |= FO_SYNCHRONOUS_IO;

	fileStream->RelatedFileObject = 0;

	// Allocate dedicated buffer for the open request because drivers
	// underneath us are re-allocating it sometimes. Seen on Vista with DFS
	fileStream->FileName.Length		   = (USHORT) (shortNameStart * sizeof(WCHAR));
	fileStream->FileName.MaximumLength = fileStream->FileName.Length + sizeof(WCHAR);
	fileStream->FileName.Buffer		   = (LPWSTR) ExAllocatePool(PagedPool, fileStream->FileName.MaximumLength);

	if(!fileStream->FileName.Buffer)
	{
		ObDereferenceObject(fileStream);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(fileStream->FileName.Buffer, fileStream->FileName.MaximumLength);
	RtlCopyMemory(fileStream->FileName.Buffer, path->Buffer, fileStream->FileName.Length);

	// save access mask
	IO_STATUS_BLOCK const ioStatus		= createIrp->IoStatus;
	KPROCESSOR_MODE const requestorMode = createIrp->RequestorMode;
	ACCESS_MASK const access			= stack->Parameters.Create.SecurityContext->DesiredAccess;
	
	createIrp->RequestorMode = KernelMode;

	IoCopyCurrentIrpStackLocationToNext(createIrp);

	IO_STACK_LOCATION *nextStack = IoGetNextIrpStackLocation(createIrp);
	ASSERT(nextStack);

	nextStack->Parameters.Create.SecurityContext->DesiredAccess	= FILE_LIST_DIRECTORY;
	nextStack->Parameters.Create.Options						= FILE_DIRECTORY_FILE | (FILE_OPEN << 24);
	nextStack->Parameters.Create.FileAttributes					= 0;
	nextStack->Parameters.Create.ShareAccess					= FILE_SHARE_VALID_FLAGS;

	nextStack->Flags	  = 0;
	nextStack->FileObject = fileStream;

	NTSTATUS status = SimpleSend(extension->Lower, createIrp);

	if(STATUS_SUCCESS == status)
	{
		UNICODE_STRING fileName;

		fileName.Length			= (USHORT) (path->Length - (shortNameStart * sizeof(WCHAR)));
		fileName.MaximumLength  = fileName.Length;
		fileName.Buffer			= path->Buffer + shortNameStart;
			
		// retrieve long name from newly opened directory
		status = QueryDirectoryInfo(extension->Lower, fileStream, FileNamesInformation, buffer, bufferSize, &fileName);

		if(NT_ERROR(status))
		{
			DBGPRINT(("GetLongName -ERROR: QueryDirectoryInfo() failed [0x%08x]\n", status));
		}

		CFilterBase::SendCleanupClose(extension->Lower, fileStream, true);
	}
	else
	{
		DBGPRINT(("GetLongName -ERROR: open DIRECTORY failed [0x%08x]\n", status));
	}

	if(stack->Parameters.Create.SecurityContext)
	{
		stack->Parameters.Create.SecurityContext->DesiredAccess = access;
	}

	// restore next stack  loc
	IoCopyCurrentIrpStackLocationToNext(createIrp);
	IoSetCompletionRoutine(createIrp, 0,0, false, false, false);

	createIrp->RequestorMode	= requestorMode;
	createIrp->PendingReturned	= false;
	createIrp->IoStatus			= ioStatus;
	
	if(!fileStream->Vpb)
	{
		ASSERT(extension->Real);

		if(extension->Real->Vpb)
		{
			// see CFilterVolume::AutoConfigCheck() for further information
			DBGPRINT(("GetLongName: injected VPB\n"));

			fileStream->Vpb = extension->Real->Vpb;
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

ULONG CFilterBase::GetAttributes(DEVICE_OBJECT *device, FILE_OBJECT *file)
{
	ASSERT(device);
	ASSERT(file);

	PAGED_CODE();

	FILE_BASIC_INFORMATION basicInfo;
	RtlZeroMemory(&basicInfo, sizeof(basicInfo));

	NTSTATUS status = QueryFileInfo(device, file, FileBasicInformation, &basicInfo, sizeof(basicInfo));

	if(NT_SUCCESS(status))
	{
		return basicInfo.FileAttributes;
	}

	DBGPRINT(("GetAttributes -ERROR: QueryFileInfo() FO[0x%p] failed [0x%08x]\n", file, status));

	return ~0u;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryDirectoryInfo(DEVICE_OBJECT*			device, 
										 FILE_OBJECT*			file, 
										 FILE_INFORMATION_CLASS	fileInfo, 
										 void*					buffer, 
										 ULONG					bufferSize,
										 UNICODE_STRING*		fileName,
										 ULONG					fileIndex)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(buffer);
	ASSERT(bufferSize);

	PAGED_CODE();

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	IRP* const irp = IoAllocateIrp(device->StackSize, false);

	if(irp)
	{
		IO_STATUS_BLOCK ioStatus = {0,0};

		irp->UserBuffer				= buffer;
		irp->UserIosb				= &ioStatus;
		irp->RequestorMode			= KernelMode;
		irp->Tail.Overlay.Thread	= PsGetCurrentThread();
		irp->Flags				   |= IRP_SYNCHRONOUS_API;
		
		IO_STACK_LOCATION *const stack = IoGetNextIrpStackLocation(irp);
		ASSERT(stack);

		stack->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
		stack->MinorFunction = IRP_MN_QUERY_DIRECTORY;
		stack->DeviceObject	 = device;
		stack->FileObject	 = file;

		stack->Parameters.QueryDirectory.Length				  = bufferSize;
		stack->Parameters.QueryDirectory.FileName			  = fileName;
		stack->Parameters.QueryDirectory.FileInformationClass = fileInfo;
		stack->Parameters.QueryDirectory.FileIndex			  = fileIndex;

		status = SimpleSend(device, irp);
		
		if(NT_ERROR(status))
		{
			DBGPRINT(("QueryFileInfo -ERROR: IRP_MJ_DIRECTORY_CONTROL failed [0x%08x]\n", status));
		}

		IoFreeIrp(irp);
	}
	else
	{
		DBGPRINT(("QueryFileInfo -ERROR: IoAllocateIrp() failed\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::SetFileInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_INFORMATION_CLASS fileInfo, void *buffer, ULONG bufferSize)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(buffer);
	ASSERT(bufferSize);

	PAGED_CODE();

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	IRP* const irp = IoAllocateIrp(device->StackSize, false);

	if(irp)
	{
		IO_STATUS_BLOCK ioStatus = {0,0};

		irp->UserIosb				= &ioStatus;
		irp->UserEvent				= 0;
		irp->RequestorMode			= KernelMode;
		irp->Tail.Overlay.Thread	= PsGetCurrentThread();
		irp->Flags				   |= IRP_SYNCHRONOUS_API;

		irp->AssociatedIrp.SystemBuffer	= buffer;
		
		IO_STACK_LOCATION *const stack = IoGetNextIrpStackLocation(irp);
		ASSERT(stack);

		stack->MajorFunction = IRP_MJ_SET_INFORMATION;
		stack->MinorFunction = IRP_MN_NORMAL;
		stack->DeviceObject	 = device;
		stack->FileObject	 = file;

		stack->Parameters.SetFile.FileObject			= file;
		stack->Parameters.SetFile.Length				= bufferSize;
		stack->Parameters.SetFile.FileInformationClass	= fileInfo;
		stack->Parameters.SetFile.AdvanceOnly			= false;

		status = SimpleSend(device, irp);

		if(NT_ERROR(status))
		{
			DBGPRINT(("SetFileInfo -ERROR: IRP_MJ_SET_INFORMATION [0x%08x]\n", status));
		}

		IoFreeIrp(irp);
	}
	else
	{
		DBGPRINT(("SetFileInfo -ERROR: IoAllocateIrp() failed\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::ZeroData(DEVICE_OBJECT *device, FILE_OBJECT *file, LARGE_INTEGER *start, LARGE_INTEGER *end)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(start);
	ASSERT(end);

	DBGPRINT(("ZeroData: Zero start[0x%I64x] end[0x%I64x]\n", *start, *end));

	ASSERT(end->QuadPart > start->QuadPart);
	LONGLONG size = end->QuadPart - start->QuadPart;
	ASSERT(size);

	ULONG const bufSize = (size > MM_MAXIMUM_DISK_IO_SIZE) ? MM_MAXIMUM_DISK_IO_SIZE : (ULONG) size;

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	
	FILFILE_READ_WRITE readWrite;
	RtlZeroMemory(&readWrite, sizeof(readWrite));

	readWrite.Buffer = (UCHAR*) ExAllocatePool(NonPagedPool, bufSize);

	if(readWrite.Buffer)
	{
		RtlZeroMemory(readWrite.Buffer, bufSize);

		readWrite.Offset.QuadPart = start->QuadPart;
		readWrite.Flags			  = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
		readWrite.Major			  = IRP_MJ_WRITE;
		readWrite.Wait			  = true;
		readWrite.Mdl			  = IoAllocateMdl(readWrite.Buffer, bufSize, false, false, 0);

		if(readWrite.Mdl)
		{
			MmBuildMdlForNonPagedPool(readWrite.Mdl);

			do
			{
				readWrite.Length = (ULONG) size;

				if(!readWrite.Length || (readWrite.Length > MM_MAXIMUM_DISK_IO_SIZE))
				{
					readWrite.Length = MM_MAXIMUM_DISK_IO_SIZE;
				}

				ASSERT(readWrite.Offset.QuadPart >= start->QuadPart);
				ASSERT(readWrite.Offset.QuadPart < end->QuadPart);
				ASSERT(readWrite.Offset.QuadPart + readWrite.Length <= end->QuadPart);

				// Not sector Aligned?
				if(readWrite.Offset.LowPart & (c_sectorSize - 1))
				{
					status = WriteNonAligned(device, file, &readWrite);
				}
				else
				{
					status = ReadWrite(device, file, &readWrite);
				}

				if(NT_ERROR(status))
				{
					DBGPRINT(("ZeroData -ERROR: ReadWrite() failed [0x%08x]\n", status));
					break;
				}

				readWrite.Offset.QuadPart += readWrite.Length;

				ASSERT(size >= readWrite.Length);
				size -= readWrite.Length;
			}
			while(size);

			IoFreeMdl(readWrite.Mdl);
		}

		ExFreePool(readWrite.Buffer);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::ReadWrite(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* readWrite)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(readWrite);

	ASSERT(readWrite->Major == IRP_MJ_READ || (readWrite->Major == IRP_MJ_WRITE));
	ASSERT(readWrite->Buffer);
	ASSERT(readWrite->Length);

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	IRP *const irp = IoAllocateIrp(device->StackSize, false);

	if(irp)
	{
		IO_STATUS_BLOCK ioStatus = {0,0};

		irp->UserIosb			 = &ioStatus;
		irp->UserBuffer			 = readWrite->Buffer;//返回缓冲区 
		irp->MdlAddress			 = readWrite->Mdl;//MDL地址
		irp->Flags				 = readWrite->Flags;
		irp->RequestorMode		 = KernelMode;//内核模式请求
		irp->Tail.Overlay.Thread = PsGetCurrentThread();
						
		IO_STACK_LOCATION *const stack = IoGetNextIrpStackLocation(irp);//获得Next stack
		ASSERT(stack);

		stack->MajorFunction = readWrite->Major;
		stack->MinorFunction = IRP_MN_NORMAL;
		stack->DeviceObject	 = device;
		stack->FileObject	 = file;

		if(readWrite->Major == IRP_MJ_READ)//如果为读
		{
			stack->Parameters.Read.Length	   = readWrite->Length;
			stack->Parameters.Read.Key		   = 0;
			stack->Parameters.Read.ByteOffset  = readWrite->Offset;
		}
		else//如果为写
		{
			stack->Parameters.Write.Length	   = readWrite->Length;
			stack->Parameters.Write.Key		   = 0;
			stack->Parameters.Write.ByteOffset = readWrite->Offset;
		}

		KEVENT event;
		KeInitializeEvent(&event, NotificationEvent, false);
		
		IoSetCompletionRoutine(irp, SimpleCompletionFree, &event, true, true, true);
		
		status = IoCallDriver(device, irp);

		if(STATUS_PENDING == status)
		{	
			if(readWrite->Wait)
			{
				KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);	

				status = ioStatus.Status;
			}
			else
			{
				DBGPRINT(("ReadWrite: STATUS_PENDING, don't wait\n"));
			}
		}

		if(NT_ERROR(status))
		{
			DBGPRINT(("ReadWrite -ERROR: IoCallDriver() failed [0x%08x]\n", status));
		}
	}
	else
	{
		DBGPRINT(("ReadWrite -ERROR: IoAllocateIrp() failed\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::ReadNonAligned(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* target)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(target);

	ASSERT(target->Buffer);
	ASSERT(target->Length);

	LARGE_INTEGER targetOffset = target->Offset;
	LONG		  targetSize   = target->Length;

	DBGPRINT(("ReadNonAligned: FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, targetSize, targetOffset));

	// Compute how much to read additionally around given request. That is, before and/or after.
	ULONG const deltaOffset = targetOffset.LowPart & (c_sectorSize - 1);

	if(deltaOffset)
	{
		ASSERT(targetOffset.QuadPart >= deltaOffset);
		targetOffset.QuadPart -= deltaOffset;
		targetSize			  += deltaOffset;
	}

	ULONG const deltaSize = (-targetSize) & (c_sectorSize - 1);

	if(deltaSize)
	{
		targetSize += deltaSize;
	}

	ASSERT(deltaOffset || deltaSize);
	ASSERT(0 == (targetOffset.LowPart % c_sectorSize));
	ASSERT(0 == (targetSize % c_sectorSize));

	UCHAR* buffer = (UCHAR*) ExAllocatePool(NonPagedPool, targetSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory(buffer, targetSize);

	FILFILE_READ_WRITE readWrite;
	RtlZeroMemory(&readWrite, sizeof(readWrite));

	readWrite.Mdl = IoAllocateMdl(buffer, targetSize, false, false, 0);

	if(!readWrite.Mdl)
	{
		ExFreePool(buffer);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	MmBuildMdlForNonPagedPool(readWrite.Mdl);

	readWrite.Buffer = buffer;
	readWrite.Offset = targetOffset;	
	readWrite.Length = targetSize;
	readWrite.Flags  = target->Flags;
	readWrite.Major  = IRP_MJ_READ;
	readWrite.Wait   = true;

	DBGPRINT(("ReadNonAligned: FO[0x%p] Read [0x%x] at [0x%I64x]\n", file, readWrite.Length, readWrite.Offset));

	NTSTATUS status = ReadWrite(device, file, &readWrite);

	if(NT_SUCCESS(status))
	{
		ASSERT((ULONG) targetSize >= target->Length);
		
		// Copy requested portion into caller's buffer
		RtlCopyMemory(target->Buffer, buffer + deltaOffset, target->Length);
	}
	 
	IoFreeMdl(readWrite.Mdl);

	ExFreePool(buffer);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterBase::WriteNonAligned(DEVICE_OBJECT *device, FILE_OBJECT *file, FILFILE_READ_WRITE const* source)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(source);

	ASSERT(source->Buffer);
	ASSERT(source->Length);
	
	LARGE_INTEGER targetOffset = source->Offset;
	LONG		  targetSize   = source->Length;

	DBGPRINT(("WriteNonAligned: FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, targetSize, targetOffset));

	// Compute how much to read around given request prior to perform the actual write.
	LONG const deltaOffset = targetOffset.LowPart & (c_sectorSize - 1);

	if(deltaOffset)
	{
		ASSERT(targetOffset.QuadPart >= deltaOffset);
		targetOffset.QuadPart -= deltaOffset;
		targetSize			  += deltaOffset;
	}

	LONG const deltaSize = (-targetSize) & (c_sectorSize - 1);

	if(deltaSize)
	{
		targetSize += deltaSize;
	}

	ASSERT(deltaOffset || deltaSize);
	ASSERT(0 == (targetOffset.LowPart % c_sectorSize));
	ASSERT(0 == (targetSize % c_sectorSize));
	
	// Allocate intermediate composite buffer
	LONG   const bufferSize = targetSize;
	UCHAR *const buffer	    = (UCHAR*) ExAllocatePool(NonPagedPool, bufferSize);

	if(!buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory(buffer, bufferSize);

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
	readWrite.Length = c_sectorSize;
	readWrite.Flags  = IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	readWrite.Major  = IRP_MJ_READ;
	readWrite.Wait   = true;

	NTSTATUS status = STATUS_SUCCESS;

	// Read LHS sector, if any
	if(deltaOffset)
	{
		readWrite.Offset = targetOffset;
	
		DBGPRINT(("WriteNonAligned: FO[0x%p] Fetch LHS at [0x%I64x]\n", file, readWrite.Offset));
		
		status = ReadWrite(device, file, &readWrite);
	}

	if(NT_SUCCESS(status))
	{
		if(deltaSize && ((targetSize > c_sectorSize) || !deltaOffset))
		{
			// Read RHS sector, if not already done
			ASSERT(targetSize > c_sectorSize);
			LONG const rhs = targetSize - c_sectorSize;

			readWrite.Offset.QuadPart = targetOffset.QuadPart + rhs;
			readWrite.Buffer		  = buffer + rhs;
			
			MmPrepareMdlForReuse(readWrite.Mdl);
			MmInitializeMdl(readWrite.Mdl, readWrite.Buffer, CFilterBase::c_sectorSize);
			MmBuildMdlForNonPagedPool(readWrite.Mdl);

			DBGPRINT(("WriteNonAligned: FO[0x%p] Fetch RHS at [0x%I64x]\n", file, readWrite.Offset));
			
			status = ReadWrite(device, file, &readWrite);
		}

		if(NT_SUCCESS(status))
		{
			// Copy source into intermediate buffer
			ASSERT(deltaOffset + source->Length <= (ULONG) targetSize);
			RtlCopyMemory(buffer + deltaOffset, source->Buffer, source->Length);

			MmPrepareMdlForReuse(readWrite.Mdl);
			MmInitializeMdl(readWrite.Mdl, buffer, bufferSize);
			MmBuildMdlForNonPagedPool(readWrite.Mdl);

			readWrite.Buffer = buffer;
			readWrite.Offset = targetOffset;
			readWrite.Length = bufferSize;
			readWrite.Flags  = source->Flags;
			readWrite.Major  = IRP_MJ_WRITE;

			DBGPRINT(("WriteNonAligned: FO[0x%p] Write [0x%x] at [0x%I64x]\n", file, readWrite.Length, readWrite.Offset));

			// Write composite buffer back
			status = ReadWrite(device, file, &readWrite);			
		}
	}

	IoFreeMdl(readWrite.Mdl);

	ExFreePool(buffer);

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::GetFileSize(DEVICE_OBJECT *device, FILE_OBJECT *file, LARGE_INTEGER *fileSize)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(fileSize);

	PAGED_CODE();
    
	FILE_STANDARD_INFORMATION standard;
	RtlZeroMemory(&standard, sizeof(standard));

	// be a good citizen
	NTSTATUS status = QueryFileInfo(device, file, FileStandardInformation, &standard, sizeof(standard));

	if(NT_SUCCESS(status))
	{
		*fileSize = standard.EndOfFile;
	}
	else
	{
		DBGPRINT(("GetFileSize -WARN: device path failed [0x%08x]\n", status));

		// don't give up
		FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;

		if(fcb && fcb->Resource)
		{
			FsRtlEnterFileSystem();
			ExAcquireResourceSharedLite(fcb->Resource, true);

			*fileSize = fcb->FileSize;

			ExReleaseResourceLite(fcb->Resource);
			FsRtlExitFileSystem();

			status = STATUS_SUCCESS;
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryFileInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_INFORMATION_CLASS infoClass, void *buffer, ULONG bufferSize)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(buffer);
	ASSERT(bufferSize);

	PAGED_CODE();
        
	IO_STATUS_BLOCK ioStatus = {0,0};

	// first try FastIo path
	ASSERT(device->DriverObject);
	if(device->DriverObject->FastIoDispatch)
	{
		FAST_IO_DISPATCH *const fastIo = device->DriverObject->FastIoDispatch;

		switch(infoClass)
		{
			case FileBasicInformation:

				if(fastIo->FastIoQueryBasicInfo)
				{
					ASSERT(bufferSize >= sizeof(FILE_BASIC_INFORMATION));

					if(fastIo->FastIoQueryBasicInfo(file, true, (FILE_BASIC_INFORMATION*) buffer, &ioStatus, device))
					{
						return ioStatus.Status;
					}
				}
				break;

			case FileStandardInformation:

				if(fastIo->FastIoQueryStandardInfo)
				{
					ASSERT(bufferSize >= sizeof(FILE_STANDARD_INFORMATION));

					if(fastIo->FastIoQueryStandardInfo(file, true, (FILE_STANDARD_INFORMATION*) buffer, &ioStatus, device))
					{
						return ioStatus.Status;
					}
				}
				break;

			case FileNetworkOpenInformation:

				if(fastIo->FastIoQueryNetworkOpenInfo)
				{
					ASSERT(bufferSize >= sizeof(FILE_NETWORK_OPEN_INFORMATION));

					if(fastIo->FastIoQueryNetworkOpenInfo(file, true, (FILE_NETWORK_OPEN_INFORMATION*) buffer, &ioStatus, device))
					{
						return ioStatus.Status;
					}
				}
				break;


			default:
				break;
		}
	}

	// roll our own IRP

	//DBGPRINT(("QueryFileInfo: roll IRP, FileInformationClass(%d)\n", fileInfo));

	ioStatus.Status		 = 0;
	ioStatus.Information = 0;

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	IRP *const irp = IoAllocateIrp(device->StackSize, false);

	if(irp)
	{
		irp->AssociatedIrp.SystemBuffer	= buffer;
		irp->UserIosb					= &ioStatus;
		irp->UserEvent					= 0;
		irp->RequestorMode				= KernelMode;
		irp->Tail.Overlay.Thread		= PsGetCurrentThread();
		irp->Flags						= IRP_SYNCHRONOUS_API | IRP_DEFER_IO_COMPLETION;
		
		IO_STACK_LOCATION *const stack = IoGetNextIrpStackLocation(irp);
		ASSERT(stack);

		stack->MajorFunction	= IRP_MJ_QUERY_INFORMATION;
		stack->MinorFunction	= IRP_MN_NORMAL;
		stack->DeviceObject		= device;
		stack->FileObject		= file;

		stack->Parameters.QueryFile.Length				 = bufferSize;
		stack->Parameters.QueryFile.FileInformationClass = infoClass;

		status = SimpleSend(device, irp);

		if(NT_ERROR(status))
		{
			DBGPRINT(("QueryFileInfo -ERROR: IRP_MJ_QUERY_INFORMATION for [%d] failed [0x%08x]\n", infoClass, status));
		}

		IoFreeIrp(irp);
	}
	else
	{
		DBGPRINT(("QueryFileInfo -ERROR: IoAllocateIrp() failed\n"));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryFileNameInfo(DEVICE_OBJECT *device, FILE_OBJECT *file, FILE_NAME_INFORMATION **fileInfo)
{
	ASSERT(device);
	ASSERT(file);
	ASSERT(fileInfo);

	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	ULONG infoSize  = PAGE_SIZE;		

	// spin with increasing size
	for(;;)
	{
		*fileInfo = (FILE_NAME_INFORMATION*) ExAllocatePool(PagedPool, infoSize);

		if(!*fileInfo)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(*fileInfo, infoSize);

		status = QueryFileInfo(device, file, FileNameInformation, *fileInfo, infoSize);	

		if(NT_SUCCESS(status))
		{
			break;
		}

		ExFreePool(*fileInfo);
		*fileInfo = 0;

		if(STATUS_BUFFER_TOO_SMALL != status)
		{
			break;
		}

		infoSize *= 2;								
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::LockFile(FILE_OBJECT *file, bool acquire)
{
	ASSERT(file);

	PAGED_CODE();

	if(file->FsContext)
	{
		ERESOURCE *const main   = ((FSRTL_COMMON_FCB_HEADER*) file->FsContext)->Resource;
		ERESOURCE *const paging = ((FSRTL_COMMON_FCB_HEADER*) file->FsContext)->PagingIoResource;

		if(acquire)
		{
			if(main && paging)
			{
				LARGE_INTEGER time;
				time.QuadPart = RELATIVE(MILLISECONDS(20));

				// spinning for the locks ...
				for(;;)
				{
					ExAcquireResourceExclusiveLite(main, true);

					if(ExAcquireResourceExclusiveLite(paging, false))
					{
						break;
					}

					ExReleaseResourceLite(main);

					DBGPRINT(("LockFile: FO[0x%p] FCB[0x%p] waiting...\n", file, file->FsContext));

					// wait some amount of time
					KeDelayExecutionThread(KernelMode, false, &time);
				}
			}
			else if(main)
			{
				ExAcquireResourceExclusiveLite(main, true);
			}
			else if(paging)
			{
				ExAcquireResourceExclusiveLite(paging, true);
			}
		}
		else
		{
			if(main)
			{
				ExReleaseResourceLite(main);
			}
			if(paging)
			{
				ExReleaseResourceLite(paging);
			}
		}
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterBase::IsStackBased(FILE_OBJECT *file)
{
	ASSERT(file);

	PAGED_CODE();

	// Check if we have a fake FO (i.e. stack based). RefCounting shouldn't be used on such objects since 
	// they have no effect at all. Interestingly, MSFT decided to remove it totally starting with Vista.

	ULONG_PTR low  = 0;
	ULONG_PTR high = 0;

	IoGetStackLimits(&low, &high);

	if(((ULONG_PTR) file >= low) && ((ULONG_PTR) file < high))
	{
		//DBGPRINT(("IsStackBased -WARN: FO[0x%p] FCB[0x%p] is stack-based\n", file, file->FsContext));

		return true;
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CFilterBase::TearDownCache(FILE_OBJECT *file, ULONG loop, ULONG timeout)
{
	ASSERT(file);
	ASSERT(loop);
	ASSERT(timeout);

	PAGED_CODE();

	if(!IsCached(file))
	{
		return true;
	}

	LARGE_INTEGER time;
	time.QuadPart = RELATIVE(MILLISECONDS(timeout));

	// Try to flush/purge it
	for(ULONG step = 0; step < loop; ++step)
	{
		if(NT_SUCCESS(FlushAndPurgeCache(file, !step)))
		{
			if(!IsCached(file))
			{
				return true;
			}
		}

		DBGPRINT(("TearDownCache: FO[0x%p] cached, waiting (%d,%d)...\n", file, step, loop));

		KeDelayExecutionThread(KernelMode, false, &time);
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::FlushAndPurgeCache(FILE_OBJECT *file, bool flush, bool pin)
{
	PAGED_CODE();

	IO_STATUS_BLOCK status = {STATUS_SUCCESS, 0};
	
	if(file)
	{
		DBGPRINT(("FlushAndPurgeCache: FO[0x%p] FCB[0x%p] Flags[0x%x] IN\n", file, file->FsContext, file->Flags));

		SECTION_OBJECT_POINTERS *const sectionPtrs = file->SectionObjectPointer;

		if(sectionPtrs && (sectionPtrs->DataSectionObject || sectionPtrs->ImageSectionObject))
		{
			if(pin)
			{
				// Pin FO
				ObReferenceObject(file);
			}

			// Acquire locks
			LockFile(file, true);

			if(flush)
			{
				if(sectionPtrs->DataSectionObject)
				{
					// Flush dirty pages (if any), even for mapped files
					CcFlushCache(sectionPtrs, 0,0, &status);
				}
				else// if(sectionPtrs->ImageSectionObject)
				{
					MmFlushImageSection(sectionPtrs, MmFlushForWrite);
				}

				status.Status = STATUS_SUCCESS;
			}

			if(sectionPtrs->DataSectionObject)
			{
				ASSERT(!IsStackBased(file));
				
				if(!CcPurgeCacheSection(sectionPtrs, 0,0, true))
				{
					MmForceSectionClosed(sectionPtrs, true);

					DBGPRINT(("FlushAndPurgeCache -ERROR: CcPurgeCacheSection() failed\n"));

					status.Status = STATUS_UNSUCCESSFUL;
				}
			}

			// Release locks
			LockFile(file, false);

			if(pin)
			{
				// Unpin FO
				ObDereferenceObject(file);
			}
		}

		DBGPRINT(("FlushAndPurgeCache: FO[0x%p] OUT\n", file));
	}

	return status.Status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::CreateFile(DEVICE_OBJECT*		device, 
								 UNICODE_STRING*	path, 
								 ULONG				access, 
								 ULONG				share,
								 ULONG				options,	// combination of dispo and create options
								 ULONG				attribs,
								 FILE_OBJECT**		file,
								 HANDLE*			fileHandle)
{
	ASSERT(device);
	ASSERT(path);

	PAGED_CODE();

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

	HANDLE handle			 = 0;
	IO_STATUS_BLOCK	ioStatus = {0,0};

	// Open file without re-entering the file system stack
	NTSTATUS status = IoCreateFileSpecifyDeviceObjectHint(&handle,
														  access,
														  &oa,
														  &ioStatus,
														  0,
														  attribs,
														  share,
														  options >> 24,
														  options & 0x00ffffff,
														  0,
														  0,
														  CreateFileTypeNone,
														  0,
														  0,
														  device);
	if(NT_SUCCESS(status))
	{
		if(file)
		{
			status = ObReferenceObjectByHandle(handle, 
											   access, 
											   *IoFileObjectType, 
											   KernelMode, 
											   (void**) file, 
											   0);
		}

		if(fileHandle)
		{
			*fileHandle = handle;
		}
		else
		{
			ZwClose(handle);
		}
	}
	else
	{
		DBGPRINT(("CreateFile -ERROR: IoCreateFileSpecifyDeviceObjectHint() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryRegistryLong(LPCWSTR keyPath, LPCWSTR valueName, ULONG *value)
{
	ASSERT(keyPath);
	
	PAGED_CODE();

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, keyPath);

	OBJECT_ATTRIBUTES keyAttribs;
	InitializeObjectAttributes(&keyAttribs, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

	HANDLE key = 0;

	NTSTATUS status = ZwOpenKey(&key, KEY_QUERY_VALUE, &keyAttribs);

	if(NT_SUCCESS(status) && valueName)
	{
		RtlInitUnicodeString(&name, valueName);

		ULONG valueLength = 0;

		char valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
		RtlZeroMemory(valueBuffer, sizeof(valueBuffer));

		status = ZwQueryValueKey(key, &name, KeyValuePartialInformation, valueBuffer, sizeof(valueBuffer), &valueLength);

		if(NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;

			KEY_VALUE_PARTIAL_INFORMATION const*const valueInfo = (KEY_VALUE_PARTIAL_INFORMATION*) valueBuffer;

			if((valueInfo->Type == REG_DWORD) && (valueInfo->DataLength == sizeof(ULONG)))
			{
				if(value)
				{
					*value = *((ULONG*) valueInfo->Data);
				}

				status = STATUS_SUCCESS;
			}
		}
		else
		{
			DBGPRINT(("QueryRegistryLong -ERROR: ZwQueryValueKey() failed [0x%08x]\n", status));
		}
		
		ZwClose(key);
	}
	else
	{
		DBGPRINT(("QueryRegistryLong -ERROR: ZwOpenKey() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryRegistryString(LPCWSTR keyPath, LPCWSTR valueName, LPWSTR wstr, ULONG *wstrLength)
{
	ASSERT(keyPath);

	PAGED_CODE();

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, keyPath);

	OBJECT_ATTRIBUTES keyAttribs;
	InitializeObjectAttributes(&keyAttribs, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

	HANDLE key = 0;

	NTSTATUS status = ZwOpenKey(&key, KEY_QUERY_VALUE, &keyAttribs);

	if(NT_SUCCESS(status))
	{
		if(valueName)
		{
			RtlInitUnicodeString(&name, valueName);

			ULONG valueLength = 0;

			// get buffer size
			status = ZwQueryValueKey(key, &name, KeyValuePartialInformation, 0,0, &valueLength);

			if((STATUS_BUFFER_OVERFLOW == status) || (STATUS_BUFFER_TOO_SMALL == status))
			{
				ULONG const dataLength = valueLength - (sizeof(KEY_VALUE_PARTIAL_INFORMATION) - sizeof(UCHAR));

				if(wstrLength)
				{
					if(*wstrLength >= dataLength)
					{
						status = STATUS_INSUFFICIENT_RESOURCES;

						KEY_VALUE_PARTIAL_INFORMATION *const valueInfo = (KEY_VALUE_PARTIAL_INFORMATION*) ExAllocatePool(PagedPool, valueLength);

						if(valueInfo)
						{
							RtlZeroMemory(valueInfo, valueLength);

							status = ZwQueryValueKey(key, &name, KeyValuePartialInformation, valueInfo, valueLength, &valueLength);

							if(NT_SUCCESS(status))
							{
								status = STATUS_UNSUCCESSFUL;

								if(REG_SZ == valueInfo->Type)
								{
									status = STATUS_SUCCESS;

									// reg data requested ?
									if(wstr)
									{
										RtlCopyMemory(wstr, valueInfo->Data, valueInfo->DataLength);
									}
								}
							}

							ExFreePool(valueInfo);
						}
					}

					*wstrLength = dataLength;
				}
			}
			else
			{
				DBGPRINT(("QueryRegistryString -ERROR: ZwQueryValueKey() failed [0x%08x]\n", status));
			}
		}
	
		ZwClose(key);
	}
	else
	{
		DBGPRINT(("QueryRegistryString -ERROR: ZwOpenKey() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::QueryRegistrySubKeys(LPCWSTR keyPath, ULONG *subKeys)
{
	ASSERT(keyPath);
	ASSERT(subKeys);

	PAGED_CODE();

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, keyPath);

	OBJECT_ATTRIBUTES keyAttribs;
	InitializeObjectAttributes(&keyAttribs, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0,0);

	HANDLE key = 0;

	NTSTATUS status = ZwOpenKey(&key, KEY_QUERY_VALUE, &keyAttribs);

	if(NT_SUCCESS(status))
	{
		KEY_FULL_INFORMATION info;
		RtlZeroMemory(&info, sizeof(info));

		ULONG size = sizeof(info);

		status = ZwQueryKey(key, KeyFullInformation, &info, size, &size);

		if(NT_SUCCESS(status))
		{
			*subKeys = info.SubKeys;
		}

		ZwClose(key);
	}

	return status;
}	

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterBase::GetMacAddress(UCHAR macAddr[6])
{
	LPCWSTR const s_regPath	= L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";

	PAGED_CODE();

	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

	ULONG const regLen  = 75;
	ULONG const regSize = regLen + 4;
	LPWSTR regPath		= (LPWSTR) ExAllocatePool(PagedPool, regSize * sizeof(WCHAR));
	LPWSTR regValue		= (LPWSTR) ExAllocatePool(PagedPool, regSize * sizeof(WCHAR));

	if(regPath && regValue)
	{
		RtlZeroMemory(regPath, regSize * sizeof(WCHAR));
		RtlCopyMemory(regPath, s_regPath, regLen * sizeof(WCHAR));

		ULONG count = 0;

		// Does network key exist ?
		status = QueryRegistrySubKeys(regPath, &count);

		for(USHORT index = 1; count && (index < 99); ++index)
		{
			// just try key names, [1,2,..., 10,11,...,99]
			regPath[regLen]		= L'\\';
			regPath[regLen + 1] = L'0' + index;
			regPath[regLen + 2] = UNICODE_NULL;

			if(index >= 10)
			{
				regPath[regLen + 1] = (index / 10) + L'0';
				regPath[regLen + 2] = (index % 10) + L'0';
				regPath[regLen + 3] = UNICODE_NULL;
			}

			// init device name string
			RtlZeroMemory(regValue, regSize * sizeof(WCHAR));
			RtlCopyMemory(regValue, L"\\Device\\", 8 * sizeof(WCHAR));
			
			ULONG wstrLen = (regSize - 9) * sizeof(WCHAR);

			status = QueryRegistryString(regPath, L"ServiceName", regValue + 8, &wstrLen);

			if(NT_ERROR(status))
			{
				continue;
			}

			count--;

			bool finished = false;

			UNICODE_STRING deviceName;
			RtlInitUnicodeString(&deviceName, regValue);

			FILE_OBJECT *ndisFile	   = 0;
			DEVICE_OBJECT *ndisDevice  = 0;

			// get this NDIS device
			status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &ndisFile, &ndisDevice);

			if(NT_SUCCESS(status))
			{
				status = STATUS_INSUFFICIENT_RESOURCES;

				KEVENT event;
				KeInitializeEvent(&event, NotificationEvent, false);

				ULONG oidCode = OID_GEN_MEDIA_IN_USE;

				IO_STATUS_BLOCK ioStatus = {0,0};

				UCHAR oidData[8] = {0};

				// get medium type
				IRP *irp = IoBuildDeviceIoControlRequest(IOCTL_NDIS_QUERY_GLOBAL_STATS,
														 ndisDevice,  
														 &oidCode, 
														 sizeof(oidCode), 
														 &oidData, 
														 sizeof(oidData), 
														 false, 
														 &event, 
														 &ioStatus);
				if(irp)
				{
					IO_STACK_LOCATION *stack = IoGetNextIrpStackLocation(irp);
					ASSERT(stack);

					stack->FileObject = ndisFile;

					// active NDIS object ?
					status = IoCallDriver(ndisDevice, irp);

					if(STATUS_PENDING == status)
					{
						KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);	

						status = ioStatus.Status;
					}
	
					if(NT_SUCCESS(status))
					{
						NDIS_MEDIUM const medium = *((NDIS_MEDIUM*) oidData);

						RtlZeroMemory(oidData, sizeof(oidData));
		
						// which medium ?
						if(NdisMedium802_3 == medium)
						{
							oidCode = OID_802_3_CURRENT_ADDRESS;
						}
						else if(NdisMediumWan == medium)
						{
							oidCode = OID_WAN_CURRENT_ADDRESS;
						}
						else if(NdisMediumWirelessWan == medium)
						{
							oidCode = OID_WW_GEN_CURRENT_ADDRESS;
						}

						status = STATUS_INSUFFICIENT_RESOURCES;

						// get desired address
						irp = IoBuildDeviceIoControlRequest(IOCTL_NDIS_QUERY_GLOBAL_STATS,
															ndisDevice,  
															&oidCode, 
															sizeof(oidCode), 
															&oidData, 
															sizeof(oidData), 
															false, 
															&event, 
															&ioStatus);

						if(irp)
						{
							stack = IoGetNextIrpStackLocation(irp);
							ASSERT(stack);

							stack->FileObject = ndisFile;

							KeClearEvent(&event);

							ioStatus.Status		 = 0;
							ioStatus.Information = 0;

							status = IoCallDriver(ndisDevice, irp);

							if(STATUS_PENDING == status)
							{
								KeWaitForSingleObject(&event, Executive, KernelMode, false, 0);	

								status = ioStatus.Status;
							}

							if(NT_SUCCESS(status))
							{
								// valid ?
								if(ioStatus.Information >= 6)
								{
									RtlCopyMemory(macAddr, oidData, 6);

									// finish
									finished = true;
								}
							}
						}
					}
				}
				else
				{
					DBGPRINT(("InitMacChecksum - ERROR: IoGetDeviceObjectPointer() failed [0x%08x]\n", status));
				}

				ObDereferenceObject(ndisFile);
			}
			
			// finished ?
			if(finished)
			{
				break;
			}
		}
	}

	if(regPath)
	{
		ExFreePool(regPath);
	}
	if(regValue)
	{
		ExFreePool(regValue);
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

