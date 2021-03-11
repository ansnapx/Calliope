////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterFastIo.cpp: implementation of the CFilterFastIo class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "CFilterEngine.h"
#include "CFilterFile.h"

#include "CFilterFastIo.h"

// MACROS ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName)													\
     (((_FastIoDispatchPtr) != NULL) &&																					\
     (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void*))) &&	\
     ((_FastIoDispatchPtr)->_FieldName != NULL))

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

NTSTATUS CFilterFastIo::Init(FAST_IO_DISPATCH **fastIoDispatch)
{
	ASSERT(fastIoDispatch);

	FAST_IO_DISPATCH *const fastIo = (FAST_IO_DISPATCH*) ExAllocatePool(NonPagedPool, sizeof(FAST_IO_DISPATCH));

	if(!fastIo)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory(fastIo, sizeof(FAST_IO_DISPATCH));
	
	fastIo->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);

	fastIo->FastIoCheckIfPossible		= Check;
	fastIo->FastIoRead					= Read;
	fastIo->FastIoWrite					= Write;
	fastIo->FastIoQueryBasicInfo		= QueryBasic;
	fastIo->FastIoQueryStandardInfo		= QueryStandard;
	fastIo->FastIoLock					= Lock;
	fastIo->FastIoUnlockSingle			= UnlockOne;
	fastIo->FastIoUnlockAll				= UnlockAll;
	fastIo->FastIoUnlockAllByKey		= UnlockKey;
	fastIo->FastIoDeviceControl			= DeviceControl;
	fastIo->FastIoDetachDevice			= Detach;
	fastIo->FastIoQueryNetworkOpenInfo	= QueryNetworkOpenInfo;
	fastIo->MdlRead						= MdlRead;
	fastIo->MdlReadComplete				= MdlReadComplete;
	fastIo->PrepareMdlWrite				= PrepareMdlWrite;
	fastIo->MdlWriteComplete			= MdlWriteComplete;
	fastIo->FastIoReadCompressed		= ReadCompressed;
	fastIo->FastIoWriteCompressed		= WriteCompressed;
	fastIo->MdlReadCompleteCompressed	= MdlReadCompleteCompressed;
	fastIo->MdlWriteCompleteCompressed	= MdlWriteCompleteCompressed;
	fastIo->FastIoQueryOpen				= QueryOpen;

	*fastIoDispatch = fastIo;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterFastIo::Detach(DEVICE_OBJECT *source, DEVICE_OBJECT *target)
{
	ASSERT(source);
	ASSERT(target);

    PAGED_CODE();

    // Simply acquire the database lock for exclusive access, and detach from
    // the file system's volume device object.
	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) source->DeviceExtension;

	if(extension)
	{
		// ignore control device
		if((FILFILE_FILTER_VOLUME == extension->Common.Type) || (FILFILE_FILTER_FILE_SYSTEM == extension->Common.Type))
		{
			DBGPRINT(("FastIoDetach: from [%ws]\n", (extension->LowerName.Buffer) ? extension->LowerName.Buffer : L"UNKNOWN"));

			IoDetachDevice(target);

			if(FILFILE_FILTER_VOLUME == extension->Common.Type)
			{
				// remove from list
				CFilterControl::RemoveVolumeDevice(source);
			}

			if(extension->LowerName.Buffer)
			{
				ExFreePool(extension->LowerName.Buffer);
				extension->LowerName.Buffer = 0;
			}

			extension->LowerName.Length		   = 0;
			extension->LowerName.MaximumLength = 0;
			
			IoDeleteDevice(source);
		}
		else
		{
			ASSERT(false);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::Check(FILE_OBJECT*	 file, 
							LARGE_INTEGER*	 offset, 
							ULONG			 length,
							BOOLEAN			 wait,
							ULONG			 lock,
							BOOLEAN			 checkForReadOperation,
							IO_STATUS_BLOCK* ioStatus,
							DEVICE_OBJECT*	 device)
{
	ASSERT(device);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoCheckIfPossible))
		{
			return fastIoDispatch->FastIoCheckIfPossible(file, offset, length, wait, lock, checkForReadOperation, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::Read(FILE_OBJECT*	file, 
						   LARGE_INTEGER*	offset, 
						   ULONG			length,
						   BOOLEAN			wait,
						   ULONG			lock,
						   void*			buffer,
						   IO_STATUS_BLOCK* ioStatus,
						   DEVICE_OBJECT*	device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoRead))
		{
			// totally inactive ? 
			if( !(CFilterEngine::s_state & FILFILE_STATE_FILE))
			{
				return fastIoDispatch->FastIoRead(file, offset, length, wait, lock, buffer, ioStatus, lower);
			}

			ASSERT(file);
			ASSERT(offset);
			ASSERT(ioStatus);

			CFilterContextLink link;
			RtlZeroMemory(&link, sizeof(link));

			int const state = extension->Volume.CheckFileCooked(file, &link);

			if(!state)
			{
				return fastIoDispatch->FastIoRead(file, offset, length, wait, lock, buffer, ioStatus, lower);
			}

			// be paranoid
			link.m_fileKey.Clear();

			if(file->Flags & FO_REMOTE_ORIGIN)
			{
				return false;
			}

			// doomed FO ?
			if(state == -1)
			{
				ioStatus->Information = STATUS_FILE_CLOSED;
				ioStatus->Information = 0;
             
				return true;
			}

			if(extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS)
			{
				return false;
			}

			DBGPRINT(("FastIoRead: FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, length, *offset));		

			FSRTL_COMMON_FCB_HEADER* const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
			ASSERT(fcb);
			
			FsRtlEnterFileSystem();

			if(!ExAcquireResourceSharedLite(fcb->Resource, wait))
			{
				FsRtlExitFileSystem();

				return false;
			}

			LONGLONG const cookedFileSize = fcb->FileSize.QuadPart - (link.m_headerBlockSize + CFilterContext::c_tail);

 			ExReleaseResourceLite(fcb->Resource);
			FsRtlExitFileSystem();

			// beyond EOF ?
			if(offset->QuadPart >= cookedFileSize)
			{
				ioStatus->Status	  = STATUS_END_OF_FILE;
				ioStatus->Information = 0;

				return true;
			}

			BOOLEAN const result = fastIoDispatch->FastIoRead(file, offset, length, wait, lock, buffer, ioStatus, lower);

			// good AND overlap EOF ?
			if(result && (offset->QuadPart + length > cookedFileSize))
			{
				if(NT_SUCCESS(ioStatus->Status))
				{
					ULONG const overlap = (ULONG) (cookedFileSize - offset->QuadPart);

					// adjust it
					ioStatus->Information = overlap;
				}
			}

			return result;
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::Write(FILE_OBJECT*		file, 
							 LARGE_INTEGER*		offset, 
							 ULONG				length,
							 BOOLEAN			wait,
							 ULONG				lock,
							 void*				buffer,
							 IO_STATUS_BLOCK*	ioStatus,
							 DEVICE_OBJECT*		device)

{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoWrite))
		{
			// not totally inactive ? 
			if(CFilterEngine::s_state & FILFILE_STATE_FILE)
			{
				ASSERT(file);
				ASSERT(offset);
				ASSERT(ioStatus);

				CFilterContextLink link;
				RtlZeroMemory(&link, sizeof(link));

				int const state = extension->Volume.CheckFileCooked(file, &link);

				// file of interest ?
				if(!state)
				{
					return fastIoDispatch->FastIoWrite(file, offset, length, wait, lock, buffer, ioStatus, lower);
				}

				// be paranoid
				link.m_fileKey.Clear();

				if(file->Flags & FO_REMOTE_ORIGIN)
				{
					return false;
				}

				// doomed FO ?
				if(state == -1)
				{
					ioStatus->Information = STATUS_FILE_CLOSED;
					ioStatus->Information = 0;
	             
					return true;
				}

				if(extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS)
				{
					return false;
				}

				DBGPRINT(("FastIoWrite: FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, length, *offset));		

				FSRTL_COMMON_FCB_HEADER *const fcb = (FSRTL_COMMON_FCB_HEADER*) file->FsContext;
				ASSERT(fcb);

				FsRtlEnterFileSystem();

				if(!ExAcquireResourceSharedLite(fcb->Resource, wait))
				{
					FsRtlExitFileSystem();

					return false;
				}
				
				LONGLONG const requestSize = offset->QuadPart + length + link.m_headerBlockSize + CFilterContext::c_tail;

				bool const extendVDL = (requestSize > fcb->ValidDataLength.QuadPart);
				bool const extendEOF = (requestSize > fcb->FileSize.QuadPart);

				ExReleaseResourceLite(fcb->Resource);
				FsRtlExitFileSystem();
								
				if(extendEOF || extendVDL)
				{
					if(extension->LowerType & FILFILE_DEVICE_REDIRECTOR)
					{
						if(file->Flags & FO_SEQUENTIAL_ONLY)
						{
							// Put in cache hint for write handler. Only needed on redirectors
							extension->Volume.UpdateLink(file, TRACK_USE_CACHE);
						}
					}

					// trigger irp path
					return false;
				}
			}

			return fastIoDispatch->FastIoWrite(file, offset, length, wait, lock, buffer, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::QueryBasic(FILE_OBJECT *file, BOOLEAN wait, FILE_BASIC_INFORMATION *buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryBasicInfo))
		{
			return fastIoDispatch->FastIoQueryBasicInfo(file, wait, buffer, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::QueryStandard(FILE_OBJECT*				file, 
									 BOOLEAN					wait, 
									 FILE_STANDARD_INFORMATION* info, 
									 IO_STATUS_BLOCK*			ioStatus, 
									 DEVICE_OBJECT*				device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryStandardInfo))
		{
			if(fastIoDispatch->FastIoQueryStandardInfo(file, wait, info, ioStatus, lower))
			{
				ASSERT(file);
				ASSERT(info);

				CFilterContextLink link;
				RtlZeroMemory(&link, sizeof(link));

				if(extension->Volume.CheckFileCooked(file, &link))
				{
					// be paranoid
					link.m_fileKey.Clear();

					if( !(extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS))
					{
						ULONG metaSize = link.m_headerBlockSize;

						// Only substract Tail if there is one
						if(info->EndOfFile.QuadPart > metaSize)
						{
							metaSize += CFilterContext::c_tail;
						}

						if(info->EndOfFile.QuadPart >= metaSize)
						{
							info->EndOfFile.QuadPart -= metaSize;
						}

						if(info->AllocationSize.QuadPart >= metaSize)
						{
 							info->AllocationSize.QuadPart -= metaSize;
						}

						ASSERT(info->AllocationSize.QuadPart >= info->EndOfFile.QuadPart);

						DBGPRINT(("FastIoQueryStandard: FO[0x%p] [ALC:0x%I64x EOF:0x%I64x]\n", file, info->AllocationSize, info->EndOfFile));		
					}
					else
					{
						DBGPRINT(("FastIoQueryStandard: FO[0x%p] File is bypassed, ignore\n", file));
					}
				}

				return true;
			}
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::QueryNetworkOpenInfo(FILE_OBJECT*				   file, 
											BOOLEAN						   wait, 
											FILE_NETWORK_OPEN_INFORMATION* info, 
											IO_STATUS_BLOCK*			   ioStatus, 
											DEVICE_OBJECT*				   device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryNetworkOpenInfo))
		{
			if(fastIoDispatch->FastIoQueryNetworkOpenInfo(file, wait, info, ioStatus, lower))
			{
				ASSERT(file);

				if( !(file->Flags & FO_REMOTE_ORIGIN))
				{
					CFilterContextLink link;
					RtlZeroMemory(&link, sizeof(link));

					if(extension->Volume.CheckFileCooked(file, &link))
					{
						// be paranoid
						link.m_fileKey.Clear();

						if( !(extension->Volume.m_context->Tracker().Check(file) & FILFILE_TRACKER_BYPASS))
						{
							ULONG metaSize = link.m_headerBlockSize;

							// only substract Tail if there is one					
							if(info->EndOfFile.QuadPart > metaSize)
							{
								metaSize += CFilterContext::c_tail;
							}

							if(info->EndOfFile.QuadPart >= metaSize)
							{
								info->EndOfFile.QuadPart -= metaSize;
							}
							if(info->AllocationSize.QuadPart >= metaSize)
							{
								info->AllocationSize.QuadPart -= metaSize;
							}

							DBGPRINT(("FastIoQueryNetworkOpenInfo: FO[0x%p] [ALC:0x%I64x EOF:0x%I64x]\n", file, info->AllocationSize.QuadPart, info->EndOfFile.QuadPart));
						}
						else
						{
							DBGPRINT(("FastIoQueryNetworkOpenInfo: FO[0x%p] File is bypassed, ignore\n", file));
						}
					}
				}
				else
				{
					DBGPRINT(("FastIoQueryNetworkOpenInfo: FO[0x%p] remote request, finished\n", file));		
				}

				return true;
			}
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::QueryOpen(IRP *irp, FILE_NETWORK_OPEN_INFORMATION *info, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	BOOLEAN result = false;

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryOpen))
		{
			IO_STACK_LOCATION *const stack = IoGetCurrentIrpStackLocation(irp);
			ASSERT(stack);

			stack->DeviceObject = lower;

			// Are we inactive?
			if((CFilterEngine::s_state & FILFILE_STATE_CREATE) != FILFILE_STATE_CREATE)
			{
				result = fastIoDispatch->FastIoQueryOpen(irp, info, lower);
			}
			else
			{
				ULONG const access = stack->Parameters.Create.SecurityContext->DesiredAccess;

				// Handle access modes that won't touch the file data
				if((FILE_READ_ATTRIBUTES == access) || ((FILE_READ_ATTRIBUTES | SYNCHRONIZE) == access))
				{
					result = fastIoDispatch->FastIoQueryOpen(irp, info, lower);

					if(result && (STATUS_SUCCESS == irp->IoStatus.Status))
					{
						//DBGPRINT(("FastIoQueryOpen: FO[0x%p] handled Attr query\n", stack->FileObject));

						// Add this FO to the ignore List
						extension->Volume.m_context->Tracker().Add(stack->FileObject, FILFILE_TRACKER_IGNORE);
					}
				}
				else
				{
					// We cannot easily check if the file name belongs to a tracked file, so trigger IRP path here
					DBGPRINT(("FastIoQueryOpen: FO[0x%p] trigger IRP path\n", stack->FileObject));		
				}
			}

			stack->DeviceObject = device;
		}
	}

	return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::Lock(FILE_OBJECT*	 file,
							LARGE_INTEGER*	 offset,
							LARGE_INTEGER*	 length,
							PEPROCESS		 processId,
							ULONG			 key,
							BOOLEAN			 failImmediately,
							BOOLEAN			 exclusiveLock,
							IO_STATUS_BLOCK* ioStatus,
							DEVICE_OBJECT*	 device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoLock))
		{
			return fastIoDispatch->FastIoLock(file, offset, length, processId, key, failImmediately, exclusiveLock, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::UnlockOne(FILE_OBJECT*	 file, 
								LARGE_INTEGER*	 offset,
								LARGE_INTEGER*   length,
								PEPROCESS		 processId,
								ULONG			 key,
								IO_STATUS_BLOCK* ioStatus,
								DEVICE_OBJECT*   device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockSingle))
		{
			return fastIoDispatch->FastIoUnlockSingle(file, offset, length, processId, key, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::UnlockAll(FILE_OBJECT *file, PEPROCESS processId, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockAll))
		{
			return fastIoDispatch->FastIoUnlockAll(file, processId, ioStatus, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::UnlockKey(FILE_OBJECT *file, void *processId, ULONG key, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockAllByKey))
		{
			return fastIoDispatch->FastIoUnlockAllByKey(file, processId, key, ioStatus, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::DeviceControl(FILE_OBJECT*	 file,
									BOOLEAN			 wait,
									void*			 inputBuffer,
									ULONG			 inputBufferLength,
									void*			 outputBuffer,
									ULONG			 outputBufferLength,
									ULONG			 ctrlCode,
									IO_STATUS_BLOCK* ioStatus,
									DEVICE_OBJECT*   device)
{
	ASSERT(device);

    PAGED_CODE();

	// if not targeted to our CDO, trigger IRP path
	if(device != CFilterControl::s_control)
	{
		FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
		ASSERT(extension);

	//	ASSERT(FILFILE_FILTER_VOLUME == extension->Common.Type);

		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoDeviceControl))
		{
			return fastIoDispatch->FastIoDeviceControl(file, 
													   wait, 
													   inputBuffer, 
													   inputBufferLength, 
													   outputBuffer, 
													   outputBufferLength, 
													   ctrlCode, 
													   ioStatus, 
													   lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::MdlRead(FILE_OBJECT*	 file,
							LARGE_INTEGER*	 offset,
							ULONG			 length,
							ULONG			 lock,
							MDL**			 mdlChain,
							IO_STATUS_BLOCK* ioStatus,
							DEVICE_OBJECT*	 device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoMdlRead: called FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, length, *offset));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlRead))
		{
			ASSERT(file);

			if((file->Flags & FO_REMOTE_ORIGIN) && extension->Volume.CheckFileCooked(file))
			{
				return false;
			}

			return fastIoDispatch->MdlRead(file, offset, length, lock, mdlChain, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::MdlReadComplete(FILE_OBJECT *file, MDL *mdlChain, DEVICE_OBJECT *device)
{
	ASSERT(device);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoMdlReadComplete: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlReadComplete))
		{
			ASSERT(file);

			if((file->Flags & FO_REMOTE_ORIGIN) && extension->Volume.CheckFileCooked(file))
			{
				DBGPRINT(("FastIoMdlReadComplete: FO[0x%p] tracked and remote, trigger IRP\n", file));

				return false;
			}

			return fastIoDispatch->MdlReadComplete(file, mdlChain, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::PrepareMdlWrite(FILE_OBJECT*	 file, 
									LARGE_INTEGER*	 offset,
									ULONG			 length,
									ULONG			 lock,
									MDL**			 mdlChain,
									IO_STATUS_BLOCK* ioStatus,
									DEVICE_OBJECT*	 device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoPrepareMdlWrite:  called FO[0x%p] Size[0x%x] Offset[0x%I64x]\n", file, length, *offset));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, PrepareMdlWrite))
		{
			ASSERT(file);

			if((file->Flags & FO_REMOTE_ORIGIN) && extension->Volume.CheckFileCooked(file))
			{
				return false;
			}

			return fastIoDispatch->PrepareMdlWrite(file, offset, length, lock, mdlChain, ioStatus, lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::MdlWriteComplete(FILE_OBJECT *file, LARGE_INTEGER *offset, MDL *mdlChain, DEVICE_OBJECT *device)
{
	ASSERT(device);

	PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoMdlWriteComplete: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlWriteComplete))
		{
			ASSERT(file);

			if((file->Flags & FO_REMOTE_ORIGIN) && extension->Volume.CheckFileCooked(file))
			{
				return false;
			}

			return fastIoDispatch->MdlWriteComplete(file, offset, mdlChain, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::ReadCompressed(FILE_OBJECT*			file,
									LARGE_INTEGER*			offset,
									ULONG					length,
									ULONG					lock,
									void*					buffer,
									MDL**					mdlChain,
									IO_STATUS_BLOCK*		ioStatus,
									_COMPRESSED_DATA_INFO*	compressedDataInfo,
									ULONG					compressedDataInfoLength,
									DEVICE_OBJECT*			device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoReadCompressed: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoReadCompressed))
		{
			return fastIoDispatch->FastIoReadCompressed(file, 
														offset, 
														length, 
														lock, 
														buffer, 
														mdlChain, 
														ioStatus, 
														compressedDataInfo, 
														compressedDataInfoLength, 
														lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::WriteCompressed(FILE_OBJECT*			file, 
									LARGE_INTEGER*			offset,
									ULONG					length,
									ULONG					lock,
									void*					buffer,
									MDL**					mdlChain,
									IO_STATUS_BLOCK*		ioStatus,
									_COMPRESSED_DATA_INFO*	compressedDataInfo,
									ULONG					compressedDataInfoLength,
									DEVICE_OBJECT*			device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoWriteCompressed: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoWriteCompressed))
		{
			return fastIoDispatch->FastIoWriteCompressed(file, 
														 offset, 
														 length, 
														 lock, 
														 buffer, 
														 mdlChain, 
														 ioStatus, 
														 compressedDataInfo, 
														 compressedDataInfoLength, 
														 lower);
		}
	}

	return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::MdlReadCompleteCompressed(FILE_OBJECT *file, MDL *mdlChain, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoMdlReadCompleteCompressed: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlReadCompleteCompressed))
		{
			return fastIoDispatch->MdlReadCompleteCompressed(file, mdlChain, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

BOOLEAN CFilterFastIo::MdlWriteCompleteCompressed(FILE_OBJECT *file, LARGE_INTEGER *offset, MDL *mdlChain, DEVICE_OBJECT *device)
{
	ASSERT(device);

    PAGED_CODE();

	FILFILE_VOLUME_EXTENSION *const extension = (FILFILE_VOLUME_EXTENSION*) device->DeviceExtension;
	ASSERT(extension);

	// ignore control device
	if(FILFILE_FILTER_VOLUME == extension->Common.Type)
	{
		DEVICE_OBJECT *const lower			   = extension->Lower;
		FAST_IO_DISPATCH *const fastIoDispatch = lower->DriverObject->FastIoDispatch;

		DBGPRINT(("FastIoMdlWriteCompleteCompressed: called FO[0x%p]\n", file));

		if(VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlWriteCompleteCompressed))
		{
			return fastIoDispatch->MdlWriteCompleteCompressed(file, offset, mdlChain, lower);
		}
	}

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
