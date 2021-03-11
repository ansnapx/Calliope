////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// FilFile.cpp
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterFastIo.h"
#include "CFilterControl.h"
#include "CFilterEngine.h"

// GLOBALS /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if DBG
 char* g_debugHeader = "FilFile: ";
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if DBG

#pragma PAGEDCODE

void DriverUnload(DRIVER_OBJECT *driver)
{
	DBGPRINT(("DriverUnload - IN\n"));

	ASSERT(driver);

	PAGED_CODE();

	UNICODE_STRING deviceNameDos;
	RtlInitUnicodeString(&deviceNameDos, CFilterControl::s_deviceNameDos);

	// delete our symbolic link
	IoDeleteSymbolicLink(&deviceNameDos);

	// shutdown everything
	CFilterControl::Close(driver);

	//ÊÍ·ÅFastIO±í
	if(driver->FastIoDispatch)
	{
		RtlZeroMemory(driver->FastIoDispatch, sizeof(FAST_IO_DISPATCH));

		ExFreePool(driver->FastIoDispatch);
		driver->FastIoDispatch = 0;
	}
	
	DBGPRINT(("DriverUnload - OUT\n"));
}

#endif //DBG
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma INITCODE

extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT *driver, UNICODE_STRING *registry)
{
	ASSERT(driver);

	DBGPRINT(("Driver was built on [%s - %s]\n", __DATE__, __TIME__));

	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\FileSystem\\XAzFileCrypt");
//FilFileControl
	DEVICE_OBJECT* device = 0;

	NTSTATUS status = IoCreateDevice(driver, 
									 sizeof(FILFILE_CONTROL_EXTENSION), 
									 &deviceName, 
									 FILE_DEVICE_UNKNOWN,
									 FILE_DEVICE_SECURE_OPEN, 
									 false, 
									 &device);

	if(NT_SUCCESS(status))
	{
		FAST_IO_DISPATCH* fastIo = 0;

		status = CFilterFastIo::Init(&fastIo);

		if(NT_SUCCESS(status))
		{
			driver->FastIoDispatch = fastIo;

			#if DBG
  			// driver->DriverUnload = DriverUnload;
			#endif

			for(ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index)
			{
				driver->MajorFunction[index] = CFilterEngine::DispatchPass;
			}

			driver->MajorFunction[IRP_MJ_CREATE]			  = CFilterEngine::DispatchCreate;
			driver->MajorFunction[IRP_MJ_CLOSE]				  = CFilterEngine::DispatchClose;
			driver->MajorFunction[IRP_MJ_READ]				  = CFilterEngine::DispatchRead;
			driver->MajorFunction[IRP_MJ_WRITE]				  = CFilterEngine::DispatchWrite;
			driver->MajorFunction[IRP_MJ_QUERY_INFORMATION]	  = CFilterEngine::DispatchQueryInformation;
			driver->MajorFunction[IRP_MJ_SET_INFORMATION]	  = CFilterEngine::DispatchSetInformation;
			driver->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]	  = CFilterEngine::DispatchDirectoryControl;
			driver->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = CFilterEngine::DispatchFsControl;
			driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]	  = CFilterEngine::DispatchDeviceControl;
			driver->MajorFunction[IRP_MJ_SHUTDOWN]			  = CFilterEngine::DispatchShutdown;
			driver->MajorFunction[IRP_MJ_CLEANUP]			  = CFilterEngine::DispatchCleanup;
			
			// init engine implicitly
			status = CFilterControl::Init(driver, registry, device);

			if(NT_SUCCESS(status))
			{
				// create symbolic link, so that clients can access our control object
				UNICODE_STRING deviceNameDos;
				RtlInitUnicodeString(&deviceNameDos, CFilterControl::s_deviceNameDos);

				status = IoCreateSymbolicLink(&deviceNameDos, &deviceName);

				if(NT_SUCCESS(status)) 
				{
					DBGPRINT(("DriverEntry: Ready\n"));

					return status;
				}

				DBGPRINT(("DriverEntry -ERROR: IoCreateSymbolicLink() failed [0x%08x]\n", status));
			}

			ExFreePool(fastIo);
		}

		IoDeleteDevice(device);	
	}
	else
	{
		DBGPRINT(("DriverEntry -ERROR: IoCreateDevice() failed [0x%08x]\n", status));
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


