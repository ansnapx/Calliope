////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterEngine.h: interface for the CFilterEngine class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterEngine__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
#define AFX_CFilterEngine__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

typedef
NTSTATUS
( *PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS ) ( 
	IN PDRIVER_OBJECT DriverObject,
	IN PFS_FILTER_CALLBACKS Callbacks
	);

typedef
NTSTATUS
( *PSF_ENUMERATE_DEVICE_OBJECT_LIST ) ( 
									   IN  PDRIVER_OBJECT DriverObject,
									   IN  PDEVICE_OBJECT *DeviceObjectList,
									   IN  ULONG DeviceObjectListSize,
									   OUT PULONG ActualNumberDeviceObjects
									   );

typedef
NTSTATUS
( *PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE ) ( 
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice,
	OUT PDEVICE_OBJECT *AttachedToDeviceObject
	);

typedef
PDEVICE_OBJECT
( *PSF_GET_LOWER_DEVICE_OBJECT ) ( 
								  IN  PDEVICE_OBJECT  DeviceObject
								  );

typedef
PDEVICE_OBJECT
( *PSF_GET_DEVICE_ATTACHMENT_BASE_REF ) ( 
	IN PDEVICE_OBJECT DeviceObject
	);

typedef
NTSTATUS
( *PSF_GET_DISK_DEVICE_OBJECT ) ( 
								 IN  PDEVICE_OBJECT  FileSystemDeviceObject,
								 OUT PDEVICE_OBJECT  *DiskDeviceObject
								 );

typedef
PDEVICE_OBJECT
( *PSF_GET_ATTACHED_DEVICE_REFERENCE ) ( 
										IN PDEVICE_OBJECT DeviceObject
										);

typedef
NTSTATUS
( *PSF_GET_VERSION ) ( 
					  IN OUT PRTL_OSVERSIONINFOW VersionInformation
					  );

typedef struct _SF_DYNAMIC_FUNCTION_POINTERS {

	//
	//  The following routines should all be available on Windows XP ( 5.1 ) and
	//  later.
	
	PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS RegisterFileSystemFilterCallbacks;
	PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE AttachDeviceToDeviceStackSafe;
	PSF_ENUMERATE_DEVICE_OBJECT_LIST EnumerateDeviceObjectList;
	PSF_GET_LOWER_DEVICE_OBJECT GetLowerDeviceObject;
	PSF_GET_DEVICE_ATTACHMENT_BASE_REF GetDeviceAttachmentBaseRef;
	PSF_GET_DISK_DEVICE_OBJECT GetDiskDeviceObject;
	PSF_GET_ATTACHED_DEVICE_REFERENCE GetAttachedDeviceReference;
	PSF_GET_VERSION GetVersion;

} SF_DYNAMIC_FUNCTION_POINTERS, *PSF_DYNAMIC_FUNCTION_POINTERS;

extern SF_DYNAMIC_FUNCTION_POINTERS g_SfDynamicFunctions;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterEngine  
{
	struct READ_WRITE_CONTEXT
	{
		MDL*	RequestMdl;
		void*	RequestUserBuffer;
		MDL*	RequestUserBufferMdl;

		UCHAR*	Buffer;
		ULONG	BufferSize;
	};

public:

	static NTSTATUS					Init(DRIVER_OBJECT* driverObject, DEVICE_OBJECT* control, LPCWSTR regPath = 0);
	static NTSTATUS					Close(DRIVER_OBJECT* driver);
									
	static NTSTATUS					DispatchCreate(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchCleanup(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchClose(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchRead(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchWrite(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchQueryInformation(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchSetInformation(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchDirectoryControl(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchPass(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchShutdown(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchDeviceControl(DEVICE_OBJECT* device, IRP* irp);
	static NTSTATUS					DispatchFsControl(DEVICE_OBJECT* device, IRP* irp);
	
	static void						FileSystemRegister(DEVICE_OBJECT* device, BOOLEAN active);
	static NTSTATUS					LogonTermination(LUID *luid = 0);
	static void                     SfLoadDynamicFunctions ();
	static NTSTATUS                 SfEnumerateFileSystemVolumes(IN DEVICE_OBJECT *device);

	static LONG						s_state;	// controls states the driver operates in

private:
		
#if FILFILE_USE_PADDING
	static NTSTATUS					ReadNonAligned(FILFILE_VOLUME_EXTENSION* extension, IRP *irp, LONGLONG vdl, FILFILE_CRYPT_CONTEXT *crypt);
	static NTSTATUS					WriteNonAligned(FILFILE_VOLUME_EXTENSION* extension, IRP* irp, CFilterContextLink *link);
#endif

	static NTSTATUS					ReadMdl(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link);
	static NTSTATUS					ReadBypass(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link);

	static NTSTATUS					Write(FILFILE_VOLUME_EXTENSION* extension, IRP* irp, CFilterContextLink *link);
	static NTSTATUS					WriteMdl(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link);
	static NTSTATUS					WriteBypass(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp, CFilterContextLink *link);
	static NTSTATUS					WritePrepare(FILFILE_VOLUME_EXTENSION* extension, IRP* irp, CFilterContextLink *link);
	static NTSTATUS					WritePreparePaging(FILFILE_VOLUME_EXTENSION* extension, IRP* irp, CFilterContextLink *link);

	static NTSTATUS					WriteAlreadyEncrypted(FILFILE_VOLUME_EXTENSION *const extension, IRP *irp);

	static NTSTATUS					CompletionRead(DEVICE_OBJECT *device, IRP *irp, void *context);
	static NTSTATUS					CompletionReadNonAligned(DEVICE_OBJECT *device, IRP *irp, void *context);
	static NTSTATUS					CompletionReadCached(DEVICE_OBJECT *device, IRP *irp, void *context);
	static NTSTATUS					CompletionSetInformation(DEVICE_OBJECT *device, IRP *irp, void *context);
	static NTSTATUS					CompletionWrite(DEVICE_OBJECT* device, IRP* irp, void* context);
#if DBG
	 static NTSTATUS				CompletionWriteCached(DEVICE_OBJECT* device, IRP* irp, void *context);
#endif

	static NTSTATUS					Rename(FILFILE_VOLUME_EXTENSION *extension, IRP *irp); 

	static NTSTATUS					Delete(FILFILE_VOLUME_EXTENSION *extension, IRP *irp);
	static NTSTATUS					Delete(FILFILE_VOLUME_EXTENSION *extension, FILFILE_TRACK_CONTEXT *track);

	static NTSTATUS					DirectoryQuery(IRP *irp, ULONG headerSize);
	static NTSTATUS					DirectoryQuerySizes(void *entry, ULONG entryType, ULONG headerSize);
	static ULONG					DirectoryQueryNames(UCHAR *buffer, ULONG bufferSize, void *entry, ULONG entryType);

	static NTSTATUS					FsMountVolume(DEVICE_OBJECT *device, IRP *irp);
	static NTSTATUS					FsLoadFileSystem(DEVICE_OBJECT *device, IRP *irp);
	static NTSTATUS					FsUserRequest(DEVICE_OBJECT *device, IRP *irp);

	static bool						EstimateCaching(FILFILE_VOLUME_EXTENSION *extension, IRP *irp, FILE_OBJECT *file, CFilterContextLink *link);
	static bool						SkipCreate(DEVICE_OBJECT *device, IRP *irp);
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterEngine__282CD2A0_AD3A_4F79_96F8_376CE0B39421__INCLUDED_)
