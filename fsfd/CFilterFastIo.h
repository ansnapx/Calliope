////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterFastIo.h: interface for the CFilterFastIo class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERFASTIO_H__35472D28_B024_48C3_A7EC_903CE086520F__INCLUDED_)
#define AFX_CFILTERFASTIO_H__35472D28_B024_48C3_A7EC_903CE086520F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterFastIo  
{

public:

	static NTSTATUS		Init(FAST_IO_DISPATCH **fastIoDispatch);

private:

	static void			Detach(DEVICE_OBJECT *SourceDevice, DEVICE_OBJECT *TargetDevice);

	static BOOLEAN		Check(FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, BOOLEAN wait, ULONG lock, BOOLEAN CheckForReadOperation, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		Read( FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, BOOLEAN wait, ULONG lock, void *Buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		Write(FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, BOOLEAN wait, ULONG lock, void *Buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);

	static BOOLEAN		QueryBasic(FILE_OBJECT *file, BOOLEAN wait, FILE_BASIC_INFORMATION *buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		QueryStandard(FILE_OBJECT *file, BOOLEAN wait, FILE_STANDARD_INFORMATION *buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);

	static BOOLEAN		Lock(FILE_OBJECT *file, LARGE_INTEGER *offset, LARGE_INTEGER *length, PEPROCESS ProcessId, ULONG Key, BOOLEAN FailImmediately, BOOLEAN	ExclusiveLock, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		UnlockOne(FILE_OBJECT *file, LARGE_INTEGER *offset, LARGE_INTEGER *length, PEPROCESS ProcessId, ULONG key, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		UnlockAll(FILE_OBJECT *file, PEPROCESS ProcessId, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		UnlockKey(FILE_OBJECT *file, void *ProcessId, ULONG key, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);

	static BOOLEAN		MdlRead(FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, ULONG	lock, MDL** MdlChain, IO_STATUS_BLOCK* ioStatus, DEVICE_OBJECT* device);
	static BOOLEAN		MdlReadComplete(FILE_OBJECT *file, MDL *MdlChain, DEVICE_OBJECT *device);
	static BOOLEAN		PrepareMdlWrite(FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, ULONG lock, MDL **MdlChain, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		MdlWriteComplete(FILE_OBJECT*file, LARGE_INTEGER *offset, MDL *MdlChain, DEVICE_OBJECT *device);

	static BOOLEAN		ReadCompressed(FILE_OBJECT  *file, LARGE_INTEGER *offset, ULONG length, ULONG lock, void *buffer, MDL **MdlChain, IO_STATUS_BLOCK *ioStatus, struct _COMPRESSED_DATA_INFO *CompressedDataInfo, ULONG CompressedDataInfoLength, DEVICE_OBJECT *device);
	static BOOLEAN		WriteCompressed(FILE_OBJECT *file, LARGE_INTEGER *offset, ULONG length, ULONG lock, void *buffer, MDL **MdlChain, IO_STATUS_BLOCK *ioStatus, struct _COMPRESSED_DATA_INFO *CompressedDataInfo, ULONG CompressedDataInfoLength, DEVICE_OBJECT *device);

	static BOOLEAN		MdlReadCompleteCompressed(FILE_OBJECT  *file, MDL *MdlChain, DEVICE_OBJECT *device);
	static BOOLEAN		MdlWriteCompleteCompressed(FILE_OBJECT *file, LARGE_INTEGER *offset, MDL *MdlChain, DEVICE_OBJECT *device);

	static BOOLEAN		DeviceControl(FILE_OBJECT *file, BOOLEAN wait, void *inputBuffer, ULONG inputBufferLength, void *outputBuffer, ULONG outputBufferLength, ULONG ctrlCode, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		QueryNetworkOpenInfo(FILE_OBJECT *file, BOOLEAN wait, FILE_NETWORK_OPEN_INFORMATION *buffer, IO_STATUS_BLOCK *ioStatus, DEVICE_OBJECT *device);
	static BOOLEAN		QueryOpen(IRP *irp, FILE_NETWORK_OPEN_INFORMATION *info, DEVICE_OBJECT *device);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // !defined(AFX_CFILTERFASTIO_H__35472D28_B024_48C3_A7EC_903CE086520F__INCLUDED_)
