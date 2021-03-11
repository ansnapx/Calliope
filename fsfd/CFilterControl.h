////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterControl.h: interface for the CFilterControl class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERCONTROL_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERCONTROL_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct FILFILE_CONTROL;
struct FILFILE_TRACK_CONTEXT;

/////////////////////////////////

class CFilterControl
{

public:

	static NTSTATUS						Init(DRIVER_OBJECT* driver, UNICODE_STRING* registryPath, DEVICE_OBJECT* control);
	static NTSTATUS						InitDeferred();
	static NTSTATUS						Close(DRIVER_OBJECT* driver);

	static NTSTATUS						Dispatch(DEVICE_OBJECT *device, IRP *irp);

	static NTSTATUS						GetVolumeDevice(FILE_OBJECT *file, DEVICE_OBJECT **device);
	static NTSTATUS						GetVolumeDevice(ULONG identifier, DEVICE_OBJECT **device);
	static NTSTATUS						GetVolumeDevice(UNICODE_STRING *deviceName, DEVICE_OBJECT **device);

	static NTSTATUS						AddVolumeDevice(DEVICE_OBJECT* device);
	static NTSTATUS						RemoveVolumeDevice(DEVICE_OBJECT* device);

	static FILFILE_CONTROL_EXTENSION*	Extension();
	static CFilterCallbackDisp&			Callback();

	static NTSTATUS						Connection(FILFILE_CONTROL *control, LUID const* luid = 0);

	static NTSTATUS                     AddCredibleProcess(FILFILE_CONTROL* control);

	static NTSTATUS                     SetControlReadOnly(FILFILE_CONTROL* control);

	static bool							IsWindows2000();
	static bool							IsWindowsXP();
	static bool							IsWindows2003();
	static bool							IsWindowsVista();	// Includes Windows server 2008
	static bool							IsWindows7();
	static bool							IsWindowsVistaOrLater();
	static bool							IsTerminalServices();

										// DATA
	static DEVICE_OBJECT*				s_control;
	static LPCWSTR						s_deviceNameDos;
	static ULONG						s_cdrom;
	static ULONG						s_transIEcache;

private:
	static NTSTATUS						DispatchValidate(IRP *irp);

	static NTSTATUS						State(FILFILE_CONTROL *control, UCHAR *userBuffer = 0, ULONG *userBufferSize = 0);

	static NTSTATUS						ManageEntity(FILFILE_CONTROL *control);
	static NTSTATUS						EnumEntitiesBool(FILFILE_CONTROL *control);
	static NTSTATUS						EnumEntities(FILFILE_CONTROL *control, UCHAR *userBuffer = 0, ULONG *userBufferSize = 0);
	static NTSTATUS						RemoveEntities(ULONG flags = ENTITY_REGULAR);
	
	static NTSTATUS						OpenFile(FILFILE_CONTROL *control, UCHAR *userBuffer, ULONG *userBufferSize);
	static NTSTATUS						Wiper(FILFILE_CONTROL *control);
	static NTSTATUS						ManageEncryption(FILFILE_CONTROL *control);

	static NTSTATUS						GetHeader(FILFILE_CONTROL *control, UCHAR* header, ULONG *headerSize);
	static NTSTATUS						SetHeader(FILFILE_CONTROL *control);

	static NTSTATUS						AppLists(FILFILE_CONTROL *control, ULONG cipher);
	static NTSTATUS						Blacklist(FILFILE_CONTROL *control, UCHAR *userBuffer = 0, ULONG *userBufferSize = 0);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
FILFILE_CONTROL_EXTENSION* CFilterControl::Extension()
{
	ASSERT(s_control);
	ASSERT(s_control->DeviceExtension);

	return (FILFILE_CONTROL_EXTENSION*) s_control->DeviceExtension;
}

inline
bool CFilterControl::IsWindows2000()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_WIN2000));
}

inline
bool CFilterControl::IsWindowsXP()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_WINXP));
}

inline
bool CFilterControl::IsWindows2003()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_WIN2003));
}

inline
bool CFilterControl::IsWindowsVista()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_WINVISTA));
}

inline
bool CFilterControl::IsWindows7()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_WIN7));
}

inline
bool CFilterControl::IsWindowsVistaOrLater()
{
	return (0 != (Extension()->SystemVersion & (FILFILE_SYSTEM_WINVISTA | FILFILE_SYSTEM_WIN7)));
}

inline
bool CFilterControl::IsTerminalServices()
{
	return (0 != (Extension()->SystemVersion & FILFILE_SYSTEM_TERMINAL));
}

inline
CFilterCallbackDisp& CFilterControl::Callback()
{
	return Extension()->Callback;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFILTERCONTROL_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_