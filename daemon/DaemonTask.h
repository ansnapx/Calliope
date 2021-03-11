/////////////////////////////////////////////////////////////////////////////////////////
//
// DemonTask.h: Interface for the DemonTask class.
//
// Author: Michael Alexander Priske
//
/////////////////////////////////////////////////////////////////////////////////////////

#if !defined(DemonTask__INCLUDED_)
#define DemonTask__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif

#include <windows.h>

//#define kPGPclReloadKeyRingMsg			PGPTXT_MACHINE("XDisk Keyrings Reload")
#define kPGPclReloadPrefsMsg			PGPTXT_MACHINE("XDisk Prefs Reload")
//#define kPGPclReloadPolicyMsg			PGPTXT_MACHINE("XDisk Policy Reload")
//#define kPGPclReloadKeyserverPrefsMsg	PGPTXT_MACHINE("XDisk Keyserver Prefs Reload")
#define WM_DRIVER_EVENT WM_USER+0x10
#define WM_FILE_CRYPT_END WM_USER+0x20


typedef BOOL (WINAPI *_ChangeWindowMessageFilter)( UINT , DWORD); 

/////////////////////////////////////////////////////////////////////////////////////////

class DaemonTask
{
public:
							DaemonTask()
							{ memset(this, 0, sizeof(*this)); }
	
	HRESULT					Start(HANDLE shutdown, HANDLE prefs=NULL);
	void					Stop();

private:

	HRESULT					EnumDevices();
	HRESULT					AddDevice(LPWSTR device, ULONG pos);

	HRESULT					RemoveDeviceNetwork(ULONG mask);
	HRESULT					RemoveDeviceRemovable(ULONG mask);

	HANDLE					m_shutdown;		// Is set when logoff is detectecd

	HANDLE					m_prefs;		// Is set on Prefs file updates
	UINT					m_prefsWnd;		// Window message for Pref updates

	HANDLE					m_watcher;
	DWORD					m_watcherId;

	LPWSTR					m_devices[26];

							// STATIC
	static DWORD WINAPI		Watcher(void *context);

	static LRESULT CALLBACK	WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

	static LPCWSTR			c_wndClass;
	static LPCWSTR			c_wndTitle;

	static DaemonTask*		s_instance;

	static BOOL AllowMeesageForVista(UINT uMessageID, BOOL bAllow);// ×¢²áVistaÈ«
};

/////////////////////////////////////////////////////////////////////////////////////////
#endif //DemonTask__INCLUDED_