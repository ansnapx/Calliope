/////////////////////////////////////////////////////////////////////////////////////////
//
// DaemonTask.cpp: implementation for the DaemonTask class.
//
// Author: Michael Alexander Priske
//
/////////////////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include <assert.h>
#include "CFilterClient.h"

#include "Daemon.h"
#include "DaemonTask.h"
#include "dbt.h"
#include "CheckParentThread.h"
/////////////////////////////////////////////////////////////////////////////////////////

DaemonTask*	DaemonTask::s_instance = 0;

LPCWSTR DaemonTask::c_wndClass = L"FileCryptOfAZClass";
LPCWSTR DaemonTask::c_wndTitle = L"FileCryptOfAZTitle";

HRESULT DaemonTask::Start(HANDLE shutdown, HANDLE prefs)
{
	m_shutdown = shutdown;
	m_prefs	   = prefs;

	s_instance = this;

	// Should not be set already
	assert(!m_watcher);
	m_watcher = ::CreateThread(0,0, Watcher, this, 0, &m_watcherId);

	if(!m_watcher)
	{
		return HRESULT_FROM_WIN32(::GetLastError());
	}

	return S_OK;
}

void DaemonTask::Stop()
{
	if(m_watcher)
	{
		assert(m_watcherId);

		// Stop Logoff Watcher
		::PostThreadMessage(m_watcherId, WM_QUIT, 0,0);

		::WaitForSingleObject(m_watcher, INFINITE);
		::CloseHandle(m_watcher);

		m_watcher   = 0;
		m_watcherId = 0;
	}

	for(ULONG index = 0; index < sizeof(m_devices)/sizeof(m_devices[0]); ++index)
	{
		if(m_devices[index])
		{
			free(m_devices[index]);
			m_devices[index] = 0;
		}
	}

	s_instance = 0;
}

LRESULT CALLBACK DaemonTask::WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if(!s_instance)
	{
		// Handle the impossible
		return ::DefWindowProc(hwnd, message, wParam, lParam);
	}
	 
	if(s_instance->m_prefsWnd == message)
	{
		if(s_instance->m_prefs)
		{
			// Forward Prefs file update notifications
			::SetEvent(s_instance->m_prefs);
		}

		return 1;
	}

	switch(message)
	{
		case WM_CREATE:
			// Enumerate active devices
			s_instance->EnumDevices();
			return 0;
		case WM_DRIVER_EVENT:
			  {
				  int nStatus=(int)wParam;
				  if (nStatus==1)
				  {
					//  ::MessageBox(NULL,L"FileCrypt",L"yes",MB_OK);
					  Daemon::StartDriver();
				  }
				  else
				  {
					 // ::MessageBox(NULL,L"FileCrypt",L"no",MB_OK);
					  Daemon::StopDriver();
				  }
			  }
			  break;

		case WM_DESTROY:
			::PostQuitMessage(0);
			return 0;

		case WM_QUERYENDSESSION:
			break;

		case WM_FILE_CRYPT_END:

			if((1 == (int)wParam) && (1==(int)lParam) )
			{
				Daemon::StopDriver();
				if(s_instance->m_shutdown)
				{
					::SetEvent(s_instance->m_shutdown);
				}				
			}
			break;

		 case WM_DEVICECHANGE:
		 {
			if((DBT_DEVICEARRIVAL == wParam) || (DBT_DEVICEREMOVECOMPLETE == wParam))
			{
				if(lParam && (DBT_DEVTYP_VOLUME == ((DEV_BROADCAST_HDR*) lParam)->dbch_devicetype))
				{
					DEV_BROADCAST_VOLUME *const vol = (DEV_BROADCAST_VOLUME*) lParam;

					if(vol->dbcv_flags & DBTF_NET)
					{
						if(DBT_DEVICEARRIVAL == wParam)
						{
							// Enumerate active devices
							s_instance->EnumDevices();
						}
						else //if(DBT_DEVICEREMOVECOMPLETE == wParam)
						{
							// Cleanup disconnected network drive
							s_instance->RemoveDeviceNetwork(vol->dbcv_unitmask);
						}
					}
					else if(vol->dbcv_flags & DBTF_MEDIA)
					{
						if(DBT_DEVICEREMOVECOMPLETE == wParam)
						{
							// Cleanup removed media
							s_instance->RemoveDeviceRemovable(vol->dbcv_unitmask);
						}
					}
				}
			}

			return 1;
		}
		default:
			break;
	};

	return ::DefWindowProc(hwnd, message, wParam, lParam);
}

DWORD WINAPI DaemonTask::Watcher(void *context)
{
	assert(context);

	WNDCLASS wcl;
	memset(&wcl, 0, sizeof(wcl));

	wcl.lpfnWndProc	  = WndProc;
	wcl.lpszClassName = c_wndClass;

	if(::RegisterClass(&wcl))
	{
		// Create hidden Window for all sorts of notifications: 
		// logoff detection, device changes and Prefs file updates
		HWND const wnd = ::CreateWindow(c_wndClass, 
										c_wndTitle, 
										WS_OVERLAPPED, 
										0,
										0,
										0,
										0,
										0,
										0,
										0,
										0);

		if(wnd)
		{
			DaemonTask::AllowMeesageForVista(WM_DRIVER_EVENT,true);
			// Get Prefs File Update Window message
			s_instance->m_prefsWnd = ::RegisterWindowMessage(kPGPclReloadPrefsMsg);

			DEV_BROADCAST_DEVICEINTERFACE filter;
			memset(&filter, 0, sizeof(filter));

			filter.dbcc_size		= sizeof(DEV_BROADCAST_DEVICEINTERFACE);
			filter.dbcc_devicetype	= DBT_DEVTYP_DEVICEINTERFACE;
			filter.dbcc_classguid	= GUID_DEVINTERFACE_VOLUME;
			
			// We want being notified on device changes
			HDEVNOTIFY const dev = ::RegisterDeviceNotification(wnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);

			MSG  msg;
			BOOL ret;

			while(ret = ::GetMessage(&msg, 0,0,0))
			{ 
				if(-1 == ret)
				{
					break;
				}
				else
				{
					::TranslateMessage(&msg); 
					::DispatchMessage(&msg); 
				}
			} 

			if(dev)
			{
				::UnregisterDeviceNotification(dev);
			}
		}
	}

	return NO_ERROR;
}

HRESULT	DaemonTask::EnumDevices()
{
	ULONG const drives = ::GetLogicalDrives();

	for(ULONG index = 0; index < 26; ++index)
	{
		if( !(drives & (1 << index)))
		{
			if(m_devices[index])
			{
				free(m_devices[index]);
				m_devices[index] = 0;
			}

			continue;
		}

		WCHAR const drive[] = { WCHAR (L'A' + index), L':', UNICODE_NULL };

		// Query only remote drives
		if(DRIVE_REMOTE != ::GetDriveType(drive))
		{
			if(m_devices[index])
			{
				free(m_devices[index]);
				m_devices[index] = 0;
			}

			continue;
		}

		WCHAR device[256] = {0};

		if(::QueryDosDevice(drive, device, sizeof(device)/sizeof(WCHAR)))
		{
			HRESULT hr = AddDevice(device, index);

			if(FAILED(hr))
			{
				return hr;
			}
		}
	}

	return S_OK;
}

HRESULT	DaemonTask::AddDevice(LPWSTR device, ULONG pos)
{
	if(pos >= 26)
	{
		return E_INVALIDARG;
	}

	ULONG const deviceLen = (ULONG) wcslen(device);

	if(deviceLen < 8)	 
	{
		return E_INVALIDARG;
	}

	LPWSTR back = wcschr(device + 8, L'\\');

	if(back)
	{
		back = wcschr(back + 1, L'\\');

		if(back)
		{
			if(back[1] == L';')
			{
				back = wcschr(back + 1, L'\\');
			}

			if(back)
			{
				if(m_devices[pos])
				{
					if(!_wcsicmp(m_devices[pos], back))
					{
						return S_FALSE;
					}

					free(m_devices[pos]);
				}

				m_devices[pos] = (LPWSTR) malloc((deviceLen - (back - device) + 1) * sizeof(WCHAR));

				if(!m_devices[pos])
				{
					return E_OUTOFMEMORY;
				}

				wcscpy(m_devices[pos], back);

				return S_OK;
			}
		}
	}

	return E_INVALIDARG;
}

HRESULT	DaemonTask::RemoveDeviceRemovable(ULONG mask)
{
	if(!mask)
	{
		return E_INVALIDARG;
	}

	// Transform to drive index
	ULONG pos = 0;

	while( !(mask & (1 << pos)))
	{
		pos++;
	}

	if(pos >= 26)
	{
		return E_INVALIDARG;
	}

	WCHAR const drive[3] = { (WCHAR) (pos + L'A'), L':', UNICODE_NULL };

	WCHAR device[256] = {0};

	::QueryDosDevice(drive, device, sizeof(device)/sizeof(device[0]));

	ULONG deviceLen = (ULONG) wcslen(device);

	if(deviceLen)
	{
		// Add trailing backslash to compare the device name completely
		device[deviceLen] = L'\\';
		deviceLen++;
		device[deviceLen] = UNICODE_NULL;

		// Enumerate all active Entities natively, i.e. including device names
		ULONG entitiesSize  = 0;
		LPWSTR entities		= 0;

		HRESULT hr = CFilterClient::EnumEntities(&entities, &entitiesSize, true);

		if(S_OK == hr)
		{
			assert(entities);
			assert(entitiesSize);

			ULONG index = 0;
			
			while(index < entitiesSize)
			{
				LPWSTR const current = entities + index;
				ULONG const len		 = (ULONG) wcslen(current);

				if(!len)
				{
					break;
				}

				if(len >= deviceLen)
				{
					// Does path start with same device?
					if(!_wcsnicmp(current, device, deviceLen))
					{
						CFilterClient::RemoveEntity(current);
					}
				}
				
				index += 1 + len;
			};

			free(entities);
		}
	}

	return S_OK;
}

HRESULT	DaemonTask::RemoveDeviceNetwork(ULONG mask)
{
	if(!mask)
	{
		return E_INVALIDARG;
	}

	// Transform to position info
	ULONG pos = 0;

	while( !(mask & (1 << pos)))
	{
		pos++;
	}

	if(pos >= 26)
	{
		return E_INVALIDARG;
	}

	if(!m_devices[pos])
	{
		return S_FALSE;
	}

	ULONG const deviceLen = (ULONG) wcslen(m_devices[pos]);

	if(deviceLen)
	{
		// Enumerate all active Entities, denormalized
		ULONG entitiesSize  = 0;
		LPWSTR entities		= 0;

		HRESULT hr = CFilterClient::EnumEntities(&entities, &entitiesSize);

		if(S_OK == hr)
		{
			assert(entities);
			assert(entitiesSize);

			ULONG index = 0;
			
			while(index < entitiesSize)
			{
				LPWSTR const current = entities + index;
				ULONG const len		 = (ULONG) wcslen(current);

				if(!len)
				{
					break;
				}

				if(len >= deviceLen)
				{
					// Does path start with same server/share?
					if(!_wcsnicmp(current + 1, m_devices[pos], deviceLen))
					{
						CFilterClient::RemoveEntity(current);
					}
				}
				
				index += 1 + len;
			};

			free(entities);
		}
	}

	free(m_devices[pos]);
	m_devices[pos] = 0;

	return S_OK;
}


BOOL DaemonTask::AllowMeesageForVista(UINT uMessageID, BOOL bAllow)// ×¢²áVistaÈ«
{
	OSVERSIONINFO osvi={0};
	::GetVersionEx( &osvi );
	if ( osvi.dwMajorVersion == 6 )
	{
		BOOL bResult = FALSE; 
		HMODULE hUserMod = NULL; 
		//vista and later 
		hUserMod = LoadLibrary( L"user32.dll" );
		if( NULL == hUserMod ) 
		{ 
			return FALSE; 
		} 

		_ChangeWindowMessageFilter pChangeWindowMessageFilter = (_ChangeWindowMessageFilter)GetProcAddress( hUserMod, "ChangeWindowMessageFilter" ); 
		if( NULL == pChangeWindowMessageFilter ) 
		{ 
			return FALSE; 
		}
		bResult = pChangeWindowMessageFilter( uMessageID, bAllow ? 1 : 2 );//MSGFLT_ADD: 1, MSGFLT_REMOVE: 2
		if( NULL != hUserMod )
		{
			FreeLibrary( hUserMod );
		}
		return bResult;
	}	

	return FALSE; 
}