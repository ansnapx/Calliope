#include "stdafx.h"
#include <assert.h>
#include "CFilterClient.h"
/*
#include "pgpClientLib.h"
#include "pgpClientNotifier.h"
#include "PGPrc.h"

#include "CalliopeDefinitions.h"
#include "CFilterClient.h"

#include "CalliopeHelper.h"
#include "CalliopeContext.h"
#include "CalliopeConfig.h"
#include "CalliopePayload.h"
#include "CalliopeManager.h"
#include "CalliopeAction.h"
*/
#include "CheckParentThread.h"

#include <atlbase.h>	
#include "..\daemon\wtl\atlapp.h"
#include "..\daemon\wtl\atlmisc.h"

#include "Daemon.h"
#include "DaemonTask.h"
#include <shellapi.h>
#include <fstream>
#include <iostream>

#define FILE_CONFIG_SIZE 5*1024

//CalliopePath			Daemon::s_skipList;
CRITICAL_SECTION		Daemon::s_skipLock;
//CalliopeDaemonManagerEntity Daemon::s_entity;

WCHAR*                  Daemon::s_tDirtory=NULL;

char*                   Daemon::s_keybuffer=NULL;
ULONG                   Daemon::s_KeyBufferSize=4*1024;

Daemon::~Daemon()
{
	if (s_keybuffer)
	{
		delete[] s_keybuffer;
		s_keybuffer=0;
	}

	if (s_tDirtory)
	{
		delete[] s_tDirtory;
		s_tDirtory=NULL;
	}
	
}

///////////////////////////////////////////////////////////////////////////////

bool Daemon::CheckCmdLine()
{
	bool found = false;

	int argsCount = 0;
	LPWSTR *args  = ::CommandLineToArgvW(::GetCommandLine(), &argsCount);

	if(args)
	{
		for(int index = 1; index < argsCount; ++index)
		{
			if(!_wcsicmp(args[index], L"shutdown") || 
			   !_wcsicmp(args[index], L"-shutdown"))
			{
				found = true;
				break;
			}
		}

		::LocalFree(args);
	}

	return found;
}

bool Daemon::IsInstalled()
{
	bool installed = true;
	return installed;
}

HRESULT Daemon::Observe()
{
	// Delay restart a little so a crashed process can die silently...
	//::Sleep(500);
	// Single instance mutex
	HANDLE mutex = ::CreateMutex(0, true, CalliopeDaemon_Mutex);
	if(!mutex)
	{
		return HRESULT_FROM_WIN32(::GetLastError());
	}
	// Check mutex state
	if(ERROR_ALREADY_EXISTS == ::GetLastError())
	{	
		return E_FAIL;		
	}	

	HANDLE events=0;
	// Create the Shutdown event, if not already done
	events= ::CreateEvent(0, true, false, CalliopeDaemon_Event_Shutdown);
	if(!events)
	{
		::CloseHandle(mutex);

		return HRESULT_FROM_WIN32(::GetLastError());
	}

	// Attached to existing event?
	if(ERROR_ALREADY_EXISTS == ::GetLastError())
	{
		// Check whether we should stop immediately
		if(WAIT_OBJECT_0 == ::WaitForSingleObject(events,0))
		{
			::CloseHandle(events);
			//::CloseHandle(mutex);
			
			events = ::CreateEvent(0, true, false, CalliopeDaemon_Event_Shutdown);
			if(!events)
			{
				::CloseHandle(mutex);

				return HRESULT_FROM_WIN32(::GetLastError());
			}
			//return S_FALSE;
		}
	}

	// Create reset skipped zones event
// 	events[1] = ::CreateEvent(0, false, false, CalliopeDaemon_Event_ResetSkippedZones);
// 	if(!events[1])
// 	{
// 		::CloseHandle(events[0]);
// 		::CloseHandle(mutex);
// 
// 		return HRESULT_FROM_WIN32(::GetLastError());
// 	}

	// Create internal Prefs File update event

//	CalliopeDaemonManagerEntity::s_ADDEntityEvent=::CreateEvent(0, false, true, CalliopeDaemonManagerEntity::CalliopeDaemon_Event_ADDEntity);

//	if(!CalliopeDaemonManagerEntity::s_ADDEntityEvent)
	//{
		//::CloseHandle(events[0]);
	//	::CloseHandle(events[1]);
		//::CloseHandle(prefs);
		//::CloseHandle(mutex);

	//	return HRESULT_FROM_WIN32(::GetLastError());
	//}
//读取文件
	//WCHAR Temp[MAX_PATH]={0};
	//try
	//{
	//	wprintf(Temp,L"%s%s",s_tDirtory,L"mbc.dat");
//	}
	//catch (...)
	//{
		//goto INI;
	//}

// 	std::ifstream fin (s_tDirtory,std::ios::binary);
// 	
// 	try
// 	{
// 		s_keybuffer=new char[FILE_CONFIG_SIZE];
// 		ZeroMemory(s_keybuffer,FILE_CONFIG_SIZE);
// 		fin.seekg(0,std::ios_base::end);   //   把文件指针到尾部 
// 		s_KeyBufferSize=fin.tellg();   //   获得文件字节数
// 		//   如果读取文件，需要把文件指针指向文件开始出 
// 		fin.seekg(0,std::ios_base::beg); 
// 		fin.read((char *)s_keybuffer,FILE_CONFIG_SIZE); 
// 		fin.close();
// 	}
// 	catch (...)
// 	{
// 		fin.close();
// 	}
	

	// Start Watcher
INI:	DaemonTask watcher;
	watcher.Start(events);
	// Switch driver on and connect our callbacks
	HRESULT hr = StartDriver();

	if (hr!=S_OK)
	{
		return false;
	}		

	//CCheckParentThread ct;
	//ct.Start();

	//if(SUCCEEDED(hr))
	//{
	// Set Black and Whitelist and have Whitelist processed triggered 
	// by the Prefs file event set by our hidden window

	while(true)
	{
		// Handle shutdown/skip events
		DWORD const wait = ::WaitForSingleObject(events,INFINITE);
		// Shutdown or Error?
		if((wait == WAIT_OBJECT_0) || (wait == WAIT_FAILED))
		{
			break;
		}
// 		else if(wait == WAIT_OBJECT_0 + 1)
// 		{
// 			// Skip recent zones
// 			ResetSkipped();
// 		}
	}
	//}
	// Stop Watcher
	watcher.Stop();
	// Tear down key cache, disconnect and switch driver off
	StopDriver();
	::CloseHandle(events);
	::CloseHandle(mutex);
	ResetSkipped();
	
	return S_OK;
}

HRESULT Daemon::StartDriver()
{
	HRESULT hr = CFilterClient::SetDriverState(CFilterClient::Active);

	if(CFilterClient::GetDriverState() == CFilterClient::Active)
	{
		if(SUCCEEDED(hr))
		{
			// Register callback functions
			CFilterClient::RegisterCallbacks(0, RequestRandomProc,RequestKeyProc,NotifyProc);
		}
	}

	return hr;
}

HRESULT Daemon::StopDriver()
{
	CFilterClient::RegisterCallbacks();
		// Tear down driver key cache
	CFilterClient::RemoveEntities();
		// Switch off
	CFilterClient::SetDriverState(CFilterClient::Passive);
	return S_OK;
}

HRESULT Daemon::Restart()
{
	// Here goes the restart code...
	LRESULT lResult = (LRESULT) ::ShellExecute(0, L"open", L"FileCrypt.exe", 0,0, SW_HIDE);
	if (lResult <= 32)
	{
		// Error...
		return HRESULT_FROM_WIN32(lResult);
	}

	return S_OK;
}

HRESULT Daemon::Shutdown()
{
	HANDLE shutdown = ::OpenEvent(EVENT_MODIFY_STATE, false, CalliopeDaemon_Event_Shutdown);
	if(!shutdown)
	{
		return HRESULT_FROM_WIN32(::GetLastError());
	}

	::SetEvent(shutdown); 
	::CloseHandle(shutdown);

	return S_OK;
}

HRESULT Daemon::RequestRandomProc(void*, UCHAR *buffer, ULONG size)
{
	if(!buffer || !size)
	{
		return E_INVALIDARG;
	}

//	CalliopeHelper helper;
//	helper.Init(CalliopeContext::GetContext());

	//PGPError err = helper.GetRandom(buffer, size);

	return S_OK;
}

HRESULT Daemon::RequestKeyProc(void*, UCHAR* key, ULONG* keySize, LPCWSTR path, UCHAR* header, ULONG headerSize)
{
	return S_OK;
}

HRESULT Daemon::NotifyProc(void* context, UCHAR** path, ULONG* size)
{
	*path=(UCHAR*)((byte*)s_keybuffer);
	*size=s_KeyBufferSize;
	return S_OK;
}

bool Daemon::IsSkipped(LPCWSTR path)
{
	if(!path)
	{
		return false;
	}

	::EnterCriticalSection(&s_skipLock);
	::LeaveCriticalSection(&s_skipLock);

	return 0;
}

void Daemon::Skip(LPCWSTR path)
{
	::EnterCriticalSection(&s_skipLock);

//	s_skipList.AddChecked(path);

	::LeaveCriticalSection(&s_skipLock);
}

void Daemon::ResetSkipped()
{
	::EnterCriticalSection(&s_skipLock);

	//s_skipList.Close();

	::LeaveCriticalSection(&s_skipLock);
}
