
#ifndef Included_Daemon_h
#define Included_Daemon_h

#include <windows.h>
//#include "CalliopeListHandler.h"

class Daemon
{
	friend class DaemonTask;

public:
	Daemon();
	~Daemon();

	static HRESULT					Init();
	static void						Close();

	static HRESULT					Observe();
	static HRESULT					Restart();
	static HRESULT					Shutdown();
	static void						ResetSkipped();
	static HRESULT					StopDriver();
	static WCHAR*                   s_tDirtory;

	static char*                   s_keybuffer;
	static ULONG                   s_KeyBufferSize;

private:

	static HRESULT					StartDriver();
	
	//static BOOL                     UninstallPGPfsfd();
									// Callbacks registered with driver
	static HRESULT					RequestRandomProc(void*, UCHAR* buffer, ULONG size);
	static HRESULT					RequestKeyProc(void*, UCHAR* key, ULONG* keySize, LPCWSTR path, UCHAR* header, ULONG headerSize);
	static HRESULT					NotifyProc(void* context, UCHAR** path, ULONG* size);

	static bool						CheckCmdLine();
	static bool						IsInstalled();

	static bool						IsSkipped(LPCWSTR path);
	static void						Skip(LPCWSTR path);

//	static CalliopeListHandler		s_handler;
	static CRITICAL_SECTION			s_skipLock;			// Sync
	//static CalliopePath				s_skipList;
	//static CalliopeDaemonManagerEntity  s_entity;
	
};

inline HRESULT Daemon::Init()
{
	::InitializeCriticalSection(&s_skipLock);
	return S_OK;
}

inline void Daemon::Close()
{
	::DeleteCriticalSection(&s_skipLock);
}
#endif /* Included_Daemon_h */
