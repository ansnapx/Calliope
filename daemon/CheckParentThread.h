#pragma once

typedef struct _CMD_LINE
{
	WORD Magic;//±ê×¢Î»
	WCHAR ProcessId[10];
	WCHAR  HidePath[10];
	WCHAR  bootPath[10];
}CmdLine,*pCmdLine;


class CCheckParentThread
{
public:
	static CmdLine s_CmdLine;

	BOOL static CreateCmdLine(WCHAR* output);
	CCheckParentThread(void);
	void Start();
	~CCheckParentThread(void);
private:
	HANDLE m_hThread;
	DWORD m_dwParentProcessID;
	TCHAR m_tcharParentProcessName[MAX_PATH];
	DWORD static WINAPI _Worker(LPVOID lp);
	DWORD static WINAPI _Worker2(LPVOID lp);
public:
	DWORD GetParent();
	DWORD CopyConfigFile();
	void GetProcessName(DWORD pdwId,TCHAR* pName);
public:
	HANDLE m_hEventshutdown;
	static bool                     s_IsUnInstall;
	
};
