#include "StdAfx.h"
#include ".\checkparentthread.h"
#include <PSAPI.H>
#include <Iphlpapi.h>
#include <tlhelp32.h>

#pragma comment(lib,"PSAPI.LIB")


bool CCheckParentThread::s_IsUnInstall=false;
CmdLine CCheckParentThread::s_CmdLine={0};

CCheckParentThread::CCheckParentThread(void)
{
	m_hEventshutdown=NULL;
	m_hEventshutdown= ::OpenEvent(EVENT_MODIFY_STATE, false, CalliopeDaemon_Event_Shutdown);
	
	m_dwParentProcessID=0;
	ZeroMemory(m_tcharParentProcessName,MAX_PATH);
	m_hThread=NULL;
}

CCheckParentThread::~CCheckParentThread(void)
{
	if (m_hThread)
	{
		CloseHandle(m_hThread);
	}
}

BOOL CCheckParentThread::CreateCmdLine(WCHAR* output)
{
	BOOL bRet=TRUE;

	if (!output)
	{
		bRet=FALSE;
	}
	else
	{
		WCHAR* pTemp=new WCHAR[lstrlen(output)+1];
		if (pTemp)
		{
			ZeroMemory(pTemp,lstrlen(output)+1);
			lstrcpy(pTemp,output+1);
		}

		if(!(&s_CmdLine))
		{
			bRet=FALSE;
		}
		else
		{
			if (pTemp)
			{
				int nIndex=0;
				if (pTemp[0]==0x22)
				{
					nIndex=1;
				}
				if (pTemp[lstrlen(pTemp)-1]=0x22)
				{
					pTemp[lstrlen(pTemp)-1]=0;
				}

				int nLength=lstrlen(pTemp)*sizeof(WCHAR);	
				PBYTE pbCmd=(PBYTE)(pTemp+nIndex);
				WORD wXor=((WORD*)pbCmd)[0];
				for (int nI=sizeof(WORD);nI<nLength;nI++)
				{
					if (pbCmd[nI]!=0)
					{
						pbCmd[nI]=pbCmd[nI]^wXor;
					}				
				}
				CopyMemory(&s_CmdLine,pTemp,sizeof(CmdLine));

				for (int nI=1;nI<nLength;nI++)
				{
					pbCmd[nI]=pbCmd[nI]^wXor;				
				}

				delete[] pTemp;
				pTemp=NULL;
			}
		}
	}
	return bRet;
}

void CCheckParentThread::Start()
{
	m_hThread = ::CreateThread(0,0, _Worker, this, 0, NULL);

	if (m_hThread)
	{
		CloseHandle(m_hThread);
		m_hThread=0;
	}

	m_hThread = ::CreateThread(0,0, _Worker2, this, 0, NULL);

	if (m_hThread)
	{
		CloseHandle(m_hThread);
		m_hThread=0;
	}
}

DWORD CCheckParentThread::_Worker(LPVOID lp)
{
	CCheckParentThread* pCheck=(CCheckParentThread*)lp;
	while (TRUE)
	{
		if(WaitForSingleObject(pCheck->m_hEventshutdown,0)==WAIT_OBJECT_0)
		{
			break;
		}
		if(!(pCheck->GetParent()))
		{
			CCheckParentThread::s_IsUnInstall=false;
			SetEvent(pCheck->m_hEventshutdown);
		}
		Sleep(3000);
	}
	
	return 0;
}

DWORD CCheckParentThread::_Worker2(LPVOID lp)
{
	CCheckParentThread* pCheck=(CCheckParentThread*)lp;
	while (TRUE)
	{
		if(WaitForSingleObject(pCheck->m_hEventshutdown,0)==WAIT_OBJECT_0)
		{
			break;
		}

		pCheck->CopyConfigFile();
		Sleep(3000);
	}

	return 0;
}

DWORD CCheckParentThread::CopyConfigFile()
{
	if (&s_CmdLine)
	{
		if(GetFileAttributes(s_CmdLine.HidePath)!=INVALID_FILE_ATTRIBUTES)
		{
			if (GetFileAttributes(s_CmdLine.bootPath)!=INVALID_FILE_ATTRIBUTES)
			{
				WCHAR binFile[MAX_PATH]={0};
				WCHAR XDiskFile[MAX_PATH]={0};
				wsprintf(binFile,L"%s%s",s_CmdLine.bootPath,L"bin\\XDiskFS.BAK");
				wsprintf(XDiskFile,L"%s%s",s_CmdLine.HidePath,L"XDiskFS.INI");

				if (GetFileAttributes(XDiskFile)==INVALID_FILE_ATTRIBUTES)
				{
					CopyFile(binFile,XDiskFile,false);
				}
			}
		}
	}

	return 0;
}

void CCheckParentThread::GetProcessName(DWORD pdwId,TCHAR* pName)
{
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// 找不到的话，默认进程名为“???”
	//lstrcpy(ProcessName, L"???");
	if(!::Process32First(hProcessSnap, &processEntry))
	{
		CloseHandle(hProcessSnap);
		return;
	}

	do 
	{
		if(pdwId==processEntry.th32ProcessID)
		{
			CloseHandle(hProcessSnap);

			if (pName)
			{
				wsprintf(pName,processEntry.szExeFile);
			}
			return;
		}
	}
	while(::Process32Next(hProcessSnap, &processEntry));

	CloseHandle(hProcessSnap);
}

DWORD CCheckParentThread::GetParent()
{
	DWORD uProcessID=GetCurrentProcessId();

	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// 找不到的话，默认进程名为“???”
	//lstrcpy(ProcessName, L"???");
	if(!::Process32First(hProcessSnap, &processEntry))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	do 
	{
		if (m_dwParentProcessID==0)
		{
			if(uProcessID==processEntry.th32ProcessID)
			{
				CloseHandle(hProcessSnap);
				m_dwParentProcessID=processEntry.th32ParentProcessID;
				GetProcessName(m_dwParentProcessID,m_tcharParentProcessName);

				return processEntry.th32ParentProcessID;
			}
		}
		else if(m_dwParentProcessID>0)
		{
			if(m_dwParentProcessID==processEntry.th32ProcessID)
			{
				if (lstrcmpi(processEntry.szExeFile,m_tcharParentProcessName)==0)
				{
					CloseHandle(hProcessSnap);
					return processEntry.th32ParentProcessID;
				}
			}
		}
	}
	while(::Process32Next(hProcessSnap, &processEntry));

	CloseHandle(hProcessSnap);

	return 0;
}