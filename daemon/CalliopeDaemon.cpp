#include "stdafx.h"
#include "Daemon.h"
#include "CFilterClient.h"
#include "CheckParentThread.h"

static PGPError Run()
{
	Daemon::Init();

	if(FAILED(Daemon::Observe()))
	{
	}

	Daemon::Close();
	return 1;
}

// WinMain /////////////////////////////////////////////////////////////////////////////////////////

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
	PGPError err = kPGPError_UnknownError;
	__try
	{
		//MessageBox(NULL,L"23234",L"122323",MB_OK);

		/************************************************************************/
		/* 策略发到驱动之前的 预判过程                                                                     */
		/************************************************************************/

		//int nLength=lstrlen(lpCmdLine);

	//	if (nLength<sizeof(CmdLine) || nLength<sizeof(CmdLine)+2)
	//	{
		//	return 0;
		//}

		
		//解析参数
	//	CCheckParentThread::CreateCmdLine(lpCmdLine);
		//CCheckParentThread check;
		//DWORD dwId=0;
	//	dwId=check.GetParent();
	//	if (_wtol(CCheckParentThread::s_CmdLine.ProcessId)==dwId)
		//{			
		//	WCHAR szProcessName[MAX_PATH]={0};
		//	check.GetProcessName(dwId,szProcessName);
		//	char s_process[25]={0xdc,0x0e,0x3d,0x04,0x4d,0x1a,0xab,0x23,0x1a,0x38,0x9d,0xdc,0x3d,0x03,0x7b,0x55,0x30,0x55,0x2d,0x55,0x30,0x55};
		//	char* pTitle=(char*)s_process;
		//	int nMAX=(int)strlen(s_process);
		//	for (int nI=0;nI<nMAX;nI++)
		//	{
		//		pTitle[nI]=pTitle[nI]^0x55;
		//	}

		//	if (wcsicmp((WCHAR*)pTitle,szProcessName)!=0)
			//{
			//	nLength=0;
		//	}

// 			if (nLength>0)
// 			{
// 				
// 				Daemon::s_tDirtory=new WCHAR[nLength];
// 				if (Daemon::s_tDirtory)
// 				{
// 					ZeroMemory(Daemon::s_tDirtory,nLength*sizeof(WCHAR));
// 					int nI=0;
// 					int nPos=0;
// 
// 					while(nI<nLength)
// 					{
// 						if (lpCmdLine[nI]!=34)
// 						{
// 							Daemon::s_tDirtory[nPos]=lpCmdLine[nI];
// 							nPos++;
// 						}
// 						nI++;
// 					}
// 				}
			err = Run();
			//}	
	//	}
		//Daemon::StopDriver();
		//	CFilterClient::RegisterCallbacks();
		//CFilterClient::RemoveEntities();

		// Switch off
		//CFilterClient::SetDriverState(CFilterClient::Passive);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		// We better bail out here or probably keep crashing infinite...
		Daemon::Restart();
	}

	return err;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
