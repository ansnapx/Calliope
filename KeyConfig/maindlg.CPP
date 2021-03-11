#include "StdAfx.h"
#include "MainDlg.h"

char* CMainDlg::ReadConfigFile(char* pFile)
{
	std::ifstream fin (pFile,std::ios::binary);
	char* buffer=NULL;
	try
	{
		buffer=new char[FILE_CONFIG_SIZE];
		ZeroMemory(buffer,FILE_CONFIG_SIZE);
		fin.seekg(0,std::ios_base::end);   //   把文件指针到尾部 
		ULONG uSize=fin.tellg();   //   获得文件字节数
		//   如果读取文件，需要把文件指针指向文件开始出 
		fin.seekg(0,std::ios_base::beg); 
		fin.read((char *)buffer,FILE_CONFIG_SIZE); 
		fin.close();
	}
	catch (...)
	{
		fin.close();

		if (buffer)
		{
			delete[] buffer;
			buffer=NULL;
		}
	}

	return buffer;
}

void CMainDlg::WritrConfigFile(char* pFile,char* buffer,ULONG uSize)
{
	// 定义打开输出流 
	std::ofstream fout(pFile, std::ios::binary);
	// 写入 
	fout.write((char *)buffer,uSize);

}


