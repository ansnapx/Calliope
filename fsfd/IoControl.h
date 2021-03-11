///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// IoControl.h - common definitions/structs shared by the driver and its user mode part
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _FILFILE_IOCONTROL_H_
#define _FILFILE_IOCONTROL_H_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define FILFILE_CONTROL_MAGIC 'FF'
#define FILFILE_CONTROL_VERSION 2		// Increased for 64-bit support

enum FILFILE_CONTROL_FLAGS
{
	FILFILE_CONTROL_NULL			= 0x0,
	FILFILE_CONTROL_ADD				= 0x1,
	FILFILE_CONTROL_REM				= 0x2,
	FILFILE_CONTROL_SET				= 0x4,
	FILFILE_CONTROL_ACTIVE			= 0x8,
	FILFILE_CONTROL_AUTOCONF		= 0x10,
	FILFILE_CONTROL_RANDOM			= 0x20,
	FILFILE_CONTROL_NOTIFY			= 0x40,
	FILFILE_CONTROL_HANDLE			= 0x80,
	FILFILE_CONTROL_BLACKLIST		= 0x100,
	FILFILE_CONTROL_SHARED			= 0x200,
	FILFILE_CONTROL_DIRECTORY		= 0x400,
	FILFILE_CONTROL_WIPE_ON_DELETE	= 0x800,
	FILFILE_CONTROL_RECOVER			= 0x1000,
	FILFILE_CONTROL_APPLICATION		= 0x2000,
};

struct FILFILE_CONTROL
{	
	USHORT			Magic;
	USHORT			Version;
	ULONG			Size;

	ULONG			Flags;					// State, control Encryption

	ULONGLONG		Value1;					// defined by corresponding operation
	ULONGLONG		Value2;					// dito
	ULONGLONG		Value3;					// dito

	ULONG			PathOffset;				// Entity access, Payload access, manage Encryption
	ULONG			PathLength;

	ULONG			PayloadOffset;			// Entity access, Payload access
	ULONG			PayloadSize;

	ULONG			CryptoOffset;			// Session Key or Random data
	ULONG			CryptoSize;

	ULONG			DataOffset;				// Curr Session Key on changes
	ULONG			DataSize;
};	

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

LPCWSTR	const g_filFileAutoConfigName		= L"XAZFileCrypt.INI";	// must be upcase
ULONG	const g_filFileAutoConfigNameLength	= 16;

enum FILFILE_CONSTANTS
{		
	FILFILE_HEADER_MAX_SIZE			= 1024 * 1024,	// bytes
	FILFILE_HEADER_META_SIZE		= 18 * sizeof(ULONG),
	FILFILE_WIPE_PROGRESS_STEP		= 1024 * 1024,	// must be a multiple of 64k
	FILFILE_RANDOM_REQUEST_SIZE		= 1024,			
	FILFILE_RANDOM_REQUEST_TIMEOUT	= 12,			// seconds
	FILFILE_KEY_REQUEST_TIMEOUT		= 30,			
};

struct FILFILE_CONTROL_OUT
{	
	ULONG			Flags;			// Layout: Path and Payload following this struct
	ULONGLONG		Value;
	ULONG			PathSize;
	ULONG			PayloadSize;
};	

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CTL_CODE
#pragma message("CTL_CODE is undefined, include WINIOCTL.H or NTDDK.H (WDM.H)")
#endif

#define IOCTL_FILFILE_BASE					FILE_DEVICE_DISK_FILE_SYSTEM

#define IOCTL_FILFILE_GET_STATE				CTL_CODE(IOCTL_FILFILE_BASE, 0x0600, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define IOCTL_FILFILE_SET_STATE				CTL_CODE(IOCTL_FILFILE_BASE, 0x0601, METHOD_BUFFERED,   FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_ENTITY				CTL_CODE(IOCTL_FILFILE_BASE, 0x0602, METHOD_BUFFERED,	FILE_WRITE_ACCESS)
#define IOCTL_FILFILE_ENUM_ENTITIES			CTL_CODE(IOCTL_FILFILE_BASE, 0x0603, METHOD_OUT_DIRECT,	FILE_READ_ACCESS)

#define IOCTL_FILFILE_GET_HEADER			CTL_CODE(IOCTL_FILFILE_BASE, 0x0604, METHOD_OUT_DIRECT,	FILE_READ_ACCESS)
#define IOCTL_FILFILE_SET_HEADER			CTL_CODE(IOCTL_FILFILE_BASE, 0x0605, METHOD_BUFFERED,	FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_ENCRYPTION			CTL_CODE(IOCTL_FILFILE_BASE, 0x0606, METHOD_BUFFERED,	FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_CALLBACK_CONNECTION	CTL_CODE(IOCTL_FILFILE_BASE, 0x0607, METHOD_BUFFERED,	FILE_WRITE_ACCESS)
#define IOCTL_FILFILE_CALLBACK_REQUEST		CTL_CODE(IOCTL_FILFILE_BASE, 0x0608, METHOD_OUT_DIRECT,	FILE_READ_ACCESS)
#define IOCTL_FILFILE_CALLBACK_RESPONSE		CTL_CODE(IOCTL_FILFILE_BASE, 0x060a, METHOD_BUFFERED,	FILE_WRITE_ACCESS)
#define IOCTL_FILFILE_CALLBACK_RESPONSE_HEADER  CTL_CODE(IOCTL_FILFILE_BASE, 0x0611, METHOD_BUFFERED,	FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_OPEN_FILE				CTL_CODE(IOCTL_FILFILE_BASE, 0x060b, METHOD_OUT_DIRECT,	FILE_READ_ACCESS)

#define IOCTL_FILFILE_GET_BLACKLIST			CTL_CODE(IOCTL_FILFILE_BASE, 0x060c, METHOD_OUT_DIRECT,	FILE_READ_ACCESS)
#define IOCTL_FILFILE_SET_BLACKLIST			CTL_CODE(IOCTL_FILFILE_BASE, 0x060d, METHOD_BUFFERED,	FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_WIPER					CTL_CODE(IOCTL_FILFILE_BASE, 0x060e, METHOD_BUFFERED,	FILE_READ_ACCESS)

#define IOCTL_FILFILE_ADD_CREDIBLE_PROCESS	CTL_CODE(IOCTL_FILFILE_BASE, 0x060f, METHOD_BUFFERED,	FILE_WRITE_ACCESS)

#define IOCTL_FILFILE_SET_READONLY				CTL_CODE(IOCTL_FILFILE_BASE, 0x0610, METHOD_BUFFERED,   FILE_WRITE_ACCESS)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // _FILFILE_IOCONTROL_H_


