// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#ifndef Included_stdafx_h
#define Included_stdafx_h


// Windows Header Files:
#include <windows.h>
// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <assert.h>

// TODO: reference additional headers your program requires here
#endif /* Included_stdafx_h */


#define CalliopeDaemon_Mutex					L"CalliopeDemon_Mutex-{C0CAC01A-9962-4e37-86AC-1E7D282892F6}"

// Daemon shutdown event
#define CalliopeDaemon_Event_Shutdown			L"XDiskDemon_Event_Shutdown-{C0CAC01A-4B4F-4c32-9EB5-89DB9230B116}"

// Reset Skipped zones event
#define CalliopeDaemon_Event_ResetSkippedZones	L"CalliopeDemon_Event_ResetSkippedZones-{C0CAC01A-8F29-4A2C-972F-FB1E1C14DB73}"

// Recent Folder Update event
#define CalliopeLibrary_EventName_Update		L"CalliopeUpdate-{B127C959-97A0-4FD2-B0AD-D2CA2C5CE7DF}"

// Reset Overlay icon event
#define CalliopeLibrary_EventName_Overlay		L"CalliopeOverlay-{B127C959-97A0-4FD2-B0AD-D2CA2C5CE7EF}"

typedef short			PGPInt16;
typedef	unsigned char		PGPUTF8;
typedef unsigned int	PGPUInt32;
typedef int				PGPInt32;
typedef PGPInt32			PGPError;
typedef unsigned short	PGPUInt16;

typedef	char				PGPChar8;
typedef	PGPUInt16			PGPChar16;
typedef	PGPUInt32			PGPChar32;

#define kPGPError_UnknownError -100

#if UNICODE
#define PGPTEXT(literal)				L##literal
#else
#define PGPTEXT(literal)				literal
#endif

#define PGPTXT_MACHINE(literal)			PGPTEXT(literal)	/* MAC */