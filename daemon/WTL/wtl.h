// wtl.h: interface for the wtl.
// -------------------------------------------------------------------
// *** 12.10.2004 ?Frank Melber ***
// -------------------------------------------------------------------
// (last modified: 12.10.2004 Frank Melber)
//////////////////////////////////////////////////////////////////////

// For API based property pages...
#define _WTL_NEW_PAGE_NOTIFY_HANDLERS

// For "CString"...
#define _WTL_USE_CSTRING

#include <atlbase.h>

#include "..\daemon\wtl\atlapp.h"
#include "..\daemon\wtl\atlcrack.h"
#include "..\daemon\wtl\atlctrls.h"
#include "..\daemon\wtl\atlctrlw.h"
#include "..\daemon\wtl\atlctrlx.h"
#include "..\daemon\wtl\atlddx.h"

#include "..\daemon\wtl\atldlgs.h"
#include "..\daemon\wtl\atlframe.h"
#include "..\daemon\wtl\atlgdi.h"
#include "..\daemon\wtl\atlmisc.h"
#include "..\daemon\wtl\atlprint.h"
#include "..\daemon\wtl\atlres.h"

#ifdef _WIN32_WCE
	//#include <atlresce.h>
#include "..\daemon\wtl\atlresce.h"
#endif // _WIN32_WCE

#include "..\daemon\wtl\atlscrl.h"
#include "..\daemon\wtl\atlsplit.h"

#if (_WIN32_WINNT >= 0x0501)
	#include <atltheme.h>
#endif // (_WIN32_WINNT >= 0x0501)

#include "..\daemon\wtl\atluser.h"
#include "..\daemon\wtl\atlwinx.h"

