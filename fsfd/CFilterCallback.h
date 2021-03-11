////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCallback.h: interface for the CFilterCallback classes.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERCALLBACK_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERCALLBACK_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct FILFILE_TRACK_CONTEXT;
struct FILFILE_CONTROL_OUT;

class CFilterCallback
{
	friend class CFilterCallbackDisp;

public:

	NTSTATUS				Init(LUID const* luid);
	void					Close(bool wake = false);

	NTSTATUS				Connect(HANDLE random = 0, HANDLE key = 0, HANDLE notify = 0);
	bool					Check(LUID const* luid);
									
	NTSTATUS				Request(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize);
	NTSTATUS				Response(ULONG keyCookie, UCHAR *response, ULONG responseSize);
	NTSTATUS                ResponseHeader(UCHAR *response, ULONG responseSize);

	NTSTATUS				FireNotify(ULONG flags, UCHAR** notify, ULONG notifySize);
	NTSTATUS				FireKey(ULONG flags, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS				FireRandom(ULONG flags, UCHAR **random = 0, ULONG *randomSize = 0);

private:

	NTSTATUS				RequestKey(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize);
	NTSTATUS				RequestNotify(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize);
	
							// DATA
	LUID					m_luid;					// LUID of connected client. Zero if TS mode is disabled
	LIST_ENTRY				m_link;
	FAST_MUTEX				m_lock;


	KEVENT*					m_notifyTrigger;		// Client triggers
	KEVENT*					m_keyTrigger;			//
	KEVENT*					m_randomTrigger;		//
	
	UCHAR*					m_notify;				// Notification requests
	ULONG					m_notifySize;			//
	ULONG					m_notifyFlags;			//
	
	UCHAR*					m_random;				// Random requests
	ULONG					m_randomSize;			//
	KEVENT					m_randomReady;			//
	
	LPWSTR					m_keyPath;				// Key requests
	UCHAR*					m_keyPayload;			//
	ULONG					m_keyPayloadSize;		//
    ULONG					m_keyPathLength;		//
	ULONG					m_keyCookie;			// current/next cookie
	CFilterKey				m_key;					//
	KEVENT					m_keyReady;				// 
	KEVENT					m_notifyReady;	
};

inline
bool CFilterCallback::Check(LUID const* luid)
{
	ASSERT(luid);
	return *((ULONGLONG*) &m_luid) == *((ULONGLONG*) luid);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterCallbackDisp
{
	enum c_constants		{	c_incrementCount   = 8,
								c_fireKeyLoopCount = 120,
								c_fireKeyLoopWait  = 300,	// effective timeout: ~30 sec 
							};
public:

	NTSTATUS				Init(struct FILFILE_CONTROL_EXTENSION *extension);
	void					Close();

	NTSTATUS				Connect(HANDLE random, HANDLE key, HANDLE notify);
	NTSTATUS				Disconnect(LUID const* luid = 0);

	NTSTATUS				Request(ULONG flags, FILFILE_CONTROL_OUT *request, ULONG *requestSize);
	NTSTATUS				Response(ULONG keyCookie, UCHAR *response, ULONG responseSize);
	NTSTATUS                ResponseHeader(UCHAR *response, ULONG responseSize);

	NTSTATUS				FireNotify(ULONG flags, UCHAR** notify, ULONG notifySize);
	NTSTATUS				FireKey(ULONG flags, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS				FireRandom(ULONG flags, UCHAR **random = 0, ULONG *randomSize = 0);
		
private:

	CFilterCallback*		Find(LUID const* luid = 0);

							// DATA		
	CFilterHeaderCont*		m_headers;
	LIST_ENTRY				m_head;		// Head of list of connected clients
	ERESOURCE				m_lock;
};

///////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFILTERCALLBACK_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_