////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterCipherManager.h: interface for the CFilterCipherManager class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterCipherManager_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFilterCipherManager_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CFilterHeader.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterCipherManager
{
public:

	explicit CFilterCipherManager(FILFILE_VOLUME_EXTENSION *extension)
	{	
		RtlZeroMemory(this, sizeof(*this)); 
		m_extension = extension; 
	}
	~CFilterCipherManager()
	{ Close(); }

	NTSTATUS					Init(ULONG bufferSize);
	void						Close();
	void						Clear();
	void						SetFlags(ULONG flags);

	NTSTATUS					RecognizeHeader(FILE_OBJECT *file, CFilterHeader *header = 0, ULONG flags = 0,FILFILE_TRACK_CONTEXT *track=NULL);
	NTSTATUS					WriteHeader(FILE_OBJECT *file, CFilterHeader* header);

	NTSTATUS					ProcessFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *current, FILFILE_TRACK_CONTEXT *future);
	NTSTATUS					UpdateTail(FILE_OBJECT *file, CFilterContextLink *link, LARGE_INTEGER *fileSize = 0);

	NTSTATUS					AutoConfigRead( FILE_OBJECT *file, CFilterHeader *header, ULONG flags = 0,FILFILE_TRACK_CONTEXT *track=NULL);
	NTSTATUS					AutoConfigWrite(FILE_OBJECT *file, CFilterHeader *header);

	NTSTATUS					RetrieveTail(FILE_OBJECT *file, CFilterHeader *header, ULONG *tail = 0);

private:

	NTSTATUS					ProcessFileUp(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *read, FILFILE_TRACK_CONTEXT *write, LONG distance);
	NTSTATUS					ProcessFileEqualDown(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *read, FILFILE_TRACK_CONTEXT *write, LONG distance);

	NTSTATUS					ReadHeader(FILE_OBJECT *file, ULONG flags = 0);
	NTSTATUS					AutoConfigPost(FILE_OBJECT *file);

								// DATA
	FILFILE_VOLUME_EXTENSION*	m_extension; 

	UCHAR*						m_buffer;
	ULONG						m_bufferSize;
	ULONG						m_flags;

	LARGE_INTEGER				m_fileSize;

	FILFILE_READ_WRITE			m_readWrite;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
void CFilterCipherManager::Clear()
{
	m_fileSize.QuadPart = 0;
}

inline
void CFilterCipherManager::SetFlags(ULONG flags)
{
	m_flags = flags;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFilterCipherManager_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

