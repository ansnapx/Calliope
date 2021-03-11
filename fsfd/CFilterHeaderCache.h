////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterHeaderCache.h: interface for the CFilterHeaderCache class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterHeaderCache_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFilterHeaderCache_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

class CFilterHeaderCache  
{
	enum c_constants			{	c_increment  = 16,
									c_timeout    = 120,  // default entry timeout in sec
									c_scavenging = (c_timeout / 2) + 11 };

	struct CFilterHeaderCacheEntry
	{
		NTSTATUS	Init(LPWSTR path, ULONG pathLen, ULONG hash, CFilterHeader *header);
		void		Close();

		LPWSTR		m_path;
		ULONG		m_pathLen;
		ULONG		m_hash;
		ULONG		m_tick;
		UCHAR*		m_header;
		ULONG		m_headerSize;
	};

public:

	NTSTATUS					Init(LPCWSTR regPath = 0);
	void						Close();
	void						Clear();

	NTSTATUS					Query(LPCWSTR path, ULONG pathLen, CFilterHeader *header = 0);
	NTSTATUS					Add(LPWSTR path, ULONG pathLen, CFilterHeader *header = 0);
	NTSTATUS					Remove(LPCWSTR path, ULONG pathLength);

								// Utility functions:
	NTSTATUS					Remove(FILFILE_VOLUME_EXTENSION *extension, FILE_OBJECT *file);
	NTSTATUS					Inject(CFilterPath *source, CFilterHeader *header);
	
private:

	ULONG						Search(LPCWSTR path, ULONG pathLen, ULONG hash, ULONG tick = 0);
	NTSTATUS					Remove(LPCWSTR path, ULONG pathLen, ULONG hash, ULONG pos = ~0u);
	bool						Validate();
	
	NTSTATUS					WorkerStart();
	NTSTATUS					WorkerStop();
	static void NTAPI			Worker(void *context);

								// DATA
	CFilterHeaderCacheEntry*	m_headers;
	ULONG						m_count;
	ULONG						m_capacity;
	ULONG						m_timeout;

	ERESOURCE					m_lock;

	HANDLE						m_worker;
	KEVENT						m_workerStop;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterHeaderCache_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
