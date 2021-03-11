////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterNormalizer.h: interface for the CFilterNormalizer class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERNORMALIZER_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_)
#define AFX_CFILTERNORMALIZER_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterNormalizer : public CFilterPath
{
	enum c_constants { c_bufferAlign = 512 };

public:

	CFilterNormalizer(FILFILE_VOLUME_EXTENSION *extension, ULONG flags = 0)
	{ 
		RtlZeroMemory(this, sizeof(*this));

		m_extension = extension;
		m_flags		= flags;
	}

	NTSTATUS					NormalizeCreate(IRP *irp);
	NTSTATUS					NormalizeFileID(FILE_OBJECT* file);

	#if DBG
	 void						Dump(IRP* irp, CFilterPath *normalized = 0);
	#endif

private:

	NTSTATUS					NormalizeAbsolute(FILE_OBJECT* file);
	NTSTATUS					NormalizeRelative(FILE_OBJECT* file);
	
	NTSTATUS					EnsureCapacity(ULONG size);
	NTSTATUS					ShortNameResolver(IRP* irp);

								// DATA
	FILFILE_VOLUME_EXTENSION*	m_extension;
	ULONG						m_capacity;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif //AFX_CFILTERNORMALIZER_H__7A8B8AA6_9F38_4944_ACDA_25EE47780ADA__INCLUDED_