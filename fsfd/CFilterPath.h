////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterPath.h: definition of the CFilterEntity,CFilterEntityCont classes
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFILTERPATH_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_CFILTERPATH_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CFilterPath
{
public:

	enum c_constants
	{
		PATH_NONE			= 0x0,
		PATH_VOLUME			= 0x1,
		PATH_DIRECTORY		= 0x2,
		PATH_FILE			= 0x4,
		PATH_DEEPNESS		= 0x8,
		PATH_PREFIX			= 0x10,	// usually redirector based
		PATH_DYNAMIC		= 0x20,
		PATH_PREFIX_DYN		= PATH_PREFIX | PATH_DYNAMIC,
		PATH_TAIL			= 0x40,
		PATH_AUTOCONFIG		= 0x80,
	};

	NTSTATUS				Init(LPCWSTR path, ULONG pathLength, ULONG type, UNICODE_STRING const* device = 0);
	NTSTATUS				InitClient(LPCWSTR path, ULONG pathLength, ULONG pathFlags = PATH_NONE);
	void					Close();

	NTSTATUS				Build(LPCWSTR path, ULONG pathLength, UNICODE_STRING const* prefix = 0);
	NTSTATUS				Parse(ULONG type = FILFILE_DEVICE_NULL, ULONG pathFlags = PATH_NONE);

	ULONG					GetType() const;
	NTSTATUS				SetType(ULONG type);
	ULONG					GetLength(ULONG flags) const;
	NTSTATUS				GetAutoConfig(UNICODE_STRING *autoConfig, ULONG flags = 0) const;

	bool					Match(CFilterPath const* candidate, bool exact) const;
	bool					MatchSpecial(CFilterPath const* candidate) const;
	ULONG					Hash(ULONG flags) const;

	ULONG					Write(LPWSTR buffer, ULONG bufferLength, ULONG flags) const;
	NTSTATUS				Swap(CFilterPath *path, bool takeOver = false);

	NTSTATUS				CopyFrom(CFilterPath const* that, ULONG flags = 0);
	LPWSTR					CopyTo(ULONG flags, ULONG *length = 0) const;

	UNICODE_STRING*			UnicodeString(UNICODE_STRING *ustr) const;

	#if DBG
	 void					Print(ULONG flags = PATH_NONE);
	#endif
							// DATA
	LPWSTR					m_volume;
	LPWSTR					m_directory;
	LPWSTR					m_file;
	ULONG					m_flags;
	
	USHORT					m_volumeLength;
	USHORT					m_directoryLength;

	USHORT					m_fileLength;
	USHORT					m_directoryDepth;		

	ULONG					m_deepness;			// -1 := infinite, otherwise max depth difference that match
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
ULONG CFilterPath::GetType() const
{
	return m_flags & (TRACK_TYPE_FILE | TRACK_TYPE_DIRECTORY);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // AFX_CFILTERPATH_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_