
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// driverMrx.h: Header file for interaction with the Redirector (RDBSS/SMBMRX)
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_DRIVER_MRX_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_)
#define AFX_DRIVER_MRX_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Merged together from various files in the IFS/WDK kit (fcb.h, mrxfcb.h) 
// and from different versions to reduce header file dependencies.

#define FCB_STATE_SRVOPEN_USED                   ( 0x80000000 )
#define FCB_STATE_FOBX_USED                      ( 0x40000000 )
#define FCB_STATE_ADDEDBACKSLASH                 ( 0x20000000 )
#define FCB_STATE_NAME_ALREADY_REMOVED           ( 0x10000000 )
#define FCB_STATE_WRITECACHEING_ENABLED          ( 0x08000000 )
#define FCB_STATE_WRITEBUFFERING_ENABLED         ( 0x04000000 )
#define FCB_STATE_READCACHEING_ENABLED           ( 0x02000000 )
#define FCB_STATE_READBUFFERING_ENABLED          ( 0x01000000 )
#define FCB_STATE_OPENSHARING_ENABLED            ( 0x00800000 )
#define FCB_STATE_COLLAPSING_ENABLED             ( 0x00400000 )
#define FCB_STATE_LOCK_BUFFERING_ENABLED         ( 0x00200000 )
#define FCB_STATE_FILESIZECACHEING_ENABLED       ( 0x00100000 )
#define FCB_STATE_FILETIMECACHEING_ENABLED       ( 0x00080000 )
#define FCB_STATE_TIME_AND_SIZE_ALREADY_SET      ( 0x00040000 )
#define FCB_STATE_FILE_IS_SHADOWED               ( 0x00010000 )
#define FCB_STATE_FILE_IS_DISK_COMPRESSED        ( 0x00008000 )
#define FCB_STATE_FILE_IS_BUF_COMPRESSED         ( 0x00004000 )
#define FCB_STATE_BUFFERSTATE_CHANGING           ( 0x00002000 )
#define FCB_STATE_FAKEFCB                        ( 0x00001000 )
#define FCB_STATE_DELAY_CLOSE                    ( 0x00000800 )
#define FCB_STATE_READAHEAD_DEFERRED             ( 0x00000100 )
#define FCB_STATE_ORPHANED                       ( 0x00000080 )
#define FCB_STATE_BUFFERING_STATE_CHANGE_PENDING ( 0x00000040 )
#define FCB_STATE_TEMPORARY                      ( 0x00000020 )
#define FCB_STATE_DISABLE_LOCAL_BUFFERING        ( 0x00000010 )
#define FCB_STATE_LWIO_ENABLED                   ( 0x00000008 )
#define FCB_STATE_PAGING_FILE                    ( 0x00000004 )
#define FCB_STATE_TRUNCATE_ON_CLOSE              ( 0x00000002 )
#define FCB_STATE_DELETE_ON_CLOSE                ( 0x00000001 )

#define FSRTL_FLAG_ADVANCED_HEADER				 (0x40)
#define FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS	 (0x02)

#define SRVOPEN_FLAG_DONTUSE_READ_CACHEING                  (0x1)
#define SRVOPEN_FLAG_DONTUSE_WRITE_CACHEING                 (0x2)
#define SRVOPEN_FLAG_CLOSED                                 (0x4)
#define SRVOPEN_FLAG_CLOSE_DELAYED                          (0x8)
#define SRVOPEN_FLAG_FILE_RENAMED                           (0x10)
#define SRVOPEN_FLAG_FILE_DELETED                           (0x20)
#define SRVOPEN_FLAG_BUFFERING_STATE_CHANGE_PENDING         (0x40)
#define SRVOPEN_FLAG_COLLAPSING_DISABLED                    (0x80)
#define SRVOPEN_FLAG_BUFFERING_STATE_CHANGE_REQUESTS_PURGED (0x100)
#define SRVOPEN_FLAG_NO_BUFFERING_STATE_CHANGE              (0x200)
#define SRVOPEN_FLAG_ORPHANED                               (0x400)

#define RxWriteCacheingAllowed(Fcb,SrvOpen) \
      ( FlagOn((Fcb)->FcbState,FCB_STATE_WRITECACHEING_ENABLED) \
      && !FlagOn((SrvOpen)->Flags, SRVOPEN_FLAG_DONTUSE_WRITE_CACHEING))

#define NODE_TYPE_FOBX		 (0xeb07)
#define NODE_TYPE_SRVOPEN	 (0xeb1c)

typedef USHORT  NODE_TYPE_CODE;
typedef CSHORT	NODE_BYTE_SIZE;

typedef struct _MRX_NORMAL_NODE_HEADER 
{
   NODE_TYPE_CODE           NodeTypeCode;
   NODE_BYTE_SIZE           NodeByteSize;
   ULONG                    NodeReferenceCount;
} MRX_NORMAL_NODE_HEADER;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _MRX_SRV_OPEN_ 
{
	MRX_NORMAL_NODE_HEADER nodeHeader;

	// the MRX_FCB instance with which the SRV_OPEN is associated.

	//PMRX_FCB pFcb;
	PVOID		pFcb;

	// the V_NET_ROOT instance with which the SRV_OPEN is associated

	//PMRX_V_NET_ROOT pVNetRoot;
	PVOID		pVNetRoot;

	// !!!! changes above this require realignment with fcb.h

	// the context fields to store additional state information as deemed necessary
	// by the mini redirectors

	PVOID        Context;
	PVOID        Context2;

	// The flags are split into two groups, i.e., visible to mini rdrs and invisible
	// to mini rdrs. The visible ones are defined above and the definitions for the
	// invisible ones can be found in fcb.h. The convention that has been adopted is
	// that the lower 16 flags will be visible to the mini rdr and the upper 16 flags
	// will be reserved for the wrapper. This needs to be enforced in defining new flags.

	ULONG        Flags;

	// the name alongwith the MRX_NET_ROOT prefix, i.e. fully qualified name

	PUNICODE_STRING pAlreadyPrefixedName;


	// the number of Fobx's associated with this open for which a cleanup IRP
	// has not been processed.

	CLONG        UncleanFobxCount;

	// the number of local opens associated with this open on the server

	CLONG        OpenCount;

	// the Key assigned by the mini redirector for this SRV_OPEN. Since the various mini
	// redirectors do not always get to pick the unique id for a open instance, the key
	// used to identify the open to the server is different for different mini redirectors
	// based upon the convention adopted at the server.

	PVOID        Key;

	// the access and sharing rights specified for this SRV_OPEN. This is used in
	// determining is subsequent open requests can be collapsed  with an existing
	// SRV_OPEN instance.

	ACCESS_MASK  DesiredAccess;
	ULONG        ShareAccess;
	ULONG        CreateOptions;

	// The BufferingFlags field is temporal.....it does not really belong to the
	// srvopen; rather the srvopen is used as a representative of the fcb. On
	// each open, the bufferingflags field of the srvopen is taken as the minirdr's
	// contribution to the buffering state. On an oplock break, a srvopen is passed
	// (the one that's being broken) whose bufferflags field is taken as the new
	// proxy. On a close that changes the minirdr's contribution, the minirdr should
	// take steps to cause a ChangeBufferingState to the new state.
	//
	// just to reiterate, the field is just used to carry the information from
	// the minirdr to RxChangeBufferingState and does not hold longterm coherent
	// information.

	ULONG        BufferingFlags;

	// List Entry to wire the SRV_OPEN to the list of SRV_OPENS maintained as
	// part of theFCB
	//  THIS FIELD IS READONLY FOR MINIS

	ULONG       ulFileSizeVersion;

	LIST_ENTRY    SrvOpenQLinks;

} MRX_SRV_OPEN, *PMRX_SRV_OPEN;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _MRX_FOBX_ 
{
	MRX_NORMAL_NODE_HEADER nodeHeader;

	// the MRX_SRV_OPEN instance with which the FOBX is associated

	PMRX_SRV_OPEN    pSrvOpen;

	// the FILE_OBJECT with which this FOBX is associated
	// In certain instances the I/O subsystem creates a FILE_OBJECT instance
	// on the stack in the interests of efficiency. In such cases this field
	// is NULL.

	PFILE_OBJECT     AssociatedFileObject;

	// !!!! changes above this require realignment with fcb.h

	// The fields provided to accomodate additional state to be associated
	// by the various mini redirectors

	PVOID            Context;
	PVOID            Context2;

	// The FOBX flags are split into two groups, i.e., visible to mini rdrs and invisible to mini rdrs.
	// The visible ones are defined above and the definitions for the invisible ones can be found
	// in fcb.h. The convention that has been adopted is that the lower 16 flags will be visible
	// to the mini rdr and the upper 16 flags will be reserved for the wrapper. This needs to be
	// enforced in defining new flags.

	ULONG            Flags;

	union 
	{
		struct 
		{
			//
			//  The query template is used to filter directory query requests.
			//  It originally is set to null and on the first call the NtQueryDirectory
			//  it is set to the input filename or "*" if the name is not supplied.
			//  All subsquent queries then use this template.

			UNICODE_STRING UnicodeQueryTemplate;
		}; //for directories

		//PMRX_PIPE_HANDLE_INFORMATION PipeHandleInformation;   //for pipes
		PVOID PipeHandleInformation;   //for pipes
	};

	//
	//  The following field is used as an offset into the Eas for a
	//  particular file.  This will be the offset for the next
	//  Ea to return.  A value of 0xffffffff indicates that the
	//  Ea's are exhausted.
	//

	// This field is manipulated directly by the smbmini....maybe it should move down
	// one thing is that it is a reminder that NT allows a resume on getting EAs

	ULONG OffsetOfNextEaToReturn;

} MRX_FOBX, *PMRX_FOBX;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// ALL FIELDS IN AN FCB ARE READONLY EXCEPT Context and Context2....
// Also, Context is read only the the mini has specified RDBSS_MANAGE_FCB_EXTENSION
typedef struct _MRX_FCB_ 
{
	FSRTL_COMMON_FCB_HEADER Header;

	// The MRX_NET_ROOT instance with which this is associated

	//PMRX_NET_ROOT		pNetRoot;
	PVOID				pNetRoot;		// make our live easier ...

	// !!!! changes above this require realignment with fcb.h

	// the context fields to store additional information as deemed necessary by the
	// mini redirectors.

	PVOID				Context;
	PVOID				Context2;

	// The reference count: in a different place because we must prefix with
	// the FSRTL_COMMON_FCB_HEADER structure.

	ULONG				NodeReferenceCount;

	//
	//  The internal state of the Fcb.  THIS FIELD IS READONLY FOR MINIRDRS
	//

	ULONG				FcbState;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet.  This count
	//  is only used for data file objects, not for the Acl or Ea stream
	//  file objects.  This count gets decremented in RxCommonCleanup,
	//  while the OpenCount below gets decremented in RxCommonClose.

	CLONG				UncleanCount;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet and for which
	//  cacheing is not supported. This is used in cleanup.c to tell if extra
	//  purges are required to maintain coherence.

	CLONG				UncachedUncleanCount;

	//  A count of the number of file objects that have opened
	//  this file/directory.  For files & directories the FsContext of the
	//  file object points to this record.

	CLONG				OpenCount;


	// The outstanding locks count: if this count is nonzero, the we silently
	// ignore adding LOCK_BUFFERING in a ChangeBufferingState request. This field
	// is manipulated by interlocked operations so you only have to have the fcb
	// shared to manipulate it but you have to have it exclusive to use it.

	ULONG            OutstandingLockOperationsCount;

	// The actual allocation length as opposed to the valid data length

	ULONGLONG        ActualAllocationLength;

	// Attributes of the MRX_FCB,

	ULONG            Attributes;

	// Intended for future use, currently used to round off allocation to
	// DWORD boundaries.

	USHORT           Spare1;
	BOOLEAN          fMiniInited;

	// Type of the associated MRX_NET_ROOT, intended to avoid pointer chasing.

	UCHAR            CachedNetRootType;

	//  Header for the list of srv_opens for this FCB....
	//  THIS FIELD IS READONLY FOR MINIS

	LIST_ENTRY              SrvOpenList;

	//  changes whenever the list changes..prevents extra lookups
	//  THIS FIELD IS READONLY FOR MINIS

	ULONG                   SrvOpenListVersion;

} MRX_FCB;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _MRX_FCB_ADVANCED 
{
	FSRTL_ADVANCED_FCB_HEADER Header;

	// The MRX_NET_ROOT instance with which this is associated
	//PMRX_NET_ROOT		pNetRoot;
	PVOID				pNetRoot;		// make our live easier ...

	// !!!! changes above this require realignment with fcb.h

	// the context fields to store additional information as deemed necessary by the
	// mini redirectors.

	PVOID				Context;
	PVOID				Context2;

	// The reference count: in a different place because we must prefix with
	// the FSRTL_COMMON_FCB_HEADER structure.

	ULONG				NodeReferenceCount;

	//
	//  The internal state of the Fcb.  THIS FIELD IS READONLY FOR MINIRDRS
	//

	ULONG				FcbState;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet.  This count
	//  is only used for data file objects, not for the Acl or Ea stream
	//  file objects.  This count gets decremented in RxCommonCleanup,
	//  while the OpenCount below gets decremented in RxCommonClose.

	CLONG				UncleanCount;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet and for which
	//  cacheing is not supported. This is used in cleanup.c to tell if extra
	//  purges are required to maintain coherence.

	CLONG				UncachedUncleanCount;

	//  A count of the number of file objects that have opened
	//  this file/directory.  For files & directories the FsContext of the
	//  file object points to this record.

	CLONG				OpenCount;


	// The outstanding locks count: if this count is nonzero, the we silently
	// ignore adding LOCK_BUFFERING in a ChangeBufferingState request. This field
	// is manipulated by interlocked operations so you only have to have the fcb
	// shared to manipulate it but you have to have it exclusive to use it.

	ULONG            OutstandingLockOperationsCount;

	// The actual allocation length as opposed to the valid data length

	ULONGLONG        ActualAllocationLength;

	// Attributes of the MRX_FCB,

	ULONG            Attributes;

	// Intended for future use, currently used to round off allocation to
	// DWORD boundaries.

	USHORT           Spare1;
	BOOLEAN          fMiniInited;

	// Type of the associated MRX_NET_ROOT, intended to avoid pointer chasing.

	UCHAR            CachedNetRootType;

	//  Header for the list of srv_opens for this FCB....
	//  THIS FIELD IS READONLY FOR MINIS

	LIST_ENTRY      SrvOpenList;

	//  changes whenever the list changes..prevents extra lookups
	//  THIS FIELD IS READONLY FOR MINIS

	ULONG           SrvOpenListVersion;

} MRX_FCB_ADVANCED;

#ifndef EX_PUSH_LOCK
#define EX_PUSH_LOCK ULONG_PTR
#endif

typedef struct _MRX_FCB_ADVANCED_VISTA
{
	FSRTL_ADVANCED_FCB_HEADER Header;

	// Additional fields From Vista WDK
	LIST_ENTRY			FilterContexts;

	EX_PUSH_LOCK		PushLock;
	
	// The MRX_NET_ROOT instance with which this is associated
	//PMRX_NET_ROOT		pNetRoot;
	PVOID				pNetRoot;		// make our live easier ...

	// !!!! changes above this require realignment with fcb.h

	// the context fields to store additional information as deemed necessary by the
	// mini redirectors.

	PVOID				Context;
	PVOID				Context2;

	// The reference count: in a different place because we must prefix with
	// the FSRTL_COMMON_FCB_HEADER structure.

	ULONG				NodeReferenceCount;

	//
	//  The internal state of the Fcb.  THIS FIELD IS READONLY FOR MINIRDRS
	//

	ULONG				FcbState;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet.  This count
	//  is only used for data file objects, not for the Acl or Ea stream
	//  file objects.  This count gets decremented in RxCommonCleanup,
	//  while the OpenCount below gets decremented in RxCommonClose.

	CLONG				UncleanCount;

	//  A count of the number of file objects that have been opened for
	//  this file/directory, but not yet been cleaned up yet and for which
	//  cacheing is not supported. This is used in cleanup.c to tell if extra
	//  purges are required to maintain coherence.

	CLONG				UncachedUncleanCount;

	//  A count of the number of file objects that have opened
	//  this file/directory.  For files & directories the FsContext of the
	//  file object points to this record.

	CLONG				OpenCount;


	// The outstanding locks count: if this count is nonzero, the we silently
	// ignore adding LOCK_BUFFERING in a ChangeBufferingState request. This field
	// is manipulated by interlocked operations so you only have to have the fcb
	// shared to manipulate it but you have to have it exclusive to use it.

	ULONG            OutstandingLockOperationsCount;

	// The actual allocation length as opposed to the valid data length

	ULONGLONG        ActualAllocationLength;

	// Attributes of the MRX_FCB,

	ULONG            Attributes;

	// Intended for future use, currently used to round off allocation to
	// DWORD boundaries.

	USHORT           Spare1;
	BOOLEAN          fMiniInited;

	// Type of the associated MRX_NET_ROOT, intended to avoid pointer chasing.

	UCHAR            CachedNetRootType;

	//  Header for the list of srv_opens for this FCB....
	//  THIS FIELD IS READONLY FOR MINIS

	LIST_ENTRY      SrvOpenList;

	//  changes whenever the list changes..prevents extra lookups
	//  THIS FIELD IS READONLY FOR MINIS

	ULONG           SrvOpenListVersion;

} MRX_FCB_ADVANCED_VISTA;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//
//  For use by filter drivers to get information on provider corresponding to a given
//  fileobject on the remote filesystem stack. Without this, filters will always end up
//  getting \Device\Mup for providers registering with FsRtlRegisterUncProviderEx().
//

NTSTATUS NTAPI FsRtlMupGetProviderInfoFromFileObject(PFILE_OBJECT pFileObject, ULONG Level, PVOID pBuffer, PULONG pBufferSize);

//
//  Format of output in pBuffer.
//

typedef struct _FSRTL_MUP_PROVIDER_INFO_LEVEL_1 
{
    ULONG			ProviderId;         // ID for quick comparison, stable across provider load/unload.

} FSRTL_MUP_PROVIDER_INFO_LEVEL_1, *PFSRTL_MUP_PROVIDER_INFO_LEVEL_1;

typedef struct _FSRTL_MUP_PROVIDER_INFO_LEVEL_2 
{
    ULONG			ProviderId;         // ID for quick comparison, stable across provider load/unload.
    UNICODE_STRING  ProviderName;       // Device name of provider.

} FSRTL_MUP_PROVIDER_INFO_LEVEL_2, *PFSRTL_MUP_PROVIDER_INFO_LEVEL_2;

NTSTATUS NTAPI FsRtlMupGetProviderIdFromName(PUNICODE_STRING pProviderName, PULONG32 pProviderId);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // AFX_DRIVER_MRX_H__79614BBC_7357_4922_9A59_CA05B3CF7200__INCLUDED_