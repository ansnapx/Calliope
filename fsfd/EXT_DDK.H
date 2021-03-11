
#ifndef _EXT_H_INCLUDED
#define _EXT_H_INCLUDED


#ifndef DDK_TYPE_WXP

/////////////////////////////////////////////////////////
// The following definitions are from the XP DDK
/////////////////////////////////////////////////////////

// ntddisk.h /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define IOCTL_DISK_GET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_PARTITION_INFO_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0013, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX      CTL_CODE(IOCTL_DISK_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
//#define IOCTL_DISK_CREATE_DISK              CTL_CODE(IOCTL_DISK_BASE, 0x0016, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
//#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)

// mountdev.h
#define IOCTL_MOUNTDEV_QUERY_STABLE_GUID    CTL_CODE(MOUNTDEVCONTROLTYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// The structure GET_LENGTH_INFORMATION is used with the ioctl
// IOCTL_DISK_GET_LENGTH_INFO to obtain the length, in bytes, of the
// disk, partition, or volume.
//
typedef struct _GET_LENGTH_INFORMATION 
{
    LARGE_INTEGER   Length;
} GET_LENGTH_INFORMATION, *PGET_LENGTH_INFORMATION;

//
// There are currently two ways a disk can be partitioned. With a traditional
// AT-style master boot record (PARTITION_STYLE_MBR) and with a new, GPT
// partition table (PARTITION_STYLE_GPT). RAW is for an unrecognizable
// partition style. There are a very limited number of things you can
// do with a RAW partititon.
//

typedef enum _PARTITION_STYLE {
    PARTITION_STYLE_MBR,
    PARTITION_STYLE_GPT,
    PARTITION_STYLE_RAW
} PARTITION_STYLE;

//
// The following structure defines information in an MBR partition that is not
// common to both GPT and MBR partitions.
//

typedef struct _PARTITION_INFORMATION_MBR {
    UCHAR PartitionType;
    BOOLEAN BootIndicator;
    BOOLEAN RecognizedPartition;
    ULONG HiddenSectors;
} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;


//
// The following structure defines information in a GPT partition that is
// not common to both GPT and MBR partitions.
//

typedef struct _PARTITION_INFORMATION_GPT {
    GUID PartitionType;                 // Partition type. See table 16-3.
    GUID PartitionId;                   // Unique GUID for this partition.
    ULONG64 Attributes;                 // See table 16-4.
    WCHAR Name [36];                    // Partition Name in Unicode.
} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;


//
// The PARTITION_INFORMATION_EX structure is used with the
// IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
// IOCTL_DISK_GET_PARTITION_INFO_EX and IOCTL_DISK_GET_PARTITION_INFO_EX calls.
//

typedef struct _PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    LARGE_INTEGER StartingOffset;
    LARGE_INTEGER PartitionLength;
    ULONG PartitionNumber;
    BOOLEAN RewritePartition;
    union {
        PARTITION_INFORMATION_MBR Mbr;
        PARTITION_INFORMATION_GPT Gpt;
    };
} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;


//
// GPT specific drive layout information.
//

typedef struct _DRIVE_LAYOUT_INFORMATION_GPT {
    GUID DiskId;
    LARGE_INTEGER StartingUsableOffset;
    LARGE_INTEGER UsableLength;
    ULONG MaxPartitionCount;
} DRIVE_LAYOUT_INFORMATION_GPT, *PDRIVE_LAYOUT_INFORMATION_GPT;


//
// MBR specific drive layout information.
//

typedef struct _DRIVE_LAYOUT_INFORMATION_MBR {
    ULONG Signature;
} DRIVE_LAYOUT_INFORMATION_MBR, *PDRIVE_LAYOUT_INFORMATION_MBR;


//
// The structure SET_PARTITION_INFO_EX is used with the ioctl
// IOCTL_SET_PARTITION_INFO_EX to set information about a specific
// partition. Note that for MBR partitions, you can only set the partition
// signature, whereas GPT partitions allow setting of all fields that
// you can get.
//


typedef SET_PARTITION_INFORMATION SET_PARTITION_INFORMATION_MBR;
typedef PARTITION_INFORMATION_GPT SET_PARTITION_INFORMATION_GPT;


typedef struct _SET_PARTITION_INFORMATION_EX {
    PARTITION_STYLE PartitionStyle;
    union {
        SET_PARTITION_INFORMATION_MBR Mbr;
        SET_PARTITION_INFORMATION_GPT Gpt;
    };
} SET_PARTITION_INFORMATION_EX, *PSET_PARTITION_INFORMATION_EX;


// ntddstor.h ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define IOCTL_STORAGE_GET_HOTPLUG_INFO CTL_CODE(IOCTL_STORAGE_BASE, 0x0305, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ntddvol.h /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define IOCTL_VOLUME_GET_GPT_ATTRIBUTES CTL_CODE(IOCTL_VOLUME_BASE, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)


#endif //DDK_TYPE_WXP


/////////////////////////////////////////////////////////
// The following definitions are from NTIFS.H
/////////////////////////////////////////////////////////

#define FSCTL_LOCK_VOLUME		CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME		CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define SECURITY_MAX_IMPERSONATION_LEVEL SecurityDelegation
#define DEFAULT_IMPERSONATION_LEVEL SecurityImpersonation

NTKERNELAPI void IoSetTopLevelIrp(IN PIRP Irp);
NTKERNELAPI PIRP IoGetTopLevelIrp(void);

//
// VOID
// PsDereferencePrimaryToken(
//    IN PACCESS_TOKEN PrimaryToken
//    );
//
#define PsDereferencePrimaryToken(T) (ObDereferenceObject((T)))

//
// VOID
// PsDereferenceImpersonationToken(
//    In PACCESS_TOKEN ImpersonationToken
//    );
//
#define PsDereferenceImpersonationToken(T)                                    \
            {if (ARGUMENT_PRESENT(T)) {                                       \
                (ObDereferenceObject((T)));                                   \
             } else {                                                         \
                ;                                                             \
             }                                                                \
            }


#define SeDeleteClientSecurity(C)  {                                           \
            if (SeTokenType((C)->ClientToken) == TokenPrimary) {               \
                PsDereferencePrimaryToken( (C)->ClientToken );                 \
            } else {                                                           \
                PsDereferenceImpersonationToken( (C)->ClientToken );           \
            }                                                                  \
        }


//
// Security Tracking Mode
//

#define SECURITY_DYNAMIC_TRACKING      (TRUE)
#define SECURITY_STATIC_TRACKING       (FALSE)

typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE, * PSECURITY_CONTEXT_TRACKING_MODE;

#define TOKEN_SOURCE_LENGTH 8

//
//
// Token Types
//

typedef enum _TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
    } TOKEN_TYPE;
typedef TOKEN_TYPE *PTOKEN_TYPE;


typedef struct _TOKEN_SOURCE {
    CHAR SourceName[TOKEN_SOURCE_LENGTH];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;


typedef struct _TOKEN_CONTROL {
    LUID TokenId;
    LUID AuthenticationId;
    LUID ModifiedId;
    TOKEN_SOURCE TokenSource;
    } TOKEN_CONTROL, *PTOKEN_CONTROL;

//
// Data structure used to represent client security context for a thread.
// This data structure is used to support impersonation.
//
//  THE FIELDS OF THIS DATA STRUCTURE SHOULD BE CONSIDERED OPAQUE
//  BY ALL EXCEPT THE SECURITY ROUTINES.
//

typedef struct _SECURITY_CLIENT_CONTEXT 
{
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PACCESS_TOKEN ClientToken;
    BOOLEAN DirectlyAccessClientToken;
    BOOLEAN DirectAccessEffectiveOnly;
    BOOLEAN ServerIsRemote;
    TOKEN_CONTROL ClientTokenControl;
    } SECURITY_CLIENT_CONTEXT, *PSECURITY_CLIENT_CONTEXT;

extern "C"
{
	/*
	NTSTATUS ObOpenObjectByPointer(IN PVOID Object, 
								   IN ULONG HandleAttributes,                                  
								   IN PACCESS_STATE PassedAccessState OPTIONAL,                
								   IN ACCESS_MASK DesiredAccess		  OPTIONAL,                      
								   IN POBJECT_TYPE ObjectType		  OPTIONAL,                        
								   IN KPROCESSOR_MODE AccessMode,                              
								   OUT PHANDLE Handle);                                                          
	*/
	//void NTAPI KeAttachProcess(PEPROCESS Process);
	//void KeDetachProcess(void);

	NTSTATUS SeCreateClientSecurity (IN PETHREAD ClientThread,
									 IN PSECURITY_QUALITY_OF_SERVICE ClientSecurityQos,
									 IN BOOLEAN RemoteSession,
									 OUT PSECURITY_CLIENT_CONTEXT ClientContext);


	VOID SeImpersonateClient(IN PSECURITY_CLIENT_CONTEXT ClientContext,
							 IN PETHREAD ServerThread OPTIONAL);


	NTSTATUS SeImpersonateClientEx(IN PSECURITY_CLIENT_CONTEXT ClientContext,
								   IN PETHREAD ServerThread OPTIONAL); 

	TOKEN_TYPE SeTokenType(IN PACCESS_TOKEN Token);                                          

	VOID PsRevertToSelf(void);

	NTSTATUS ObCreateObject(IN KPROCESSOR_MODE ProbeMode, 
							IN POBJECT_TYPE ObjectType, 
							IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
							IN KPROCESSOR_MODE OwnershipMode, 
							IN OUT PVOID ParseContext OPTIONAL, 
							IN ULONG ObjectBodySize, 
							IN ULONG PagedPoolCharge, 
							IN ULONG NonPagedPoolCharge, 
							OUT PVOID *Object); 

	NTSTATUS SeCreateAccessState(PACCESS_STATE pAccessState, PVOID pAuxData, ACCESS_MASK AccessMask, PGENERIC_MAPPING pMapping); 
}


// END
#endif //_EXT_H_INCLUDED