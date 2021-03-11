////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterVolume.h: interface for the CFilterVolume class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_CFilterVolume_H__51B15847_87CB_4E09_9F51_061696E8901B__INCLUDED_)
#define AFX_CFilterVolume_H__51B15847_87CB_4E09_9F51_061696E8901B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CFilterContext.h"

struct FILFILE_VOLUME_EXTENSION;
struct FILFILE_HEADER_BLOCK;
class CFilterEngineObject;

////////////////////////////////

class CFilterVolume  
{
	friend class CFilterControl;
		
public:

	NTSTATUS					Init(FILFILE_VOLUME_EXTENSION *extension, ULONG volumeIdentifier);
	NTSTATUS					Close();

	NTSTATUS					GetEntityInfo(ULONG entityIdentifier, CFilterEntity *target);
	NTSTATUS					ManageEntity(FILFILE_TRACK_CONTEXT *context, ULONG flags);
	NTSTATUS					ManageEncryption(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *present, FILFILE_TRACK_CONTEXT *future, ULONG flags);

	int							CheckDirectoryCooked(FILE_OBJECT *file, CFilterDirectory *directory = 0);
	int							CheckFileCooked(FILE_OBJECT *file, CFilterContextLink *link = 0);
	NTSTATUS					LonelyEntity(FILE_OBJECT *file, ULONG type, ULONG identifier = 0);
    		
	NTSTATUS					OnFileCreate(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track, ULONG dispo);
	NTSTATUS					OnFileCleanup(FILE_OBJECT *file);
	NTSTATUS					OnFileClose(FILE_OBJECT *file, bool discard = false);
	NTSTATUS					OnDirectoryClose(FILE_OBJECT *directory);

	NTSTATUS					PreCreate(IRP  *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					PostCreate(IRP *irp, FILFILE_TRACK_CONTEXT *track);
		
	NTSTATUS					UpdateLink(FILE_OBJECT *file, ULONG flags, bool clear = false);

	NTSTATUS					UpdateEntity(ULONG identifier, CFilterPath *path);
	NTSTATUS					RemoveEntity(ULONG identifier, ULONG type, ULONG flags = ENTITY_PURGE, LUID const* luid = 0);
	NTSTATUS					RemoveEntity(FILE_OBJECT *file, ULONG flags = ENTITY_NULL);

private:

	NTSTATUS					ManageEncryptionFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *present, FILFILE_TRACK_CONTEXT *future, ULONG flags);

	NTSTATUS					FileCheck(IRP *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					AutoConfigCheck(IRP *irp, FILFILE_TRACK_CONTEXT* track, FILE_OBJECT *related = 0);
	NTSTATUS					AutoConfigCheckGeneric(CFilterPath *path, CFilterHeader *header);
	NTSTATUS					AutoConfigVerify(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags = 0);

	NTSTATUS					PostCreateAuthenticate(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG headerIdentifier, ULONG flags);
	NTSTATUS					PostCreateEntity(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags);
	NTSTATUS					PostCreateEscape(IRP *irp, FILFILE_TRACK_CONTEXT *track, ULONG flags);

	NTSTATUS					PostCreateFile(IRP *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					PostCreateFileOpened(IRP  *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					PostCreateFileCreated(IRP *irp, FILFILE_TRACK_CONTEXT *track);

	NTSTATUS					PostCreateDirectory(IRP *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					PostCreateDirectoryOpened(IRP *irp, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					PostCreateDirectoryCreated(IRP *irp, FILFILE_TRACK_CONTEXT *track);

	NTSTATUS					CreateEntity(FILFILE_TRACK_CONTEXT *track, ULONG flags);
	NTSTATUS					AddEntity(FILFILE_TRACK_CONTEXT *track, ULONG flags = 0);
	NTSTATUS					UpdateEntity(ULONG currIdentifier, ULONG newIdentifier);
		
	NTSTATUS					RemoveEntity(CFilterPath const* path, LUID const* luid = 0, ULONG pos = ~0u, ULONG flags = ENTITY_PURGE);
	NTSTATUS					RemoveEntities(ULONG flags, LUID const* luid = 0);
	NTSTATUS					PurgeEntities(ULONG flags, LUID const* luid = 0);

	NTSTATUS					InitNewFile(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track, ULONG dispo);
	NTSTATUS					InitNewDirectory(CFilterEntity const* entity, ULONG deepness,FILFILE_TRACK_CONTEXT *track=NULL);
	
	NTSTATUS					RemoteFileChange(FILE_OBJECT *file, FILFILE_TRACK_CONTEXT *track);
	NTSTATUS					ConsolidateEntities(ULONG *identifier);
	ULONG						GenerateEntityIdentifier();

	bool						IsSpecific(FILFILE_TRACK_CONTEXT *track, ULONG flags);

								// STATIC
	static bool					IsRemoteRequest(FILFILE_TRACK_CONTEXT *track, IRP *createIrp = 0);

public:
								
	FILFILE_VOLUME_EXTENSION*	m_extension;
	CFilterContext*				m_context;

private:

	ULONG						m_nextIdentifier;
								
	CFilterEntityCont			m_entities;
	ERESOURCE					m_entitiesResource;

	CFilterEntityCont			m_negatives;
	ERESOURCE					m_negativesResource;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

inline
ULONG CFilterVolume::GenerateEntityIdentifier()
{
	// Wraped ?
	if((m_nextIdentifier & 0x00ffffff) == 0x00ffffff)
	{
		ASSERT(false);

		//
		// TODO: search list for new identifier
		//
	}

	return m_nextIdentifier++;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // !defined(AFX_CFilterVolume_H__51B15847_87CB_4E09_9F51_061696E8901B__INCLUDED_)
