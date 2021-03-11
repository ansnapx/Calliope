/*____________________________________________________________________________
	Copyright (C) 2002 PGP Corporation
	All rights reserved.

	$Id: pflTypes.h 20641 2004-02-10 01:55:29Z ajivsov $
____________________________________________________________________________*/
#ifndef Included_pflTypes_h	/* [ */
#define Included_pflTypes_h



/* opaque declarations */
typedef struct PFLFileSpec *		PFLFileSpecRef;
typedef struct PFLFileSpec const *	PFLConstFileSpecRef;

typedef struct PFLDirectoryIter *		PFLDirectoryIterRef;
typedef struct PFLDirectoryIter const *	PFLConstDirectoryIterRef;

/* Validity checks */
#define	kInvalidPFLFileSpecRef			((PFLFileSpecRef) NULL)
#define	kInvalidPFLDirectoryIterRef		((PFLDirectoryIterRef) NULL)

#define PFLFileSpecRefIsValid( ref )		( (ref) != kInvalidPFLFileSpecRef )
#define PFLDirectoryIterRefIsValid( ref )	\
			( (ref) != kInvalidPFLDirectoryIterRef )

#endif /* ] Included_pflTypes_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
