// CalliopeUser.h: interface for the CalliopeUser class.
// -------------------------------------------------------------------
// *** 09.06.2005 Frank Melber ***
// -------------------------------------------------------------------
// (last modified: 09.06.2005 Frank Melber)
//////////////////////////////////////////////////////////////////////
#ifndef Included_CalliopeUser_h
#define Included_CalliopeUser_h

#include <atlbase.h>
#include "CalliopeLibraryInterface.h"
#include "CalliopeUserBaseImpl.h"
#include "PGPInterfaceMap.h"



// ***************************************************************************************
// CalliopeUser: A Calliope user implementation...
// ***************************************************************************************
class CalliopeUser : public PGPRefCountImpl<CalliopeUserBaseImpl<ICalliopeUser> >  
{
// Interface map...
PGPInterfaceMap_Begin
	PGPInterfaceMap_Entry(ICalliopeUser)
PGPInterfaceMap_End

public:
// Construction/Destruction...
	CalliopeUser();
	~CalliopeUser();
};
#endif /* Included_CalliopeUser_h */
