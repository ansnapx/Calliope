// CalliopeEnumeration.h: interface for the CalliopeEnumeration class.
// -------------------------------------------------------------------
// *** 09.06.2005 Frank Melber ***
// -------------------------------------------------------------------
// (last modified: 09.06.2005 Frank Melber)
//////////////////////////////////////////////////////////////////////
#ifndef Included_CalliopeEnumeration_h
#define Included_CalliopeEnumeration_h

#include <atlbase.h>
#include "CalliopeLibraryInterface.h"
#include "PGPInterfaceMap.h"

// ***************************************************************************************
// CalliopeEnumeration: A Calliope enumeration implementation...
// ***************************************************************************************
class CalliopeEnumeration : public PGPRefCountImpl<ICalliopeEnumeration>  
{
// Interface map...
PGPInterfaceMap_Begin
	PGPInterfaceMap_Entry(ICalliopeEnumeration)
PGPInterfaceMap_End

public:
// Construction/Destruction...
	CalliopeEnumeration();
	~CalliopeEnumeration();

public:
// Overridables...
	// Get the count of items...
	STDMETHOD_(UINT, GetItemCount)() const;

	// Get an item...
	STDMETHOD(GetItem)(const UINT uiIndex, IUnknown** pUnknown);	

	// Add an item...
	STDMETHOD(AddItem)(IUnknown* pUnknown);
	// Add an enumeration...
	STDMETHOD(AddEnumeration)(ICalliopeEnumeration* pEnumeration);	

	// Delete an item...
	STDMETHOD(DeleteItem)(IUnknown* pUnknown);
	// Delete an item...
	STDMETHOD(DeleteItem)(const UINT uiIndex);

private:
// Internal data...
	CSimpleArray<IUnknown*> m_arr;
};
#endif /* Included_CalliopeEnumeration_h */
