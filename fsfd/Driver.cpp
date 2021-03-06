///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Driver.cpp - generic for all drivers
//
// Author: Michael Alexander Priske
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "Driver.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#if DBG && defined(_X86_)
#pragma LOCKEDCODE

extern "C" void __declspec(naked) __cdecl _chkesp(void)
{
	_asm je okay
	ASSERT(!"FilFile: - Stack pointer mismatch!");
okay:
	_asm ret
}

#endif // DBG
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////