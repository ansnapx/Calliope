////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CWipePattern.h: interface for the CWipePattern class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
	This wiping code is based on Colin Plumb's  sterilize.c - v1.01. 
	See this for more details.

	For the theory behind, see "Secure Deletion of Data from Magnetic and 
	Solid-State Memory" from Peter Gutmann, online at: 
	http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html

	Changes to Plumb's version:	1) external PRNG 
								2) different shuffle logic
*/

#if !defined(AFX_CWipePattern_H__B9B71423_C4A8_45EA_878B_6A9B539045A1__INCLUDED_)
#define AFX_CWipePattern_H__B9B71423_C4A8_45EA_878B_6A9B539045A1__INCLUDED_

// support for internal pattern generation
//#define FILFILE_WIPE_PATTERN_GEN

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CWipePattern
{
	
public:

	static bool			Fill(int pattern, unsigned char *target, unsigned int targetSize);

#ifdef FILFILE_WIPE_PATTERN_GEN
						// Note: the size of provided random buffer (if any) must be at least patternsCount long
	static bool			Generate(int *patterns, char patternsCount, unsigned char *random = 0);
private:
	static int const	s_patterns[];
#endif

};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#endif // AFX_CWipePattern_H__B9B71423_C4A8_45EA_878B_6A9B539045A1__INCLUDED_