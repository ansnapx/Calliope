////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CWipePattern.cpp: implementation for the CWipePattern class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the NTIFS header
#include "driver.h"

#include "CWipePattern.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef FILFILE_WIPE_PATTERN_GEN

int const CWipePattern::s_patterns[] =
{
	// 2 random passes
	-2,
	// 1 bit
	2,  0x000, 0xfff,
	// 2 bit
	2,  0x555, 0xaaa,
	// random pass
	-1,
	// 3 bit
	6,  0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,
	// 4 bit
	12, 0x111, 0x222, 0x333, 0x444, 0x666, 0x777, 0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE,
	// The following patterns have the first bit per block flipped 
	8,  0x1000, 0x1249, 0x1492, 0x16DB, 0x1924, 0x1B6D, 0x1DB6, 0x1FFF,
	14, 0x1111, 0x1222, 0x1333, 0x1444, 0x1555, 0x1666, 0x1777, 0x1888, 0x1999, 0x1AAA, 0x1BBB, 0x1CCC, 0x1DDD, 0x1EEE,
	// random pass
	-1,
};

#endif //FILFILE_WIPE_PATTERN_GEN

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef FILFILE_WIPE_PATTERN_GEN

#pragma PAGEDCODE
bool CWipePattern::Generate(int *patterns, char patternsCount, unsigned char *random)
{
	if(!patterns || !patternsCount)
	{
		return false;
	}

	// ensure bounds
	if(patternsCount > sizeof(s_patterns)/sizeof(patterns[0]))
	{
		patternsCount = sizeof(s_patterns)/sizeof(patterns[0]);
	}

	// initialize with the random pattern
	memset(patterns, 0xff, patternsCount * sizeof(patterns[0]));

	int  index  = 0;
	int *target = patterns;
	int  passes = patternsCount;

	do
	{
		ASSERT(target < patterns + patternsCount);

		// wraped ?
		if(index >= sizeof(s_patterns)/sizeof(s_patterns[0]))
		{
			index = 0;
		}

		int const pattern = s_patterns[index];

		index++;

		if(pattern < 0)
		{
			// random passes
			target  += -pattern;
			passes  -= -pattern;
		}
		else
		{
			// use as much as fit
			int count = (pattern > passes) ? passes : pattern;

			passes -= count;

			do
			{
				ASSERT(target < patterns + patternsCount);
				ASSERT(index < sizeof(s_patterns)/sizeof(s_patterns[0]));

				*target++ = s_patterns[index];
				index++;

				count--;
			}
			while(count);
		}
	}
	while(passes > 0);

	if(patternsCount > 2)
	{
		if(random)
		{
			// shuffle selected patterns
			for(int index = 2; index < patternsCount; ++index)
			{
				int const dest = random[index - 2] % patternsCount;
				ASSERT(dest < patternsCount);

				if(dest > 1)
				{
					int const temp	= patterns[index];
					patterns[index]	= patterns[dest];
					patterns[dest]  = temp;
				}
			}
		}

		// ensure random pattern at start and end
		if((patterns[patternsCount - 1] >= 0) && (patterns[1] < 0))
		{
			patterns[1]				   = patterns[patternsCount - 1];
			patterns[patternsCount - 1] = -1;
		}
	}

	return true;
}

#endif //FILFILE_WIPE_PATTERN_GEN

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

bool CWipePattern::Fill(int pattern, unsigned char *target, unsigned int targetSize)
{
	// target buffer must be at least 3 bytes long
	if(!target || targetSize < 3)
	{
		return false;
	}
	// reject the random pattern - as it's handled elsewhere
	if(pattern < 0)
	{
		return false;
	}

	if(!pattern)
	{
		memset(target, 0, targetSize);
	}
	else
	{
		unsigned int bits = pattern & 0xfff;
		bits			 |= bits << 12;

		// set first 3 values manually
		target[0] = (unsigned char) ((bits >> 4) & 0xff);
		target[1] = (unsigned char) ((bits >> 8) & 0xff);
		target[2] = (unsigned char) (bits & 0xff);

		unsigned int index;

		// double copied size in each run
		for(index = 3; index < targetSize / 2; index *= 2)
		{
			memcpy(target + index, target, index);
		}

		// bytes left ?
		if(index < targetSize)
		{
			memcpy(target + index, target, targetSize - index);
		}

		// invert the first bit of every 512 byte block, if selected
		if(pattern & 0x1000)
		{
			for(index = 0; index < targetSize; index += 512)
			{
				target[index] ^= 0x80;
			}
		}
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////