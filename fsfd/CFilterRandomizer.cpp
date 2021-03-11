////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// CFilterRandomizer.h: interface for the CFilterRandomizer class.
//
// Author: Michael Alexander Priske
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define DRIVER_USE_NTIFS	// use the IFS header
#include "driver.h"

#include "CFilterBase.h"
#include "CFilterControl.h"
#include "RijndaelCoder.h"

#include "CFilterRandomizer.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

void CFilterRandomizer::Close()
{
	PAGED_CODE();

	ExAcquireFastMutex(&m_lock);

	if(m_random)
	{
		ASSERT(m_size);

		// be paranoid
		RtlZeroMemory(m_random, m_size);

		ExFreePool(m_random);
		m_random = 0;
	}

	m_size = 0;
	m_next = 0;

	ExReleaseFastMutex(&m_lock);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma PAGEDCODE

NTSTATUS CFilterRandomizer::Prepare(ULONG size)
{
	PAGED_CODE();

	if(!size)
	{
		C_ASSERT(0 == (c_sizeHigh % c_blockSize));
		C_ASSERT(0 == (c_sizeLow  % c_blockSize));

		size = (m_high) ? c_sizeHigh : c_sizeLow;
	}

	ASSERT(0 == (size % c_blockSize));

	if(!m_random)
	{
		DBGPRINT(("CFilterRandomizer(%s): init pool, Size[0x%x]\n", (m_high)? "high":"low", size));

		m_random = (UCHAR*) ExAllocatePool(NonPagedPool, size);

		if(!m_random)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		m_size = size;
		m_next = size;

		if(!m_high)
		{
			// initialize with some minimum entropy
			Gather();
		}

		m_fired = false;
	}

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterRandomizer::Get(UCHAR *target, ULONG size)
{
	ASSERT(target);
	ASSERT(size);

	DBGPRINT(("CFilterRandomizer(%s): retrieve random Size[0x%x]\n", (m_high)? "high":"low", size));
    
	ExAcquireFastMutex(&m_lock);

	if(!m_random)
	{
		NTSTATUS status = Prepare();

		if(NT_ERROR(status))
		{
			ExReleaseFastMutex(&m_lock);

			return status;
		}
	}

	ASSERT(m_random);
	ASSERT(m_size);
	ASSERT(m_size >= m_next);

	// ensure we never give out data used internally
	ASSERT(m_next >= c_blockSize);
	
	// enough random data available ?
	if(size <= m_size - m_next)
	{
		RtlCopyMemory(target, m_random + m_next, size);

		m_next += size;
	}
	else
	{
		ULONG current = 0;

		while(current < size)
		{
			if(m_next >= m_size)
			{
				if(m_high)
				{
					// gather new random data
					Gather();
				}

				// never use gatherred random data directly
				Permutate();

				// ensure we never give out data used internally
				ASSERT(m_next >= c_blockSize);
			}

			ASSERT(m_size > m_next);
        
			ULONG copy = size - current;

			if(copy > m_size - m_next)
			{
				copy = m_size - m_next;
			}

			ASSERT(current + copy <= size);
			RtlCopyMemory(target + current, m_random + m_next, copy);

			m_next  += copy;
			current += copy;
		}
	}

	ASSERT(m_size >= m_next);
	
	// if random data left is nearly empty request new, asynchronously
	if(m_high && (m_size - m_next < m_size / 4))
	{
		if(!m_fired)
		{
			m_fired = true;

			DBGPRINT(("CFilterRandomizer: request async\n"));

			// just fire event w/o waiting for response
			CFilterControl::Callback().FireRandom(FILFILE_CONTROL_NULL);
		}
	}

	ExReleaseFastMutex(&m_lock);

    return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterRandomizer::Gather()
{
	ASSERT(m_random);
	ASSERT(m_size);

	ASSERT(0 == (m_size % c_blockSize));

	// lock must be already held
	NTSTATUS status = STATUS_ALERTED;

	if(m_high)
	{
		m_fired = true;

		// retrieve random data from UserMode component, synchronously
		status = CFilterControl::Callback().FireRandom(FILFILE_CONTROL_ACTIVE, &m_random, &m_size);

		m_fired = false;
	}
    
	if(STATUS_SUCCESS != status)
	{
		DBGPRINT(("CFilterRandomizer(%s): gathering entropy\n", (m_high)? "high":"low"));

		// internal Gather function to provide a miniumum of entropy, used as fallback if above has failed
		UCHAR block[c_blockSize];

		// retrieve data for key to be used
		KeQuerySystemTime((LARGE_INTEGER*) block);
		KeQueryTickCount((LARGE_INTEGER*) (block + 8));

		// use 128 bit key
		RijndealCoder<AES_128> aes;
		aes.Init(block, false);

		for(ULONG blockIndex = 0; blockIndex < m_size; blockIndex += c_blockSize)
		{
			// Don't call this function in the inner loop. First, its value doesn't change much
			// and second, it disables system-wide interrupts, which is generally a bad thing.
			LARGE_INTEGER const current = KeQueryPerformanceCounter(0);

			// use only lowest 16 bit for selection
			for(ULONG counter = 0; counter < 16; ++counter)
			{
				ULONG const xor = (current.LowPart & (1u << counter)) ? 0x55555555 : 0xffffffff;

				// xor seed block with selected value
				ULONG *s = (ULONG*) block;

				*s++ ^= xor;
				*s++ ^= xor;
				*s++ ^= xor;
				*s   ^= xor;

				// re-seed block
				aes.EncodeBlock(block);

				s = (ULONG*) block;

				// xor random pool with seeded block
				ULONG *t = (ULONG*) (m_random + blockIndex);
				
				*t++ ^= *s++;
				*t++ ^= *s++;
				*t++ ^= *s++;
				*t   ^= *s;

				blockIndex += c_blockSize;

				// finished ?
				if(blockIndex >= m_size)
				{
					break;
				}
			}
		}
	
		// inform caller about fallback use
		status = STATUS_ALERTED;
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma LOCKEDCODE

NTSTATUS CFilterRandomizer::Permutate()
{
	// lock must be already held

	ASSERT(m_random);
	ASSERT(m_size);
	ASSERT(0 == (m_size % c_blockSize));
	      
	// use 256 bit key
	UCHAR key[32];

	// get some system variables for new key
	*((LARGE_INTEGER*) key) = KeQueryPerformanceCounter(0);
	KeQuerySystemTime((LARGE_INTEGER*) (key + 8));
	
	// use first (reserved) block (128 bit) as part of new key
	ASSERT(m_size > c_blockSize);
	RtlCopyMemory(key + 16, m_random, c_blockSize);

	RijndealCoder<AES_256> aes;
	C_ASSERT(c_blockSize == aes.c_blockSize);

	aes.Init(key, false);

	// encode current random buffer using new key
	for(ULONG current = 0; current < m_size; current += c_blockSize)
	{
		aes.EncodeBlock(m_random + current);
	}

	// reserve first block for internal use
	m_next = c_blockSize;

	return STATUS_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
