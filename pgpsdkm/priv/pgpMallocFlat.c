/*____________________________________________________________________________
	Copyright (C) 2006 PGP Corporation
	All rights reserved.

	Flat random access memory manager. 

	Written by Andrey Jivsov for fun during free time and given to PGP, so it 
	is PGP property now. 

	Lighweight memory manager that serves memory allocations from passed memory 
	buffer without system calls.

	Its advantage is economical memory management. This implementation prefers 
	storage efficiency to speed, however, it should be good enough for 
	high-performance code (it is much faster than glibc-2.3.3-27). 
	Each allocated block incurrs 5 bytes of overhead for header and alignment. 

	Complies with malloc/realloc/free calling convention. It returns
	4 byte-aligned pointers. There are no global variables here, so this
	code is thread-safe (assuming that threads use non-overlapping buffers).
	
	Caller must first initialize the descriptor of buffer with malloc_flat_init(). 
	malloc_flat_init can accept any size < 2^32, but the size is effectively 
	capped at 2971215073 (2.8Gb). Check array F for the most efficient
	sizes of passed buffer. For example, for passed size 4096 less than 2584
	bytes will be available for allocations. On return malloc_flat_init
	provides the accepted size in output descriptor. This descriptor
	then must be passed to malloc/realloc/free.

	Here are some suggestions for size:
	
	Need at least			Pass this value
	-----------------------------------------------
	  4K				      4181
	 64K				     75025
	150K				 165580141
	  1G				1134903170

	You can expect to get smaller total aggregate amount of available memory 
	than numbers on the left, depending on allocation sizes and sequence of calls.

	$Id: pgpMallocFlat.c 51127 2007-01-31 23:37:51Z ajivsov $
____________________________________________________________________________*/

//#define TEST 1

#include "pgpMallocFlat.h"

#ifdef TEST
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#ifndef NULL
#define NULL (void*)0
#endif

/* How can we live without these anywhere? */
#ifndef MEM_MEMCPY
#ifndef _WIN64
void *memcpy( void *, const void *, unsigned );
#endif
#define MEM_MEMCPY(dst,src,cnt) memcpy(dst,src,cnt)
#endif
#ifndef MEM_ASSERT
#define MEM_ASSERT(x) // assert(x)
#endif

#ifndef MEM_INLINE
#ifdef _WIN32
#define MEM_INLINE __inline
#else
#define MEM_INLINE inline
#endif
#endif


#define MEM_SIG ('F'<<24 | 'M'<<16 | 'M'<<8 | 'j' )

/**
 * __msb - find MSB in a word on Intel, returning 0-based index.
 * @word: The word to search
 *
 * You will need to define this for your platform, or implement with bitwise operations
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
#ifdef _WIN32
#include <intrin.h>
#pragma intrinsic(_BitScanReverse)
static __inline unsigned long __msb(unsigned long word)  {
	unsigned long ret;
	_BitScanReverse( &ret, word );
	return ret;
}
#else
static inline unsigned long __msb(unsigned long word)
{
        __asm__("bsrl %1,%0"
                :"=r" (word)
                :"rm" (word));
        return word;
}
#endif

#define MAX_LEFT_CNT 0xe0	/* catches errors */

/* Fibonacci numbers < 2^32. Choose the buffer size from one of these
 */
static unsigned int F[] = {
8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765, 10946, 
17711, 28657, 46368, 75025, 121393, 196418, 317811, 514229, 832040, 1346269, 2178309, 3524578, 5702887, 9227465, 14930352, 24157817,
39088169, 63245986, 102334155, 165580141, 267914296, 433494437, 701408733, 1134903170, 1836311903, 2971215073UL };

// For highest i: x > 2^i returns highest j: x > F[j], 
// so we can start sequential search for the lowest k>=j: x < F[k]
// This method underestimates the value by 2 steps max
static unsigned char log_to_idx[] = {
	0/*2^0*/,0/*2^1*/,0/*2^2*/,0/*2^3*/,1/*2^4*/,2/*2^5*/,4/*2^6*/,5/*2^7*/,7/*2^8*/,8/*2^9*/,10/*2^10*/,11/*2^11*/,12/*2^12*/,14/*2^13*/,15/*2^14*/, 
	17/*2^15*/,18/*2^16*/,20/*2^17*/,21/*2^18*/,23/*2^19*/,24/*2^20*/,25/*2^21*/,27/*2^22*/,28/*2^23*/,30/*2^24*/,31/*2^25*/,33/*2^26*/,34/*2^27*/,36/*2^28*/,
	37/*2^29*/,38/*2^30*/,40/*2^31*/
};

/* 2 bytes */
#pragma pack(push, mem_flat_header, 2)
struct mem_flat_header  {
	unsigned short is_empty:1;
	unsigned short idx:6;
	unsigned short left_cnt:8;	/* ~log(total_size)/1.6 ? See MAX_LEFT_CNT */
	unsigned short is_gap:1;	/* keep it last; see not_a_mem_flat_header_tail */
};
#pragma pack(pop, mem_flat_header)

#define not_a_mem_flat_header_tail 0xff

int malloc_flat_init( void *buf, unsigned size, struct mem_flat_region_descriptor *descr )  {
	unsigned i;
	struct mem_flat_header *h = (struct mem_flat_header *)buf;

	descr->signature = 0;
	descr->p = NULL;
	descr->size = 0;

	if( size <= F[0] || sizeof(struct mem_flat_header)>2 )
		return -1;

	for( i=0; i<sizeof(F)/sizeof(F[0]); i++ )
		if( F[i] > size )
			break;
	
	if( i>=sizeof(F)/sizeof(F[0]) )
		i=sizeof(F)/sizeof(F[0]) - 1;
	if( F[i] > size && i>0 )
		i--;

	descr->p = buf;
	descr->size = F[i];
	descr->signature = MEM_SIG;

	/* boorstrap with single block */
	h->is_empty = 1;
	h->idx = i;
	h->left_cnt = 0;  

	return 0;
}

/* get best i: F[i] > size */
static int idx_from_size(unsigned size)  {
	int i;
	unsigned bit = __msb(size);

	if( size<=F[0] )
		return 0; 

	if( bit >= sizeof(log_to_idx)/sizeof(log_to_idx[0]) )
		return -1;

	i = log_to_idx[bit];
	
	MEM_ASSERT( F[i] < size );
		
	if( F[++i] >= size )
		return i;
	if( F[++i] >= size )
		return i;
	MEM_ASSERT( F[i+1] > size );
	return i+1;
}

/* Recursively: S_i = S_i-1 (left) + S_i-2 (right) */
static unsigned char *split( unsigned char *p, int idx )  {
	struct mem_flat_header *h, *h2;

	MEM_ASSERT( idx>=2 );

	h = (struct mem_flat_header *)p;
	MEM_ASSERT( h->is_empty );
	MEM_ASSERT( idx <= h->idx );

	if( idx == h->idx /*|| idx < 2*/ )  {
		return p;
	}
	MEM_ASSERT( idx < h->idx );
	
	/* make new left (the bigger one) */
	h->idx--;
	h->left_cnt++;

	/* make new empty right (the smaller one) */
	h2 = (struct mem_flat_header *)(p + F[h->idx]);
	h2->is_empty = 1;
	h2->idx = h->idx-1;
	h2->left_cnt = 0;

	MEM_ASSERT( idx <= h->idx );
	if( idx >= h->idx-1 )
		return h2->idx == idx ? (unsigned char *)h2 : (unsigned char *)h;

	/* tail recursion */
	return split( (unsigned char *)h2, idx );
}

/* Called to merge freed block pointed by p. 
 * Inverse to split(). 
 */
static void merge( unsigned char *p, void *start_p )  {
	struct mem_flat_header *h = (struct mem_flat_header *)p;
	struct mem_flat_header *h2;

	MEM_ASSERT(h->is_empty==1);
	
	/* freeing a right block */
	if( h->left_cnt==0 )  {
		if( (void*)p==start_p )	/* this is actually the very last block */
			return;

		/* left header */
		h2 = (struct mem_flat_header *)(p-F[h->idx+1]);
		if( h2->is_empty==1 && h2->idx == h->idx+1 )  {
			MEM_ASSERT( h2->left_cnt>0 );
			h2->idx = h->idx+2;
			h2->left_cnt--;
			// todo: clean the h
			merge( (void*)h2, start_p );
		}
	}
	else  {
		/* freeing a left block */
		MEM_ASSERT( h->left_cnt>=1 );
		h2 = (struct mem_flat_header *)(p+F[h->idx]);
		if( h2->is_empty==1 && h2->idx == h->idx-1 )  {
			MEM_ASSERT( h2->left_cnt==0 );
			h->idx ++;
			h->left_cnt--;
			// todo: clean the h2
			merge( (void*)h, start_p );
		}
	}
}

/* returns preceeding header; takes care of ptr alignment */
static struct mem_flat_header *header_from_ptr(void *ptr)  {
	unsigned char *p = ptr;
	if( p==NULL )
		return NULL;

	/* sizeof(usigned) aligned */
	if( p[-1] == not_a_mem_flat_header_tail )
		p--;
	if( p[-1] == not_a_mem_flat_header_tail )
		p--;
	if( p[-1] == not_a_mem_flat_header_tail )
		p--;

	MEM_ASSERT( !(((struct mem_flat_header *)p)-1)->is_empty );
	MEM_ASSERT( (((struct mem_flat_header *)p)-1)->left_cnt < MAX_LEFT_CNT );
	MEM_ASSERT( p!=ptr || (((struct mem_flat_header *)p)-1)->is_gap==0 );

	return ((struct mem_flat_header *)p)-1;
}

MEM_INLINE static void *ptr_from_header( struct mem_flat_header *h )  {
	unsigned char *p = (unsigned char *)(h+1);
	if( (h->is_gap = ((((unsigned)p) & (sizeof(unsigned)-1)) != 0)) == 0 )  {
		MEM_ASSERT( p[-1] != not_a_mem_flat_header_tail );
		return p;
	}

	MEM_ASSERT(F[0]>sizeof(unsigned));

	*p++ = not_a_mem_flat_header_tail;
	if( ((unsigned)p & (sizeof(unsigned)-1)) == 2 )
		*p++ = not_a_mem_flat_header_tail;
	if( ((unsigned)p & (sizeof(unsigned)-1)) == 3 )
		*p++ = not_a_mem_flat_header_tail;

	/* aligned? */
	MEM_ASSERT( (((unsigned)p) & (sizeof(unsigned)-1)) == 0 );

	return p;
}

void *malloc_flat( struct mem_flat_region_descriptor const *descr, unsigned size )  {
	int idx;
	unsigned char *p;
	struct mem_flat_header *h;
	struct mem_flat_header *h0;

	unsigned char *p_best;
	int idx_best;

	if( descr==NULL || descr->signature != MEM_SIG || descr->p==NULL )
		return NULL;

	idx = idx_from_size(size+sizeof(struct mem_flat_header)+sizeof(unsigned)-1);
	if( idx < 0 )
		return NULL;

	MEM_ASSERT( F[idx] >= size+sizeof(struct mem_flat_header)+sizeof(unsigned)-1 );
	MEM_ASSERT( idx >= 0 );

	/* Go over free blocks and find the best one */	
	p = descr->p;

	h0 = h = (struct mem_flat_header*)p;

	idx_best = h0->idx+1;	/* infinity */
	p_best = NULL;

	/* look for the best empty block */
	while( p-(const unsigned char *)descr->p < descr->size )  {
		if( h->is_empty && h->idx >= idx && h->idx < idx_best )  {
			p_best = p;
			idx_best = h->idx;
		}
		MEM_ASSERT(h->idx>=0 && h->idx < sizeof(F)/sizeof(F[0]));
		p += F[h->idx];
		h = (struct mem_flat_header*)p;
	}

	/* now split the empty block and return it */
	if( (h = (struct mem_flat_header*)p_best) != NULL )  {
		struct mem_flat_header *h2[2];
		if( idx < 2 )  {
			if( idx_best >= 2 )  {
				/* squeeze more out of F[2] block: split one more time */
				h2[1] = (struct mem_flat_header*)split( p_best, 2 /*F[2]*/ );
				MEM_ASSERT(h2[1]->idx==2 && idx < 2);

				h2[1]->idx--;	/* F[1] */
				h2[1]->left_cnt++;

				h2[0] = (struct mem_flat_header*)(((unsigned char *)(h2[1]))+F[1]);
				h2[0]->is_empty = 1;
				h2[0]->idx=0;	/* F[0] */
				h2[0]->left_cnt = 0;

				h = h2[idx];
			}
			/* else use best block h which we cannot split further */
		}
		else
			h = (struct mem_flat_header*)split( p_best, idx );

		/* return the body of block pointed by h: take care of sizeof(unsigned) alignment */
		h->is_empty = 0;
		MEM_ASSERT( h->left_cnt < MAX_LEFT_CNT );
		return ptr_from_header(h);
	}

	return NULL;
}

void free_flat( struct mem_flat_region_descriptor const *descr, void *ptr )  {
	struct mem_flat_header *h;

	h = header_from_ptr( ptr );
	if( h==NULL )
		return;

	//debug_print_all();

	MEM_ASSERT( ((unsigned)ptr & (sizeof(unsigned)-1)) == 0 );
	MEM_ASSERT( h->left_cnt < MAX_LEFT_CNT );
	MEM_ASSERT( h->is_empty==0 );

	h->is_empty = 1;
	merge( (unsigned char *)h, descr->p );
}

/* TODO: this only works OK for increasing in size blocks */
void *realloc_flat(struct mem_flat_region_descriptor const *descr, void *ptr, unsigned size)  {
	//unsigned char *p = ptr;
	struct mem_flat_header *h;
	struct mem_flat_header *h2;
	unsigned char *p2;
	int old_body_size;

	size = size+sizeof(struct mem_flat_header)+sizeof(unsigned)-1;

	h = header_from_ptr(ptr);
	if( h != NULL )  {
		MEM_ASSERT( !h->is_empty );
		MEM_ASSERT( h->left_cnt < MAX_LEFT_CNT );
		old_body_size = F[h->idx]-sizeof(struct mem_flat_header)-sizeof(unsigned)+1;
		MEM_ASSERT( old_body_size > 0 );
		/* quick attempt to merge with the right block without memcpy */
		while( F[h->idx] < size )  {
			h2 = (struct mem_flat_header *)((unsigned char*)h+F[h->idx]);
			if( h->left_cnt>0 && h2->is_empty && h2->idx == h->idx-1 )  {
				MEM_ASSERT( h2->left_cnt<MAX_LEFT_CNT );	/* this one is really bad */
				MEM_ASSERT( h2->left_cnt==0 );
				h->idx++;
				MEM_ASSERT( h->idx < sizeof(F)/sizeof(F[0]) );	/* due to existence of left block */
				h->left_cnt--;
			}
			else
				break;
		}
		if( F[h->idx] >= size )  {
			MEM_ASSERT( !h->is_empty );
			/* TODO: reduce the block if F[h->idx-1] > size too */
			return ptr;	/* lucky to maintain the same ptr */
		}

		p2 = malloc_flat( descr, size );
		if( p2==NULL )
			return NULL;

		MEM_MEMCPY( p2, ptr, old_body_size );

		/* shortcut to free_flat() */
		MEM_ASSERT( ptr != p2 );
		h->is_empty = 1;
		merge( (unsigned char *)h, descr->p );

		MEM_ASSERT( ((unsigned)p2 & (sizeof(unsigned)-1)) == 0 );

		return p2;
	}
	else  {
		return malloc_flat( descr, size );
	}
}

#ifdef TEST
void debug_print_all( struct mem_flat_region_descriptor const *descr )  {
	struct mem_flat_header *h = (struct mem_flat_header *)descr->p;
	unsigned char *p = descr->p;
	int n=0;
	if( h==NULL )  {
		printf("The heap is empty\n");
		return;
	}
	while( p - (unsigned char *)descr->p < descr->size )  {
		printf("%p [F[%02u]=%08d] is_empty=%d left_cnt=%02d\n", 
			ptr_from_header(h), h->idx, F[h->idx], h->is_empty, h->left_cnt );
		n++;

		p += F[h->idx];
		h = (struct mem_flat_header*)p;
	}
	printf("%d total blocks\n", n);
	
}
#endif

#ifdef TEST

//#define malloc_flat( descr, size ) malloc( size )
//#define free_flat( descr, ptr ) free( ptr )
//#define mem_rand() rand()

static mem_rand()  {
	static unsigned i=2147483647;
	const unsigned p = 4294967291;
	i %= p;
	return i;
}

int main()  {
	const unsigned BUF_SIZE = 100*1024*1024UL;
	unsigned char *buf = malloc(BUF_SIZE);
	unsigned char **p = malloc(BUF_SIZE*sizeof(void*));
	unsigned char *p1;
	struct mem_flat_region_descriptor descr;
	int n=0;
	unsigned i;

	if( buf==NULL || p==NULL )  {
		printf("no memory for buffer %d\n", BUF_SIZE);
		return -1;
	}
	
	malloc_flat_init( buf, BUF_SIZE, &descr );

	debug_print_all( &descr );

	printf("Starting from rand %08x\n", mem_rand());

#if 1
	int same_ptrs=0;
	int different_ptrs=0;
	for( i=0; i<BUF_SIZE; i++ )  {
		unsigned s = mem_rand() % (BUF_SIZE/10000);
		void *p1_saved;
		void *p2;
		//printf("\tallocating %d", s);
		p1_saved = p1 = malloc_flat( &descr, s );
		if( p1 ) memset( p1, 0xff, s );
		p2 = realloc_flat( &descr, p1, s*2 );
		if( p2 ) memset( p2, 0xff, s*2 );
		if( p1==p2 )
			same_ptrs++;
		else
			different_ptrs++;
		p1 = p2;

		if( p1 ) p1[0] = i;
		//printf(", got %p, realloced %p\n", p1, p1_saved);
		p[i] = p1;
		if( p1==NULL )  {
			free_flat(&descr, p1_saved);
			break;
		}
		n++;
	}
	p[n] = NULL;
	printf("%d same ptrs and %d different ptrs\n", same_ptrs, different_ptrs);
//	printf("After allocations:\n");
//	debug_print_all( &descr );

	for( i=0; p[i]; i++ )  {
		//printf("freeing %p p[0]=%d\n", p[i], (unsigned)p[i][0]);
		MEM_ASSERT( p[i][0] == (unsigned char)i );
		free_flat( &descr, p[i] );
	}
#endif

//	p1 = malloc_flat( &descr, 10 );
//	printf("malloc_flat returned %p\n", p1);

//	printf("Served %d allocations (total size %d v.s. passed %d)\n", n, n*30, BUF_SIZE);
//	debug_print_all( &descr );

//	free_flat( &descr, p1);
//	printf("after free_flat(%p)\n", p1);

	debug_print_all( &descr );
	printf("Done\n");

	return 0;
}
#endif /*TEST*/
