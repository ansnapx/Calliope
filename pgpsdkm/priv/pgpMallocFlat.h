/*____________________________________________________________________________
        Copyright (C) 2006 PGP Corporation
        All rights reserved.

        $Id: pgpMallocFlat.h 47014 2006-08-16 02:24:28Z ajivsov $
____________________________________________________________________________*/
                                                                                                                                                              
#ifndef PGP_MALLOC_FLAT_H
#define PGP_MALLOC_FLAT_H 1

/* Public API */


/* This structure is initialized in malloc_flat_init. Caller must not change values of this structure.  */
struct mem_flat_region_descriptor  {
	unsigned signature;
	void *p;
	int size;
};

extern int malloc_flat_init( void *buf, unsigned size, struct mem_flat_region_descriptor *descr );
extern void *malloc_flat(struct mem_flat_region_descriptor const *descr, unsigned size);
extern void free_flat(struct mem_flat_region_descriptor const *descr, void *ptr);
extern void *realloc_flat(struct mem_flat_region_descriptor const *descr, void *ptr, unsigned size); 

#endif /* PGP_MALLOC_FLAT_H */
