/* unix/pgpPFLConfig.h.  Generated automatically by configure.  */
/*
 * pgpPFLConfig.h -- Configuration for PFL.  This file contains
 * the configuration information for the PFL, and it should be
 * included in all PFL source files.
 *
 * $Id: pgpPFLConfig.h 37664 2005-08-09 04:46:54Z jason $
 */

#ifndef Included_pgpPFLConfig_h	/* [ */
#define Included_pgpPFLConfig_h

/* Define to empty if the compiler does not support 'const' variables. */
/* #undef const */

/* Define to `long' if <sys/types.h> doesn't define.  */
/* #undef off_t */

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Checks for various types */
#define HAVE_UCHAR 0
#define HAVE_USHORT 1
#define HAVE_UINT 1
#define HAVE_ULONG 0

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Checks for various specific header files */
#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 0
#define HAVE_MACHINE_LIMITS_H 1
#define HAVE_STDARG_H 1
#define HAVE_STDLIB_H 1
#define HAVE_UNISTD_H 1
#define HAVE_PATHS_H 1
#define HAVE_DIRENT_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TIMEB_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1

/* Check if <sys/time.h> is broken and #includes <time.h> wrong */
#define TIME_WITH_SYS_TIME 1

/* Checks for various functions */
#define HAVE_GETHRTIME 0
#define HAVE_CLOCK_GETTIME 0
#define HAVE_CLOCK_GETRES 0
#define HAVE_GETTIMEOFDAY 1
#define HAVE_GETITIMER 1
#define HAVE_SETITIMER 1
#define HAVE_FTIME 0
#define HAVE_MKTEMP 1
#define HAVE_MKSTEMP 1
#define HAVE_THR_CREATE 0
#define HAVE_PTHREAD_CREATE 1
#define HAVE_PTHREAD_ATTR_CREATE 0
#define HAVE_SEM_INIT 1
#define HAVE_SEMGET 1

/* Redefine the string compare functions to unix friendly ones */
#define stricmp		strcasecmp
#define strnicmp	strncasecmp

/* Sun's C++ compiler does not define "true" and "false" */
#if PGP_COMPILER_SUN
#ifndef false
#define false 0
#define true 1
#endif
#if PGP_COMPILER_SUN_VER == 4
typedef int bool;
#endif
#endif

/*
 * Define "PGP_UNIX" if we are on PGP_UNIX and "PGP_UNIX" is
 * not already defined.
 */
#if defined(unix) || defined(__unix) || defined (__unix__) || (_AIX)
#ifndef PGP_UNIX
#define PGP_UNIX 1
#endif
#endif

#endif	/* ] Included_pgpPFLConfig_h */
#ifndef PGP_UNIX_DARWIN
#define PGP_UNIX_DARWIN 1
#endif
