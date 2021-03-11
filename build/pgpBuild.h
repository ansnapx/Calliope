/*____________________________________________________________________________
	Copyright (C) 2008 PGP Corporation
	All rights reserved.
	
	$Id: pgpBuild.h 68954 2008-11-03 19:15:51Z vinnie $
____________________________________________________________________________*/

#ifndef Included_MastrBld_h	/* [ */
#define Included_MastrBld_h

/* This file can be used to control the build settings for the
   entire sdk and client workspace. Set OVERRIDE_BUILDFLAGS
   to 1 in the client project and the settings in this file will be 
   used. */


/*____________________________________________________________________________
	Client Version information
____________________________________________________________________________*/

#define PGPVERSIONSTRING		"9.9.0" 
#define PGPVERSIONMAJOR			9
#define PGPVERSIONMINOR			9
#define PGPVERSIONSUBMINOR		0
#define PGPVERSIONSUBSUBMINOR   39

#define PGPVERSIONRELEASESTAGE	0	/* 0 = Development, 1 = Alpha, */
									/* 2 = Beta, 3 = Release */
#define PGPBUILDNUMBER			"39" 
#define PGPSVNREVISION			0 
#define PGPCOMPANYNAME			"PGP Corporation"
#define PGPCOPYRIGHT			"Copyright (C) 2008 PGP Corporation"
#define PGPTRADEMARKS			"Pretty Good Privacy, PGP"
#define PGPPRODUCTNAME			"PGP"

/*____________________________________________________________________________
	License information
____________________________________________________________________________*/
#define PGPPRODUCTID_DESKTOP800	0	/* PGP 8.0.0, PGP 8.0.1 */
#define PGPPRODUCTID_UNUSED1	1	/* Unused */
#define PGPPRODUCTID_DESKTOP802	2	/* PGP 8.0.2, PGP 8.0.3, PGP 8.0.4, PGP 8.1.x */
#define PGPPRODUCTID_DESKTOP900	3	/* PGP 9.0.x */
#define PGPPRODUCTID_DESKTOP950	4	/* PGP 9.5 */

#define PGPPRODUCTID_OVID100	32	/* Ovid 1.x */
#define PGPPRODUCTID_OVID200	33	/* Ovid 2.0 */

#define PGPPRODUCTID_CMDLN850	64	/* Command Line 8.5.x, Command Line 9.0.x */
#define PGPPRODUCTID_CMDLN950	65	/* Command Line 9.5 */

/* Deprecated defines */
#define PGPPRODUCTID800			PGPPRODUCTID_DESKTOP800
#define PGPPRODUCTID801			PGPPRODUCTID_DESKTOP802	/* Yes, this is correct */
#define PGPPRODUCTID900			PGPPRODUCTID_DESKTOP900

#define PGPPRODUCTID			PGPPRODUCTID_DESKTOP950

#define PGP_I18NINVERT			0
#define PGP_ENGLISH_ONLY        0   /* toggles English only UI */

#define PGP_LICENSENUMBERS		1	/* 0 =  No License Check, 1 = License Check */
#define PGP_LICENSENUMBERS_LIVE 0	/* 0 =  internal LNs, 1 = external LNs */
#define PGP_LICENSEGRACEPERIOD	60	/* Expiration date extension in days */
									/* Only applies to non-eval licenses */

/*____________________________________________________________________________
	SDK Version information
____________________________________________________________________________*/

#define PGPSDK_SHORT_VERSION_STRING		"3.12.0"

#define PGPSDK_MAJOR_VERSION			3
#define PGPSDK_MINOR_VERSION			12
#define PGPSDK_SUBMINOR_VERSION			0
#define PGPSDK_SUBSUBMINOR_VERSION		39
#define PGPSDK_RELEASE_STAGE			0	/* 0 = Development, 1 = Alpha, */
											/* 2 = Beta, 3 = Release */
#define PGPSDK_BUILD					1

#define PGPSDK_BUILDNUMBER				"39"
#define PGPSDK_BUILDNUMBERN				39
#define PGPSDK_INSTALLEDWITH			"PGP 9.9.0 (Build 39 Alpha)"

#define PGPSDK_COPYRIGHT 	"Copyright (C) 2008 PGP Corporation"

/*____________________________________________________________________________
	Other Client flags
____________________________________________________________________________*/

#ifndef PGP_BETA
#define PGP_BETA					1		// zero for release
#endif

#ifndef PGPNET
#define PGPNET						0
#endif

#define UNFINISHED_CODE_ALLOWED		1		// *Must* be set to zero for release

/*____________________________________________________________________________
	Beta and Eval timeout periods
____________________________________________________________________________*/

#define PGP_BETA_DAYS				60

/*____________________________________________________________________________
	SDK Algorithm support
____________________________________________________________________________*/

#define PGP_RSA				1
#define PGP_RSA_KEYGEN		1

#define PGP_USECAPIFORRSA	0	/* Try to use Microsoft CAPI library for RSA */
#define PGP_USECAPIFORMD2	0	/* Try to use Microsoft CAPI library for MD2 */
#define PGP_USEBSAFEFORRSA  0	/* Use RSA's BSAFE library for RSA support */
#define PGP_USEPGPFORRSA	1	/* Use the PGP implementation for RSA support */
#define PGP_USERSAREF		0	/* Use the non-commercial RSAREF library for RSA */

#define PGP_EC				0	/* Elliptic Curve support */


/* These probably will always be on */
#define PGP_CAST5		1
#define PGP_DES3		1
#define PGP_IDEA		1
#define PGP_TWOFISH		1
#define PGP_AES			1

/*____________________________________________________________________________
	Other optional SDK flags
____________________________________________________________________________*/

#if PGP_WIN32
	#define PGP_CRYPTOAPI_RNG_ENTROPY	1
#else
	#define PGP_CRYPTOAPI_RNG_ENTROPY	0
#endif

/* Allows turning off signing/verification capability in library */
#ifndef PGP_SIGN_DISABLE
	#define PGP_SIGN_DISABLE	0
#endif

#ifndef PGP_VERIFY_DISABLE
	#define PGP_VERIFY_DISABLE	0
#endif

/* Allows turning off encryption/decryption capability in library */
#ifndef PGP_ENCRYPT_DISABLE
	#define PGP_ENCRYPT_DISABLE	0
#endif

#ifndef PGP_DECRYPT_DISABLE
	#define PGP_DECRYPT_DISABLE	0
#endif

/*___________________________________________________________________________
    Other Macros
---------------------------------------------------------------------------*/
#define PGPVERSIONSTR(x,y,z) PGPVERSTR(x,y,z) 
#define PGPVERSTR(x, y, z) #x "." #y "." #z
/* usage: PGPVERSIONSTR(PGPVERSIONMAJOR, PGPVERSIONMINOR, PGPVRSIONSUBMINOR) */

#endif /* ] Included_MastrBld_h */


/*__Editor_settings____

	Local Variables:
	tab-width: 4
	End:
	vi: ts=4 sw=4
	vim: si
_____________________*/
