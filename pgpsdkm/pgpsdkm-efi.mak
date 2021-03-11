#_____________________________________________________________________________
#	pgpsdkm.mak
#	bootloader
#
#	Build control file pgpsdkm library for the EFI bootloader.
#
#	Copyright (C) 2007 PGP Corporation
#	All rights reserved.
#	
#	$Id: pgpsdkm-efi.mak 59758 2008-01-10 20:29:11Z vinnie $
#
#	To Do:
#
#_____________________________________________________________________________

#
# Include sdk.env environment
#

!include $(SDK_INSTALL_DIR)\build\$(SDK_BUILD_ENV)\sdk.env

#
#  Set the base output name
#

BASE_NAME = pgpsdkm

#
# Globals needed by master.mak
#
# NOTE: TARGET_LIB is special and causes the library to be linked with OBJECTS

PGP_DIR    = $(SDK_INSTALL_DIR)\..\..\clients2
WDE_DIR    = $(PGP_DIR)\wde
TARGET_LIB = $(BASE_NAME)
SOURCE_DIR = $(WDE_DIR)\$(BASE_NAME)
BUILD_DIR  = $(SDK_BUILD_DIR)\pgp\$(BASE_NAME)

#
# Adjust compiler flags for this build
# Define PGP_WIN32 for now. We may have to extend this to PGP_EFI if there is
# some incompatibility.
#
C_FLAGS = $(C_FLAGS) /Oi /D PGP_WIN32 /D PGP_EFI
!IF "$(EFI_DEBUG)" == "YES"
C_FLAGS = $(C_FLAGS) /D PGP_DEBUG=1
!ENDIF

#
# Include paths
#

!include $(SDK_INSTALL_DIR)\include\$(EFI_INC_DIR)\makefile.hdr
INC = -I $(SDK_INSTALL_DIR)\include\$(EFI_INC_DIR) \
      -I $(SDK_INSTALL_DIR)\include\$(EFI_INC_DIR)\$(PROCESSOR)

INC = -I $(SDK_INSTALL_DIR)\include\bsd $(INC)

#!include .\makefile.hdr
INC = -I .\priv \
      -I .\pub \
      -I .\efi \
      $(INC)

INC_DEPS = $(INC_DEPS) \
	$(SOURCE_DIR)\efi\pgpConfig.h \
	$(SOURCE_DIR)\efi\pgpPFLConfig.h \
\
	$(SOURCE_DIR)\priv\pgpAES.h \
	$(SOURCE_DIR)\priv\pgpAESboxes.h \
	$(SOURCE_DIR)\priv\pgpCBCPriv.h \
	$(SOURCE_DIR)\priv\pgpCFBPriv.h \
	$(SOURCE_DIR)\priv\pgpDES3.h \
	$(SOURCE_DIR)\priv\pgpEMEPriv.h \
	$(SOURCE_DIR)\priv\pgpEME2Priv.h \
	$(SOURCE_DIR)\priv\pgpHashPriv.h \
	$(SOURCE_DIR)\priv\pgpOpaqueStructs.h \
	$(SOURCE_DIR)\priv\pgpSDKBuildFlags.h \
	$(SOURCE_DIR)\priv\pgpSDKPriv.h \
	$(SOURCE_DIR)\priv\pgpSHA.h \
	$(SOURCE_DIR)\priv\pgpSHA2.h \
	$(SOURCE_DIR)\priv\pgpStr2Key.h \
	$(SOURCE_DIR)\priv\pgpSymmetricCipherPriv.h \
	$(SOURCE_DIR)\priv\pgpUsuals.h \
\
	$(SOURCE_DIR)\pub\pflTypes.h \
	$(SOURCE_DIR)\pub\pgpBase.h \
	$(SOURCE_DIR)\pub\pgpCBC.h \
	$(SOURCE_DIR)\pub\pgpCFB.h \
	$(SOURCE_DIR)\pub\pgpDebug.h \
	$(SOURCE_DIR)\pub\pgpEME.h \
	$(SOURCE_DIR)\pub\pgpEME2.h \
	$(SOURCE_DIR)\pub\pgpErrors.h \
	$(SOURCE_DIR)\pub\pgpHMAC.h \
	$(SOURCE_DIR)\pub\pgpHash.h \
	$(SOURCE_DIR)\pub\pgpMem.h \
	$(SOURCE_DIR)\pub\pgpMiniUtil.h \
	$(SOURCE_DIR)\pub\pgpPFLErrors.h \
	$(SOURCE_DIR)\pub\pgpPFLPriv.h \
	$(SOURCE_DIR)\pub\pgpPubTypes.h \
	$(SOURCE_DIR)\pub\pgpSDKAPINamespace.h \
	$(SOURCE_DIR)\pub\pgpSymmetricCipher.h \
	$(SOURCE_DIR)\pub\pgpTypes.h \
	$(SOURCE_DIR)\pub\pgpUtilities.h \
	$(SOURCE_DIR)\pub\pgpMemoryMgr.h

#	$(SOURCE_DIR)\priv\pgpMallocFlat.h

#
# Default target
#

all : dirs $(OBJECTS)

#
#  Library object files
#

OBJECTS = $(OBJECTS) \
    $(BUILD_DIR)\crc32.obj \
	$(BUILD_DIR)\pAES.obj \
	$(BUILD_DIR)\pCBC.obj \
	$(BUILD_DIR)\pCFB.obj \
	$(BUILD_DIR)\pDES3.obj \
	$(BUILD_DIR)\pEME.obj \
	$(BUILD_DIR)\pEME2.obj \
	$(BUILD_DIR)\pHMAC.obj \
	$(BUILD_DIR)\pHash.obj \
	$(BUILD_DIR)\pKeyMisc.obj \
	$(BUILD_DIR)\pMMFlat.obj \
	$(BUILD_DIR)\pSHA.obj \
	$(BUILD_DIR)\pSHA256.obj \
	$(BUILD_DIR)\pSHA512.obj \
	$(BUILD_DIR)\pSHA5122.obj \
	$(BUILD_DIR)\pStr2Key.obj \
	$(BUILD_DIR)\pSym.obj \
	$(BUILD_DIR)\pgpMemoryMgr.obj
#	$(BUILD_DIR)\pgpMallocFlat.obj 

#
# Source file dependencies
#

$(BUILD_DIR)\crc32.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pAES.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pCBC.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pCFB.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pDES3.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pEME.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pEME2.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pHMAC.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pHash.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pKeyMisc.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pMMFlat.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pSHA.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pSHA256.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pSHA512.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pSHA5122.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pStr2Key.obj		: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pSym.obj			: priv\$(*B).c $(INC_DEPS)
$(BUILD_DIR)\pgpMemoryMgr.obj	: priv\$(*B).c $(INC_DEPS)

# pgpMallocFlat requires a definition for msb that we don't have
# $(BUILD_DIR)\pgpMallocFlat.obj	: priv\$(*B).c $(INC_DEPS)

#
# Because pgpsdkm compiles out of a sub-directory, we need some of our own
# inference rules.  $(CC_LINE) is defined in master.mak
#

{priv}.c{$(BUILD_DIR)}.obj:           ; $(CC_LINE)

#
# Handoff to master.mak
#

!include $(SDK_INSTALL_DIR)\build\master.mak
