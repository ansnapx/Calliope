@echo off

attrib *.suo -s -h
del BuildLog.htm
del *.ncb
del *.user
del *.log
del *.err
del *.wrn
del *.bin
del *.aps
del *.bak
del *.suo
del *.sdf
rmdir /s /q  ipch
rmdir /s /q  Debug
rmdir /s /q  Release
rmdir /s /q  x64
rmdir /s /q  BIN

set OldPath=%cd%
pushd %cd%

cd build
rmdir /s /q win32
cd ..

cd daemon
rmdir /s /q  Debug
rmdir /s /q  Release
rmdir /s /q  x64
attrib *.suo -s -h
del *.suo
del *.ncb
del *.user
del *.log
del *.err
del *.wrn
del *.bin
del *.aps
del *.bak
del *.sdf
cd ..

cd fsfd
rmdir /s /q  objchk
rmdir /s /q  objfre
attrib *.suo -s -h
del *.suo
del *.ncb
del *.user
del *.log
del *.err
del *.wrn
del *.bin
del *.aps
del *.bak
del *.sdf
cd ..

cd KeyConfig
rmdir /s /q  Debug
rmdir /s /q  Release
rmdir /s /q  x64
attrib *.suo -s -h
del *.suo
del *.ncb
del *.user
del *.log
del *.err
del *.wrn
del *.bin
del *.aps
del *.bak
del *.sdf
cd ..


cd pgpsdkm
attrib *.suo -s -h
del *.suo
del *.ncb
del *.user
del *.log
del *.err
del *.wrn
del *.bin
del *.aps
del *.bak
del *.sdf
cd win32
rmdir /s /q  Debug
rmdir /s /q  Release
rmdir /s /q  x64
rmdir /s /q  Debug($CPU)
cd ..
cd ..

popd

::pause

