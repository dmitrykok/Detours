##############################################################################
##
##  Utility to trace HeapAlloc APIs.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

CFLAGS=$(CFLAGS) /std:c++20 /WX-

LIBS=$(LIBS) kernel32.lib ntdll.lib shell32.lib

all: dirs \
    $(BIND)\WTLocalStateHook$(DETOURS_BITS).dll \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\WTLocalStateHook$(DETOURS_BITS).bsc \
!ENDIF
    option

clean:
    -del *~ test.txt 2>nul
    -del $(BIND)\WTLocalStateHook*.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

##############################################################################

$(OBJD)\WTLocalStateHook.obj : WTLocalStateHook.cpp

$(OBJD)\WTLocalStateHook.res : WTLocalStateHook.rc

$(BIND)\WTLocalStateHook$(DETOURS_BITS).dll : $(OBJD)\WTLocalStateHook.obj $(OBJD)\WTLocalStateHook.res $(DEPS)
    cl /LD $(CFLAGS) /Fe$@ /Fd$(@R).pdb \
        $(OBJD)\WTLocalStateHook.obj $(OBJD)\WTLocalStateHook.res \
        /link $(LINKFLAGS) /subsystem:console \
        /export:DetourFinishHelperProcess,@1,NONAME \
        $(LIBS)

$(OBJD)\WTLocalStateHook$(DETOURS_BITS).bsc : $(OBJD)\WTLocalStateHook.obj
    bscmake /v /n /o $@ $(OBJD)\WTLocalStateHook.sbr

############################################### Install non-bit-size binaries.

!IF "$(DETOURS_OPTION_PROCESSOR)" != ""

$(OPTD)\WTLocalStateHook$(DETOURS_OPTION_BITS).dll:
$(OPTD)\WTLocalStateHook$(DETOURS_OPTION_BITS).pdb:

$(BIND)\WTLocalStateHook$(DETOURS_OPTION_BITS).dll : $(OPTD)\WTLocalStateHook$(DETOURS_OPTION_BITS).dll
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).
$(BIND)\WTLocalStateHook$(DETOURS_OPTION_BITS).pdb : $(OPTD)\WTLocalStateHook$(DETOURS_OPTION_BITS).pdb
    @if exist $? copy /y $? $(BIND) >nul && echo $@ copied from $(DETOURS_OPTION_PROCESSOR).

option: \
    $(BIND)\WTLocalStateHook$(DETOURS_OPTION_BITS).dll \
    $(BIND)\WTLocalStateHook$(DETOURS_OPTION_BITS).pdb \

!ELSE

option:

!ENDIF

##############################################################################

################################################################# End of File.
