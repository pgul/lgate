@echo off
if "%1"=="t" set MODL=TINY
if "%1"=="s" set MODL=SMALL
if "%1"=="m" set MODL=MEDIUM
if "%1"=="c" set MODL=COMPACT
if "%1"=="l" set MODL=LARGE
if "%1"=="h" set MODL=HUGE
if not "%MODL%"=="" goto make
echo Incorrect param!
goto end

:make
if not exist obj%1\nul mkdir obj%1
make -DMODL=%MODL% -DDEST=flib_%1.lib -DCFLAGS=-m%1 -DOBJDIR=obj%1 -f makefile.tc

:end
