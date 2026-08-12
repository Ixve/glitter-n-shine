@echo off
setlocal

set "csc=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%csc%" (
  echo [-] .NET Framework csc.exe not found
  exit /b 1
)
"%csc%" /nologo /target:library /optimize+ /out:"%~dp0shine\bridge.dll" "%~dp0shine\bridge.cs"
if errorlevel 1 (
  echo [-] Managed helper build failed
  exit /b 1
)

set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%vswhere%" exit /b 1
for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "msbuild=%%i"
if not defined msbuild exit /b 1
"%msbuild%" "%~dp0glitter&shine.sln" /t:Rebuild /p:Configuration=Release /p:Platform=x64 /m
exit /b %errorlevel%
