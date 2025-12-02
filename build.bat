@echo off
REM CloudClear - Windows Build Script
REM Automates the build process for Windows users

echo ========================================
echo CloudClear Windows Build Script
echo ========================================
echo.

REM Check for CMake
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found in PATH
    echo Please install CMake from https://cmake.org/download/
    exit /b 1
)

REM Check for vcpkg (optional but recommended)
if exist "C:\vcpkg\vcpkg.exe" (
    set VCPKG_TOOLCHAIN=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
    echo Found vcpkg at C:\vcpkg
) else (
    echo Warning: vcpkg not found at C:\vcpkg
    echo You may need to manually specify library paths
    set VCPKG_TOOLCHAIN=
)

REM Parse command line arguments
set BUILD_TYPE=Release
set BUILD_RECON=OFF
set BUILD_TUI=OFF
set BUILD_TESTS=ON

:parse_args
if "%1"=="" goto end_parse
if /i "%1"=="--debug" set BUILD_TYPE=Debug
if /i "%1"=="--recon" set BUILD_RECON=ON
if /i "%1"=="--tui" set BUILD_TUI=ON
if /i "%1"=="--all" (
    set BUILD_RECON=ON
    set BUILD_TUI=ON
)
if /i "%1"=="--help" (
    echo Usage: build.bat [options]
    echo.
    echo Options:
    echo   --debug      Build in Debug mode (default: Release)
    echo   --recon      Build with reconnaissance modules
    echo   --tui        Build Terminal UI version
    echo   --all        Build all variants
    echo   --clean      Clean build directory
    echo   --help       Show this help message
    echo.
    echo Examples:
    echo   build.bat                  Build standard version
    echo   build.bat --all            Build all variants
    echo   build.bat --recon --tui    Build with recon and TUI
    exit /b 0
)
if /i "%1"=="--clean" (
    echo Cleaning build directory...
    if exist build rmdir /s /q build
    echo Build directory cleaned
    exit /b 0
)
shift
goto parse_args
:end_parse

echo.
echo Build Configuration:
echo   Build Type: %BUILD_TYPE%
echo   Recon Modules: %BUILD_RECON%
echo   TUI Support: %BUILD_TUI%
echo   Tests: %BUILD_TESTS%
echo.

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
if defined VCPKG_TOOLCHAIN (
    cmake .. ^
        -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
        -DBUILD_RECON=%BUILD_RECON% ^
        -DBUILD_TUI=%BUILD_TUI% ^
        -DBUILD_TESTS=%BUILD_TESTS% ^
        -DCMAKE_TOOLCHAIN_FILE=%VCPKG_TOOLCHAIN%
) else (
    cmake .. ^
        -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
        -DBUILD_RECON=%BUILD_RECON% ^
        -DBUILD_TUI=%BUILD_TUI% ^
        -DBUILD_TESTS=%BUILD_TESTS%
)

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed
    cd ..
    exit /b 1
)

REM Build
echo.
echo Building CloudClear...
cmake --build . --config %BUILD_TYPE%

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    cd ..
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Executables are in: build\%BUILD_TYPE%\
echo.
echo To run CloudClear:
echo   cd build\%BUILD_TYPE%
echo   cloudclear.exe example.com
echo.

cd ..
exit /b 0
