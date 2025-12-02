# CloudClear - Windows Build Guide

This guide provides instructions for building CloudClear on Windows using various toolchains.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Option 1: Visual Studio (MSVC)](#option-1-visual-studio-msvc)
- [Option 2: MinGW-w64](#option-2-mingw-w64)
- [Option 3: WSL (Windows Subsystem for Linux)](#option-3-wsl-windows-subsystem-for-linux)
- [Dependencies](#dependencies)
- [Building](#building)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

Choose one of the following build toolchains:

#### Visual Studio (MSVC) - Recommended for Windows
- **Visual Studio 2019 or later** (Community Edition is free)
  - Download: https://visualstudio.microsoft.com/
  - Select "Desktop development with C++" workload
- **CMake 3.15 or later**
  - Download: https://cmake.org/download/
  - Add CMake to PATH during installation

#### MinGW-w64
- **MinGW-w64**
  - Download: https://www.mingw-w64.org/
  - Or install via MSYS2: https://www.msys2.org/
- **CMake 3.15 or later**

#### Windows Subsystem for Linux (WSL)
- **WSL2 with Ubuntu 20.04+**
  - Installation: https://docs.microsoft.com/en-us/windows/wsl/install
  - Follow Linux build instructions in main README

---

## Dependencies

CloudClear requires the following libraries on Windows:

### 1. libcurl (Required)

**Using vcpkg (Recommended):**
```cmd
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install curl:x64-windows
.\vcpkg integrate install
```

**Or download pre-built:**
- Download from: https://curl.se/windows/
- Extract to `C:\libs\curl`

### 2. OpenSSL (Required)

**Using vcpkg:**
```cmd
.\vcpkg install openssl:x64-windows
```

**Or download pre-built:**
- Download from: https://slproweb.com/products/Win32OpenSSL.html
- Install to default location (e.g., `C:\Program Files\OpenSSL-Win64`)

### 3. json-c (Required)

**Using vcpkg:**
```cmd
.\vcpkg install json-c:x64-windows
```

**Or build from source:**
```cmd
git clone https://github.com/json-c/json-c.git
cd json-c
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=C:\libs\json-c
cmake --build . --config Release
cmake --install .
```

### 4. PDCurses (Optional - for TUI)

**Using vcpkg:**
```cmd
.\vcpkg install pdcurses:x64-windows
```

**Or build from source:**
```cmd
git clone https://github.com/wmcbrine/PDCurses.git
cd PDCurses\wincon
nmake -f Makefile.vc
```

---

## Option 1: Visual Studio (MSVC)

### Using vcpkg (Recommended)

1. **Install dependencies with vcpkg:**
   ```cmd
   cd C:\
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   .\vcpkg integrate install
   .\vcpkg install curl:x64-windows openssl:x64-windows json-c:x64-windows
   ```

2. **Clone CloudClear:**
   ```cmd
   cd C:\Projects
   git clone https://github.com/SWORDIntel/CLOUDCLEAR.git
   cd CLOUDCLEAR
   ```

3. **Configure with CMake:**
   ```cmd
   mkdir build
   cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
   ```

4. **Build:**
   ```cmd
   cmake --build . --config Release
   ```

5. **Run:**
   ```cmd
   .\Release\cloudclear.exe example.com
   ```

### Using Visual Studio GUI

1. Open Visual Studio
2. File → Open → CMake → Select `CMakeLists.txt`
3. Configure CMake settings (set vcpkg toolchain file in CMake Settings)
4. Build → Build All
5. Run from `out\build\x64-Release\cloudclear.exe`

---

## Option 2: MinGW-w64

### Using MSYS2

1. **Install MSYS2:**
   - Download from: https://www.msys2.org/
   - Run installer and follow prompts

2. **Open MSYS2 MinGW 64-bit terminal**

3. **Install dependencies:**
   ```bash
   pacman -S --needed base-devel mingw-w64-x86_64-toolchain
   pacman -S mingw-w64-x86_64-cmake
   pacman -S mingw-w64-x86_64-curl
   pacman -S mingw-w64-x86_64-openssl
   pacman -S mingw-w64-x86_64-json-c
   ```

4. **Clone and build:**
   ```bash
   cd /c/Projects
   git clone https://github.com/SWORDIntel/CLOUDCLEAR.git
   cd CLOUDCLEAR
   mkdir build && cd build
   cmake .. -G "MinGW Makefiles"
   cmake --build .
   ```

5. **Run:**
   ```bash
   ./cloudclear.exe example.com
   ```

---

## Option 3: WSL (Windows Subsystem for Linux)

This is the easiest option for developers familiar with Linux.

1. **Install WSL2:**
   ```powershell
   wsl --install -d Ubuntu-22.04
   ```

2. **Open Ubuntu terminal and follow Linux instructions:**
   ```bash
   sudo apt update
   sudo apt install -y build-essential libcurl4-openssl-dev \
       libssl-dev libjson-c-dev libncurses5-dev

   git clone https://github.com/SWORDIntel/CLOUDCLEAR.git
   cd CLOUDCLEAR
   make all
   ./cloudclear example.com
   ```

---

## Building

### Standard Build (CLI only)

```cmd
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

### Build with Recon Modules

```cmd
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_RECON=ON
cmake --build . --config Release
```

### Build with TUI (Terminal UI)

```cmd
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TUI=ON
cmake --build . --config Release
```

### Build All Variants

```cmd
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_RECON=ON -DBUILD_TUI=ON
cmake --build . --config Release
```

---

## Python API Server (Windows)

The API server works on Windows with Python 3.8+.

### Install Python Dependencies

```cmd
cd api
pip install -r requirements.txt
```

### Run API Server

```cmd
python server.py
```

### Run with Virtual Environment (Recommended)

```cmd
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

### Access API

- Health: http://localhost:8080/health
- Web UI: http://localhost:8080/web/
- API Docs: See `api/README.md`

---

## Running Tests

### Python API Tests

```cmd
cd api
pip install -r requirements-test.txt
pytest test_server.py --cov=server
```

### C Unit Tests

```cmd
cd build
ctest --output-on-failure
```

---

## Troubleshooting

### Issue: CMake can't find dependencies

**Solution:** Use vcpkg and specify the toolchain file:
```cmd
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
```

### Issue: Missing DLLs when running

**Solution:** Copy required DLLs to the executable directory:
```cmd
copy C:\vcpkg\installed\x64-windows\bin\*.dll .\Release\
```

Or add vcpkg bin directory to PATH:
```cmd
set PATH=%PATH%;C:\vcpkg\installed\x64-windows\bin
```

### Issue: OpenSSL certificate errors

**Solution:** Set SSL certificate path:
```cmd
set CURL_CA_BUNDLE=C:\path\to\cacert.pem
```

Download cacert.pem from: https://curl.se/docs/caextract.html

### Issue: Permission denied errors

**Solution:** Run terminal as Administrator or adjust Windows Defender settings.

### Issue: Long path errors

**Solution:** Enable long paths in Windows:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1
```

Or use Git Bash / WSL which handle long paths better.

---

## Platform-Specific Notes

### Windows Limitations

1. **Threading**: Uses Windows threads instead of pthreads
2. **Signals**: Limited signal handling compared to POSIX
3. **Permissions**: Some OPSEC features may require Administrator privileges
4. **Networking**: Winsock2 used instead of POSIX sockets

### Performance

- Performance on Windows is comparable to Linux for most operations
- DNS operations may be slightly slower due to Windows DNS client caching
- For best performance, use WSL2 which runs a real Linux kernel

### Security Features

Most security features work on Windows, but some limitations:
- Memory locking (`mlock`) uses `VirtualLock`
- Process isolation is handled differently
- Some OPSEC features may require Administrator privileges

---

## Recommended Setup

For **Windows developers**, we recommend:

1. **Quick Testing**: WSL2 (fastest to set up, full Linux compatibility)
2. **Native Windows**: Visual Studio + vcpkg (best Windows integration)
3. **CI/CD**: MinGW via MSYS2 (reproducible builds)

For **Production Deployment**:
- Use Docker (works on Windows with Docker Desktop)
- See `docker/` directory for production Docker images

---

## Additional Resources

- Main README: `../README.md`
- API Documentation: `../api/README.md`
- Docker Guide: `../docker/README.md`
- Contributing: `../CONTRIBUTING.md`

---

## Support

For Windows-specific issues:
- GitHub Issues: https://github.com/SWORDIntel/CLOUDCLEAR/issues
- Tag with `platform:windows`

For general build issues:
- Check main README.md
- Review CMake configuration in `CMakeLists.txt`
