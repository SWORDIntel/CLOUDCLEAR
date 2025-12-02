# CloudClear - Cross-Platform CMake Build Configuration
# Supports Windows (MSVC/MinGW), Linux, and macOS
cmake_minimum_required(VERSION 3.15)

project(CloudClear
    VERSION 2.0
    DESCRIPTION "Advanced Cloud Provider Detection & Intelligence Platform"
    LANGUAGES C
)

# Build options
option(BUILD_TUI "Build Terminal UI version" ON)
option(BUILD_RECON "Build with reconnaissance modules" ON)
option(BUILD_TESTS "Build test suite" ON)
option(ENABLE_OPSEC "Enable OPSEC features" ON)

# C Standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(MSVC)
    # MSVC flags
    add_compile_options(/W4 /O2 /D_CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang flags
    add_compile_options(
        -Wall -Wextra -O3
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Release>:-DNDEBUG>
    )
endif()

# Platform-specific definitions
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601) # Windows 7+
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/modules
)

# Core source files
set(CORE_SOURCES
    src/core/cloudunflare.c
    src/core/dns_enhanced.c
    src/modules/advanced_ip_detection.c
)

# Recon common sources
set(RECON_COMMON_SOURCES
    src/modules/recon/common/recon_common.c
    src/modules/recon/common/recon_opsec.c
    src/modules/recon/common/recon_proxy.c
)

# Recon module sources (optional)
set(RECON_SOURCES
    src/modules/recon/dns_zone_transfer/dns_zone_transfer.c
    src/modules/recon/dns_zone_transfer/dns_zone_transfer_enhanced.c
    src/modules/recon/dns_bruteforce/dns_bruteforce.c
    src/modules/recon/http_banner/http_banner.c
    src/modules/recon/port_scanner/port_scanner.c
    src/modules/recon/cloudflare_radar/cloudflare_radar.c
    src/modules/recon/cloudflare_radar/cloudflare_radar_api.c
    src/modules/recon/cloudflare_radar/cloudflare_radar_parser.c
    src/modules/recon/cve_2025_detector/cve_2025_detector.c
    src/modules/recon/advanced_recon/advanced_recon.c
    src/modules/recon/crypto_offensive/crypto_offensive.c
)

# Cloud provider sources
set(CLOUD_SOURCES
    src/modules/cloud/akamai/akamai.c
    src/modules/cloud/aws/aws.c
    src/modules/cloud/azure/azure.c
    src/modules/cloud/gcp/gcp.c
    src/modules/cloud/fastly/fastly.c
    src/modules/cloud/digitalocean/digitalocean.c
    src/modules/cloud/oracle/oracle.c
    src/modules/cloud/alibaba/alibaba.c
    src/modules/cloud/shodan/shodan_api.c
    src/modules/cloud/censys/censys_api.c
    src/modules/cloud/virustotal/virustotal_api.c
    src/modules/cloud/cloud_detector.c
)

# Find required libraries
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

# Platform-specific libraries
if(WIN32)
    # Windows libraries
    set(PLATFORM_LIBS ws2_32 crypt32)
else()
    # POSIX libraries
    set(PLATFORM_LIBS pthread resolv atomic)
endif()

# Find json-c (different names on different platforms)
find_library(JSON_C_LIBRARY NAMES json-c json-c.lib libjson-c)
if(NOT JSON_C_LIBRARY)
    message(WARNING "json-c not found, some features may be disabled")
    set(JSON_C_LIBRARY "")
endif()

# Main executable
add_executable(cloudclear
    ${CORE_SOURCES}
    ${RECON_COMMON_SOURCES}
    ${CLOUD_SOURCES}
)

target_link_libraries(cloudclear
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARY}
    ${PLATFORM_LIBS}
)

# Recon version with all modules
if(BUILD_RECON)
    add_executable(cloudclear-recon
        ${CORE_SOURCES}
        ${RECON_COMMON_SOURCES}
        ${RECON_SOURCES}
        ${CLOUD_SOURCES}
    )

    target_compile_definitions(cloudclear-recon PRIVATE RECON_MODULES_ENABLED)
    target_link_libraries(cloudclear-recon
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
        ${JSON_C_LIBRARY}
        ${PLATFORM_LIBS}
    )
endif()

# TUI version (requires ncurses on POSIX, pdcurses on Windows)
if(BUILD_TUI)
    if(WIN32)
        # Try to find PDCurses for Windows
        find_library(CURSES_LIBRARY NAMES pdcurses)
        if(CURSES_LIBRARY)
            set(TUI_ENABLED TRUE)
        else()
            message(WARNING "PDCurses not found, TUI build disabled")
            set(TUI_ENABLED FALSE)
        endif()
    else()
        # ncurses on POSIX
        find_package(Curses REQUIRED)
        set(TUI_ENABLED TRUE)
    endif()

    if(TUI_ENABLED)
        add_executable(cloudclear-tui
            src/tui/cloudunflare_tui_main.c
            src/tui/cloudclear_tui.c
            src/tui/cloudclear_tui_enhanced.c
            ${CORE_SOURCES}
            ${RECON_COMMON_SOURCES}
            ${CLOUD_SOURCES}
        )

        target_compile_definitions(cloudclear-tui PRIVATE TUI_ENABLED)
        target_link_libraries(cloudclear-tui
            CURL::libcurl
            OpenSSL::SSL
            OpenSSL::Crypto
            ${JSON_C_LIBRARY}
            ${CURSES_LIBRARY}
            ${PLATFORM_LIBS}
        )
    endif()
endif()

# Installation
install(TARGETS cloudclear
    RUNTIME DESTINATION bin
)

if(BUILD_RECON)
    install(TARGETS cloudclear-recon
        RUNTIME DESTINATION bin
    )
endif()

if(BUILD_TUI AND TUI_ENABLED)
    install(TARGETS cloudclear-tui
        RUNTIME DESTINATION bin
    )
endif()

# Configuration files
install(FILES .env.example
    DESTINATION share/cloudclear
)

# Print build configuration
message(STATUS "CloudClear Build Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build TUI: ${BUILD_TUI}")
message(STATUS "  Build Recon: ${BUILD_RECON}")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler: ${CMAKE_C_COMPILER_ID}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
