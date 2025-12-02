/*
 * CloudClear - Cross-Platform Compatibility Layer
 * Provides Windows/Linux/macOS compatibility for POSIX APIs
 */

#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

/* Standard headers needed for type definitions */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
    /* Windows-specific headers and definitions */
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
        #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <process.h>
    #include <io.h>
    #include <fcntl.h>
    #include <direct.h>
    #include <string.h>  /* strings.h functions are in string.h on Windows */
    #include <sys/types.h>  /* For some type definitions */
    
    /* _Atomic keyword compatibility for MSVC */
    /* MSVC doesn't support C11 _Atomic, use volatile instead */
    #ifndef _Atomic
        #define _Atomic volatile
    #endif
    
    /* _Thread_local compatibility for MSVC */
    #ifndef _Thread_local
        #define _Thread_local __declspec(thread)
    #endif

    /* netdb.h compatibility - functions available via ws2tcpip.h */
    /* getaddrinfo, getnameinfo, etc. are available */

    /* arpa/nameser.h compatibility - DNS message structures */
    /* Windows doesn't have this, define minimal compatibility */
    #ifndef _ARPA_NAMESER_H
        #define _ARPA_NAMESER_H
        #define NS_PACKETSZ 512
        #define NS_MAXDNAME 1025
        #define NS_MAXMSG 65535
        typedef struct {
            unsigned short id;
            unsigned short flags;
            unsigned short qdcount;
            unsigned short ancount;
            unsigned short nscount;
            unsigned short arcount;
        } HEADER;
    #endif

    /* resolv.h compatibility - minimal definitions */
    #ifndef _RESOLV_H
        #define _RESOLV_H
        #define RES_INIT 0x0001
        #define RES_DEBUG 0x0002
    #endif

    /* Ensure INET6_ADDRSTRLEN is defined (available in ws2tcpip.h on modern Windows) */
    #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 46
    #endif

    /* sys/types.h compatibility */
    typedef int pid_t;
    typedef unsigned int uid_t;
    typedef unsigned int gid_t;
    typedef long ssize_t;
    /* off_t is already defined in Windows sys/types.h, don't redefine */
    #ifndef _OFF_T_DEFINED
        typedef long long off_t;
    #endif

    /* sys/random.h compatibility - use Windows Cryptography API */
    #include <wincrypt.h>
    static inline ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
        HCRYPTPROV hProv;
        (void)flags; /* Unused on Windows */
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return -1;
        }
        if (!CryptGenRandom(hProv, (DWORD)buflen, (BYTE*)buf)) {
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        CryptReleaseContext(hProv, 0);
        return (ssize_t)buflen;
    }

    /* Map POSIX functions to Windows equivalents */
    #define sleep(x) Sleep((x) * 1000)
    #define usleep(x) Sleep((x) / 1000)
    #define strcasecmp _stricmp
    #define strncasecmp _strnicmp
    /* snprintf exists in modern Windows (VS 2015+), only define if needed */
    #if _MSC_VER < 1900
        #define snprintf _snprintf
    #endif
    #define getpid _getpid
    #define mkdir(path, mode) _mkdir(path)

    /* strcasestr - case-insensitive string search */
    static inline char* strcasestr(const char *haystack, const char *needle) {
        if (!haystack || !needle) return NULL;
        size_t needle_len = strlen(needle);
        if (needle_len == 0) return (char*)haystack;
        for (const char *p = haystack; *p; p++) {
            if (_strnicmp(p, needle, needle_len) == 0) {
                return (char*)p;
            }
        }
        return NULL;
    }

    /* Thread compatibility */
    typedef HANDLE pthread_t;
    typedef CRITICAL_SECTION pthread_mutex_t;
    typedef void* (*pthread_start_routine)(void*);

    #define pthread_mutex_init(m, attr) InitializeCriticalSection(m)
    #define pthread_mutex_lock(m) EnterCriticalSection(m)
    #define pthread_mutex_unlock(m) LeaveCriticalSection(m)
    #define pthread_mutex_destroy(m) DeleteCriticalSection(m)

    /* Socket compatibility */
    #define close closesocket
    typedef int socklen_t;

    /* Path separator */
    #define PATH_SEPARATOR "\\"

    /* Initialize Winsock */
    static inline int init_networking(void) {
        WSADATA wsa_data;
        return WSAStartup(MAKEWORD(2, 2), &wsa_data);
    }

    static inline void cleanup_networking(void) {
        WSACleanup();
    }

    /* pthread_create wrapper for Windows */
    static inline int pthread_create(pthread_t *thread, void *attr,
                                    pthread_start_routine start_routine,
                                    void *arg) {
        (void)attr; /* Unused on Windows */
        *thread = CreateThread(NULL, 0,
                              (LPTHREAD_START_ROUTINE)start_routine,
                              arg, 0, NULL);
        return (*thread == NULL) ? -1 : 0;
    }

    /* pthread_join wrapper for Windows */
    static inline int pthread_join(pthread_t thread, void **retval) {
        (void)retval; /* Unused on Windows */
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }

    /* Signal handling - limited on Windows */
    #include <signal.h>
    #ifndef SIGPIPE
        #define SIGPIPE 13
    #endif
    /* SIG_IGN is defined in signal.h on Windows, don't redefine */

#else
    /* POSIX systems (Linux, macOS, BSD) */
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/mman.h>
    #include <signal.h>

    /* Path separator */
    #define PATH_SEPARATOR "/"

    /* No-op initialization for POSIX */
    static inline int init_networking(void) { return 0; }
    static inline void cleanup_networking(void) { }

#endif

/* Common definitions across all platforms */
#ifndef MAX_PATH
    #define MAX_PATH 4096
#endif

/* Memory locking - optional on Windows */
#ifdef _WIN32
    #define mlock(addr, len) VirtualLock(addr, len)
    #define munlock(addr, len) VirtualUnlock(addr, len)
#endif

/* Atomic operations compatibility */
#ifdef _WIN32
    /* Atomic operation wrappers for Windows using Interlocked functions */
    #define ATOMIC_FETCH_ADD_32(ptr, val) InterlockedExchangeAdd((LONG volatile*)(ptr), (LONG)(val))
    #define ATOMIC_FETCH_ADD_64(ptr, val) InterlockedExchangeAdd64((LONGLONG volatile*)(ptr), (LONGLONG)(val))
    #define ATOMIC_LOAD_32(ptr) InterlockedOr((LONG volatile*)(ptr), 0)
    #define ATOMIC_LOAD_64(ptr) InterlockedOr64((LONGLONG volatile*)(ptr), 0)
    #define ATOMIC_STORE_32(ptr, val) InterlockedExchange((LONG volatile*)(ptr), (LONG)(val))
    #define ATOMIC_STORE_64(ptr, val) InterlockedExchange64((LONGLONG volatile*)(ptr), (LONGLONG)(val))
#else
    /* POSIX: Use standard C11 atomic operations */
    #include <stdatomic.h>
    #define ATOMIC_FETCH_ADD_32(ptr, val) atomic_fetch_add(ptr, val)
    #define ATOMIC_FETCH_ADD_64(ptr, val) atomic_fetch_add(ptr, val)
    #define ATOMIC_LOAD_32(ptr) atomic_load(ptr)
    #define ATOMIC_LOAD_64(ptr) atomic_load(ptr)
    #define ATOMIC_STORE_32(ptr, val) atomic_store(ptr, val)
    #define ATOMIC_STORE_64(ptr, val) atomic_store(ptr, val)
#endif

#endif /* PLATFORM_COMPAT_H */
