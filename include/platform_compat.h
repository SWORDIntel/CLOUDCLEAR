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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
    /* ========================================================================
     * WINDOWS PLATFORM COMPATIBILITY
     * ======================================================================== */
    
    /* Windows-specific headers */
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
    #include <signal.h>
    
    /* ========================================================================
     * ssize_t compatibility - must handle json-c conflict
     * json-c defines ssize_t in json_inttypes.h, so we need to be careful
     * We use SSIZE_T from Windows BaseTsd.h if available, or define our own
     * ======================================================================== */
    #ifndef _SSIZE_T_DEFINED
        #define _SSIZE_T_DEFINED
        /* Check if BaseTsd.h SSIZE_T is available */
        #ifdef SSIZE_T
            typedef SSIZE_T ssize_t;
        #else
            #ifdef _WIN64
                typedef __int64 ssize_t;
            #else
                typedef long ssize_t;
            #endif
        #endif
    #endif
    
    /* _Atomic keyword compatibility for MSVC */
    #ifndef _Atomic
        #define _Atomic volatile
    #endif
    
    /* _Thread_local compatibility for MSVC */
    #ifndef _Thread_local
        #define _Thread_local __declspec(thread)
    #endif
    
    /* C11 atomic operations - map to simple volatile operations for Windows */
    #define atomic_store(ptr, val) (*(ptr) = (val))
    #define atomic_load(ptr) (*(ptr))
    #define atomic_fetch_add(ptr, val) (_InterlockedExchangeAdd((long volatile*)(ptr), (long)(val)))
    #define atomic_fetch_sub(ptr, val) (_InterlockedExchangeAdd((long volatile*)(ptr), -(long)(val)))
    #define atomic_init(ptr, val) (*(ptr) = (val))
    #define atomic_compare_exchange_weak(ptr, expected, desired) \
        (_InterlockedCompareExchange((long volatile*)(ptr), (long)(desired), (long)(*(expected))) == (long)(*(expected)))
    #define atomic_compare_exchange_strong(ptr, expected, desired) \
        atomic_compare_exchange_weak(ptr, expected, desired)
    
    /* ========================================================================
     * mmap/munmap compatibility using VirtualAlloc/VirtualFree
     * ======================================================================== */
    #define PROT_NONE  0x0
    #define PROT_READ  0x1
    #define PROT_WRITE 0x2
    #define PROT_EXEC  0x4
    
    #define MAP_SHARED    0x01
    #define MAP_PRIVATE   0x02
    #define MAP_ANONYMOUS 0x20
    #define MAP_ANON      MAP_ANONYMOUS
    #define MAP_FAILED    ((void*)-1)
    
    static inline void* mmap(void *addr, size_t length, int prot, int flags, int fd, size_t offset) {
        DWORD protect = PAGE_NOACCESS;
        DWORD access = 0;
        
        (void)addr;
        (void)fd;
        (void)offset;
        (void)flags;
        
        /* Map protection flags */
        if ((prot & PROT_WRITE) && (prot & PROT_READ)) {
            protect = PAGE_READWRITE;
        } else if (prot & PROT_READ) {
            protect = PAGE_READONLY;
        } else if (prot & PROT_WRITE) {
            protect = PAGE_READWRITE;
        }
        
        if (prot & PROT_EXEC) {
            if (protect == PAGE_READWRITE) {
                protect = PAGE_EXECUTE_READWRITE;
            } else if (protect == PAGE_READONLY) {
                protect = PAGE_EXECUTE_READ;
            } else {
                protect = PAGE_EXECUTE;
            }
        }
        
        void *ptr = VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, protect);
        return ptr ? ptr : MAP_FAILED;
    }
    
    static inline int munmap(void *addr, size_t length) {
        (void)length;
        return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
    }
    
    /* ========================================================================
     * DNS/Network structures
     * ======================================================================== */
    
    /* DNS message structures (arpa/nameser.h) */
    #ifndef NS_PACKETSZ
        #define NS_PACKETSZ 512
        #define NS_MAXDNAME 1025
        #define NS_MAXMSG 65535
    #endif
    
    /* resolv.h compatibility */
    #ifndef RES_INIT
        #define RES_INIT 0x0001
        #define RES_DEBUG 0x0002
    #endif
    
    /* INET6_ADDRSTRLEN */
    #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 46
    #endif
    
    /* ========================================================================
     * sys/types.h compatibility
     * ======================================================================== */
    typedef int pid_t;
    typedef unsigned int uid_t;
    typedef unsigned int gid_t;
    
    /* ========================================================================
     * clock_gettime compatibility
     * ======================================================================== */
    #ifndef CLOCK_MONOTONIC
        #define CLOCK_MONOTONIC 1
        #define CLOCK_REALTIME 0
        
        #ifndef _TIMESPEC_DEFINED
            #define _TIMESPEC_DEFINED
            struct timespec {
                time_t tv_sec;
                long tv_nsec;
            };
        #endif
        
        static inline int clock_gettime(int clk_id, struct timespec *tp) {
            LARGE_INTEGER freq, count;
            (void)clk_id;
            if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&count)) {
                return -1;
            }
            tp->tv_sec = (time_t)(count.QuadPart / freq.QuadPart);
            tp->tv_nsec = (long)((count.QuadPart % freq.QuadPart) * 1000000000LL / freq.QuadPart);
            return 0;
        }
    #endif
    
    /* nanosleep compatibility */
    static inline int nanosleep(const struct timespec *req, struct timespec *rem) {
        (void)rem;
        DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
        Sleep(ms);
        return 0;
    }
    
    /* ========================================================================
     * Random number generation
     * ======================================================================== */
    #include <wincrypt.h>
    static inline ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
        HCRYPTPROV hProv;
        (void)flags;
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
    
    /* syscall/SYS_getrandom compatibility - use getrandom directly */
    #define SYS_getrandom 0
    #define syscall(num, buf, len, flags) getrandom(buf, len, flags)
    
    /* ========================================================================
     * fcntl compatibility
     * ======================================================================== */
    #ifndef F_GETFL
        #define F_GETFL 3
        #define F_SETFL 4
        #define O_NONBLOCK 0x0004
        
        static inline int fcntl(int fd, int cmd, ...) {
            if (cmd == F_SETFL) {
                unsigned long mode = 1;
                return ioctlsocket((SOCKET)fd, FIONBIO, &mode);
            }
            return 0;
        }
    #endif
    
    /* MSG_NOSIGNAL doesn't exist on Windows */
    #ifndef MSG_NOSIGNAL
        #define MSG_NOSIGNAL 0
    #endif
    
    /* ========================================================================
     * POSIX function mappings
     * ======================================================================== */
    #define sleep(x) Sleep((x) * 1000)
    #define usleep(x) Sleep((x) / 1000)
    #define strcasecmp _stricmp
    #define strncasecmp _strnicmp
    #define strdup _strdup
    #define getpid _getpid
    #define mkdir(path, mode) _mkdir(path)
    #define unlink _unlink
    
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
    
    /* ========================================================================
     * pthread compatibility
     * ======================================================================== */
    typedef HANDLE pthread_t;
    typedef CRITICAL_SECTION pthread_mutex_t;
    typedef void* pthread_mutexattr_t;
    typedef void* (*pthread_start_routine)(void*);
    
    /* Static mutex initializer - Windows needs runtime init, so we use a sentinel */
    #define PTHREAD_MUTEX_INITIALIZER {(void*)-1, -1, 0, 0, 0, 0}
    
    /* pthread_mutex_init wrapper */
    static inline int pthread_mutex_init_compat(pthread_mutex_t *m, const pthread_mutexattr_t *attr) {
        (void)attr;
        InitializeCriticalSection(m);
        return 0;
    }
    #define pthread_mutex_init(m, attr) pthread_mutex_init_compat(m, attr)
    #define pthread_mutex_lock(m) (EnterCriticalSection(m), 0)
    #define pthread_mutex_unlock(m) (LeaveCriticalSection(m), 0)
    #define pthread_mutex_destroy(m) (DeleteCriticalSection(m), 0)
    
    /* pthread_cancel - not directly supported on Windows, stub it */
    static inline int pthread_cancel(pthread_t thread) {
        /* TerminateThread is dangerous, but it's the only option */
        return TerminateThread(thread, 0) ? 0 : -1;
    }
    
    /* pthread_create wrapper */
    static inline int pthread_create(pthread_t *thread, void *attr,
                                    pthread_start_routine start_routine,
                                    void *arg) {
        (void)attr;
        *thread = CreateThread(NULL, 0,
                              (LPTHREAD_START_ROUTINE)start_routine,
                              arg, 0, NULL);
        return (*thread == NULL) ? -1 : 0;
    }
    
    /* pthread_join wrapper */
    static inline int pthread_join(pthread_t thread, void **retval) {
        (void)retval;
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return 0;
    }
    
    /* ========================================================================
     * Socket compatibility
     * ======================================================================== */
    #define close closesocket
    typedef int socklen_t;
    
    /* setsockopt compatibility - Windows uses char* for optval */
    #define SETSOCKOPT_OPTVAL_TYPE const char*
    
    /* ========================================================================
     * Path and signal handling
     * ======================================================================== */
    #define PATH_SEPARATOR "\\"
    
    #ifndef SIGPIPE
        #define SIGPIPE 13
    #endif
    
    /* ========================================================================
     * Winsock initialization
     * ======================================================================== */
    static inline int init_networking(void) {
        WSADATA wsa_data;
        return WSAStartup(MAKEWORD(2, 2), &wsa_data);
    }
    
    static inline void cleanup_networking(void) {
        WSACleanup();
    }

#else
    /* ========================================================================
     * POSIX PLATFORM (Linux, macOS, BSD)
     * ======================================================================== */
    
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/mman.h>
    #include <signal.h>
    #include <fcntl.h>
    #include <stdatomic.h>
    
    /* setsockopt uses void* on POSIX */
    #define SETSOCKOPT_OPTVAL_TYPE const void*
    
    /* Path separator */
    #define PATH_SEPARATOR "/"
    
    /* No-op initialization for POSIX */
    static inline int init_networking(void) { return 0; }
    static inline void cleanup_networking(void) { }

#endif

/* ============================================================================
 * COMMON DEFINITIONS (ALL PLATFORMS)
 * ============================================================================ */

#ifndef MAX_PATH
    #define MAX_PATH 4096
#endif

/* Memory locking */
#ifdef _WIN32
    #define mlock(addr, len) (VirtualLock(addr, len) ? 0 : -1)
    #define munlock(addr, len) (VirtualUnlock(addr, len) ? 0 : -1)
#endif

/* Macro-based atomic operations for cross-platform use */
#ifdef _WIN32
    #define ATOMIC_FETCH_ADD_32(ptr, val) InterlockedExchangeAdd((LONG volatile*)(ptr), (LONG)(val))
    #define ATOMIC_FETCH_ADD_64(ptr, val) InterlockedExchangeAdd64((LONGLONG volatile*)(ptr), (LONGLONG)(val))
    #define ATOMIC_LOAD_32(ptr) InterlockedOr((LONG volatile*)(ptr), 0)
    #define ATOMIC_LOAD_64(ptr) InterlockedOr64((LONGLONG volatile*)(ptr), 0)
    #define ATOMIC_STORE_32(ptr, val) InterlockedExchange((LONG volatile*)(ptr), (LONG)(val))
    #define ATOMIC_STORE_64(ptr, val) InterlockedExchange64((LONGLONG volatile*)(ptr), (LONGLONG)(val))
#else
    #define ATOMIC_FETCH_ADD_32(ptr, val) atomic_fetch_add(ptr, val)
    #define ATOMIC_FETCH_ADD_64(ptr, val) atomic_fetch_add(ptr, val)
    #define ATOMIC_LOAD_32(ptr) atomic_load(ptr)
    #define ATOMIC_LOAD_64(ptr) atomic_load(ptr)
    #define ATOMIC_STORE_32(ptr, val) atomic_store(ptr, val)
    #define ATOMIC_STORE_64(ptr, val) atomic_store(ptr, val)
#endif

#endif /* PLATFORM_COMPAT_H */
