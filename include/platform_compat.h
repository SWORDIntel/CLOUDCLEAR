/*
 * CloudClear - Cross-Platform Compatibility Layer
 * Provides Windows/Linux/macOS compatibility for POSIX APIs
 */

#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

#ifdef _WIN32
    /* Windows-specific headers and definitions */
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <process.h>
    #include <io.h>
    #include <fcntl.h>
    #include <direct.h>
    
    /* Ensure INET6_ADDRSTRLEN is defined (available in ws2tcpip.h on modern Windows) */
    #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 46
    #endif
    
    /* sys/types.h compatibility */
    typedef int pid_t;
    typedef unsigned int uid_t;
    typedef unsigned int gid_t;
    typedef long ssize_t;
    typedef long long off_t;
    
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
    #define snprintf _snprintf
    #define getpid _getpid
    #define mkdir(path, mode) _mkdir(path)

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
    #define SIGPIPE 13
    #define SIG_IGN ((void (*)(int))1)

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
    #define atomic_fetch_add(ptr, val) InterlockedExchangeAdd((LONG volatile*)(ptr), (val))
    #define atomic_load(ptr) InterlockedOr((LONG volatile*)(ptr), 0)
#else
    #include <stdatomic.h>
    #define atomic_fetch_add(ptr, val) __atomic_fetch_add(ptr, val, __ATOMIC_SEQ_CST)
    #define atomic_load(ptr) __atomic_load_n(ptr, __ATOMIC_SEQ_CST)
#endif

#endif /* PLATFORM_COMPAT_H */
