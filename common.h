#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
typedef struct _MEMORY_BASIC_INFORMATION2 {
  PVOID  BaseAddress;
  PVOID  AllocationBase;
  DWORD  AllocationProtect;
  WORD   PartitionId;
  SIZE_T RegionSize;
  DWORD  State;
  DWORD  Protect;
  DWORD  Type;
} MEMORY_BASIC_INFORMATION2, *PMEMORY_BASIC_INFORMATION2;

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

DECLSPEC_IMPORT LPVOID KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

DECLSPEC_IMPORT SIZE_T KERNEL32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION2 lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT BOOL KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE hSnapshot, void *lppe);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE hSnapshot, void *lppe);

#ifdef PRINT_PROCESS_OWNER
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR lpSystemName, PSID lpSid, LPWSTR Name, LPDWORD cchName, LPWSTR DomainName, LPDWORD cchDomainName, PSID_NAME_USE peUse);
#endif
