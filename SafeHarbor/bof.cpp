#include <Windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <securitybaseapi.h>
#include <memoryapi.h>
#include <wintrust.h>
#include <softpub.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "wintrust.lib")
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"

    DFR(KERNEL32, GetLastError);
    DFR(KERNEL32, OpenProcess);
    DFR(KERNEL32, VirtualQueryEx);
    DFR(KERNEL32, CloseHandle);
    DFR(KERNEL32, VirtualAlloc);
    DFR(KERNEL32, VirtualFree);

    DFR(PSAPI, EnumProcesses);
    DFR(PSAPI, EnumProcessModules);
    DFR(PSAPI, GetModuleFileNameExA);

    DFR(ADVAPI32, OpenProcessToken);
    DFR(ADVAPI32, GetTokenInformation);
    DFR(ADVAPI32, GetUserNameA);

    DFR(WINTRUST, WinVerifyTrust);

#define GetLastError KERNEL32$GetLastError
#define EnumProcesses PSAPI$EnumProcesses
#define EnumProcessModules PSAPI$EnumProcessModules
#define GetModuleFileNameExA PSAPI$GetModuleFileNameExA
#define GetUserNameA ADVAPI32$GetUserNameA
#define OpenProcess KERNEL32$OpenProcess
#define VirtualQueryEx KERNEL32$VirtualQueryEx
#define CloseHandle KERNEL32$CloseHandle
#define VirtualAlloc KERNEL32$VirtualAlloc
#define VirtualFree KERNEL32$VirtualFree
#define OpenProcessToken ADVAPI32$OpenProcessToken
#define GetTokenInformation ADVAPI32$GetTokenInformation
#define WinVerifyTrust WINTRUST$WinVerifyTrust

    void* MyAlloc(SIZE_T size) {
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    void MyFree(void* ptr) {
        if (ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    }

    SIZE_T my_strlen(const char* str) {
        SIZE_T len = 0;
        while (str && str[len]) len++;
        return len;
    }

    void my_strcpy(char* dest, const char* src) {
        while (src && *src) {
            *dest++ = *src++;
        }
        *dest = '\0';
    }

    void my_strcat(char* dest, const char* src) {
        SIZE_T dlen = my_strlen(dest);
        SIZE_T i = 0;
        while (src && src[i]) {
            dest[dlen + i] = src[i];
            i++;
        }
        dest[dlen + i] = '\0';
    }

    void my_memset(char* buf, char c, SIZE_T size) {
        for (SIZE_T i = 0; i < size; i++) {
            buf[i] = c;
        }
    }

    void my_uint_to_str(SIZE_T value, char* buf, SIZE_T bufSize) {
        if (bufSize == 0) return;

        if (value == 0) {
            if (bufSize > 1) {
                buf[0] = '0';
                buf[1] = '\0';
            }
            else if (bufSize == 1) {
                buf[0] = '\0';
            }
            return;
        }

        SIZE_T pos = bufSize - 1;
        buf[pos] = '\0';

        while (value > 0 && pos > 0) {
            pos--;
            buf[pos] = (char)('0' + (value % 10));
            value /= 10;
        }

        if (pos > 0) {
            SIZE_T start = pos;
            SIZE_T len = (bufSize - 1) - start;
            for (SIZE_T i = 0; i < len; i++) {
                buf[i] = buf[start + i];
            }
            buf[len] = '\0';
        }
    }

    WCHAR* my_alloc_wide(const char* str) {
        SIZE_T len = my_strlen(str);
        SIZE_T size = (len + 1) * sizeof(WCHAR);
        WCHAR* wstr = (WCHAR*)MyAlloc(size);
        if (!wstr) return NULL;
        for (SIZE_T i = 0; i < len; i++) {
            wstr[i] = (WCHAR)str[i];
        }
        wstr[len] = L'\0';
        return wstr;
    }

    void my_ptr_to_hex(void* ptr, char* buf, SIZE_T bufSize) {
        if (bufSize < 19) {
            if (bufSize > 0) buf[0] = '\0';
            return;
        }
        const char* hex = "0123456789ABCDEF";
        buf[0] = '0'; buf[1] = 'x';
        unsigned char* p = (unsigned char*)&ptr;
        for (int i = 0; i < 8; i++) {
            unsigned char byte = p[7 - i];
            buf[2 + i * 2] = hex[(byte >> 4) & 0xF];
            buf[3 + i * 2] = hex[byte & 0xF];
        }
        buf[18] = '\0';
    }

    const char* ExtractProcessName(const char* fullPath) {
        const char* name = fullPath;
        for (const char* p = fullPath; *p; p++) {
            if (*p == '\\' || *p == '/') {
                name = p + 1;
            }
        }
        return name;
    }

    bool IsCurrentUserProcess(HANDLE hProcess, const char* currentUser) {
        HANDLE tokenHandle;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &tokenHandle)) {
            return false;
        }

        char* buffer = (char*)MyAlloc(256);
        if (!buffer) {
            CloseHandle(tokenHandle);
            return false;
        }

        DWORD size = 0;
        bool result = false;
        if (GetTokenInformation(tokenHandle, TokenUser, buffer, 256, &size)) {
            result = true;
        }

        MyFree(buffer);
        CloseHandle(tokenHandle);
        return result;
    }

    const char* custom_strstr(const char* haystack, const char* needle) {
        if (!*needle) return haystack;

        for (const char* h = haystack; *h; h++) {
            const char* h_iter = h;
            const char* n_iter = needle;

            while (*h_iter && *n_iter && (*h_iter == *n_iter)) {
                h_iter++;
                n_iter++;
            }

            if (!*n_iter) return h;
        }
        return NULL;
    }

    HRESULT CheckFileSignature(const char* filePath) {
        GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_FILE_INFO FileData;
        WINTRUST_DATA WinTrustData;

        WCHAR* wFilePath = my_alloc_wide(filePath);
        if (!wFilePath) return E_OUTOFMEMORY;

        my_memset((char*)&FileData, 0, sizeof(FileData));
        FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileData.pcwszFilePath = wFilePath;

        my_memset((char*)&WinTrustData, 0, sizeof(WinTrustData));
        WinTrustData.cbStruct = sizeof(WinTrustData);
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        WinTrustData.pFile = &FileData;
        WinTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
        WinTrustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

        HRESULT hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WVTPolicyGUID, &WinTrustData);

        MyFree(wFilePath);
        return hr;
    }

    void go(char* args, int len) {
        DWORD* processes = (DWORD*)MyAlloc(sizeof(DWORD) * 1024);
        if (!processes) {
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure.");
            return;
        }

        DWORD cbNeeded;
        if (!EnumProcesses(processes, sizeof(DWORD) * 1024, &cbNeeded)) {
            MyFree(processes);
            BeaconPrintf(CALLBACK_ERROR, "Unable to enumerate processes.");
            return;
        }

        DWORD processCount = cbNeeded / sizeof(DWORD);

        char* currentUser = (char*)MyAlloc(256);
        if (!currentUser) {
            MyFree(processes);
            BeaconPrintf(CALLBACK_ERROR, "Memory allocation failure.");
            return;
        }

        DWORD userLen = 256;
        if (!GetUserNameA(currentUser, &userLen)) {
            MyFree(currentUser);
            MyFree(processes);
            BeaconPrintf(CALLBACK_ERROR, "Unable to retrieve current user.");
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "\n------------------------------------------------------------");
        BeaconPrintf(CALLBACK_OUTPUT, "  PID     Process Name                  Findings");
        BeaconPrintf(CALLBACK_OUTPUT, "------------------------------------------------------------");

        for (DWORD i = 0; i < processCount; i++) {
            DWORD pid = processes[i];
            if (pid == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProcess) continue;

            if (!IsCurrentUserProcess(hProcess, currentUser)) {
                CloseHandle(hProcess);
                continue;
            }

            char* exePath = (char*)MyAlloc(MAX_PATH);
            if (!exePath) {
                CloseHandle(hProcess);
                continue;
            }

            if (!GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) {
                MyFree(exePath);
                CloseHandle(hProcess);
                continue;
            }

            const char* processName = ExtractProcessName(exePath);

            HMODULE* modules = (HMODULE*)MyAlloc(sizeof(HMODULE) * 1024);
            bool foundWininet = false;
            bool foundWinhttp = false;
            bool isDotNet = false;

            if (modules) {
                DWORD cbModulesNeeded2;
                if (EnumProcessModules(hProcess, modules, sizeof(HMODULE) * 1024, &cbModulesNeeded2)) {
                    DWORD moduleCount = cbModulesNeeded2 / sizeof(HMODULE);

                    char* modulePath = (char*)MyAlloc(MAX_PATH);
                    if (modulePath) {
                        for (DWORD j = 0; j < moduleCount; j++) {
                            if (GetModuleFileNameExA(hProcess, modules[j], modulePath, MAX_PATH)) {
                                if (!foundWininet && custom_strstr(modulePath, "wininet.dll")) {
                                    foundWininet = true;
                                }
                                if (!foundWinhttp && custom_strstr(modulePath, "winhttp.dll")) {
                                    foundWinhttp = true;
                                }
                                if (!isDotNet && (custom_strstr(modulePath, "mscoree.dll") || custom_strstr(modulePath, "clr.dll"))) {
                                    isDotNet = true;
                                }
                                if (foundWininet && foundWinhttp && isDotNet) {
                                    break;
                                }
                            }
                        }
                        MyFree(modulePath);
                    }
                }
                MyFree(modules);
            }

            void** rwxBases = (void**)MyAlloc(sizeof(void*) * 256);
            SIZE_T rwxCount = 0;
            SIZE_T totalRWXSize = 0;
            if (rwxBases) {
                my_memset((char*)rwxBases, 0, sizeof(void*) * 256);
                MEMORY_BASIC_INFORMATION mbi;
                DWORD_PTR addr = 0;
                while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READWRITE) {
                        if (rwxCount < 256) {
                            rwxBases[rwxCount++] = mbi.BaseAddress;
                        }
                        totalRWXSize += mbi.RegionSize;
                    }
                    addr += mbi.RegionSize;
                }
            }

            HRESULT sigResult = CheckFileSignature(exePath);
            bool isSigned = (sigResult == S_OK);

            // Dynamically allocate large buffers instead of large stack arrays
            char* outBuf = (char*)MyAlloc(8192);
            if (!outBuf) {
                if (rwxBases) MyFree(rwxBases);
                MyFree(exePath);
                CloseHandle(hProcess);
                continue;
            }
            my_memset(outBuf, 0, 8192);

            char* line = (char*)MyAlloc(1024);
            if (!line) {
                MyFree(outBuf);
                if (rwxBases) MyFree(rwxBases);
                MyFree(exePath);
                CloseHandle(hProcess);
                continue;
            }
            my_memset(line, 0, 1024);

            char pidBuf[32];
            my_memset(pidBuf, 0, 32);
            my_uint_to_str(pid, pidBuf, 32);

            // Format PID & ProcessName line
            char pidLine[16];
            my_memset(pidLine, 0, 16);
            SIZE_T pidLen = my_strlen(pidBuf);
            SIZE_T pad = 6 > pidLen ? 6 - pidLen : 0;
            for (SIZE_T p = 0; p < pad; p++) my_strcat(pidLine, " ");
            my_strcat(pidLine, pidBuf);

            char nameLine[64];
            my_memset(nameLine, 0, 64);
            my_strcpy(nameLine, processName);
            SIZE_T nameLen = my_strlen(processName);
            for (SIZE_T n = nameLen; n < 30; n++) {
                my_strcat(nameLine, " ");
            }

            my_strcat(line, "  ");
            my_strcat(line, pidLine);
            my_strcat(line, "   ");
            my_strcat(line, nameLine);
            my_strcat(line, "\n");

            my_strcat(outBuf, line);

            bool anythingFound = false;

            // Modules
            if (foundWininet || foundWinhttp || isDotNet || isSigned || totalRWXSize > 0) {
                if (foundWininet || foundWinhttp) {
                    char* modLine = (char*)MyAlloc(512);
                    if (modLine) {
                        my_memset(modLine, 0, 512);
                        my_strcat(modLine, "      Modules: ");
                        if (foundWininet) {
                            my_strcat(modLine, "wininet.dll");
                            if (foundWinhttp) {
                                my_strcat(modLine, ", winhttp.dll");
                            }
                        }
                        else {
                            my_strcat(modLine, "winhttp.dll");
                        }
                        my_strcat(modLine, "\n");
                        my_strcat(outBuf, modLine);
                        MyFree(modLine);
                    }
                    anythingFound = true;
                }

                // RWX
                if (totalRWXSize > 0) {
                    char* rwxLine = (char*)MyAlloc(512);
                    if (rwxLine) {
                        my_memset(rwxLine, 0, 512);
                        my_strcat(rwxLine, "      RWX: ");
                        char sizeBuf[64];
                        my_memset(sizeBuf, 0, 64);
                        my_uint_to_str(totalRWXSize, sizeBuf, 64);
                        my_strcat(rwxLine, sizeBuf);
                        my_strcat(rwxLine, " bytes\n");
                        my_strcat(outBuf, rwxLine);
                        MyFree(rwxLine);
                    }
                    anythingFound = true;
                }

                // .NET
                if (isDotNet) {
                    my_strcat(outBuf, "      .NET process\n");
                    anythingFound = true;
                }

                // Signed
                if (isSigned) {
                    my_strcat(outBuf, "      Signed\n");
                    anythingFound = true;
                }
            }
            else {
                my_strcat(outBuf, "      No special findings\n");
            }

            // RWX Segments
            if (rwxCount > 0) {
                my_strcat(outBuf, "      RWX Segments:\n");
                for (SIZE_T k = 0; k < rwxCount; k++) {
                    char addrBuf[32];
                    my_memset(addrBuf, 0, 32);
                    my_ptr_to_hex(rwxBases[k], addrBuf, 32);
                    my_strcat(outBuf, "        ");
                    my_strcat(outBuf, addrBuf);
                    my_strcat(outBuf, "\n");
                }
            }

            BeaconPrintf(CALLBACK_OUTPUT, "%s", outBuf);

            MyFree(line);
            MyFree(outBuf);
            if (rwxBases) MyFree(rwxBases);
            MyFree(exePath);
            CloseHandle(hProcess);
        }

        BeaconPrintf(CALLBACK_OUTPUT, "------------------------------------------------------------\n");

        MyFree(currentUser);
        MyFree(processes);
    }
}

#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {
    bof::runMocked<>(go);
    return 0;
}
#elif defined(_GTEST)
#include <gtest\gtest.h>
TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got = bof::runMocked<>(go);
    ASSERT_TRUE(!got.empty());
}
#endif
