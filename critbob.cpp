// critbob_inject.cpp - self-contained loader for critbob.dll (no cp_inject.h needed).
// Finds Minecraft Bedrock, grants the UWP sandbox read access to the DLL / data folder,
// then loads critbob.dll into the game with LoadLibraryW.
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstdio>
#include <string>

#pragma comment(lib, "advapi32.lib")

#define GAME_EXE  L"Minecraft.Windows.exe"
#define DLL_NAME  L"critbob.dll"
#define DATA_DIR  L"C:\\Users\\Public\\CheesyProxxy"

static DWORD FindPid(const wchar_t* exe) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Give "ALL APPLICATION PACKAGES" access so the UWP game can read the file/folder.
static bool GrantAppPackages(const wchar_t* path, DWORD rights, DWORD inherit) {
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-15-2-1", &sid)) return false;
    PSECURITY_DESCRIPTOR sd = nullptr; PACL oldDacl = nullptr, newDacl = nullptr;
    bool ok = false;
    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, &oldDacl, nullptr, &sd) == ERROR_SUCCESS) {
        EXPLICIT_ACCESS_W ea{};
        ea.grfAccessPermissions = rights;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = inherit;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)sid;
        if (SetEntriesInAclW(1, &ea, oldDacl, &newDacl) == ERROR_SUCCESS) {
            ok = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                       nullptr, nullptr, newDacl, nullptr) == ERROR_SUCCESS;
            LocalFree(newDacl);
        }
        LocalFree(sd);
    }
    LocalFree(sid);
    return ok;
}

int main() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring dll = exePath;
    dll = dll.substr(0, dll.find_last_of(L"\\/") + 1) + DLL_NAME;

    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"Can't find %s next to the injector.\n", dll.c_str());
        return 1;
    }

    CreateDirectoryW(DATA_DIR, nullptr);
    GrantAppPackages(dll.c_str(), GENERIC_READ | GENERIC_EXECUTE, NO_INHERITANCE);
    GrantAppPackages(DATA_DIR, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
                     SUB_CONTAINERS_AND_OBJECTS_INHERIT);

    DWORD pid = FindPid(GAME_EXE);
    if (!pid) { wprintf(L"%s is not running. Start Minecraft first.\n", GAME_EXE); return 2; }

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!proc) { wprintf(L"OpenProcess failed (%lu). Try running as administrator.\n", GetLastError()); return 3; }

    SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote || !WriteProcessMemory(proc, remote, dll.c_str(), bytes, nullptr)) {
        wprintf(L"Failed to write into the game process (%lu).\n", GetLastError());
        CloseHandle(proc); return 4;
    }

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE th = CreateRemoteThread(proc, nullptr, 0, loadLib, remote, 0, nullptr);
    if (!th) { wprintf(L"CreateRemoteThread failed (%lu).\n", GetLastError()); CloseHandle(proc); return 5; }

    WaitForSingleObject(th, 10000);
    DWORD mod = 0; GetExitCodeThread(th, &mod);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    CloseHandle(th); CloseHandle(proc);

    if (!mod) { wprintf(L"LoadLibrary returned NULL - the DLL failed to load.\n"); return 6; }
    wprintf(L"Injected %s into %s (pid %lu).\n", DLL_NAME, GAME_EXE, pid);
    return 0;
}
