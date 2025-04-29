// WTLocalStateHook.cpp — Windows Terminal LocalState redirection hook
// Build: cl /std:c++17 /MD /O2 /LD WTLocalStateHook.cpp detours.lib shlwapi.lib
// Requires: Detours 4.x public headers & libs
// Usage: 1) set env var WT_REDIRECT_LOCALSTATE to your desired profile root
//        2) DetourCreateProcessWithDllExW(..., L"...\\WTLocalStateHook.dll", …)

#include <windows.h>
#include <shlobj.h>          // SHGetFolderPathW
#include <winternl.h>        // NtCreateFile, UNICODE_STRING
#include <detours.h>
#include <string>
#include <vector>
#include <filesystem>

//--------------------------------------------------------------------------
// Globals
//--------------------------------------------------------------------------
static std::wstring g_defaultPrefix;   // canonical LocalState path
static std::wstring g_newPrefix;       // replacement root (profile)

// Original function pointers ------------------------------------------------
extern "C" {

    static HANDLE(WINAPI* Real_CreateFileW)(
            LPCWSTR a0,
            DWORD a1,
            DWORD a2,
            LPSECURITY_ATTRIBUTES a3,
            DWORD a4,
            DWORD a5,
            HANDLE a6)
        = CreateFileW;

    static HANDLE(WINAPI* Real_CreateFileA)(
            LPCSTR a0,
            DWORD a1,
            DWORD a2,
            LPSECURITY_ATTRIBUTES a3,
            DWORD a4,
            DWORD a5,
            HANDLE a6)
        = CreateFileA;

    static HANDLE(WINAPI* Real_CreateFileMappingA)(
            HANDLE a0,
            LPSECURITY_ATTRIBUTES a1,
            DWORD a2,
            DWORD a3,
            DWORD a4,
            LPCSTR a5)
        = CreateFileMappingA;

    static HANDLE(WINAPI* Real_CreateFileMappingW)(
            HANDLE a0,
            LPSECURITY_ATTRIBUTES a1,
            DWORD a2,
            DWORD a3,
            DWORD a4,
            LPCWSTR a5)
        = CreateFileMappingW;

    static BOOL(WINAPI* Real_MoveFileExW)(
            LPCWSTR,
            LPCWSTR,
            DWORD)
        = MoveFileExW;
    static BOOL(WINAPI* Real_ReplaceFileW)(
            LPCWSTR,
            LPCWSTR,
            LPCWSTR,
            DWORD,
            LPVOID,
            LPVOID)
        = ReplaceFileW;
}
using PFN_NtCreateFile = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static PFN_NtCreateFile Real_NtCreateFile = nullptr;

using PathFn = std::filesystem::path(*)();
static PathFn Real_GetBasePath = nullptr;
static PathFn Real_GetReleasePath = nullptr;

//--------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------
static void InitPrefixes()
{
    if (!g_defaultPrefix.empty()) return;          // already cached

    // 1. default LocalState — build it at runtime so the hook works for any user
    wchar_t localAppData[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"WT_DEFAULT_LOCALSTATE", localAppData, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        g_defaultPrefix.assign(localAppData, len);

    // 2. new LocalState root — read once from env var
    wchar_t buf[MAX_PATH];
    len = GetEnvironmentVariableW(L"WT_REDIRECT_LOCALSTATE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        g_newPrefix.assign(buf, len);
}

// Replace beginning of |path| if it starts with the canonical LocalState root
static std::wstring RewritePath(const std::wstring& path)
{
    if (g_newPrefix.empty()) return path;

    if (path.rfind(g_defaultPrefix, 0) == 0)      // prefix‑match at pos 0
    {
        std::wstring rewritten = g_newPrefix;
        rewritten.append(path.substr(g_defaultPrefix.length()));
        return rewritten;
    }
    return path;
}

//--------------------------------------------------------------------------
// Hooked APIs
//--------------------------------------------------------------------------
static HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    InitPrefixes();
    std::wstring newName = lpFileName ? RewritePath(lpFileName) : std::wstring();
    return Real_CreateFileW(newName.empty() ? lpFileName : newName.c_str(),
        dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

static HANDLE WINAPI Hook_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    return Real_CreateFileA(lpFileName,
        dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

static HANDLE WINAPI Hook_CreateFileMappingW(
    HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCWSTR lpName)
{
    InitPrefixes();
    std::wstring newName = lpName ? RewritePath(lpName) : std::wstring();
    return Real_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow,
        newName.empty() ? lpName : newName.c_str());
}

static NTSTATUS NTAPI Hook_NtCreateFile(PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    InitPrefixes();

    UNICODE_STRING localCopy{};               // buffer lives on our stack
    OBJECT_ATTRIBUTES oaCopy = *ObjectAttributes; // shallow copy

    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer)
    {
        std::wstring original(ObjectAttributes->ObjectName->Buffer,
            ObjectAttributes->ObjectName->Length / sizeof(WCHAR));
        std::wstring rewritten = RewritePath(original);
        if (rewritten != original)
        {
            RtlInitUnicodeString(&localCopy, rewritten.c_str());
            oaCopy.ObjectName = &localCopy;   // point to rewritten path
            ObjectAttributes = &oaCopy;       // use our modified copy
        }
    }

    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

static std::filesystem::path Hook_GetBasePath()
{
    return Real_GetBasePath();
}
static std::filesystem::path Hook_GetReleasePath()
{
    return Real_GetReleasePath();
}

static BOOL WINAPI Hook_MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags)
{
    InitPrefixes();   // reuse your existing logic

    std::wstring src = from ? RewritePath(from) : std::wstring();
    std::wstring dst = to ? RewritePath(to) : std::wstring();

    return Real_MoveFileExW(src.empty() ? from : src.c_str(),
        dst.empty() ? to : dst.c_str(),
        flags);
}

static BOOL WINAPI Hook_ReplaceFileW(LPCWSTR replaced, LPCWSTR replaceWith,
    LPCWSTR backup, DWORD flags,
    LPVOID, LPVOID)
{
    InitPrefixes();

    std::wstring src = replaced ? RewritePath(replaced) : std::wstring();
    std::wstring newf = replaceWith ? RewritePath(replaceWith) : std::wstring();

    return Real_ReplaceFileW(src.empty() ? replaced : src.c_str(),
        newf.empty() ? replaceWith : newf.c_str(),
        backup,
        flags,
        nullptr, nullptr);
}

//--------------------------------------------------------------------------
// Detour attach / detach
//--------------------------------------------------------------------------
static void AttachDetours()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)Real_CreateFileW, Hook_CreateFileW);
    DetourAttach(&(PVOID&)Real_CreateFileA, Hook_CreateFileA);
    DetourAttach(&(PVOID&)Real_CreateFileMappingW, Hook_CreateFileMappingW);
    DetourAttach(&(PVOID&)Real_MoveFileExW, Hook_MoveFileExW);
    DetourAttach(&(PVOID&)Real_ReplaceFileW, Hook_ReplaceFileW);

    if (!Real_GetBasePath)
    {
        Real_GetBasePath = reinterpret_cast<PathFn>(DetourFindFunction(
            "Microsoft.Terminal.Settings.Model.dll",
            "?GetBaseSettingsPath@Model@Settings@Terminal@Microsoft@@YA?AVpath@filesystem@std@@XZ"));
    }

    if (!Real_GetReleasePath)
    {
        Real_GetReleasePath = reinterpret_cast<PathFn>(DetourFindFunction(
            "Microsoft.Terminal.Settings.Model.dll",
            "?GetReleaseSettingsPath@Model@Settings@Terminal@Microsoft@@YA?AVpath@filesystem@std@@XZ"));
    }

    if (!Real_NtCreateFile)
    {
        Real_NtCreateFile = reinterpret_cast<PFN_NtCreateFile>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    }
    if (Real_GetBasePath)
        DetourAttach(&(PVOID&)Real_GetBasePath, Hook_GetBasePath);
    if (Real_GetReleasePath)
        DetourAttach(&(PVOID&)Real_GetReleasePath, Hook_GetReleasePath);
    if (Real_NtCreateFile)
        DetourAttach(&(PVOID&)Real_NtCreateFile, Hook_NtCreateFile);

    DetourTransactionCommit();
}

static void DetachDetours()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_CreateFileW, Hook_CreateFileW);
    DetourDetach(&(PVOID&)Real_CreateFileMappingW, Hook_CreateFileMappingW);
    DetourAttach(&(PVOID&)Real_MoveFileExW, Hook_MoveFileExW);
    DetourAttach(&(PVOID&)Real_ReplaceFileW, Hook_ReplaceFileW);
    if (Real_GetBasePath)
        DetourDetach(&(PVOID&)Real_GetBasePath, Hook_GetBasePath);
    if (Real_GetReleasePath)
        DetourDetach(&(PVOID&)Real_GetReleasePath, Hook_GetReleasePath);
    if (Real_NtCreateFile)
        DetourDetach(&(PVOID&)Real_NtCreateFile, Hook_NtCreateFile);
    DetourTransactionCommit();
}

//--------------------------------------------------------------------------
// Mandatory export for Detours helper process
//--------------------------------------------------------------------------
//extern "C" __declspec(dllexport) void __cdecl DetourFinishHelperProcess() {}

//--------------------------------------------------------------------------
// DllMain
//--------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (DetourIsHelperProcess()) return TRUE;   // skip in helper

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        AttachDetours();
#ifndef NDEBUG
        if (IsDebuggerPresent())
            __debugbreak();          // pops the JIT dialog
#endif
        break;
    case DLL_PROCESS_DETACH:
        DetachDetours();
        break;
    }
    return TRUE;
}

