// WTLocalStateHook.cpp — Windows Terminal LocalState redirection hook
// Build: cl /std:c++17 /MD /O2 /LD WTLocalStateHook.cpp detours.lib shlwapi.lib
// Requires: Detours 4.x public headers & libs
// Usage: 1) set env var WT_REDIRECT_LOCALSTATE to your desired profile root
//        2) DetourCreateProcessWithDllExW(..., L"...\\WTLocalStateHook.dll", …)

#include <windows.h>
#include <shlobj.h>          // SHGetFolderPathW
#include <winternl.h>        // NtCreateFile, UNICODE_STRING
#include <string>
#include <vector>
#include <filesystem>
#include <condition_variable>
#include "detours.h"

//--------------------------------------------------------------------------
// Globals
//--------------------------------------------------------------------------
static std::wstring g_defaultPrefix;   // canonical LocalState path
static std::wstring g_newPrefix;       // replacement root (profile)
static std::once_flag g_prefixInit;
static std::wstring g_cachedName;   // e.g. "Windows Terminal Admin abcd1234…"
static std::once_flag g_nameInit;

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

    static HANDLE(WINAPI* Real_CreateMutexW)(
            LPSECURITY_ATTRIBUTES,
            BOOL,
            LPCWSTR)
        = CreateMutexW;

    static HWND(WINAPI* Real_FindWindowW)(
            LPCWSTR,
            LPCWSTR)
        = FindWindowW;
}

// ---------------------------------------------------------------------------
//  Hash helper: same 64-bit / 32-bit FNV-1a that til::hash uses
// ---------------------------------------------------------------------------
#ifdef _WIN64
static uint64_t fnv1a64(std::wstring_view s)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (wchar_t ch : s)
        h = (h ^ static_cast<uint64_t>(ch)) * 0x100000001b3ull;
    return h;
}
#else
static uint32_t fnv1a32(std::wstring_view s)
{
    uint32_t h = 0x811c9dc5ul;
    for (wchar_t ch : s)
        h = (h ^ static_cast<uint32_t>(ch)) * 0x01000193ul;
    return h;
}
#endif

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
    //if (!g_defaultPrefix.empty()) return;          // already cached

    // 1. default LocalState — build it at runtime so the hook works for any user
    wchar_t defaultPrefixData[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"WT_DEFAULT_LOCALSTATE", defaultPrefixData, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        g_defaultPrefix.assign(defaultPrefixData, len);

    // 2. new LocalState root — read once from env var
    wchar_t newPrefixData[MAX_PATH];
    len = GetEnvironmentVariableW(L"WT_REDIRECT_LOCALSTATE", newPrefixData, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        g_newPrefix.assign(newPrefixData, len);
}

// ---------------------------------------------------------------------------
//  Compute+cache new name (runs exactly once)
// ---------------------------------------------------------------------------
static void initWindowClassRewrite(LPCWSTR original)
{
    std::wstring env = [] {
        wchar_t buf[MAX_PATH]; DWORD n = GetEnvironmentVariableW(
            L"WT_REDIRECT_LOCALSTATE", buf, MAX_PATH);
        return (n && n < MAX_PATH) ? std::wstring(buf, n) : std::wstring();
        }();
    if (env.empty())
        return;                         // nothing to do

#ifdef _WIN64
    uint64_t h64 = fnv1a64(env);
    constexpr wchar_t fmt[] = L" %016llx";
    wchar_t hashPart[18];               // space + 16 hex + NUL
    swprintf(hashPart, 18, fmt, h64);
#else
    uint64_t h32 = fnv1a32(env);
    constexpr wchar_t fmt[] = L" %08x";
    wchar_t hashPart[10];
    swprintf(hashPart, 10, fmt, static_cast<uint32_t>(h32));
#endif

    g_cachedName.assign(original);
    g_cachedName.append(hashPart);
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
    std::call_once(g_prefixInit, InitPrefixes);

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
    std::call_once(g_prefixInit, InitPrefixes);

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
    std::call_once(g_prefixInit, InitPrefixes);

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
    std::call_once(g_prefixInit, InitPrefixes);

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
    std::call_once(g_prefixInit, InitPrefixes);

    std::wstring src = replaced ? RewritePath(replaced) : std::wstring();
    std::wstring newf = replaceWith ? RewritePath(replaceWith) : std::wstring();

    return Real_ReplaceFileW(src.empty() ? replaced : src.c_str(),
        newf.empty() ? replaceWith : newf.c_str(),
        backup,
        flags,
        nullptr, nullptr);
}

static HANDLE WINAPI Hook_CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL own,
    LPCWSTR name)
{
    std::call_once(g_nameInit, initWindowClassRewrite, name);

    LPCWSTR use = g_cachedName.empty() ? name : g_cachedName.c_str();
    return Real_CreateMutexW(sa, own, use);
}

static HWND WINAPI Hook_FindWindowW(LPCWSTR cls, LPCWSTR title)
{
    std::call_once(g_nameInit, initWindowClassRewrite, cls);

    LPCWSTR use = (!g_cachedName.empty() && cls &&
        g_cachedName.rfind(cls, 0) == 0)
        ? g_cachedName.c_str()
        : cls;
    return Real_FindWindowW(use, title);
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
    DetourAttach(&(PVOID&)Real_CreateMutexW, Hook_CreateMutexW);
    DetourAttach(&(PVOID&)Real_FindWindowW, Hook_FindWindowW);

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
    DetourDetach(&(PVOID&)Real_MoveFileExW, Hook_MoveFileExW);
    DetourDetach(&(PVOID&)Real_ReplaceFileW, Hook_ReplaceFileW);
    DetourDetach(&(PVOID&)Real_CreateMutexW, Hook_CreateMutexW);
    DetourDetach(&(PVOID&)Real_FindWindowW, Hook_FindWindowW);
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

