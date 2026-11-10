# Portable Windows development build

`build_portable_windows.py` builds the explicit inputs from `Dawn/Dawn.vcxproj`
or a `Dawn/unit/*.vcxproj` with clang-cl, LLD, CMake, Ninja, and an xwin SDK.
It never scans the downloaded game, captures the Git index, installs a DLL, or
changes player settings. Its generated project and outputs stay in
`build/portable/<project>/<configuration>/`.

This is a local development build. Use `build_release_candidate.ps1` and the
required Visual Studio v145 toolset for the authoritative release workflow.

## Tool layout

The default tool directory is the ignored `build/native-tools/`:

```text
build/native-tools/
  clang+llvm-23.1.5-x86_64-pc-windows-msvc/bin/
  xwin-0.10.0-x86_64-pc-windows-msvc/xwin.exe
  pylibs/cmake/data/bin/cmake.exe
  pylibs/bin/ninja.exe
  sdk/
    crt/include/
    crt/lib/x86_64/
    sdk/include/{ucrt,shared,um,winrt}/
    sdk/lib/{ucrt,um}/x86_64/
```

The official [LLVM 23.1.5 release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.5)
provides the portable Windows x64 archive. The archive used here has SHA-256
`b2be33385ddc86e83511417a060de927ae8b09d1f3017cc3cdce5c73cd5029d7`.
Verify it before extracting or running tools. The official
[xwin 0.10.0 release](https://github.com/Jake-Shadle/xwin/releases/tag/0.10.0)
provides its Windows binary and a matching `.sha256` file.

The manifest-18 CRT used here requires Clang 22 or newer. Do not disable its
compiler compatibility check. When the selected toolchain changes, the build
script refreshes CMake's cache so it cannot silently reuse an older compiler.

Install CMake and Ninja into this tool directory, without changing the system
Python environment:

```powershell
python -m pip install --target build/native-tools/pylibs cmake==4.4.4 ninja==1.13.2
```

Microsoft's SDK license must be accepted by the user before preparing the SDK.
After that acceptance, xwin can prepare only the x64 desktop SDK and CRT:

```powershell
.\build\native-tools\xwin-0.10.0-x86_64-pc-windows-msvc\xwin.exe `
  --accept-license --arch x86_64 --variant desktop --manifest-version 18 `
  --cache-dir build/native-tools/sdk-downloads splat `
  --disable-symlinks --output build/native-tools/sdk --include-debug-libs
```

This downloads development headers and libraries from Microsoft's distribution
service. It does not install Visual Studio or require registry changes.

## Build and run tests

From the repository root, using an installed Python 3.11 or newer:

```powershell
python tools/build/build_portable_windows.py --project Dawn/Dawn.vcxproj
python tools/build/build_portable_windows.py --project Dawn/unit/shared_membership_tests.vcxproj --run
```

`--run` is supported only for a project that builds an application. The script
runs the newly built unit-test EXE; it never launches `destiny2.exe`.
`--configuration Debug` selects the static Debug CRT when it has been prepared.
`--jobs 2` bounds simultaneous compiler processes. `--configure-only` generates
the CMake project without compiling.

The generator follows the project's explicit C/C++, resource, MASM and imported
source lists. It supports the project conventions used by this checkout; it is
not a general replacement for MSBuild's conditional property evaluation. It
does not reproduce the release workflow's MSVC warning policy or provenance
checks. A successful portable build is a development check, not a release
candidate certification.
