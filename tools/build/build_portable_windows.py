"""Build Dawn MSBuild project inputs with a portable clang-cl and xwin SDK.

This is a local development build, not the authoritative v145 release-candidate
workflow. It reads only explicit project inputs and never enumerates game files,
captures the Git index, installs a DLL, or edits game settings.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

NS = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}


def quote(value: object) -> str:
    return '"' + str(value).replace('\\', '/').replace('"', '\\"') + '"'


def first_directory(*paths: Path) -> Path:
    for path in paths:
        if path.is_dir():
            return path
    raise RuntimeError("Missing toolchain directory: " + ", ".join(map(str, paths)))


def changed(path: Path, text: str) -> None:
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def build(args: argparse.Namespace) -> Path:
    repo = Path(__file__).resolve().parents[2]
    project = (repo / args.project).resolve()
    if not project.is_relative_to(repo / "Dawn") or project.suffix != ".vcxproj":
        raise RuntimeError("Select a Dawn .vcxproj inside this checkout.")
    root = Path(args.tool_root).resolve() if args.tool_root else repo / "build/native-tools"
    llvm = first_directory(root / "clang+llvm-23.1.5-x86_64-pc-windows-msvc/bin",
                           root / "clang+llvm-21.1.8-x86_64-pc-windows-msvc/bin", root / "llvm/bin")
    cmake = root / "pylibs/cmake/data/bin/cmake.exe"
    ninja = root / "pylibs/bin/ninja.exe"
    for item in (cmake, ninja, llvm / "clang-cl.exe", llvm / "lld-link.exe", llvm / "llvm-rc.exe", llvm / "llvm-mt.exe"):
        if not item.is_file():
            raise RuntimeError(f"Required portable build tool is missing: {item}")
    sdk = Path(args.sdk_root).resolve() if args.sdk_root else root / "sdk"
    crt_include = first_directory(sdk / "crt/include")
    sdk_include = first_directory(sdk / "sdk/include", sdk / "sdk/Include")
    if not (sdk_include / "um").is_dir():
        versions = sorted((p for p in sdk_include.iterdir() if p.is_dir()), key=lambda p: p.name)
        sdk_include = versions[-1]
    includes = [crt_include] + [first_directory(sdk_include / name) for name in ("ucrt", "shared", "um", "winrt")]
    crt_lib = first_directory(sdk / "crt/lib/x86_64", sdk / "crt/lib/x64")
    sdk_lib = first_directory(sdk / "sdk/lib", sdk / "sdk/Lib")
    if not (sdk_lib / "um").is_dir():
        sdk_lib = first_directory(sdk_lib / sdk_include.name)
    libs = [crt_lib] + [first_directory(sdk_lib / name / "x86_64", sdk_lib / name / "x64") for name in ("um", "ucrt")]
    work = repo / "build/portable" / project.stem / args.configuration
    generated = work / "project"
    generated.mkdir(parents=True, exist_ok=True)
    artifacts = work / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    flags = "-target x86_64-pc-windows-msvc " + " ".join('/imsvc"' + str(p).replace('\\', '/') + '"' for p in includes)
    link_flags = " ".join('/libpath:"' + str(p).replace('\\', '/') + '"' for p in libs)
    tc = ["set(CMAKE_SYSTEM_NAME Windows)", "set(CMAKE_SYSTEM_PROCESSOR x86_64)",
          "set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)"]
    for key, name in (("C", "clang-cl"), ("CXX", "clang-cl"), ("RC", "llvm-rc")):
        tc.append(f"set(CMAKE_{key}_COMPILER {quote(llvm / (name + '.exe'))})")
    for key, name in (("LINKER", "lld-link"), ("AR", "llvm-lib"), ("MT", "llvm-mt")):
        tc.append(f"set(CMAKE_{key} {quote(llvm / (name + '.exe'))})")
    tc += [f"set(CMAKE_C_FLAGS_INIT {quote(flags)})", f"set(CMAKE_CXX_FLAGS_INIT {quote(flags + ' /EHsc')})",
           f"set(CMAKE_EXE_LINKER_FLAGS_INIT {quote(link_flags)})", f"set(CMAKE_SHARED_LINKER_FLAGS_INIT {quote(link_flags)})"]
    changed(generated / "toolchain.cmake", "\n".join(tc) + "\n")
    main = ET.parse(project)
    kind = main.findtext(".//m:ConfigurationType", namespaces=NS)
    target = main.findtext(".//m:TargetName", namespaces=NS) or project.stem
    if "$" in target:
        target = project.stem
    source_files: list[Path] = []
    properties: list[str] = []
    visited: set[Path] = set()
    cm = ["cmake_minimum_required(VERSION 3.25)", "project(DawnPortable C CXX RC)",
          "set(CMAKE_CXX_STANDARD 20)", "set(CMAKE_CXX_STANDARD_REQUIRED ON)",
          'set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")']

    def read_project(path: Path) -> None:
        path = path.resolve()
        if path in visited:
            return
        visited.add(path)
        tree = ET.parse(path)
        for source_kind in ("ClCompile", "ResourceCompile", "MASM"):
            for row in tree.findall(f".//m:{source_kind}[@Include]", NS):
                excluded = row.find("m:ExcludedFromBuild", NS)
                if excluded is not None and excluded.text == "true" and not excluded.get("Condition"):
                    continue
                relative = row.attrib["Include"].replace("$(MSBuildThisFileDirectory)", "").replace('\\', '/')
                source = (path.parent / relative).resolve()
                if "$" in relative or not source.is_file():
                    raise RuntimeError(f"Unresolved explicit project input: {relative}")
                if source_kind == "MASM":
                    ml = llvm / "llvm-ml.exe"
                    if not ml.is_file():
                        raise RuntimeError("llvm-ml.exe is required for the project's MASM input.")
                    obj = generated / (source.stem + ".obj")
                    cm.append(f"add_custom_command(OUTPUT {quote(obj)} COMMAND {quote(ml)} -m64 /c {quote('/Fo' + str(obj))} {quote(source)} DEPENDS {quote(source)} VERBATIM)")
                    cm.append(f"set_source_files_properties({quote(obj)} PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)")
                    source_files.append(obj)
                    continue
                source_files.append(source)
                language = row.findtext("m:CompileAs", default="", namespaces=NS)
                if language:
                    properties.append(f"set_source_files_properties({quote(source)} PROPERTIES LANGUAGE {'CXX' if language == 'CompileAsCpp' else 'C'})")
                definitions = row.findtext("m:PreprocessorDefinitions", default="", namespaces=NS)
                definitions = [d for d in definitions.split(';') if d and not d.startswith('%(')]
                if definitions:
                    properties.append(f"set_property(SOURCE {quote(source)} APPEND PROPERTY COMPILE_DEFINITIONS {' '.join(map(quote, definitions))})")
                if row.findtext("m:WarningLevel", namespaces=NS) == "TurnOffAllWarnings":
                    properties.append(f"set_property(SOURCE {quote(source)} APPEND PROPERTY COMPILE_OPTIONS /w)")
        for item in tree.findall("m:Import", NS):
            relative = item.attrib["Project"]
            if "$(VCTargetsPath)" not in relative:
                read_project(path.parent / relative.replace('\\', '/'))

    read_project(project)
    if len(source_files) != len(set(source_files)):
        raise RuntimeError("Duplicate explicit project input.")
    if kind == "DynamicLibrary":
        declaration = f"add_library({target} SHARED"
        output = artifacts / (target + ".dll")
    elif kind == "Application":
        declaration = f"add_executable({target}"
        output = artifacts / (target + ".exe")
    else:
        raise RuntimeError(f"Unsupported ConfigurationType: {kind}")
    cm += [declaration + "\n" + "\n".join(quote(p) for p in source_files) + "\n)"] + properties
    dirs = [repo / "Dawn" / name for name in ("src", "resources", "vendor/lua/src", "vendor/detours", "vendor/imgui", "vendor/imgui/backends")]
    cm += [f"target_include_directories({target} PRIVATE {' '.join(map(quote, dirs + includes))})",
           f'target_compile_definitions({target} PRIVATE WIN32 _WINDOWS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS _CRT_USE_BUILTIN_OFFSETOF IMGUI_USER_CONFIG="core/ui/imgui_user_config.h")',
           f'target_compile_options({target} PRIVATE /utf-8 /Gy /Oi $<$<COMPILE_LANGUAGE:CXX>:/EHsc>)',
           f'target_link_options({target} PRIVATE /DEBUG /PDBALTPATH:{target}.pdb $<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)',
           f"set_target_properties({target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY {quote(artifacts)})"]
    dependencies = main.findtext(".//m:Link/m:AdditionalDependencies", namespaces=NS) or ""
    dependencies = [d for d in dependencies.split(';') if d and not d.startswith('%(')]
    if dependencies:
        cm.append(f"target_link_libraries({target} PRIVATE {' '.join(map(quote, dependencies))})")
    stack_size = main.findtext(".//m:Link/m:StackReserveSize", namespaces=NS)
    if stack_size:
        cm.append(f"target_link_options({target} PRIVATE /STACK:{stack_size})")
    changed(generated / "CMakeLists.txt", "\n".join(cm) + "\n")
    env = os.environ.copy()
    env["PATH"] = str(llvm) + os.pathsep + env.get("PATH", "")
    print(f"Configuring {project.name}: {len(source_files)} explicit inputs. Game files are excluded.", flush=True)
    # CMake does not reread the compiler from a changed toolchain in an existing
    # cache. Refresh that cache when the selected compiler changes.
    cache = work / "cmake/CMakeCache.txt"
    stamp = work / "configured-toolchain.txt"
    toolchain_text = (generated / "toolchain.cmake").read_text(encoding="utf-8")
    fresh = ["--fresh"] if cache.is_file() and (
        not stamp.is_file() or stamp.read_text(encoding="utf-8") != toolchain_text) else []
    subprocess.run([str(cmake), *fresh, "-S", str(generated), "-B", str(work / "cmake"), "-G", "Ninja",
                    f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_TOOLCHAIN_FILE={generated / 'toolchain.cmake'}",
                    f"-DCMAKE_BUILD_TYPE={args.configuration}"], env=env, check=True)
    changed(stamp, toolchain_text)
    if not args.configure_only:
        subprocess.run([str(cmake), "--build", str(work / "cmake"), "--parallel", str(args.jobs)], env=env, check=True)
        if not output.is_file():
            raise RuntimeError(f"The build did not produce {output}")
        compiler_version = subprocess.check_output([str(llvm / "clang-cl.exe"), "--version"], text=True).splitlines()[0]
        (work / "latest-build.json").write_text(json.dumps({"artifact": str(output), "project": str(project), "compiler": compiler_version}, indent=2) + "\n", encoding="utf-8")
        if args.run:
            if kind != "Application":
                raise RuntimeError("--run is only supported for a test application project.")
            subprocess.run([str(output)], check=True, timeout=60)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="Dawn/Dawn.vcxproj")
    parser.add_argument("--configuration", choices=("Release", "Debug"), default="Release")
    parser.add_argument("--tool-root")
    parser.add_argument("--sdk-root")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--configure-only", action="store_true")
    parser.add_argument("--run", action="store_true", help="run the produced unit-test application, never a game")
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 8:
        parser.error("--jobs must be between 1 and 8")
    try:
        print(build(args))
        return 0
    except (RuntimeError, subprocess.SubprocessError, OSError, ET.ParseError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
