#!/usr/bin/python3
import json
from sys import exit
from os import listdir
from os.path import isfile, join
from subprocess import run as exec

# Output functions:
def err(*args):
    print("[x]", *args)


def succ(*args):
    print("[+]", *args)


# Set of tests:
def hasNoSyscalls(krf_data, toctou_data, file):
    if len(krf_data["syscalls"]) == 0:
        err(file, "has no syscalls")
        return True
    return False


def hasSyscalls(krf_data, toctou_data, file):
    if len(krf_data["syscalls"]) != 0:
        err(file, "has syscalls")
        return True
    return False


def errnoUnchecked(krf_data, toctou_data, file):
    if not krf_data["syscalls"][0]["errno_checked"]:
        err(file, "errno unchecked")
        return True
    return False


def errnoChecked(krf_data, toctou_data, file):
    if krf_data["syscalls"][0]["errno_checked"]:
        err(file, "errno checked")
        return True
    return False


def hasTainted(krf_data, toctou_data, file):
    if len(krf_data["tainted"]) != 0:
        err(file, "has tainted")
        return True
    return False


def hasNoTainted(krf_data, toctou_data, file):
    if len(krf_data["tainted"]) == 0:
        err(file, "has no tainted")
        return True
    return False


def taintedSyscall(krf_data, toctou_data, file):
    if krf_data["tainted"][0]["syscall"]:
        err(file, "marked as syscall")
        return True
    return False


def taintedNotSyscall(krf_data, toctou_data, file):
    if not krf_data["tainted"][0]["syscall"]:
        err(file, "not marked as syscall")
        return True
    return False


def taintedExternal(krf_data, toctou_data, file):
    if krf_data["tainted"][0]["external_function"]:
        err(file, "marked as external")
        return True
    return False


def taintedNotExternal(krf_data, toctou_data, file):
    if not krf_data["tainted"][0]["external_function"]:
        err(file, "not marked as external")
        return True
    return False


def taintedVariadic(krf_data, toctou_data, file):
    if krf_data["tainted"][0]["variadic_internal"]:
        err(file, "marked as variadic")
        return True
    return False


def taintedNotVariadic(krf_data, toctou_data, file):
    if not krf_data["tainted"][0]["variadic_internal"]:
        err(file, "not marked as variadic")
        return True
    return False


def hasToctou(krf_data, toctou_data, file):
    if len(toctou_data) != 0:
        err(file, "has toc/tou information")
        return True
    return False


def hasNoToctou(krf_data, toctou_data, file):
    if len(toctou_data) == 0:
        err(file, "has no toc/tou information")
        return True
    return False


def isNotAccessOpen(krf_data, toctou_data, file):
    if toctou_data[0]["type"] != "access/open":
        err(file, "not access/open, instead", toctou_data[0]["type"])
        return True
    return False


def isNotTmpnamOpen(krf_data, toctou_data, file):
    if toctou_data[0]["type"] != "tmpnam/open":
        err(file, "not tmpnam/open, instead", toctou_data[0]["type"])
        return True
    return False


tests = {
    "retValueChecked": [hasSyscalls, hasTainted, hasToctou],
    "errnoAndRetValueChecked": [hasSyscalls, hasTainted, hasToctou],
    "retValueUnchecked": [hasNoSyscalls, errnoChecked, hasToctou],
    "errnoChecked": [hasNoSyscalls, errnoUnchecked, hasToctou],
    "taintedSyscall": [
        hasNoTainted,
        taintedNotSyscall,
        taintedExternal,
        taintedVariadic,
        hasToctou,
    ],
    "taintedSyscallThroughFunc": [
        hasNoTainted,
        taintedNotSyscall,
        taintedExternal,
        taintedVariadic,
        hasToctou,
    ],
    "taintedExternal": [
        hasNoTainted,
        taintedSyscall,
        taintedNotExternal,
        taintedVariadic,
        hasToctou,
    ],
    "taintedExternalThroughFunc": [
        hasNoTainted,
        taintedSyscall,
        taintedNotExternal,
        taintedVariadic,
        hasToctou,
    ],
    "taintedVariadic": [
        hasNoTainted,
        taintedSyscall,
        taintedExternal,
        taintedNotVariadic,
        hasToctou,
    ],
    "taintedVariadicThroughFunc": [
        hasNoTainted,
        taintedSyscall,
        taintedExternal,
        taintedNotVariadic,
        hasToctou,
    ],
    "accessOpen": [hasSyscalls, hasTainted, hasNoToctou, isNotAccessOpen],
    "tmpnamOpen": [hasSyscalls, hasTainted, hasNoToctou, isNotTmpnamOpen],
}

# Do check on pass output:
def checkPassOutput(filestem):
    with open(filestem + "-krf.json") as f:
        krf_data = json.loads(f.read())
    with open(filestem + "-toctou.json") as f:
        toctou_data = json.loads(f.read())
    if filestem in tests:
        for test in tests[filestem]:
            if test(krf_data, toctou_data, filestem):
                return True
    else:
        err("Unknown test:", filestem)
        return True
    succ(filestem, "passed tests")
    return False


if __name__ == "__main__":
    # Get file list
    onlyfiles = [f for f in listdir(".") if isfile(join(".", f)) and (f[-4:] == ".cpp")]

    # Compile & run pass
    failed = False
    for f in onlyfiles:
        filestem = f[:-4]
        if exec(["clang-7", "-O0", "-emit-llvm", "-c", f]).returncode != 0:
            print("[x]", filestem, "Compilation failed")
            continue
        if (
            exec(
                [
                    "opt-8",
                    "-load",
                    "../build/libLLVMKRF.so",
                    "-KRF",
                    "-krf-output",
                    filestem + "-krf.json",
                    "-krf-json",
                    "-toctou",
                    "-toctou-output",
                    filestem + "-toctou.json",
                    "-toctou-json",
                    "-disable-output",
                    filestem + ".bc",
                ]
            ).returncode
            != 0
        ):
            print("[x]", filesteam, "Pass failed")
            continue
        failed = checkPassOutput(filestem) or failed

    # Final output
    if failed:
        print("Test failed.")
        exit(1)
    else:
        print("All tests passed!")
