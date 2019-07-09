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
def hasNoSyscalls(data, file):
    if len(data["syscalls"]) == 0:
        err(file, "has no syscalls")
        return True
    return False


def hasSyscalls(data, file):
    if len(data["syscalls"]) != 0:
        err(file, "has syscalls")
        return True
    return False


def errnoUnchecked(data, file):
    if not data["syscalls"][0]["errno_checked"]:
        err(file, "errno unchecked")
        return True
    return False


def errnoChecked(data, file):
    if data["syscalls"][0]["errno_checked"]:
        err(file, "errno checked")
        return True
    return False


def hasTainted(data, file):
    if len(data["tainted"]) != 0:
        err(file, "has tainted")
        return True
    return False


def hasNoTainted(data, file):
    if len(data["tainted"]) == 0:
        err(file, "has no tainted")
        return True
    return False


def taintedSyscall(data, file):
    if data["tainted"][0]["syscall"]:
        err(file, "marked as syscall")
        return True
    return False


def taintedNotSyscall(data, file):
    if not data["tainted"][0]["syscall"]:
        err(file, "not marked as syscall")
        return True
    return False


def taintedExternal(data, file):
    if data["tainted"][0]["external_function"]:
        err(file, "marked as external")
        return True
    return False


def taintedNotExternal(data, file):
    if not data["tainted"][0]["external_function"]:
        err(file, "not marked as external")
        return True
    return False


def taintedVariadic(data, file):
    if data["tainted"][0]["variadic_internal"]:
        err(file, "marked as variadic")
        return True
    return False


def taintedNotVariadic(data, file):
    if not data["tainted"][0]["variadic_internal"]:
        err(file, "not marked as variadic")
        return True
    return False


tests = {
    "retValueChecked": [hasSyscalls, hasTainted],
    "errnoAndRetValueChecked": [hasSyscalls, hasTainted],
    "retValueUnchecked": [hasNoSyscalls, errnoChecked],
    "errnoChecked": [hasNoSyscalls, errnoUnchecked],
    "taintedSyscall": [hasNoTainted, taintedNotSyscall, taintedExternal, taintedVariadic],
    "taintedSyscallThroughFunc": [
        hasNoTainted,
        taintedNotSyscall,
        taintedExternal,
        taintedVariadic,
    ],
    "taintedExternal": [hasNoTainted, taintedSyscall, taintedNotExternal, taintedVariadic],
    "taintedExternalThroughFunc": [
        hasNoTainted,
        taintedSyscall,
        taintedNotExternal,
        taintedVariadic,
    ],
    "taintedVariadic": [hasNoTainted, taintedSyscall, taintedExternal, taintedNotVariadic],
    "taintedVariadicThroughFunc": [
        hasNoTainted,
        taintedSyscall,
        taintedExternal,
        taintedNotVariadic,
    ],
}

# Do check on pass output:
def checkPassOutput(filestem):
    with open(filestem + ".json") as f:
        data = json.loads(f.read())
    if filestem in tests:
        for test in tests[filestem]:
            if test(data, filestem):
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
                    filestem + ".json",
                    "-krf-json",
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
