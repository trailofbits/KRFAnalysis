import os
import subprocess
import sys
from shutil import copy
import tarfile
import json

files_set = set()
curdir = os.getcwd()

# Handle an individual file
def analyze(exe, core_file):
    global files_set
    pygdb = curdir + "/gdb.py"
    lines = (
        subprocess.check_output(
            ["gdb", exe, core_file, "-batch", "-ex", "source " + pygdb, "--quiet"]
        )
        .decode("utf-8")
        .split("\n")[4:]
    )

    files = {}
    for l in lines:
        a = l.split()
        if len(a) != 2:
            continue
        addr = a[0]
        file = a[1]
        files_set.add(file)
        file = file.split("/")[-1]
        if file not in files:
            files[file] = []
        files[file].append(addr)

    return files


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:", sys.argv[0], "<executable> <core_file> <core_file2> ...")
        sys.exit(1)

    # Writes to this directory: `pwd`/krfanalysis
    os.makedirs("krfanalysis/binaries")
    os.mkdir("krfanalysis/cores")

    # Extract information from the core dump
    # And print to distinct files
    for core in sys.argv[2:]:
        gdbdata = analyze(sys.argv[1], core)
        with open("krfanalysis/cores/" + core.split("/")[-1] + ".json", "w") as f:
            f.write(json.dumps(gdbdata))

    # Copy binaries:
    for f in files_set:
        copy(f, "krfanalysis/binaries/" + f.split("/")[-1])

    # Make tarball
    with tarfile.open("krfanalysis.tar.gz", "w:gz") as tar:
        tar.add("krfanalysis")
    print("Produced tar archive krfanalysis.tar.gz in", curdir)
