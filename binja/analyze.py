import krf
import json
import tarfile
import sys
import os


def analyzeCrash(core):
    print("Analyzing crash", core)
    with open(core, "r") as f:
        crash_data = json.loads(f.read())
    for file in crash_data:
        print("  Running on file", file)
        binaries[file].run(crash_data[file])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "<path/to/krfanalysis.tar.gz>")
        sys.exit(1)
    with tarfile.open(sys.argv[1], "r:gz") as tar:
        tar.extractall()

    binaries = {}
    for filename in os.listdir("krfanalysis/binaries"):
        print("Analyzing binary", filename)
        binaries[filename] = krf.KRFAnalysis("krfanalysis/binaries/" + filename)
    print("Done")
    for filename in os.listdir("krfanalysis/cores"):
        analyzeCrash(filename)
