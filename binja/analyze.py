import json
import tarfile
import sys
import os
import krf


def analyzeCrash(core):
    print("Analyzing crash", core)
    with open(core) as f:
        crash_data = json.loads(f.read())
    taintedArgs = None
    for file in crash_data:
        data = [int(x, 16) for x in crash_data[file]]
        print("  Running on file", file)
        taintedArgs = binaries[file].run(*data, taintedArgs=taintedArgs)


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
        analyzeCrash("krfanalysis/cores/" + filename)
