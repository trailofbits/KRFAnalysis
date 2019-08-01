import json
import tarfile
import sys
import os
import krf


def analyze_crash(core):
    print("Analyzing crash", core)
    with open(core) as f:
        crash_data = json.loads(f.read())
    taintedArgs = None
    frameZero = True
    for file in crash_data:
        if taintedArgs is not None and len(taintedArgs) == 0:
            break  # All paths explored
        data = [int(x, 16) for x in file["stack"]]
        print("  Running on file", file["file"])
        taintedArgs = binaries[file["file"]].run(
            *data, taintedArgs=taintedArgs, frameZero=frameZero
        )
        frameZero = False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "<path/to/krfanalysis-{binary}-{timestamp}.tar.gz>")
        sys.exit(1)
    with tarfile.open(sys.argv[1], "r:gz") as tar:
        tar.extractall()
        dirname = tar.getnames()[0]

    binaries = {}
    for filename in os.listdir(dirname + "/binaries"):
        print("Analyzing binary", filename)
        binaries[filename] = krf.KRFAnalysis(dirname + "/binaries/" + filename)
    print("Done")
    for filename in os.listdir(dirname + "/cores"):
        analyze_crash(dirname + "/cores/" + filename)
