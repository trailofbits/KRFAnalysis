# Binary Ninja KRF Analysis
This folder contains three distinct sections of python scripts.

## Extraction set
First, a set to be run in the environment where the fuzzing occured in order to extract the binaries and coredumps and put them in a tarball.  
These are `main.py` and `gdb.py`. They must be in the same directory when `main.py` is run. 

### Use
```bash
# Variable number of coredumps
python3 main.py path/to/executable path/to/coredump1 [path/to/coredump2] ...
```

This will internally execute `gdb` on the coredump using `gdb.py` to extract the neccessary data, then create a tarball named `krfanalysis.tar.gz`.
The directory `krfanalysis` must not exist before the tool is run, or it will fail.

## Analysis set
Second, an analysis set is run on a computer with binary ninja installed and the `binaryninja` python module in the python path.
This set includes `krf.py` and `analyze.py`. They must be in the same directory when `analyze.py` is run.

### Use
```bash
python3 analyze.py path/to/krfanalysis.tar.gz
```

It uses the class defined in `krf.py` in order to do 'reverse taint analysis' on data in the tarball.
It will unpack the tarball into whatever directory it is executed from.

### Binary Ninja API
Binary Ninja can be added to the python path using `export PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python` in your shell profile. Requires headless mode.

## Binary Ninja Plugin
The binary ninja plugin is located in the `taint_plugin` subdirectory, and contains its own documentation in that directory.
