# KRFAnalysis
[![Build Status](https://travis-ci.com/trailofbits/KRFAnalysis.svg?branch=master)](https://travis-ci.com/trailofbits/KRFAnalysis)


KRFAnalysis contains an LLVM pass and related scipts that test potential vulnerability to the tool [KRF](https://github.com/trailofbits/krf)
by checking whether the result of a syscall is checked for errors.

It runs through `opt` on LLVM IR files (`.bc`)

## What?

[An LLVM Pass](http://llvm.org/docs/WritingAnLLVMPass.html#introduction-what-is-a-pass) runs on the LLVM IR and can do analysis, transformations, and optimizations.
In our case, we attempt to analyze when the results of syscalls are used.

LLVM Passes have several benefits:
 - Works on any platform (since IR is platform agnostic)
 - Works with Go, C, C++, and Rust
 - Extremely rich capability for static analysis  
 
But also some downsides:
 - Need to have the IR bytecode, which effectively means you must have the source code
 - Only works with Go, C, C++, and Rust
 - LLVM has a somewhat steep learning curve
 
 ## Setup
 ### Docker
 Docker is recommended, since it makes the setup and build process easier.
```bash
git clone https://github.com/trailofbits/KRFAnalysis && cd KRFAnalysis
docker build . -t krf
docker run -it krf
```
### Not docker
First, you needs to install the dependencies including `cmake`, `llvm`, `llvm-dev`, and `python3.7`  
Then, run the following commands to clone and build the repository, which will generate a `libLLVMKRF.so` file.
```bash
git clone https://github.com/trailofbits/KRFAnalysis && cd KRFAnalysis
mkdir build && cd build
cmake ../
cmake --build .
```
## Usage
The LLVM pass runs through `opt` (which may be `opt-6.0` or whatever version of llvm you have).

To analyze the file `file.bc` and output human readable text into the file `output.txt`, you would run:
```bash
opt -load path/to/libLLVMKRF.so -KRF -disable-output -krf-output output.txt file.bc
```

To analyze the file `file.bc` and output JSON into the file `pass_output.json`, you would run:
```bash
opt -load path/to/libLLVMKRF.so -KRF -disable-output -krf-output pass_output.json -krf-json file.bc
```

If `-krf-output` is not specified, the output will default to `krfpass.out`

After creating JSON output, it can be further analyzed and triaged by the triage script:
```bash
python3 triage/triage.py pass_output.json # Outputs human readable triaged information
python3 triage/triage.py -json pass_output.json # Outputs JSON
```
