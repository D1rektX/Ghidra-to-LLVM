# Ghidra-to-LLVM
This tool lifts a a compiled binary to LLVM.

###### Special thanks to the my advisor Arie Gurfinkel and the CMU Pharos team (https://github.com/cmu-sei/pharos). Tests taken from their repository.

## Required packages for Python 3
```shell
poetry install
poetry run python g2llvm.py /path/to/binary
poetry run python g2llvm.py ../../../binary/BMI-Calculator
```
### Mac Os
poetry might not be able to install llvm giving the following error when attempting an install:

```shell
• Installing llvmlite (0.41.1): Failed

  ChefBuildError

  Backend subprocess exited when trying to invoke build_wheel
  
  running bdist_wheel
  /private/var/folders/1z/lb5ryz0j0918kcvtjhc1_krc0000gn/T/tmp2ilxjqd0/.venv/bin/python /private/var/folders/1z/lb5ryz0j0918kcvtjhc1_krc0000gn/T/tmput0ao1q5/llvmlite-0.41.1/ffi/build.py
  LLVM version... Traceback (most recent call last):
...
Note: This error originates from the build backend, and is likely not a problem with poetry but with llvmlite (0.41.1) not supporting PEP 517 builds. You can verify this by running 'pip wheel --no-cache-dir --use-pep517 "llvmlite (==0.41.1)"'.
```

In this case simply use pip to install the dependencies and run via python

```bash
# install dependencies
pip3 install graphviz llvmlite tomli

# run lifter
python g2llvm.py ../../../binary/BMI-Calculator
```

## Installation Instructions (Linux Only)

### 1. Install Ghidra

https://github.com/NationalSecurityAgency/ghidra/releases

- Extract the JDK: tar xvf <JDK distribution .tar.gz>
- Open ~/.bashrc with an editor of your choice. For example:vi ~/.bashrc
- At the very end of the file, add the JDK bin directory to the PATH variable:export PATH=<path of extracted JDK dir>/bin:$PATH
- Save file
- Restart any open terminal windows for changes to take effect
  
### 2. Edit g2llvm.py

The script requires you to provide the location of two files (absolute path):
- ghidra_headless_loc = "/PATH/TO/ghidra_9.1.1_PUBLIC/support/analyzeHeadless"
- prj_dir = "/PATH/TO/GhidraProjects/"

## Usage
To run the the tool, simply run the g2llvm.py script. It takes a single mandatory argument, the target executable.

Optional arguments:

- '-out' emits intermediate files
- '-opt X' attempts to optimize the file. Valid options 0-3. (Currently only 0 works)
- '-cfg' saves a .PNG of the whole module CFG.


###### Extra Scripts

- HighFunction_Analysis.java: Prints readable version of high function representation
- HighFunction2LLVM.java: Makes an XML file if the high function representation

###### TODO

- Implement lifting using Ghidra's HighFunction (will eventually be the default)




# Instructions

## POPCOUNT
XML:<name>POPCOUNT</name><input_0 size="8" storage="unique">u_13400:8</input_0></pcode_6><pcode_7><output size="1" storage="unique">u_13500:1</output> 

INPUT: %"36" = and i64 %"35



