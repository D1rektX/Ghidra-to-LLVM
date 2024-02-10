# Ghidra-to-LLVM
This program lifts a compiled binary via Ghidra PCODE to LLVM IR. This fork of
[the original Ghidra-to-LLVM project](https://github.com/toor-de-force/Ghidra-to-LLVM)
intends to complete the missing PCODE operations, add support for the PCODE used
in the latest Ghidra version, add more tests for complex programs and functions,
and add complete support for architectures other than `x86_64`.

## Acknowledgements
A large number of the tests currently included with this repository were created
as part of the [Pharos framework](https://github.com/cmu-sei/pharos), developed by [Carnegie Mellon University's Software Engineering Institute](https://www.sei.cmu.edu/).

## Setup
This is a Python 3 program, and it also requires `make` to be installed to
compile the tests. If you just want to run the program and don't care about the
tests, you only need Python 3 and the modules `llvmlite` and `tomli` (and
`graphviz` to render control flow graphs).

### Required packages for Python 3
```shell
poetry install
```

### 1. Install Ghidra

Ghidra is required. 
THis project was tested with these ghidra versions:
- 10.4
- 11

To install ghidra simply download the corresponding version vom git:
https://github.com/NationalSecurityAgency/ghidra/releases

After downloading extract the files.

```shell
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip
unzip ghidra_11.0.1_PUBLIC_20240130.zip -d ../
rm ghidra_11.0.1_PUBLIC_20240130.zip

# your lifter/ghidra directory should look like this
tree -L 1
.
├── g2llvm.py
├── ghidra_11.0.1_PUBLIC
├── GhidraScripts
├── Ghidra-to-LLVM
├── README.md
├── tmp.py
└── xmltollvm.py
```

### 2. Edit config.json

Fill out the config.json file with the corresponding paths.
- base_dir
- ghidra_dir

### 3. Setup JDK

[Instructions](https://docs.oracle.com/en/java/javase/21/install/installation-jdk-linux-platforms.html#GUID-CF001E7F-7E0D-49D4-A158-9CF3ED4C247C)
```shell
# Download JDK:
curl -LO https://download.oracle.com/java/21/latest/jdk-21_linux-x64_bin.deb
# Install package:
sudo dpkg -i jdk-21_linux-x64_bin.deb
# check installation:
java -version

java version "21.0.2" 2024-01-16 LTS
Java(TM) SE Runtime Environment (build 21.0.2+13-LTS-58)
Java HotSpot(TM) 64-Bit Server VM (build 21.0.2+13-LTS-58, mixed mode, sharing)

# remove package file to save space:
rm jdk-21_linux-x64_bin.deb
```

## Usage
To run the the tool, simply run the g2llvm.py script. It takes a single mandatory argument, the target executable.

```shell
poetry run python g2llvm.py /path/to/binary

# Example
cd lifter/ghidra/Ghidra-to-LLVM/
binaryDir="/home/pascal/uni/iOSBinaryAnalysisLab/binary"
poetry run python g2llvm.py $binaryDir/BMI-Calculator
```

Optional arguments:

- '-out' emits intermediate files
- '-opt X' attempts to optimize the file. Valid options 0-3. (Currently only 0 works)
- '-cfg' saves a .PNG of the whole module CFG.

The full usage can be found in the help message below, which is also available
through `python3 g2llvm.py --help`.

```
python3 g2llvm.py [-h] [-out] [-opt OPT] [-cfg] input_file

positional arguments:
  input_file  the path of the binary file

options:
  -h, --help  show this help message and exit
  -out        emit intermediate files
  -opt OPT    select optimization level 0-3, default 0 (only 0 works)
  -cfg        if set, also creates a PNG of the CFG of all functions in the
              binary in the "graphs" folder
```


#### Mac Os
poetry might not be able to install llvm giving the following error when attempting an installation:

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




### Tests


If you want to run the tests, make sure you have `make` installed and the
version of `make` you're using supports the `-C` argument to run make from a
different folder. Then, run `python3 src/run_tests.py`.

```
usage: run_tests.py [-h] [--graph] [--clean] [--refresh] [--only TEST_OBJS]

Run tests for the Ghidra-To-LLVM project.

options:
  -h, --help        show this help message and exit
  --graph           Render all CFGs
  --clean           Completely rerun all tests
  --refresh         Rerun Ghidra analysis for all tests
  --only TEST_OBJS  Only run specified tests. If a path to a folder is specified, runs all tests in that folder.
```

Intermediate files will be created in subfolders of `tests`:
- `tests/graphs` will contain PNG renders of the control flow graph of all
  functions in all tests if the `--graph` argument is given.
- `tests/llvm` will contain a file containing the LLVM IR of a test program for
  each test.
- `tests/obj` will contain the compiled object files.
- `tests/xml` will contain the `.xml` files produced by the custom Ghidra script,
  containing the PCODE and some metadata about the program.

If you want to completely rerun all tests, you should provide the `--clean`
argument. If you want to rerun only the Ghidra analysis and PCODE translation,
you should provide the `--refresh` argument. Note that `--clean` implies `--refresh`.
If you want to only rerun the PCODE translation, no arguments need to be given.
If you just want to test a specific object file, you can specify that file using
the `--only` flag.


## Workings
This script works by loading the provided binary in Ghidra's headless analyzer
and running the automatic analysis to discover all functions. Then, it goes
through all recovered functions one-by-one, decompiles them and reads the
resulting "high" PCODE. This PCODE is then, along with some metadata about the
registers and memory locations that are used, saved to an `.xml` file.

The script then reads this `.xml` file, iterates through the functions and
translates every PCODE operation into one or multiple LLVM IR instructions and
combines them to create an LLVM module. Next, this module is optimised using
LLVM's optimisations and according to the provided optimisation level. Finally,
the optimised module is written to a `.ll` file, and the unoptimised module is
written to a `.llvmlite` file. Optionally, the control flow graphs of the
optimised module can be rendered as `.png` files and saved to the `graphs`
folder.

## Extra Scripts

There are some extra scripts located in the `src` folder.

- `GhidraToXML.java`: converts a binary through ghidra into XML
- `FindWarnings.java`: finds warnings that are in the ghidra listing and prints out an inspection of the code.

There are some extra scripts located in the `extra_scripts` folder.

- `HighFunction_Analysis.java`: Prints a readable version of the high function
  representation.
- `HighFunction2LLVM.java`: Makes an XML file of the the high function
  representation of all functions in a program. This might be a potential earlier
  version of the `src/GhidraToXML.java` file.

## TODO

- Implement lifting using Ghidra's HighFunction (will eventually be the default)





