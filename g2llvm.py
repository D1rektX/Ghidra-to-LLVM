#!/usr/bin/python3

import importlib
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

xmltollvm = importlib.import_module('src.xmltollvm')
opt_verify = importlib.import_module('src.lifting-opt-verify')

def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)

def construct_paths(config, base_dir):
    paths = {
        "ghidra_dir": os.path.join(base_dir, config["directories"]["ghidra_dir"]),
        "ghidra_headless": os.path.join(base_dir, config["directories"]["headless_dir"][platform.system().lower()]),
        "project_dir": os.path.join(base_dir, config["directories"]["project_dir"]),
        "script_dir": os.path.join(base_dir, config["directories"]["script_dir"][platform.system().lower()]),
        "xml_tmp_file": os.path.join(base_dir, config["directories"]["xml_tmp_file"][platform.system().lower()]),
        "output_dir": os.path.join(base_dir, config["directories"]["output_dir"])
    }
    return paths

# windows
base_dir_win = "C:\\Users\\pasca\\Documents\\Code\\Uni\\iOSBinaryAnalysisLab\\"
ghidra_headless_loc_win = base_dir_win + "lifter\\ghidra\\ghidra_10.4_PUBLIC\\support\\analyzeHeadless.bat"
prj_dir_win = base_dir_win + "lifter\\ghidra"
script_dir_win = "C:\\Users\\pasca\\Documents\\Code\\Uni\\iOSBinaryAnalysisLab\\lifter\\ghidra\\Ghidra-to-LLVM\\src"
xml_tmp_file_win = "C:\\Users\\pasca\\Documents\\Code\\Uni\\iOSBinaryAnalysisLab\\lifter\\ghidra\\GhidraScripts\\output.xml"
output_dir_win = base_dir_win + "results\\"
# linux

base_dir_lin = "/home/pascal/Documents/Uni/iOSBinaryAnalysisLab/"
ghidra_headless_loc_lin = base_dir_lin + "lifter/ghidra/ghidra_10.4_PUBLIC/support/analyzeHeadless"
prj_dir_lin = base_dir_lin + "lifter/ghidra"
script_dir_lin = base_dir_lin + "lifter/ghidra/Ghidra-to-LLVM/src"
xml_tmp_file_lin = "/tmp/output.xml"
output_dir_lin = base_dir_lin + "results/"

# These need to change in your local installation
ghidra_headless_loc = ghidra_headless_loc_win
prj_dir = prj_dir_win
script_dir = script_dir_win
xml_tmp_file = xml_tmp_file_win
output_dir = output_dir_win

# chose if ghidra should run
recompile = True

# These shouldn't need to be changed
prj_name = "lifting"
xml_script = "GhidraToXML.java"

# Argument parsing
parser = argparse.ArgumentParser(description = 'This script lifts a binary from executable to LLVM IR.')
parser.add_argument('input_file', action='store')
parser.add_argument('-out', action='store_true', help='emit intermediate files', default=False, dest='out')
parser.add_argument('-opt', action='store', help='select optimization level 0-3', default=None, dest='opt')
parser.add_argument('-o', action='store', help='LLVM IR output path', default=None, dest='output')
parser.add_argument('-cfg', action='store_true', help='emit cfg', default=False, dest='cfg')
results = parser.parse_args()

# Load configuration
config = load_config()

# Determine base directory based on the current OS
current_os = platform.system().lower()
base_dir = config["base_dir"][current_os]

# Construct paths using the base directory
paths = construct_paths(config, base_dir)

# Access constructed paths
ghidra_dir = paths["ghidra_dir"]
project_dir = paths["project_dir"]
script_dir = paths["script_dir"]

# Check arguments
if results.opt is not None:
    opt_level = int(results.opt)
    if opt_level not in range(4):
        raise argparse.ArgumentTypeError("%s is an invalid optimization level, 0-3 only" % opt_level)
else:
    opt_level = results.opt

# Convert P-code to XML
# Convert P-code to XML
if recompile:
    subprocess.run([
        ghidra_headless_loc,  # Path to the Ghidra analyzeHeadless executable
        prj_dir,  # Path to the Ghidra project directory
        prj_name,  # Ghidra project name
        '-import',  # Import command to specify that you want to import a binary
        results.input_file,  # Path to the input binary file to be imported
        '-scriptPath',  # Path to the ghidra scripts
        script_dir,
        '-postScript',  # PostScript command to specify that you want to run a script after import
        xml_script,  # Name of the GhidraToXML.java script
        '-overwrite',  # Overwrite command to specify that you want to overwrite an existing project
        '-deleteProject'  # DeleteProject command to specify that you want to delete the existing project
    ])

# get line seperator
if sys.platform.startswith('win'):
    # Windows-specific code
    seperator = "\\"
else:
    seperator = "/"
    # Add code specific to Windows here

filename = results.input_file.split(seperator)[-1]
xmlfile = output_dir + filename + '.xml'
# subprocess.run(['mv', xml_tmp_file, xmlfile])
# Copy the file
shutil.copyfile(xml_tmp_file, xmlfile)
# shutil.move(xml_tmp_file, xmlfile)

print("-----------------------------------------------------")

print("-----------------------------------------------------")
print("-----------------------------------------------------")
print("-----------------------------------------------------")
# Lift to LLVM
module = xmltollvm.lift(xmlfile)
llvmlitefile = str(filename + '.llvmlite')
f = open(llvmlitefile, 'w')
f.write(str(module))
f.close()

# Optimization passes
module = opt_verify.optimize(module, opt_level)

# Verify
module = opt_verify.verify(module)
llfile = str(filename + '.ll')
if results.output:
    llfile = results.output
else:
    llfile = str(filename + '.ll')
f = open(llfile, 'w')
f.write(str(module))
f.close()

# Output CFGs
if results.cfg:
    subprocess.run(['rm', '-rf', "graphs"])
    subprocess.run(['mkdir', "graphs"])
    graphs = opt_verify.graph(module)


# Cleanup
if not results.out:
    subprocess.run(['rm', xmlfile])
    subprocess.run(['rm', llvmlitefile])
