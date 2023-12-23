#!/usr/bin/python3

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys

import src.xmltollvm as xmltollvm
import src.lifting_opt_verify as opt_verify


def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)


def construct_paths(config, base_dir):
    print("constructing paths: " + base_dir)
    paths = {
        "ghidra_dir": os.path.join(base_dir, config["directories"]["ghidra_dir"]),
        "project_dir": os.path.join(base_dir, config["directories"]["project_dir"]),
        "script_dir": os.path.join(base_dir, config["directories"]["script_dir"][platform.system().lower()]),
        "xml_tmp_file": os.path.join(base_dir, config["directories"]["xml_tmp_file"][platform.system().lower()]),
        "output_dir": os.path.join(base_dir, config["directories"]["output_dir"])
    }
    paths["ghidra_headless"] = os.path.join(
        paths["ghidra_dir"] + config["directories"]["headless_dir"][platform.system().lower()])
    for key, path in paths.items():

        if key == "xml_tmp_file" and recompile:
            continue
        assert os.path.isdir(path) or os.path.isfile(path), f"Invalid path: {key} = '{path}'"
    return paths


def check_previous_line_is_correctly_ended(previous_line):
    return previous_line and any(previous_line.strip().startswith(s) for s in valid_endings)


def fix_wrong_block_endings(file_path):

    regex = r'"([0-9a-fA-F]{9})":\n'
    pattern = re.compile(regex)
    with open(file_path, 'r') as file:
        previous_line = None
        lines = file.readlines()
        n = 0
        skipInserterLine = False
        for i, line in enumerate(lines):
            if skipInserterLine:
                skipInserterLine = False
                continue
            if pattern.match(line):
                check_previous_line_is_correctly_ended(previous_line)
                if not check_previous_line_is_correctly_ended(previous_line):
                    # adjust i with inserted lines
                    i = i - n
                    insert_text = re.match(regex, line).group(1)
                    # check if spaces need to be inserted dynamically according to previous line
                    insert_text = f"  br label %\"{insert_text}\"\n"
                    print(f"{i}: {previous_line}")
                    print(f"{i + 1}: {line}")
                    lines.insert(i + n, insert_text)
                    skipInserterLine = True
                    n = n + 1
                    # return True  # Found the pattern
            previous_line = line.rstrip('\n')  # Update the previous line
        # Write modified lines back to the file
        with open("new_" + file_path, 'w') as file:
            file.writelines(lines)


# choose if ghidra should run
# if not the resulting file is needed!
recompile = True
# choose if incorrect line endings in the llvmlite file should be fixed
should_fix_wrong_block_endings = True
# list of valid commands that can occur bevor a new label address
valid_endings = ["br ", "ret ", "indirectbr"]

# These shouldn't need to be changed
prj_name = "lifting"
xml_script = "GhidraToXML.java"

# Argument parsing
parser = argparse.ArgumentParser(description='This script lifts a binary from executable to LLVM IR.')
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
ghidra_headless_loc = paths['ghidra_headless']
project_dir = paths["project_dir"]
script_dir = paths["script_dir"]
output_dir = paths['output_dir']
xml_tmp_file = paths['xml_tmp_file']

# Check arguments
if results.opt is not None:
    opt_level = int(results.opt)
    if opt_level not in range(4):
        raise argparse.ArgumentTypeError("%s is an invalid optimization level, 0-3 only" % opt_level)
else:
    opt_level = results.opt

# Convert P-code to XML

if recompile and os.path.isdir(xml_tmp_file):
    print("-----------------------------------------------------")
    print("Cleaning up old results")
    print("-----------------------------------------------------")
    os.remove(xml_tmp_file)

print("-----------------------------------------------------")
print("Running Ghidra analysis and post script(s)")
print("-----------------------------------------------------")
if recompile:
    subprocess.run([
        ghidra_headless_loc,  # Path to the Ghidra analyzeHeadless executable
        project_dir,  # Path to the Ghidra project directory
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
try:
    shutil.copyfile(xml_tmp_file, xmlfile)
except Exception:
    print("Error: no xml output found! Exiting.. ")
    exit(1)
# shutil.move(xml_tmp_file, xmlfile)

print("-----------------------------------------------------")
print("Finished Ghidra-To-Xml conversion")
print("-----------------------------------------------------")
# Lift to LLVM
module = xmltollvm.lift(xmlfile)
llvmlitefile = str(filename + '.llvmlite')
f = open(llvmlitefile, 'w')
f.write(str(module))
f.close()

print("-----------------------------------------------------")
print("Finished lifting to llvm")
print("-----------------------------------------------------")
# Optimization passes
# TODO - find incorrect labels and correct them
# TODO - WHERE DO THEY COME FROM?
if should_fix_wrong_block_endings:
    print("-----------------------------------------------------")
    print("Finished lines: ")
    fix_wrong_block_endings(llvmlitefile)
    print("-----------------------------------------------------")
    print("Finished fixing incorrect block endings")
    print("-----------------------------------------------------")
    f = open("new_" + llvmlitefile, 'r')
    module = f.read()

module = opt_verify.optimize(module, opt_level)

print("-----------------------------------------------------")
print("Finished optimizations")
print("-----------------------------------------------------")
# Verify
module = opt_verify.verify(module)
llfile = str(filename + '.ll')
if results.output:
    llfile = results.output
else:
    llfile = paths["output_dir"] + str(filename + '.ll')
f = open(llfile, 'w')
f.write(str(module))
f.close()

print("-----------------------------------------------------")
print("Finished verification")
print("-----------------------------------------------------")

# Output CFGs
if results.cfg:
    subprocess.run(['rm', '-rf', "graphs"])
    subprocess.run(['mkdir', "graphs"])
    graphs = opt_verify.graph(module)

# Cleanup
if not results.out:
    os.remove(xmlfile)
    if should_fix_wrong_block_endings:
        os.remove("new_" + llvmlitefile)
    os.remove(llvmlitefile)
