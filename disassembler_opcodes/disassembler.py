import multiprocessing
from subprocess import Popen, PIPE
import re
import os
from textwrap import wrap
import pandas as pd
from tqdm.auto import tqdm
import pefile
import time
import multiprocessing
import sys
from pathlib import Path
import pandas as pd
import time

sys.path.insert(0, '../pe_header_features')

import pe_header_extract

hexcodes = "00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,10,11,12,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20,21,22,23,24,25,26,27,28,29,2A,2B,2C,2D,2E,2F,30,31,32,33,34,35,36,37,38,39,3A,3B,3C,3D,3E,3F,40,41,42,43,44,45,46,47,48,49,4A,4B,4C,4D,4E,4F,50,51,52,53,54,55,56,57,58,59,5A,5B,5C,5D,5E,5F,60,61,62,63,64,65,66,67,68,69,6A,6B,6C,6D,6E,6F,70,71,72,73,74,75,76,77,78,79,7A,7B,7C,7D,7E,7F,80,81,82,83,84,85,86,87,88,89,8A,8B,8C,8D,8E,8F,90,91,92,93,94,95,96,97,98,99,9A,9B,9C,9D,9E,9F,A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,AA,AB,AC,AD,AE,AF,B0,B1,B2,B3,B4,B5,B6,B7,B8,B9,BA,BB,BC,BD,BE,BF,C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,CA,CB,CC,CD,CE,CF,D0,D1,D2,D3,D4,D5,D6,D7,D8,D9,DA,DB,DC,DD,DE,DF,E0,E1,E2,E3,E4,E5,E6,E7,E8,E9,EA,EB,EC,ED,EE,EF,F0,F1,F2,F3,F4,F5,F6,F7,F8,F9,FA,FB,FC,FD,FE,FF".split(",")
hexcode_regex = re.compile(r'(:( [0-9A-F][0-9A-F])+)|(           ( [0-9A-F][0-9A-F])+)')

#store intermediate results and files in this file
helper_folder_name = "disassembler_helper_files/"

#parses the dumpbin program result which is a string
#and finds the hexcodes
def parse_disasembled_file(disassembled_file):
    hexcode_map = dict(zip(hexcodes, [0] * 256))
    matches = hexcode_regex.findall(disassembled_file)
    for match in matches:
        if not match[0] == "":
            trimmed_match = match[0]
        elif not match[2] == "":
            trimmed_match = match[2]

        #trimmed_match = trimmed_match.replace("\n", "")
        #trimmed_match = trimmed_match.replace("\r", "")
        trimmed_match = trimmed_match.replace(" ", "")
        trimmed_match = trimmed_match.replace(":", "")

        for hexcode in wrap(trimmed_match, 2):
            hexcode_map[hexcode] += 1
    
    return hexcode_map

def unpack_file(target_file_path):
    commands = ".\\upx -d -v {target_file_path}\n".format(target_file_path = target_file_path)
    process = Popen( "cmd.exe", shell=False, universal_newlines=True,
                    stdin=PIPE, stdout=PIPE, stderr=PIPE )                          
    process.communicate(commands)
    #stdout, stderr = process.communicate(commands)
    #print(stdout)
    #print(stderr)

#disassembles the target file with dumpbin and saves the result in a txt file
def disassemble(target_file, dumpbin_path, dumpbin_command, input_folder_name, temp_output_name):
    output_file = open(helper_folder_name + temp_output_name, 'w')
    target_file_path = os.getcwd() + "\\..\\" + input_folder_name + "\\" + target_file
    commands = "c:\ncd {dumpbin_path}\n{dumpbin_command} {target_file_path}\n".format(dumpbin_path = dumpbin_path, dumpbin_command = dumpbin_command, target_file_path = target_file_path)
    process = Popen( "cmd.exe", shell=False, universal_newlines=True,
                    stdin=PIPE, stdout=output_file, stderr=PIPE )                             
    process.communicate(commands)
    #stdout, stderr = process.communicate(commands)
    #print(stderr)
    output_file.close()
    output_file = open(helper_folder_name + temp_output_name, 'r', encoding='utf-8', errors='ignore')
    dissassembled_file = output_file.read()
    output_file.close()
    #print(dissassembled_file)
    result = parse_disasembled_file(dissassembled_file)
    is_packed = sum(result.values()) == 0
    return is_packed, result

#the function each child process runs
#disassembles files and writes to the output
def disassemble_files(input_folder_name, output_file, dumpbin_path, file_list, temp_output_name):
    dumpbin_command = "dumpbin /DISASM"
    csv_delimeter = ','
    output_csv = open(output_file, 'w')
    output_csv.write("FileName,")
    output_csv.write(csv_delimeter.join(hexcodes) + "\n")
    corrupted_count = 0
    packed_files = []
    for file in tqdm(file_list):
        try:
            filename = os.path.join("..", input_folder_name, file)
            pe_header_extract.extract_features(filename) #check if file is PE file
            is_packed, occurences = disassemble(file, dumpbin_path, dumpbin_command, input_folder_name, temp_output_name)
            if(is_packed):
                packed_files.append(file)
            output_csv.write(f"{file},")
            output_csv.write(csv_delimeter.join(map(lambda x: str(x[1]), occurences.items())) + "\n")
        except Exception as ex:
            #print(ex)
            #print(file)
            corrupted_count += 1
            continue

    # Try to unpack packed files with UPX.
    output_csv.close()
    df = pd.read_csv(output_file, index_col=0, encoding='utf-8',)
    for file in packed_files:
        unpack_file(os.getcwd() + "\\..\\" + input_folder_name + "\\" + file)
    time.sleep(1)
    for file in packed_files:
        is_packed, occurences = disassemble(file, dumpbin_path, dumpbin_command, input_folder_name, temp_output_name)
        if not is_packed:
            print("### UNPACKED! ###")
            df.loc[file] = occurences
    df.to_csv(output_file, encoding='utf-8', header=True)

#runs the program, creates the processes for parallel operation,
#after processes are done combines the outputs and creates the final output of the program
def run(input_folder_name, output_file):
    path_file = open(helper_folder_name + "dumpbin_path.txt")
    dumpbin_path = path_file.read()
    threads_count = os.cpu_count()
    print("CPU's detected: ", threads_count)
    
    start_time = time.time()
    
    cwd = os.getcwd()
    os.chdir(f"..\\{input_folder_name}")
    input_files = os.listdir()
    os.chdir(cwd)
    
    start_index = 0
    end_index = len(input_files)//threads_count
    equal_parts_of_list = len(input_files)//threads_count

    pool = multiprocessing.Pool(threads_count)
    args = []
    for i in range(threads_count):
        args.append([input_folder_name, f"{helper_folder_name}output_thread{i}.csv", dumpbin_path, input_files[start_index:end_index], f"temp_output{i}.txt"])
        start_index = end_index
        if(i + 2 == threads_count):
            end_index = len(input_files)
        else:
            end_index += equal_parts_of_list
    pool.starmap(disassemble_files, args)
    pool.close()
    pool.join()
    csv = pd.read_csv(f"{helper_folder_name}output_thread0.csv", sep=',', encoding="utf-8")
    for i in range(1, os.cpu_count()):
        csv = pd.concat([csv, pd.read_csv(f"{helper_folder_name}output_thread{i}.csv", encoding="utf-8")], axis=0)
    csv.to_csv(output_file, encoding='utf-8', index=False, header=True)
    print("--- %s seconds ---" % (time.time() - start_time))

def convert_counts_to_percentages(input_file, output_file):
    input_csv = pd.read_csv(input_file, sep=',', encoding="utf-8")

    file_names = input_csv['FileName']
    input_csv = input_csv.drop(['FileName'], axis=1)
    print(input_csv)
    df = input_csv.div(input_csv.sum(axis=1), axis=0)
    df = pd.concat([file_names, df], axis=1)
    df.to_csv(output_file, index=False, encoding="utf-8")

if __name__ == '__main__':
    args = sys.argv
    print("Disassembler is running...", args)
    #take the inputs from command line arguments
    input_folder, output_file = str(args[1]), str(args[2])
    #start the program
    run(input_folder, output_file)

#sample usage in notebook
#  !python3 disassembler.py newerransomsamples asdasd2_counts.csv
#   disassembler.convert_counts_to_percentages("asdasd2_counts.csv", "asdasd2_percentage.csv")