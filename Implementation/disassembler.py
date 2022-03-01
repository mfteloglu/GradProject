from subprocess import Popen, PIPE
import re
import os
from textwrap import wrap
import pandas as pd

hexcodes = "00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,10,11,12,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20,21,22,23,24,25,26,27,28,29,2A,2B,2C,2D,2E,2F,30,31,32,33,34,35,36,37,38,39,3A,3B,3C,3D,3E,3F,40,41,42,43,44,45,46,47,48,49,4A,4B,4C,4D,4E,4F,50,51,52,53,54,55,56,57,58,59,5A,5B,5C,5D,5E,5F,60,61,62,63,64,65,66,67,68,69,6A,6B,6C,6D,6E,6F,70,71,72,73,74,75,76,77,78,79,7A,7B,7C,7D,7E,7F,80,81,82,83,84,85,86,87,88,89,8A,8B,8C,8D,8E,8F,90,91,92,93,94,95,96,97,98,99,9A,9B,9C,9D,9E,9F,A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,AA,AB,AC,AD,AE,AF,B0,B1,B2,B3,B4,B5,B6,B7,B8,B9,BA,BB,BC,BD,BE,BF,C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,CA,CB,CC,CD,CE,CF,D0,D1,D2,D3,D4,D5,D6,D7,D8,D9,DA,DB,DC,DD,DE,DF,E0,E1,E2,E3,E4,E5,E6,E7,E8,E9,EA,EB,EC,ED,EE,EF,F0,F1,F2,F3,F4,F5,F6,F7,F8,F9,FA,FB,FC,FD,FE,FF".split(",")

#parses the dissasemble operation result which is a string
def parse_disasembled_file(disassembled_file):
    occurences = {}
    for hexcode in hexcodes:
        occurences[hexcode] = 0
    matches = re.findall(r'(:( [0-9A-F][0-9A-F])+)|(           ( [0-9A-F][0-9A-F])+)', disassembled_file)
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
            occurences[hexcode] += 1

    return occurences.items()

#disassembles the target file with dumpbin and saves the result in a txt file
def disassemble(target_file, dumpbin_path, dumpbin_command, input_folder_name):
    output_file = open("temp_output.txt", 'w')
    target_file_path = os.getcwd() + "\\" + input_folder_name + "\\" + target_file
    commands = "c:\ncd {dumpbin_path}\n{dumpbin_command} {target_file_path}\n".format(dumpbin_path = dumpbin_path, dumpbin_command = dumpbin_command, target_file_path = target_file_path)
    process = Popen( "cmd.exe", shell=False, universal_newlines=True,
                    stdin=PIPE, stdout=output_file, stderr=PIPE )                             
    process.communicate(commands)
    output_file.close()
    output_file = open("temp_output.txt", 'r', encoding='utf-8', errors='ignore')
    dissassembled_file = output_file.read()
    output_file.close()
    return parse_disasembled_file(dissassembled_file)

#driver function, disassembles and counts the hexcodes of the files in the input folder, returns the result as csv 
def disassemble_files(input_folder_name):
    path_file = open("dumpbin_path.txt")
    os.chdir(input_folder_name)
    input_files = os.listdir()
    os.chdir("..")
    dumpbin_path = path_file.read()
    dumpbin_command = "dumpbin /DISASM"
    csv_delimeter = ','
    output_csv = open("output.csv", 'w')
    output_csv.write(csv_delimeter.join(hexcodes) + "\n")
    
    for file in input_files:
        print(file)
        occurences = disassemble(file, dumpbin_path, dumpbin_command, input_folder_name)
        output_csv.write(csv_delimeter.join(map(lambda x: str(x[1]), occurences)) + "\n")
    output_csv.close()

#SAMPLE USAGE
"""
import disassembler
disassembler.disassemble_files("benign_test_data")
df = pd.read_csv('output.csv', sep=',')
print(df)
"""

disassemble_files("BenignTestData")