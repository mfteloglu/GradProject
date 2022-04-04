import pefile
import pandas as pd
import numpy as np
import os
import itertools
from itertools import repeat
import csv
import sys

functions = {}
functions_benign = {}
functions_ransom = {}
functions_ransom_only = {}

i = 0
args = sys.argv

directory_benign = '..\\' + args[1]
directory_ransom = '..\\' + args[2]

files = os.listdir(directory_benign) + os.listdir(directory_ransom)

for file in os.listdir(directory_benign):
    try:
        pe = pefile.PE(directory_benign + '\\' + file, fast_load=True)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name in functions:
                    functions[imp.name] += 1
                else:
                    functions[imp.name] = 1
                    
                if imp.name in functions_benign:
                    functions_benign[imp.name] += 1
                else:
                    functions_benign[imp.name] = 1
    except Exception as ex:
        i += 1
        continue
        
        
for file in os.listdir(directory_ransom):
    try:
        pe = pefile.PE(directory_ransom + '\\' + file, fast_load=True)
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name in functions:
                    functions[imp.name] += 1
                else:
                    functions[imp.name] = 1
                    
                if imp.name in functions_ransom:
                    functions_ransom[imp.name] += 1
                else:
                    functions_ransom[imp.name] = 1
                    
                if imp.name not in functions_benign:
                    if imp.name in functions_ransom_only:
                        functions_ransom_only[imp.name] += 1
                    else:
                        functions_ransom_only[imp.name] = 1
    except Exception as ex:
        i += 1
        continue
    
        
print('exception ', i, ' times')
        
func_sorted = dict(sorted(functions.items(), key=lambda item: item[1], reverse=True))
func_benign_sorted = dict(sorted(functions_benign.items(), key=lambda item: item[1], reverse=True))
func_ransom_sorted = dict(sorted(functions_ransom.items(), key=lambda item: item[1], reverse=True))
func_ransom_only_sorted = dict(sorted(functions_ransom_only.items(), key=lambda item: item[1], reverse=True))


func_limit = int(len(func_sorted) * 0.03)
ransom_limit = int(len(func_ransom_only_sorted) * 0.07)


if (ransom_limit > 192):
    ransom_limit = 192

reduced_func = dict(itertools.islice(func_sorted.items(), func_limit))
reduced_ransom = dict(itertools.islice(func_ransom_only_sorted.items(), ransom_limit))

features = ['FileName']
features.extend(list(reduced_ransom.keys()))

for item in reduced_func:
    if (item not in features) and (len(features) < 257):
        features.append(item)







with open('functions_benign.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(features)
    for file in os.listdir(directory_benign):
        values = []
        values.append(file)
        imports = []
        try:
            pe = pefile.PE(directory_benign + '\\' + file, fast_load=True)
            pe.parse_data_directories()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imports.append(imp.name)
            for item in features[1:]:
                if item in imports:
                    values.append(1)
                else:
                    values.append(0)
        except Exception as ex:
            values.extend(repeat(0, 256))
        writer.writerow(values)
            
with open('functions_ransom.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(features)
    for file in os.listdir(directory_ransom):
        values = []
        values.append(file)
        imports = []
        try:
            pe = pefile.PE(directory_ransom + '\\' + file, fast_load=True)
            pe.parse_data_directories()
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imports.append(imp.name)
            for item in features[1:]:
                if item in imports:
                    values.append(1)
                else:
                    values.append(0)
        except Exception as ex:
            if 'has no attribute' in str(ex):
                values.extend(repeat(0, 256))
            else:
                continue
        writer.writerow(values)