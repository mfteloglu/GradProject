import pandas as pd
import os
import sys

sys.path.insert(0, 'pe_header_features')

import pe_header_extract

pe_header_extract.create_dataset_csv(pe_header_extract.benign_directory, pe_header_extract.output_file_benign, "benign")
pe_header_extract.create_dataset_csv(pe_header_extract.ransomware_directory, pe_header_extract.output_file_ransomware, "ransomware")

sys.path.insert(0, 'disassembler_opcodes')

import disassembler

disassembler.convert_counts_to_percentages('disassembler_opcodes/hexcodes_benign.csv', 'disassembler_opcodes/hexcodes_benign_percentages.csv')
disassembler.convert_counts_to_percentages('disassembler_opcodes/hexcodes_ransomware.csv', 'disassembler_opcodes/hexcodes_ransomware_percentages.csv')