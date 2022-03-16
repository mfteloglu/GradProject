import os
import pefile
import yara_check

# File paths
benign_directory = "BenignTestData"
ransomware_directory = "RansomwareTestData" # ??? 

yaraRule_path = "pe_header_features/YARA/bitcoin.yara"

output_file_benign = "pe_header_features/data_benign.csv"
output_file_ransomware= "pe_header_features/data_ransomware.csv"

# CSV information
csv_delimeter = ','
csv_columns = [
    "FileName",
    "Machine",
    "DebugSize",
    "DebugRVA",
    "MajorImageVersion",
    "MajorOSVersion",
    "ExportRVA",
    "ExportSize",
    "IatVRA",
    "MajorLinkerVersion",
    "MinorLinkerVersion",
    "NumberOfSections",
    "SizeOfStackReserve",
    "DllCharacteristics",
    "ResourceSize",
    "BitcoinAddresses",
    "Benign",
]

def extract_features(file):
    # Creates an empty list for which features can later be appended into.
    features = []

    # Name of file
    features.append(os.path.basename(file))

    # Assigns pe to the input file. fast_load loads all directory information.
    pe = pefile.PE(file, fast_load=True)

    # CPU that the file is intended for.
    features.append(pe.FILE_HEADER.Machine)

    # DebugSize is the size of the debug directory table. Clean files typically have a debug directory
    # and thus, will have a non-zero values.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size)

    # DebugRVA
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress)

    # MajorImageVersion is the version of the file. This is user defined and for clean programs is often
    # populated. Malware often has a value of 0 for this.
    features.append(pe.OPTIONAL_HEADER.MajorImageVersion)

    # MajorOSVersion is the major operating system required to run exe.
    features.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)

    # ExportRVA.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress)

    # ExportSize is the size of the export table. Usually non-zero for clean files.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size)

    # IatRVA is the relative virtual address of import address table. Most clean files have 4096 for this
    # where as malware often has 0 or a very large number.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress)

    # Version of linker that produced file.
    features.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    features.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)

    # NumberOfSections is the number of sections in file.
    features.append(pe.FILE_HEADER.NumberOfSections)

    # SizeOfStackReserve denotes the amount of virtual memory to reserve for the initial thread's stack.
    features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)

    # DllCharacteristics is a set of flags indicating under which circumstances a DLL's initialization
    # function will be called.
    features.append(pe.OPTIONAL_HEADER.DllCharacteristics)

    # MinResourcesSize is the size of resources section of PE header. Malware sometimes has 0 resources.
    features.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)

    # Calls the check_bitcoinAdress function to check if the file contains a bitcoin address.
    bitcoin_check = yara_check.check_bitcoinAdress(file, yaraRule_path)
    features.append(bitcoin_check)

    # Returns the feature list.
    return features
    

def create_dataset_csv(directory, output_file, fileType):
    '''
    directory : path for the dataset
    output_file : path for output
    fileType : "benign" or "ransomware"
    '''
    
    # Opens file so features can be written too.
    feature_file = open(output_file, 'w')

    # Writes column headers to feature file.
    feature_file.write(csv_delimeter.join(csv_columns) + "\n")
    
    if fileType == "benign":
        for item in os.listdir(directory):
            try:
                filename = os.path.join(directory,item)
                features = extract_features(filename)
                features.append(1)
                feature_file.write(csv_delimeter.join(map(lambda x: str(x), features)) + "\n")
                print(features)
            except:
                print("Error occured, this file is not a PE file", item)

            
    elif fileType == "ransomware":
        for item in os.listdir(directory):
            try:
                filename = os.path.join(directory,item)
                features = extract_features(filename)
                features.append(0)
                feature_file.write(csv_delimeter.join(map(lambda x: str(x), features)) + "\n")
                print(features)
            except:
                print("Error occured, this file is not a PE file", item)