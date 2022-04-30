# GradProject

# To RUN :
 first inside disassembler_opcodes file run these two lines : <br>
 "python3 .\disassembler.py BenignTestData hexcodes_benign.csv" <br>
 "python3 .\disassembler.py RansomwareTestData hexcodes_ransomware.csv" <br>
 then go to dll_imports and run this line : <br>
 "python3 .\functions.py BenignTestData RansomwareTestData" <br>
 Then execute extract_all_features.py <br>
 Then execute ml_model.py <br>
