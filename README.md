# Ransomware Detection Using Machine Learning

## Graduation project of:
 Aykut Atmaca https://www.linkedin.com/in/aykut-atmaca-252288147/
 
 Ali Özgür Solak https://www.linkedin.com/in/ali-ozgur-solak/
 
 Mehmet Fatih Teloğlu https://www.linkedin.com/in/mehmet-fatih-telo%C4%9Flu-7920a01b8/

### To RUN :
 first inside disassembler_opcodes file run these two lines : <br>
 "python3 .\disassembler.py BenignTestData hexcodes_benign.csv" <br>
 "python3 .\disassembler.py RansomwareTestData hexcodes_ransomware.csv" <br>
 then go to dll_imports and run this line : <br>
 "python3 .\functions.py BenignTestData RansomwareTestData" <br>
 Then execute extract_all_features.py <br>
 Then execute ml_model.py <br>
