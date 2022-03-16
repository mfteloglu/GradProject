import yara

def check_bitcoinAdress(file, rulePath):
    
    rule = yara.compile(filepath = rulePath)
    
    m = rule.match(file)
    if m:
        return 1 # found
    else:
        return 0 # not found