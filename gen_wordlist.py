# http://localhost:4444/download.php?h=52265289828a822beea7dc792224b402&file_name=Diamond.txt
# https://diamond-safe.flu.xxx/download.php?h=f2d03c27433d3643ff5d20f1409cb013&file_name=FlagNotHere.txt

rockyou = open('/home/neptunian/rockyou.txt', 'r', encoding='latin-1')
newlist = open('./diamond.wordlist.txt', 'w')

file_name = 'Diamond.txt'
# file_name = 'FlagNotHere.txt'

while True:
 
    # Get next line from file
    secret = rockyou.readline()
    secret = secret.replace('\n', '').replace('\x0d', '').replace('\x0a', '')
    if not secret:
        break

    newline = f"{secret}|{file_name}|{secret}"
    newlist.write(newline + '\n')

newlist.close()
rockyou.close() 