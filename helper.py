from struct import pack
def main():
    filename =  "A7a.txt"
    formatter = '>h{}sB{}sB'  # { > - Big Endian, h - short , s - char, B - 1 byte }
    formatter = formatter.format(len(filename), len('netascii'))
    print(formatter)  # final format '>h8sB8sB'
    request = pack(formatter, 4, bytes(filename, 'utf-8'), 0, bytes("netascii", 'utf-8'), 0)
    print(f"Request {request}")
    
main()