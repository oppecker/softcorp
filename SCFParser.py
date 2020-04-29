HEADER_TYPES = {
        1: 'Rev',
        2: 'Header length',
        3: 'Signer identity length',
        4: 'Signer name',
        5: 'Cert SN',
        6: 'CA Name',
        7: 'Garbage?',
        8: 'Dig alg',
        9: 'Garbage?',
        10: 'Sig alg',
        11: 'Mod size',
        12: 'Signature',
        14: 'File Name and Extension',
        15: 'END',
}

HEADER_NO_VALUE = [3,7,9]

BODY_TYPES = {
        1: ('Record Length', 'INT'),
        2: ('Subject DNS Name', ''),
        3: ('Subject Name', ''),
        4: ('Subject Function/Role', ''),
        5: ('Subject Certificate Issuer Name', ''),
        6: ('Subject Certificate Serial Number', ''),
        7: ('Subject Public Key', ''),
        8: ('Subject Certificate Signature', ''),
        9: ('Subject X.509v3 Certificate', ''),
        10: ('Subject IP Address', ''),
        11: ('Hash of Certificate', ''),
        12: ('Hash Algorithm', ''),
}

BODY_NO_VALUE = []

def parse_tlv(data):
    #PARSE HEADER
    while data:
        if data[0] not in HEADER_TYPES:
            print('continue...', data[0])
            data = data[1:]
            continue
        else:
            type = data[0]
            length = int.from_bytes(data[1:3], byteorder='big')
            value = data[3:length+2]
            #value = int.from_bytes(data[3:length+2], byteorder='big')
        if type in HEADER_NO_VALUE:
            print(type, HEADER_TYPES[type], length)
            data = data[3:]
        else:
            print(type, HEADER_TYPES[type], length, value)
            data = data[3+length:]
        if type == 15:
            break

    #PARSE BODY
    while data:
        if data[0] not in BODY_TYPES:
            print('continue...', data[0])
            data = data[1:]
            continue
        else:
            type = data[0]
            length = int.from_bytes(data[1:3], byteorder='big')
            value = data[3:length+2]
            if BODY_TYPES[type][1] == 'INT':
                value = int.from_bytes(value, byteorder='big')
            #value = int.from_bytes(data[3:length+2], byteorder='big')
        if type in BODY_NO_VALUE:
            print(type, BODY_TYPES[type][0], length)
            data = data[3:]
        else:
            print(type, BODY_TYPES[type][0], length, value)
            data = data[3+length:]
        if type == 15:
            break



if __name__ == '__main__':
    with open('SCFFile.tlv', 'rb') as f:
        data = f.read()

    parse_tlv(data)
