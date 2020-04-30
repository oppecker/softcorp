import argparse
from collections import namedtuple

Record = namedtuple('Record', 'type name length value')
Info = namedtuple('Info', 'name value_type')

HEADER_TYPES = {
        1: Info(name='Rev', value_type=str),
        2: Info(name='Header length', value_type=int),
        3: Info(name='Signer identity length', value_type=None),
        4: Info(name='Signer name', value_type=str),
        5: Info(name='Cert SN', value_type=str),
        6: Info(name='CA Name', value_type=str),
        7: Info(name='Garbage?', value_type=None),
        8: Info(name='Dig alg', value_type=str),
        9: Info(name='Garbage?', value_type=None),
        10: Info(name='Sig alg', value_type=str),
        11: Info(name='Mod size', value_type=str),
        12: Info(name='Signature', value_type=str),
        14: Info(name='File Name and Extension', value_type=str),
        15: Info(name='END', value_type=str),
}

BODY_TYPES = {
        1: Info(name='Record Length', value_type=int),
        2: Info(name='Subject DNS Name', value_type=str),
        3: Info(name='Subject Name', value_type=str),
        4: Info(name='Subject Function/Role', value_type=str),
        5: Info(name='Subject Certificate Issuer Name', value_type=str),
        6: Info(name='Subject Certificate Serial Number', value_type=str),
        7: Info(name='Subject Public Key', value_type=str),
        8: Info(name='Subject Certificate Signature', value_type=str),
        9: Info(name='Subject X.509v3 Certificate', value_type=str),
        10: Info(name='Subject IP Address', value_type=str),
        11: Info(name='Hash of Certificate', value_type=str),
        12: Info(name='Hash Algorithm', value_type=str),
}

HEADER_REPORT = [1,2]
BODY_REPORT = [1,3,4,5,9]
REPORT = {
        'header': [],
        'body': [],
}


def parse_header(data):
    while data:
        if data[0] not in HEADER_TYPES:
            #Skip 'garbage' to avoid crashes
            data = data[1:]
            continue
        else:
            type = data[0]
            name = HEADER_TYPES[type].name
            length = int.from_bytes(data[1:3], byteorder='big')
            #value = data[3:length+2]
            value = data[3:length+3]
            if HEADER_TYPES[type].value_type is int:
                value = int.from_bytes(value, byteorder='big')
            #value = int.from_bytes(data[3:length+2], byteorder='big')
            record = Record(type=type, name=name, length=length, value=value)

        if type in HEADER_REPORT:
            REPORT['header'].append(record)

        if HEADER_TYPES[type].value_type is None:
            data = data[3:]
        else:
            data = data[3+length:]

        if type == 15:
            break
    return data


def parse_body(data):
    while data:
        record = {}
        if data[0] not in BODY_TYPES:
            #Skip 'garbage' to avoid crashes
            data = data[1:]
            continue
        else:
            type = data[0]
            name = BODY_TYPES[type].name
            length = int.from_bytes(data[1:3], byteorder='big')
            #value = data[3:length+2]
            value = data[3:length+3]
            if BODY_TYPES[type].value_type is int:
                value = int.from_bytes(value, byteorder='big')
            #value = int.from_bytes(data[3:length+2], byteorder='big')
            record = Record(type=type, name=name, length=length, value=value)

        data = data[3+length:]
        REPORT['body'].append(record)

    return data


def print_report():
    print('\nParse CTL File\n--------------\n')
    for type, name, length, value in REPORT['header']:
        print(f'{name}: type:{type} len:{length} value:{value}')

    record_count = 1
    print('\nStart CTL Records\n-----------------')
    for type, name, length, value in REPORT['body']:
        if name == 'Record Length':
            print(f'\n--- CTL Record: {record_count} ---\n')
            record_count += 1
        print(f'{name}: type:{type} len:{length} value:{value}')

def main(data):
    data = parse_header(data)
    data = parse_body(data)
    print_report()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='File to parse', default='SCFFile.tlv')
    args = parser.parse_args()

    with open(args.file, 'rb') as f:
        data = f.read()

    main(data)
