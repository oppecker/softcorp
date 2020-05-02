import argparse
from collections import namedtuple

Record = namedtuple('Record', 'tag name length value')
Field = namedtuple('Field', 'name value_type in_report')

HEADER_FIELDS = {
        1: Field(name='Rev', value_type=str, in_report=True),
        2: Field(name='Header length', value_type=int, in_report=True),
        3: Field(name='Signer identity length', value_type=None, in_report=False),
        4: Field(name='Signer name', value_type=str, in_report=False),
        5: Field(name='Cert SN', value_type=str, in_report=False),
        6: Field(name='CA Name', value_type=str, in_report=False),
        7: Field(name='Garbage?', value_type=None, in_report=False),
        8: Field(name='Dig alg', value_type=str, in_report=False),
        9: Field(name='Garbage?', value_type=None, in_report=False),
        10: Field(name='Sig alg', value_type=str, in_report=False),
        11: Field(name='Mod size', value_type=str, in_report=False),
        12: Field(name='Signature', value_type=str, in_report=False),
        14: Field(name='File Name and Extension', value_type=str, in_report=False),
        15: Field(name='END', value_type=str, in_report=False),
}

BODY_FIELDS = {
        1: Field(name='Record Length', value_type=int, in_report=True),
        2: Field(name='Subject DNS Name', value_type=str, in_report=False),
        3: Field(name='Subject Name', value_type=str, in_report=True),
        4: Field(name='Subject Function/Role', value_type=str, in_report=True),
        5: Field(name='Subject Certificate Issuer Name', value_type=str, in_report=True),
        6: Field(name='Subject Certificate Serial Number', value_type=str, in_report=False),
        7: Field(name='Subject Public Key', value_type=str, in_report=False),
        8: Field(name='Subject Certificate Signature', value_type=str, in_report=False),
        9: Field(name='Subject X.509v3 Certificate', value_type=str, in_report=False),
        10: Field(name='Subject IP Address', value_type=str, in_report=False),
        11: Field(name='Hash of Certificate', value_type=str, in_report=False),
        12: Field(name='Hash Algorithm', value_type=str, in_report=False),
}

REPORT = {
        'header': [],
        'body': [],
}

def parse_header(data):
    while data:
        if data[0] not in HEADER_FIELDS:
            #If not a valid field, advance to next data value.
            data = data[1:]
            continue
        else:
            tag = data[0]
            name = HEADER_FIELDS[tag].name
            length = int.from_bytes(data[1:3], byteorder='big')
            value = data[3:length+3]
            if HEADER_FIELDS[tag].value_type is int:
                value = int.from_bytes(value, byteorder='big')
            record = Record(tag, name, length, value)

        if HEADER_FIELDS[tag].in_report:
            REPORT['header'].append(record)

        if HEADER_FIELDS[tag].value_type is None:
            data = data[3:]
        elif HEADER_FIELDS[tag].name == 'END':
            #Best guess that works based on sample input file.
            data = data[4:]
            break
        else:
            data = data[3+length:]

    return data


def parse_body(data):
    while data:
        if data[0] not in BODY_FIELDS:
            #If not a valid field, advance to next data value.
            data = data[1:]
            continue
        else:
            tag = data[0]
            name = BODY_FIELDS[tag].name
            length = int.from_bytes(data[1:3], byteorder='big')
            value = data[3:length+3]
            if BODY_FIELDS[tag].value_type is int:
                value = int.from_bytes(value, byteorder='big')
            if BODY_FIELDS[tag].in_report:
                record = Record(tag, name, length, value)
                REPORT['body'].append(record)

        data = data[3+length:]

    return data


def print_report():
    print('\nParse CTL File\n--------------\n')
    for tag, name, length, value in REPORT['header']:
        print(f'{name}: tag:{tag} len:{length} value:{value}')

    record_count = 1
    print('\nStart CTL Records\n-----------------')
    for tag, name, length, value in REPORT['body']:
        if name == 'Record Length':
            print(f'\n--- CTL Record: {record_count} ---\n')
            record_count += 1
        print(f'{name}: tag:{tag} len:{length} value:{value}')


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
