import argparse
import random
import uuid
from pathlib import Path

def fuzz_insert(data, action_length):
    #insert random size string of bytes into random location
    insert_spot = random.randrange(len(data))
    insert_length = random.randrange(1, action_length)
    #1 byte == 8 bits
    bits = random.getrandbits(insert_length*8).to_bytes(insert_length, byteorder='big')
    data = b"".join([data[:insert_spot], bits, data[insert_spot:]])
    return data

def fuzz_replace(data, action_length):
    #replace random size string of bytes from random location
    replace_length = random.randrange(1, action_length)
    replace_spot = random.randrange(len(data))
    #1 byte == 8 bits
    bits = random.getrandbits(replace_length*8).to_bytes(replace_length, byteorder='big')
    data = b"".join([data[:replace_spot], bits, data[replace_spot+replace_length:]])
    return data

def fuzz_delete(data, action_length):
    #delete random size string of bytes from random location
    delete_length = random.randrange(1, action_length)
    delete_spot = random.randrange(len(data))
    data = b"".join([data[:delete_spot], data[delete_spot+delete_length:]])
    return data

def fuzz_shuffle(data):
    return random.sample(data, k=len(data))

def main(data, action_repitions, action_length):
    #adding fuzz_delete twice leads to larger final file size variation
    options = [fuzz_insert, fuzz_replace, fuzz_delete, fuzz_delete]

    for _ in range(random.randrange(1, action_repitions)):
        #choose from the available options and do that
        choice = random.choice(options)
        #If no data left, consider fuzzing complete :)
        if len(data) == 0:
            break
        else:
            data = choice(data, action_length)

    #Shuffle all the bits 25% of the time
    if random.choice([True, False, False, False]):
        data = fuzz_shuffle(data)
    return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='File to morph', default='fuzz_template/SCFFile.tlv')
    parser.add_argument('-d', '--directory', help='Dir to store new tlv file', default='fuzz_files/')
    parser.add_argument('-l', '--action_length', help='', type=int, default=500)
    parser.add_argument('-r', '--action_repitions', help='', type=int, default=10000)
    parser.add_argument('-n', '--number_to_make', help='Number of Fuzz Files to create', type=int, default=20)
    args = parser.parse_args()

    for _ in range(args.number_to_make):
        with open(Path(args.file), 'rb') as f:
            data = f.read()

        data = main(data, args.action_length, args.action_repitions)

        output_dir = Path(args.directory)
        output_filename = uuid.uuid4().hex + '.tlv'
        output_path = output_dir / output_filename
        with open(output_path, 'wb') as f:
            f.write(bytes(data))
