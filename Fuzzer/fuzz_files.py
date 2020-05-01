import os
import shutil
import argparse
import subprocess
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-ff', '--fuzz_files', help='Directory with fuzzing input', default='fuzz_files/')
    args = parser.parse_args()

    my_path = Path(args.fuzz_files)
    for filename in os.listdir(my_path):
        new_path = shutil.copy(my_path / filename, '.')
        print('\n============================\nTesting file: ', my_path / filename)
        shutil.move(new_path, Path('SCFFile.tlv'))
        cmd = 'SCFParser.exe'
        process = subprocess.Popen(cmd)
        process.wait()
