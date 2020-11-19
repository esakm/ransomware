from factory import AlgoFactory
import os
import argparse
import random

sym_types = ['aes', 'rc4', 'xor']
asym_types = ['rsa', 'ecc']


def encrypt_folder(folder_name, algo):
    entries = os.scandir(folder_name)
    for entry in entries:
        if os.path.isdir(entry):
            encrypt_folder(entry, algo)
        else:
            algo.encrypt(entry)


def decrypt_folder(folder_name, algo):
    entries = os.scandir(folder_name)
    for entry in entries:
        if os.path.isdir(entry):
            decrypt_folder(entry, algo)
        else:
            algo.decrypt(entry)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="""
    This scripts encrypts/decrypts all files in a folder 
    """)

    parser.add_argument("-f", "-F", "--folder", nargs='?', required=True, help="Folder(s) to encrypt")

    parser.add_argument("-s", "-S", "--secret", nargs='+', help="Secret Keys. To use built-in keys do not use this arg")

    parser.add_argument("-t", "-T", "--type", nargs='?', required=True, choices=["sym", "asym"],
                        help="Symmetric or asymmetric cipher")

    parser.add_argument("-a", "-A", "--algo", nargs='?', choices=["rsa", "xor", "rc4",
                                                                  "aes", "ecc"],
                        help="Choose cipher")

    parser.add_argument("-ac", "-AC", "--action", default="encrypt", nargs="?", choices=["encrypt", "decrypt"])

    args = parser.parse_args()

    if args.action == 'encrypt':
        if args.type == 'sym':
            if args.algo is None:
                args.algo = 'xor'
            if args.algo not in sym_types:
                raise ValueError("Chosen Algorithm is not Symmetric!")
            algo_get = AlgoFactory.get_algo(args.algo, args.secret)
            encrypt_folder(args.folder, algo_get)
        else:
            if args.algo is None:
                args.algo = 'rsa'
            if args.algo not in asym_types:
                raise ValueError("Chosen Algorithm is not Asymmetric!")
            algo_get = AlgoFactory.get_algo(args.algo, args.secret)
            encrypt_folder(args.folder, algo_get)

    elif args.action == 'decrypt':
        if args.type == 'sym':
            if args.algo is None:
                args.algo = 'xor'
            if args.algo not in sym_types:
                raise ValueError("Chosen Algorithm is not Symmetric!")
            algo_get = AlgoFactory.get_algo(args.algo, args.secret)
            decrypt_folder(args.folder, algo_get)
        else:
            if args.algo is None:
                args.algo = 'rsa'
            if args.algo not in asym_types:
                raise ValueError("Chosen Algorithm is not Asymmetric!")
            algo_get = AlgoFactory.get_algo(args.algo, args.secret)
            decrypt_folder(args.folder, algo_get)

    else:
        print("choose a valid option!")
