#!/usr/bin/env python3

__version__    = "1.1.0"
__author__     = "Althernis"
__maintainer__ = "Althernis"
__status__     = "Production"
__info__       = "Free to use, but a mention would be nice :D"

import os
import sys
import getpass
import CipherParser as cp
from CipherKey import CipherKey
from colors import colors


def main():
    parser = cp.getParser()
    args = parser.parse_args()
    keyManager = None
    filename   = None

    public_key, private_key = None, None

    if args.verbose or len(sys.argv) == 1:
        print(cp.FONT)
        return None

    if args.examples:
        print(colors.BOLD  + "\tKEYS EXAMPLE:" + colors.ENDC )
        
        print(colors.YELLOW  + "\t\tpython main.py --keys out/U1" + colors.ENDC )

        print(colors.BOLD  + "\n\tKEYS DELETION EXAMPLE:" + colors.ENDC )
        
        print(colors.YELLOW  + "\t\tpython main.py --keys out/U1 -d" + colors.ENDC )

        print(colors.BOLD  + "\n\tCUSTOM KEYS EXAMPLE:" + colors.ENDC )
        
        print(colors.YELLOW  + "\t\tpython main.py --keys out/U1 -s -p" + colors.ENDC )

        print(colors.BOLD  + "\n\tCIPHER EXAMPLE:" + colors.ENDC )
        
        print(colors.YELLOW  + "\t\tpython main.py --keys out/U1 --ciph colors.py -k out/U2 -o out/colors.py.enc" + colors.ENDC )

        print(colors.BOLD  + "\n\tUNCIPHER EXAMPLE:" + colors.ENDC )
        
        print(colors.YELLOW  + "\t\tpython main.py --keys out/U2 --unciph out/colors.py.enc -k out/U1 -o out/colors.py" + colors.ENDC )

        return None

    if args.password and args.salt:
        print(colors.BOLD + "\t-> Getting Credentials..." + colors.ENDC)
        pss = getpass.getpass('\t\t'+colors.BOLD+'Password: '+ colors.ENDC)
        salt = getpass.getpass('\t\t'+colors.BOLD+'Salt: '+ colors.ENDC)
    else:
        pss = None
        salt = None

    if args.keys:
        keyManager = CipherKey(args.keys, pss, salt)
        public_key, private_key = keyManager.load_RSA()
    else:
        print(colors.BOLD  + "\tKeys Folder  " + colors.RED + "missing" + colors.ENDC )
        return None

    

    # Example:
    #    python main.py --keys out/U1 --ciph colors.py -k out/U2 -o out/colors.py.enc
    if args.ciph:
        if args.key:
            key      = args.key
            filename = args.ciph

            dest_manager = CipherKey(args.keys, pss, salt)
            dest_pu_k, dest_pr_k = dest_manager.load_RSA()

            cipher_singed_content = keyManager.sign_and_ciph(filename, dest_pu_k)

            if args.output:
                if cipher_singed_content:
                    with open(args.output, "wb") as fp:
                        fp.write(cipher_singed_content)

                        print(colors.BOLD  + "\t\tFile " + colors.YELLOW + filename + colors.ENDC + colors.BOLD + " ciphered "+ colors.GREEN +"saved" + colors.ENDC )
            else:
                print(colors.BOLD  + "\t\tFile " + colors.YELLOW + filename + colors.ENDC + colors.BOLD + " ciphered "+ colors.YELLOW +"not saved" + colors.ENDC )
        else:
            print(colors.BOLD  + "\tDestination Keys Folder  " + colors.YELLOW + "missing" + colors.ENDC )

    # Example:
    #    python main.py --keys out/U2 --unciph out/colors.py.enc -k out/U1 -o out/colors.py
    if args.unciph:
        if args.key:
            key      = args.key
            filename = args.unciph

            dest_manager = CipherKey(args.keys, pss, salt)
            dest_pu_k, dest_pr_k = dest_manager.load_RSA()

            content = keyManager.unciph_and_checkSign(filename, dest_pu_k)

            if args.output:
                if content:
                    with open(args.output, "wb") as fp:
                        fp.write(content)

                        print(colors.BOLD  + "\t\tFile " + colors.YELLOW + filename + colors.ENDC + colors.BOLD + " unciphered "+ colors.GREEN +"saved" + colors.ENDC )
            else:
                print(colors.BOLD  + "\t\tFile " + colors.YELLOW + filename + colors.ENDC + colors.BOLD + " unciphered "+ colors.YELLOW +"not saved" + colors.ENDC )
        else:
            print(colors.BOLD  + "\tDestination Keys Folder  " + colors.YELLOW + "missing" + colors.ENDC )

    if args.delete:
        os.remove(args.keys+"/key.bin")
        print(colors.BOLD + "\t-> Deleting Keys... " + colors.GREEN + "OK" + colors.ENDC)
    

if __name__ == "__main__":
    main()