#!/usr/bin/env python3

__version__    = "1.0.0"
__author__     = "Althernis"
__maintainer__ = "Althernis"
__status__     = "Production"
__info__       = "Free to use, but a mention would be nice :D"


from colors import colors
import argparse

FONT = """

{}   _____ _       _              {} _  __              
{}  / ____(_)     | |             {}| |/ /              
{} | |     _ _ __ | |__   ___ _ __{}| ' / ___ _   _ ___ 
{} | |    | | '_ \| '_ \ / _ \ '__{}|  < / _ \ | | / __|
{} | |____| | |_) | | | |  __/ |  {}| . \  __/ |_| \__ \\
{}  \_____|_| .__/|_| |_|\___|_|  {}|_|\_\___|\__, |___/
{}          | |                   {}           __/ |    
{}          |_| {}     ╔══╗  ╔══╗  ╔══╗   {}   |___/     
{}              ╦╦╦══╣  ║  ║  ║  ║  ╠══╦╦╦   
                   ╚══╝  ╚══╝  ╚══╝         
                          
{}    Use -h to see more
""".format(colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.GREEN,colors.RED,colors.YELLOW, colors.GREEN,colors.YELLOW,colors.ENDC)



def getParser():

    parser = argparse.ArgumentParser(description="CipherKey")

    parser.add_argument('--keys','-ks',
                        help='Generate Pair RSA Keys.')

    parser.add_argument('--ciph', '-c',
                        help='Sign and Ciph a file.')

    parser.add_argument('--unciph', '-u',
                        help='Unciph and Check Sign of a file.')

    parser.add_argument('--key','-k',
                        help='Key to Use')

    parser.add_argument('--output','-o',
                        help='OutputFile')

    parser.add_argument('--verbose','-v', action='store_true',
                        help='Verbose')

    parser.add_argument('--examples','-e', action='store_true',
                        help='Show some examples')

    return parser
