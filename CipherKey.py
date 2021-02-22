#!/usr/bin/env python3

__version__    = "1.1.0"
__author__     = "Althernis"
__maintainer__ = "Althernis"
__status__     = "Production"
__info__       = "Free to use, but a mention would be nice :D"

import os
from colors import colors

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2


class CipherKey:

    RSATAM = 256 # RSA Size
    AESTAM = 32  # AES Size
    IVTAM  = 16  # IV  size

    def __init__(self, path, pss, salt):
        '''
        Constructor

        @param       path      path to store the keys
        @param       pss       password to generate RSA Keys
        @param       salt      salt to generate RSA Keys
        '''
        self.path = path
        self.pss = pss
        self.salt = salt
        if pss and salt:
            self.master_key = PBKDF2(pss, salt, count=16384)  # bigger count = better

    def rand_gen_func(self, n):
        # kluge: use PBKDF2 with count=1 and incrementing salt as deterministic PRNG
        self.counter += 1
        return PBKDF2(self.master_key, "rand_gen_func:%d" % self.counter, dkLen=n, count=1)

    ###################################################################
    ######                  INNER FUNCTIONS                      ######
    ################################################################### 

    def sign(self, file):
        """
        Sign the file 

        @param       file      File path

        @return sign + file content
        """

        if not os.path.exists(file):
            print(colors.BOLD+"The file "+colors.YELLOW + file + colors.ENDC + colors.BOLD + " doesnt exist." + colors.ENDC)
            return None
        
        f = open(file, "rb")
        content = f.read()
        f.close()
        
        print("{}\t-> Signing file...{} OK{}".format(colors.BOLD, colors.GREEN, colors.ENDC))
        key = RSA.import_key(open(self.path + '/key.bin').read()) # Import private key
        
        hash = SHA256.new(content)          # Messages Hash
        sign = pkcs1_15.new(key).sign(hash) # Hash signed with key

        return sign + content

    def check_sign(self, sign, message, user_key):
        """
        Check the validity of the sign.

        @param       sign         Messages Sign
        @param       message      Messages Content
        @param       user_key     Public User Key

        @return      True if sign is ok, False if not
        """

        key = RSA.import_key(user_key)    # Import user key
        hash = SHA256.new(message)        # Generate the messages HASH


        try:
            pkcs1_15.new(key).verify(hash, sign) # Check the sign

            print(colors.BOLD + "\t-> Verifiying sign... " + colors.GREEN + "OK" + colors.ENDC)

            return True

        except (ValueError, TypeError):

            print(colors.BOLD + "\t-> Verifiying sign... " + colors.RED + "ERROR" + colors.ENDC)

            return False

    def cipher(self, content, public_user_key):
            """
            Cipher the content using random AES key and IV

            @param       content              Content to cipher
            @param       public_user_key      Destination Public Key

            @return      IV + ciphered_key + ciphered_content or None
            """
    
            if public_user_key == None or public_user_key == '':
                return None

            print("{}\t-> Ciphing file... {}OK{}".format(colors.BOLD, colors.GREEN, colors.ENDC))
            
            # Random IV
            iv = get_random_bytes(self.IVTAM)

            # Random AES key
            key = get_random_bytes(self.AESTAM)

            # Paddint to 16 Bytes
            content = Padding.pad(content, self.IVTAM)

            # Ciphing using AES (CBC mode) with IV
            aes_key = AES.new(key, AES.MODE_CBC, iv)

            # Ciphering the content with AES
            ciphered_message = aes_key.encrypt(content)

            # Import destination key
            public_dest_key = RSA.import_key(public_user_key)


            # Cipher AES key
            ciph = PKCS1_OAEP.new(public_dest_key)
            ciphered_key =  ciph.encrypt(key)

            return iv + ciphered_key + ciphered_message

    def unciph(self, key, iv, ciphered_message):
        """
        Unchiph the message with the key and iv given

        @param       key                 AES key
        @param       iv                  IV (for AES)
        @param       ciphered_message    Mensaje cifrado

        @return      Unciphered mesage
        """
        # Get the cipher
        ciph = AES.new(key, AES.MODE_CBC, iv)

        # Unpad 
        return Padding.unpad(ciph.decrypt(ciphered_message), self.IVTAM)

    def unciph_aes_key(self, ciphered_key):
        """
        Unciph the ciphered key to get the AES Key

        @param       ciphered_key      Ciphered Key 

        @return      Key
        """
        # Read the private user key
        with open(self.path + "/key.bin", "rb") as fp:
            raw_key = fp.read()

        # Import RSA Key
        key = RSA.import_key(raw_key)

        # Get the ciph using the key
        ciph = PKCS1_OAEP.new(key)

        try: 
            return ciph.decrypt(ciphered_key)
        except:
            return None

    def unciph_file(self, file):
        """
        Unciph the file, reading it

        @param       file      Ciphered File Name

        @return      Content or None
        """
        # Check if exist file
        if not os.path.exists(file):
            return None

        # Get the content
        with open(file, 'rb') as f:
            message = f.read()

        # Get parameters
        # [IV [0:16]][CIPHERED_KEY [16:272]][CONTENT [272:-1]]
        iv = message[ : self.IVTAM]
        ciphered_key = message[self.IVTAM : self.RSATAM + self.IVTAM]
        ciphered_content = message[self.RSATAM + self.IVTAM : ]

        # Get the key
        key = self.unciph_aes_key(ciphered_key)

        if key == None:
            return None

        # Unciph using the parameters
        content = self.unciph(key, iv, ciphered_content)

        return content

    ###################################################################
    ######                  FULL FUNCTIONS                       ######
    ###################################################################     
    def load_RSA(self):
        '''
        Try to load the keys. If its imposible, generate new ones

        @return  private key, public key
        '''
        public_key = None
        private_key = None

        # Load public key
        if os.path.exists(self.path + "/key.pub"):
            with open(self.path + "/key.pub","rb") as fp:
                public_key = fp.read()

        # Load private key
        if os.path.exists(self.path + "/key.bin"):
            with open(self.path + "/key.bin","rb") as fp:
                private_key = fp.read()

        # if none are None
        if private_key and public_key:
            return private_key, public_key
        # otherwise, generate new ones
        else:
            return self.generate_RSA()

    def generate_RSA(self, size = 2048):
        '''
        Generate two files on self.path with private/public keys

        @param       size      key size

        @retrun private key, public key
        '''
        if self.pss and self.salt:
            self.counter = 0
            key = RSA.generate(size, e = 65537, randfunc=self.rand_gen_func)
        else:
            key = RSA.generate(size, e = 65537)

        # Key generation
        public_key   = key.publickey().exportKey('PEM')
        private_key  = key.exportKey('PEM')

        if not os.path.exists(self.path):
            os.makedirs(self.path)

        # Output files
        path_priv = self.path + '/key.bin'
        path_pub  = self.path + '/key.pub'

        # Export keys to files
        with open(path_priv, 'wb') as fp:
            fp.write(private_key)

        with open(path_pub, 'wb') as fp:
            fp.write(public_key)

        print(colors.BOLD + "\t-> Generating Keys... " + colors.GREEN + "OK" + colors.ENDC)

        return private_key, public_key

    def unciph_and_checkSign(self, file, public_user_key):
        """
        Unciph and check the Sign with the key
        
        @param       file      Singed and Ciphered Filename 
        @param       public_user_key     Public User Key

        @return      Content or None 
        """

        # Unciph the file, getting signed file
        content = self.unciph_file(file)

        if content != None:
            print(colors.BOLD + "\t-> Unciphing file... " + colors.GREEN + "OK" + colors.ENDC)
        else:
            print(colors.BOLD + "\t-> Unciphing file... " + colors.RED + "ERROR" + colors.ENDC)

            return None
       
        sign = content[0:self.RSATAM]   # Sign (first 256B()
        message = content[self.RSATAM:] # Message Content

        # Check the sign
        res = self.check_sign(sign, message, public_user_key)

        if res: # If is correct
            return message
        else:
            return None

    def sign_and_ciph(self, file, public_user_key):
        """

        Sign and then Ciph the file with the key
        
        @param       file                Filename
        @param       public_user_key     Public User Key

        @return      Ciphered and Singed content
        """
        # Sign, getting content
        signed_data = self.sign(file)
        if signed_data == None:
            return

        # Ciphing data
        ciphered_signed_data = self.cipher(signed_data, public_user_key)

        return ciphered_signed_data

   



