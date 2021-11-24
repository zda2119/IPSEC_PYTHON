import socket
import scapy
from scapy.layers.inet import TCP
from scapy.layers.ipsec import *

def ipseckickoff():
	p = IP(src='1.1.1.1', dst='2.2.2.2')
	p /= TCP(sport=45012, dport=80)
	p /= Raw('CSEC604:)')
	p = IP(raw(p))

	saESP = SecurityAssociation(ESP, spi=0x222,
		                 crypt_algo='AES-CBC', crypt_key=b'sixteenbytes key',
		                 auth_algo='HMAC-SHA1-96', auth_key=b'secret key')
	e = saESP.encrypt(p)

	assert(isinstance(e, IP))
	assert(e.haslayer(ESP))
	assert(not e.haslayer(TCP))
	assert(e[ESP].spi == saESP.spi)

	saAH = SecurityAssociation(AH, spi=0x221,
                     auth_algo='SHA2-256-128', auth_key=b'secret key')

	f = saAH.encrypt(e)

	assert(isinstance(f, IP))
	assert(f.src == '1.1.1.1' and e.dst == '2.2.2.2')
	assert(f.chksum != p.chksum)
	assert(f.proto == socket.IPPROTO_AH)
	#assert(f.haslayer(TCP))
	assert(f.haslayer(AH))

	
	print("\nFinal IP Packet with Encrypted & Authenticated ESP and Authenticated AH: " + str(f) + "\n")

	###DECRYPT###
	print("Copy of Encrypted and Authenticated Packet Created")
	print("Decrypting Packet using Security Associations")
	d = saESP.decrypt(e)
	print("Comparing Decrypted Packet Copy to Original Packet: " + str(d[TCP] == p[TCP]))
	print("Original Packet: " + str(p[TCP]))
	print("Encrypted & Unencrypted packet: " + str(d[TCP]))

ipseckickoff()


