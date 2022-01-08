#!/usr/bin/env python3
import array, base64, random, string
from Crypto.Cipher import AES
from hashlib import sha256
import argparse, subprocess, os


#Defined Functions

def parse_args():

	parser = argparse.ArgumentParser()	
	
	parser.add_argument("-p", "--payload", default="", type=str, help="Enter path to raw shellcode")
	parser.add_argument("-k", "--key", default="", type=str, help="Enter the encryption key if you do not want to use the self-generated key")
	parser.add_argument("-f", "--format", default="b64", type=str, help="Enter the format for the output")
	return parser.parse_args()

def encrypt(key,iv,plaintext):
	key_length = len(key)
	if (key_length >= 32):
		k = key[:32]
	elif (key_length >= 24):
		k = key[:24]
	else:
		k = key[:16]
	
	aes = AES.new(k, AES.MODE_CBC, iv)
	pad_text = pad(plaintext, 16)
	return aes.encrypt(pad_text)
	
def hash_key(key):
	h = ''
	for c in key:
		h += hex(ord(c)).replace("0x", "")
	h = bytes.fromhex(h)
	hashed = sha256(h).digest()
	return hashed
	
def pad(data, block_size):
	padding_size = (block_size - len(data)) % block_size
	if padding_size == 0:
		padding_size = block_size
	padding = (bytes([padding_size]) * padding_size)
	return data + padding
	
def random_key_gen(length):
	letters = string.ascii_letters + string.digits
	result_str = ''.join(random.choice(letters) for i in range(length))
	return result_str
	
def print_banner():
	banner = """
	
  ██████   █████   █    ██  ██▓▓█████▄  ▄████▄   ██▀███ ▓██   ██▓ ██▓███  ▄▄▄█████▓
▒██    ▒ ▒██▓  ██▒ ██  ▓██▒▓██▒▒██▀ ██▌▒██▀ ▀█  ▓██ ▒ ██▒▒██  ██▒▓██░  ██▒▓  ██▒ ▓▒
░ ▓██▄   ▒██▒  ██░▓██  ▒██░▒██▒░██   █▌▒▓█    ▄ ▓██ ░▄█ ▒ ▒██ ██░▓██░ ██▓▒▒ ▓██░ ▒░
  ▒   ██▒░██  █▀ ░▓▓█  ░██░░██░░▓█▄   ▌▒▓▓▄ ▄██▒▒██▀▀█▄   ░ ▐██▓░▒██▄█▓▒ ▒░ ▓██▓ ░ 
▒██████▒▒░▒███▒█▄ ▒▒█████▓ ░██░░▒████▓ ▒ ▓███▀ ░░██▓ ▒██▒ ░ ██▒▓░▒██▒ ░  ░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒ ░▓   ▒▒▓  ▒ ░ ░▒ ▒  ░░ ▒▓ ░▒▓░  ██▒▒▒ ▒▓▒░ ░  ░  ▒ ░░   
░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░  ▒ ░ ░ ▒  ▒   ░  ▒     ░▒ ░ ▒░▓██ ░▒░ ░▒ ░         ░    
░  ░  ░     ░   ░  ░░░ ░ ░  ▒ ░ ░ ░  ░ ░          ░░   ░ ▒ ▒ ░░  ░░         ░      
      ░      ░       ░      ░     ░    ░ ░         ░     ░ ░                       
                                ░      ░                 ░ ░                       
"""
	print(banner)
	
#Main Shellcode Encryptor

def main():
	print_banner()
	args = parse_args()
	file = args.payload
	format = args.format
	key = args.key
	if not key:
		key = random_key_gen(32)

#Encrypt the .bin file

	f = open(file, "rb")
	buf = f.read()
	f.close()
	
	print("[+] key and payload will be written to key.b64 and payload.b64")
	print("[+] Encrypting the payload with key=" + key)
	hkey = hash_key(key)
	encrypted = encrypt(hkey, hkey[:16], buf)
	b64 = base64.b64encode(encrypted)
	
	f = open("./key.b64", "w")
	f.write(key)
	f.close()
	
	f = open("./payload.b64", "w")
	f.write(b64.decode('utf-8'))
	f.close()
	
	if format == "b64":
		print("[+] Base64 output:")
		print(b64.decode('utf-8'))
		print("\n[+] Go forth and hack!")
		return
		
	if format == "c":
		print("[+] C output:")
		hex_string = 'unsigned char payload[] ={0x';
		hex = '0x'.join('{:02x},'.format(x) for x in encrypted)
		hex_string = hex_string + hex[:-1] + "};"
		print(hex_string)
		print("\n[+] Go forth and hack!")
		return
		
if __name__ == '__main__':
	main()
