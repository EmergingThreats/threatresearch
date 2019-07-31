#Decrypt Config in SystemBC
#@category Memory.SystemBC
#@menupath Scripts.XORscript

#Usage: Highlight encrypted bytes, run script, input XOR key starting address

import os

def get_plain_buf():
	#Check for the Highlight
	try:
		enc_buf_start = currentSelection.getMinAddress().getOffset()
		enc_buf_end = currentSelection.getMaxAddress().getOffset()
	except:
		print("Highlight the encrypted data!")
		exit()

	current_addr = toAddr(enc_buf_start)
	enc_buf = []
	
	#Create Encrypted Buffer
	while current_addr != toAddr(enc_buf_end):
		enc_buf.append(getByte(current_addr))
		current_addr = current_addr.add(1)

	#Retrieve Key
	key_addr = askLong("XOR Key", "Input the starting address of the XOR key.")
	key_len = 40
	plain_buf = [] 

	#XOR Key and Data
	for i, enc_byte in enumerate(enc_buf):
		key_byte = getByte(toAddr(key_addr + (i % key_len)))
		plain_byte = enc_byte ^ key_byte
        	plain_buf.append(plain_byte)
	return plain_buf

def hexdump(byte_array):
	#Create Binary File
	f = open('output.log', 'w+b')
	f.write(byte_array)
	f.close()
	
	#Save Hexdump
	os.system("rm hexdump.log")	
	os.system("hexdump -C output.log >> hexdump.log")
	os.system("rm output.log")
	
	#Dislay Results
	f = open('hexdump.log', 'r')
	content = f.read()
	f.close()
	print(content)

def run():
	plainstr = get_plain_buf()
	binary_format = bytearray(plainstr)
	hexdump(binary_format)
	print("Output saved to hexdump.log")

run()
