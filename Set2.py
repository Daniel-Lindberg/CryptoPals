"""
Internet of Things
Set 2
Author: Daniel Lindberg
"""
from Crypto.Cipher import AES
from random import randint
from collections import defaultdict


#-----------------------------------------------------------
#Challenge 9: Implement PKCS#7 padding

def padPKC27(x, k):
	# Pad some bytes k, k amount of times to end of buffer 
	ch = k - (len(x) % k)
	return x + bytes([ch] * ch)

def unpadPKC27(input_bytes):
	# Unpad some bytes , from the end of a buffer
	padding = input_bytes[-1]
	for i in range(len(input_bytes) - 1, len(input_bytes) - padding - 1, -1):
		if input_bytes[i] is not input_bytes[-1]:
			return input_bytes
	new_input_bytes = bytearray()
	new_input_bytes[:] = input_bytes[:-padding]
	return new_input_bytes
# Test it with a string
test_string = b"YELLOW SUBMARINE"
# Pad the buffer of 20 to the end of the string
y = padPKC27(test_string, 20)
print "Challenge 9:" + str(y)

#-----------------------------------------------------------
#Challenge 10: Implement CBC Mode

# This is a copy from set 1
def XORCombo(buffer1, buffer2):
	temp_buffer = bytearray(len(buffer1))
	for sub_byte in range(len(buffer1)):
		temp_buffer[sub_byte] = buffer1[sub_byte] ^ buffer2[sub_byte]
	return temp_buffer

# Decrypt the AES ECB with some key
def decryptECB(input_bytes , key):
	block = AES.new(key, AES.MODE_ECB)
	return bytearray(block.decrypt(bytes(input_bytes)))

# Decrypt the AES CBC with some key and the (IV) initialization vector
def decryptCBC(cipher_text, key, iv):
	plain_message = bytearray(len(cipher_text))
	start_block = iv
	# Go throguh the range of the blocks
	for i in range(0, len(cipher_text), AES.block_size):
		# Decrypt string with ECB
		aes_ecb = decryptECB(bytes(cipher_text[i: i+AES.block_size]), key)
		plain_message[i: i + AES.block_size] = XORCombo(aes_ecb, start_block)
		start_block = cipher_text[i: i+AES.block_size]
		# Unpad the message 
	return unpadPKC27(plain_message)

# Read the 10th document
cipher_message = bytearray("".join(list(open("10.txt", "r"))).decode("base64"))
cipher_key = b"YELLOW SUBMARINE"
# Keep the same cipher key, create initialization vector to be a bytearray of blank characters
iv = bytearray([chr(0)] * AES.block_size)
print "Challenge 10: Too long for print, uncomment if interested"
#print decryptCBC(cipher_message, cipher_key, iv)

#-----------------------------------------------------------
#Challenge 11: An ECB/CBC detection oracle

# Add the encryption of AES ECB
def encryptECB(input_bytes , key):
	block = AES.new(key, AES.MODE_ECB)
	return bytearray(block.encrypt(bytes(input_bytes)))

# Encrypt the AES CBC, copy of decrypt function with small changes
def encryptCBC(cipher_text, key, iv):
	plain_message = padPKC27(cipher_text, AES.block_size)
	cipher_message = bytearray(len(plain_message))
	start_block = iv
	for i in range(0, len(plain_message), AES.block_size):
		resultant = XORCombo(plain_message[i: i+AES.block_size], start_block)
		cipher_message[i: i + AES.block_size] = encryptECB(resultant,key)
		start_block = cipher_message[i: i+AES.block_size]
	return cipher_message

# obtain a random key given a key_length
def obtainRandomKey(key_length):
	new_key = bytearray(key_length)
	for i in range(key_length):
		new_key[i] = chr(randint(0,255))
	return new_key

print repr(obtainRandomKey(16))

def encryptionOracle(your_input):
	pad_bytes = randint(5, 10)
	plain_text = padPKC27(obtainRandomKey(pad_bytes) + your_input + obtainRandomKey(pad_bytes),
		AES.block_size)
	new_key = bytes(obtainRandomKey(16))
	# Should be about half the time
	if randint(0, 1):
		# Encrypt using ECB
		return encryptECB(plain_text, new_key)
	else:
		# Encrypt using CBC
		iv = obtainRandomKey(16)
		return encryptCBC(plain_text, new_key, iv)

encrypt_bytes = bytearray("This is a test string")
#encryptionOracle(encrypt_bytes)
print "Challenge 11: Too long for print, uncomment if interested"
#print decryptCBC(cipher_message, cipher_key, iv)

#come back to

#-----------------------------------------------------------
#Challenge 12: Byte-at-a-time ECB decyrption
# Encrypts the oracle string, which is just encrypting a buffer with either ECB or CBC
def encryptOracle(input_string):
	example_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	resultant_string = bytearray((example_string).decode("base64"))
	plain_text = padPKC27(input_string + resultant_string, AES.block_size)
	return encryptECB(plain_text, bytes(obtainRandomKey(16)))

def getBlock(oracle_message):
	cipher_length = len(oracle_message(bytearray()))
	i = 1
	while True:
		encryption = bytearray("A" * i)
		updated_length = len(oracle_message(encryption))
		if cipher_length is not updated_length:
			return updated_length - cipher_length
		i = i + 1

# Find the number of repeitions insize of blocks in a string
# Helps with finding encryption algorithm
def numberRepeats(input_string, block_size=16):
	repetitions = defaultdict(lambda: -1)
	for i in range(0, len(input_string), block_size):
		new_block = bytes(input_string[i:i+block_size])
		repetitions[new_block] = repetitions[new_block] + 1
	summation = 0
	for entry in repetitions:
		summation = summation + entry
	return summation

# Checks to see if it ECB
def isECB(input_string, block_size):
	return numberRepeats(input_string, block_size) > 0

# Get the length of some unknown string
def getUnknownLength(some_string):
	cipher_length = len(some_string(bytearray()))
	i = 1
	while True:
		data = bytearray("A" * i)
		new_length = len(some_string(data))
		if cipher_length is not new_length:
			return new_length - 1
		i = i +1

def decryptUnknownString(oracle_message):
	new_block = getBlock(oracle_message)
	if not isECB():
		raise Exception("hey this isn't ECB")
	unknown_string_length = getUnknownLength(oracle_message)
	unknown_string = bytearray()
	adjusted_length = ((unknown_string_length / new_block) + 1) * new_block
	for i in range(adjusted_length - 1, 0, -1):
		data = bytearray("A" * i)
		cipher = oracle_message(data)[:adjusted_length]
		for sub_char in range(256):
			data2 = data[:] + unknown_string + chr(c)
			cipher2 = oracle_message(data2)[:adjusted_length]
			if cipher1 is not cipher2:
				unknown_string = unknown_string + chr(c)
				break
	return unknown_string

print "Challenge 11: Too long for print, uncomment if interested"
#print decryptUnknownString(encryptOracle)

#-----------------------------------------------------------
#Challenge 13: ECB cut-and-paste

key = bytes(obtainRandomKey(AES.block_size))

def parseDict(input_string):
	# Parse dictionary for any dictionary value with an equal sign
	new_dict = {}
	for joining in string.split("&"):
		dict_entry = joining.split("=")
		new_dict[dict_entry[0]] = dict_entry[1]
	return new_dict

def obtainProfile(email_input):
	# Obtain the profile of some email string
	# remove the special characters and the profile is the email value
	email = bytes(email_input)
	email = email.replace("&", "")
	email = email.replace("=", "")
	profile = "email=" + email + "&uid=10&role=user"
	new_buffer = bytes(padPKC27(bytearray(profile), AES.block_size))
	return encryptECB(new_buffer, key)

def decryptProfile(profile_input):
	# Unpad the profile and then also decrypt it with ECB
	return bytes(unpadPKC27(decryptECB(profile_input, key)))

def createAdmin():
	# Creates the admin profile
	# Gets the data associated with the profile
	# Gets email associated with said profile
	block_size = getBlock(obtainProfile)

	minimum_bytes = len("email=&uid=10&role=")
	following_bytes = (len(minimum_bytes)/block_size +1) * block_size
	length_email = following_bytes - minimum_bytes
	data = "A" * length_email
	role_part = obtainProfile(bytearray(data))[:following_bytes]

	minimum_bytes = len("email=")
	following_bytes = (len(minimum_bytes)/block_size +1) * block_size
	length_email = following_bytes - minimum_bytes
	data = "A" * length_email
	data = data + padPKC27("admin", block_size)
	email_part = obtainProfile(data)[following_bytes:following_bytes + block_size]

	new_profile = role_part + email_part
	return bytes(decryptProfile(new_profile))

print "Challenge 13: Too long for print, uncomment if interested"
#print  createAdmin()

#-----------------------------------------------------------
#Challenge 14: Byte-at-a-time ECB decryption
key = bytes(obtainRandomKey(16))
prefix = obtainRandomKey(randint(0, 256))

# Get the prefix associated with a message
# Index of first byte n blocks is beginning of the input
# and length of the prefix
def obtainPrefix(oracle_message, block_size):
	for padding in range(block_size):
		default_reps = 10
		prefix_pad = bytearray("A" + padding)
		string_message = oracle_message(prefix_pad + bytearray("YELLOW SUBMARINE" * default_reps))
		index = None
		count = index
		prev_block = count
		for i in range (0, len(string_message), block_size):
			block = string_message[i: i + block_size]
			if block == prev_block:
				count = count + 1
			else:
				index = 1
				prev_block = block
				count = 1
			if count == default_reps:
				return index, padding

# Decrypt the unknown orcale message
# Find the unknown length which should involve the prefix
# Decrypt the oracle message
def decryptUnknownStringNew(oracle_message):
	new_block = getBlock(oracle_message)
	prefix_size , padding_size = obtainPrefix(oracle_message, new_block)
	unknown_string_length = (
		getUnknownLength(oracle_message) - prefix_size - padding_size
		)
	unknown_string = bytearray()
	adjusted_length = ((unknown_string_length/block_size) + 1) * block_size

	for i in range(adjusted_length - 1, 0, -1):
		data = bytearray("A" * (i + padding_size))
		cipher = oracle_message(data)[prefix_size:adjusted_length + prefix_size]
		for sub_char in range(256):
			data2 = data[:] + unknown_string + chr(c)
			cipher2 = oracle_message(data2)[prefix_size:adjusted_length+ prefix_size]
			if cipher1 is not cipher2:
				unknown_string = unknown_string + chr(c)
				break
	return unknown_string

print "Challenge 14: Too long for print, uncomment if interested"
#print decryptUnknownStringNew(encryptOracle)


#-----------------------------------------------------------
#Challenge 15: PKCS#7 padding validation
#Check if the string has valid PKCS padding,
# throws exception if not
def validPKCS7(input_string):
	padding = input_string[-1]
	if padding >= AES.block_size:
		return input_string
	for i in range(len(input_string)-1, len(input_string)-padding,-1):
		if input_string[i] is not input_string[-1]:
			raise Exception("Not valid PKCS padding")
	buffer = bytearray()
	buffer[:] = input_string[:-padding]
	return buffer


print "Challenge 15: "+validPKCS7(bytearray("ICE ICE BABY\x04\x04\x04\x04"))


#-----------------------------------------------------------
#Challenge 16: CBC bitflipping attacks

# Has a key be a random key
key = bytes(obtainRandomKey(AES.block_size))

# Create a random itinalization vector 
iv = bytearray(obtainRandomKey(AES.block_size))

# Encrypt the oracle string with the input strings of cooking and bacon
def encryptOracle2(input_string):
	input_string = input_string.replace(";", '%3b')
	input_string = input_string.replace('=', '%3d')
	comment_cooking = "comment1=cooking%20MCs;userdata="
	comment_bacon = ";comment2=%20like%20a%20pound%20of%20bacon"
	plain_text = bytearray(comment_cooking + input_string + comment_bacon)
	return encryptCBC(plain_text, key, iv)

# Checks to see if admin is in the profile
def isAdmin(input_string):
	plain_text = encryptCBC(input_string, key, iv)
	if ";admin=true" in plain_text:
		return True
	else:
		return False

# Crack the message by finding if admin
# Then XORing the cipher message
def crackMessage():
	first_block = bytearray("A" * AES.block_size)
	second_block = bytearray("AadminAtrueA")
	plain_text = first_block + second_block
	cipher_message = encryptOracle2(plain_text)

	cipher_message[32] = bytes(XORCombo(bytearray(chr(cipher_message[32])), XORCombo(bytearray("A"), bytearray(";"))))
	cipher_message[38] = bytes(XORCombo(bytearray(chr(cipher_message[38])), XORCombo(bytearray("A"), bytearray(";"))))
	cipher_message[43] = bytes(XORCombo(bytearray(chr(cipher_message[43])), XORCombo(bytearray("A"), bytearray(";"))))
	return isAdmin(cipher_message)

print "Challenge 16:" + print crackMessage()