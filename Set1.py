"""
Industrial Internet of Things
Author: Daniel Lindberg
"""

#Native python modules
import re

#Challenge 1: Hex to base 64
def hexToBase64(hex_string):
	# Decode as hex, encode as base 64
	return hex_string.decode("hex").encode("base64")
print "Challenge1:"+hexToBase64(hex_string="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 2: Fixed XOR
def XORCombo(buffer1, buffer2):
	# Takes input of two equal-length buffers
	# Produce XOR combination
	temp_buffer = bytearray(len(buffer1))
	for sub_byte in range(len(buffer1)):
		# Is the XOR combination
		temp_buffer[sub_byte] = buffer1[sub_byte] ^ buffer2[sub_byte]
	return temp_buffer

c2_string = bytearray.fromhex('1c0111001f010100061a024b53535009181c')
c2_string_2 = bytearray.fromhex('686974207468652062756c6c277320657965')
print "Challenge2:"+bytes(XORCombo(c2_string, c2_string_2)).encode("hex")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 3: Single-byte XOR cipher
# Finds digits within brackets (ex: [45] to 45)
RE_char_values = re.compile(r"\[(\d+)\]")

# Found the frequency of each letter below
#from https://en.wikipedia.org/wiki/Letter_frequency
character_frequencies = {
	'a': 0.08176, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
	'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06094, 'j': 0.00153,
	'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
	'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
	'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
	'z': 0.00074, ' ': 0.13000
}
def getEnglishScores(input_bytes):
	sum_score = 0
	# Find if the number associated with a character, sums them up to a score
	for sub_num in RE_char_values.findall(input_bytes):
		if character_frequencies.get(chr(int(sub_num))):
		 	sum_score = sum_score + character_frequencies.get(chr(int(sub_num)))
	return sum_score

# Obtains a character XOR
def charXOR(input_bytes, char_score):
	output_bytes = b''
	# Output byte is the second buffer of 'equal length'
	for single_byte in input_bytes:
		output_bytes = output_bytes + bytes([single_byte ^ char_score])
	return output_bytes	

# Is the initial string to start with
c3_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
# Gets a mutable seauence of intergers in nominal range (256)
c3_cipher = bytearray.fromhex(c3_string)
# Following 3 variables are what the max score will be
max_score = 0
high_message = ""
master_key = None
# Go through each key, find the score of that value, and store it
for potential_key in range(256):
	message = charXOR(c3_cipher, potential_key)
	score = getEnglishScores(message)
	if score > max_score:
		max_score = score
		high_message = message
		master_key = chr(potential_key)


RE_char_values = re.compile(r"\[(\d+)\]")
# Print the maximum value
print "Challenge 3:"
print "key :" + master_key
print "message:" + "".join([chr(int(sub_char)) for sub_char in RE_char_values.findall(high_message)])

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 4: Detect single-character XOR

#Gets the score of a string
def getScore(input_string):
	max_score = 0
	# Iterate through each character and add it to max Score
	for sub_char in input_string.lower():
		if sub_char in character_frequencies:
			max_score = max_score + character_frequencies[sub_char]
	return max_score

# Is the inital variables that will be the maximum score
max_score = None
high_message = ""
master_key = None

# Read the 4 text document and strip each line
for line in open("4.txt", "r"):
	line = line.rstrip()
	# Get hex for said line
	buffer1 = bytearray.fromhex(line)
	for potential_key in range(256):
		# Get the XOR of the two strings, get the score of said strings
		buffer2 = [potential_key] * len(buffer1)
		plain_text = bytes(XORCombo(buffer1,buffer2))
		score = getScore(plain_text)
		# If this is the highest, we record those values
		if score > max_score:
			max_score = score
			high_message = plain_text
			master_key = chr(potential_key)
print "Challenge 4:"
print "key :" + str(master_key)
print "message:" + high_message


#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 5: Repeating-key XOR

opening_stanza = ["Burning 'em, if you ain't quick and nimble\n",
					"I go crazy when I hear a cymbal"]

# get the stanza text joined into one giant string
stanza_text = "".join(opening_stanza)
# put ICE in the sequence of intergers in the stanza
key_array = bytearray("ICE" * len(stanza_text))
# XOR the new byte array with ICE and the stanza and convert it to bytes and then encode it
plain_text = bytes(XORCombo(bytearray(stanza_text), key_array))
print "Challenge 5:"+ plain_text.encode("hex")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 6: Break Repeating-key XOR
buffer1 = bytearray("this is a test")
buffer2 = bytearray("wokka wokka!!!")

# obtain hamming distance
def hammingDist(encrypted_string1, encrypted_string2):
	bits_different = 0
	# Get XOR value of two encrypted strings, bit difference is the XOR combo
	for sub_byte in XORCombo(encrypted_string1, encrypted_string2):
		bits_different = bits_different + bin(sub_byte).count("1")
	return bits_different

#get file into cipher text
cipher_array = bytearray("".join(list(open("6.txt","r"))).decode("base64"))

distances = {}
print "Challenge 6:  Too long of a printout, uncomment printouts below"
for key_length in range(2,40):
	# obtain 4 buffers which are the lengths inbtween each 4 key_lengths
	buffer1 = cipher_array[: key_length]
	buffer2 = cipher_array[key_length: key_length * 2]
	buffer3 = cipher_array[key_length * 2: key_length * 3]
	buffer4 = cipher_array[key_length * 3: key_length * 4]
	# Get the hamming distance between buffers 
	dist_1 = hammingDist(buffer1, buffer2)
	dist_2 = hammingDist(buffer2, buffer3)
	dist_3 = hammingDist(buffer3, buffer4)
	# Get the summing distance between all 3 hamming distances
	sum_dist = (key_length*3)
	sum_distance = float(dist_1+dist_2+dist_3)/sum_dist
	distances[key_length] = sum_distance

# Do the same process as 4 and 5, getting the maximum score
for key_length in distances:
	sub_distance = [[] for unit in range(len(distances.keys()))]
	for iteration, sub_byte in enumerate(cipher_array):
		sub_distance[(iteration % key_length)-1].append(sub_byte)

	keys = ""

	for sd in sub_distance:
		max_score = None
		high_message = None
		key = None

		for i in range(256):
		    buffer1 = [i] * len(sd)
		    plain_text = bytes(XORCombo(sd, buffer1))
		    score = getScore(plain_text)

		    if score > max_score:
		        max_score = score
		        high_message = plain_text
		        key = chr(i)
		keys = keys + key

	new_key = bytearray(keys * len(cipher_array))
	real_message = bytes(XORCombo(cipher_array, new_key))

	#print keys
	#print key_length
	#print real_message


#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 7: AES in ECB mode

from Crypto.Cipher import AES
# Have Yellow submarine in ECB mode
obj = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
# Open up the 7th document, decode it and then decrypt with yellow submarine
cipher_message = "".join(list(open("7.txt", "r"))).decode("base64")
plain_text = obj.decrypt(cipher_message)
print "Challenge 7: Is also too long, uncomment in code if interested in output \n" 
#print plain_text

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Challenge 8: Detect AES in ECB mode

# Count the repetitions in the cipher text
def countRepetitions(cipher_text, block_size):
	# the cipher_text along with the block used in encryption
	snippet = [cipher_text[i:i+block_size] for i in range(0, len(cipher_text), block_size)]
	snippet_set = set()
	# Break the block size up into snippets, then parse the snippet
	for sub_byte_array in snippet:
		snippet_set.add(bytes(sub_byte_array))
	repetition_numbers = len(snippet) - len(snippet_set)
	# Put the resultant numbers into a dictionary value
	resultant = {
		"Cipher_Text": cipher_text,
		"Repetiion_Numbers": repetition_numbers
	}
	return resultant

# Strip line for line the 8th document
cipher_message = [bytearray(line.rstrip()) for line in open("8.txt")]
block_size = 16 # byte
repetitions = [countRepetitions(sub_cipher, block_size) for sub_cipher in cipher_message]
#Get repeititons and count the most
most_reps = sorted(repetitions, key=lambda x: x["Repetiion_Numbers"])[-1]
# Print the highest value
print "Challenge 8:"
print "Ciphertext:"+most_reps["Cipher_Text"]
print "Repetition Numbers:" + str(most_reps["Repetiion_Numbers"])




