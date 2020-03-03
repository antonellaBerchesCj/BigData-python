from __future__ import division
import itertools
from nltk.collocations import *
import nltk

import re
import pefile
import sys
import pydasm
import distorm3

def find_entryPoint_section(pe, eop_rva):
    for section in pe.sections:
        if section.contains_rva(eop_rva):
            return section
    return None
	
def extract_info():
	pe = pefile.PE('WinRar.exe')

	#pe.parse_data_directories()
#https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
	if (pe.FILE_HEADER.Machine == 0x014c):
		print 'Executable platform: x86'
	elif (pe.FILE_HEADER.Machine == 0x0200):
		print 'Executable platform: IntelItanium'
	elif (pe.FILE_HEADER.Machine == 0x8664):
		print 'Executable platform: x64'
		
	print 'Number Of Sections: %x\n' % pe.FILE_HEADER.NumberOfSections
	# preluare nr sectiuni executabile
	for section in pe.sections:
		if pe.FILE_HEADER.Characteristics & 0x0002: #and cu al 2lea bit din characteristics
			print 'Section %d (%s) is executable' % (section.Characteristics,section.Name)

	#Entry Point is the 1st executed byte in the PE file		
	# preluare nr sectiunii in care se afla entry point-ul
	for section in pe.sections:
		if((pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress) and (pe.OPTIONAL_HEADER.AddressOfEntryPoint < (section.VirtualAddress + section.Misc_VirtualSize))):
			print '\nAddressOfEntryPoint: %x\n' % pe.OPTIONAL_HEADER.AddressOfEntryPoint # AddressOfEntryPoint if guaranteed to be the first byte executed

def clean_NOPS():
	word='nop'
	with open('opcodes.txt', 'r') as infile:
		newlist= [i for i in infile.read().split() if i!=word]
	with open('opcodes1.txt','w') as outfile:
		outfile.write('\n'.join(newlist))
	print 'opcodes1.txt file created'
	return newlist

def replace_opcodes(opcode):
	to_replace = ['sub', 'inc']
	for word in to_replace:
		opcode = opcode.replace(word, 'add')
			
	return opcode

def ngrams(text):
	tokens = nltk.wordpunct_tokenize(text)
	fourgrams=nltk.collocations.QuadgramCollocationFinder.from_words(tokens)
	for fourgram in fourgrams.ngram_fd.items():
		#print fourgram
		with open('ngrams.txt','a') as outfile:
			outfile.write(str(fourgram))
	return 'ngrams.txt file created'

def jaccard_set():
	set1 = set(line.strip() for line in open('opcodes_chrome.txt'))
	set2 = set(line.strip() for line in open('opcodes_win.txt'))

	unionList = set(set1)
	intersectList = set (set2)

	u = set(set1).union(set2)
	i = set(set1).intersection(set2)

	return len(i)/len(u)

	
def main(file_path):
	pe = pefile.PE('WinRar.exe')
	
	# Store the file in a variable
	fd = open(file_path, 'rb')
	data = fd.read()
	fd.close()
	
    # AddressOfEntryPoint if guaranteed to be the first byte executed.
	eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	code_section = find_entryPoint_section(pe, eop)
	if not code_section:
		return
	
	for section in pe.sections:
		if((pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress) and ((pe.OPTIONAL_HEADER.AddressOfEntryPoint -  section.VirtualAddress) <  section.Misc_VirtualSize)):
			print 'EntryPoint is inside the section: ', (section.Name)
		
		#print  (section.Name), 'Address Of EntryPoint', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)


	print('\nEntryPoint section found at offset: {:#x} [size: {:#x}]'.format(code_section.PointerToRawData, code_section.SizeOfRawData))

	print 'Relation [EntryPoint <-> section length]: %.2f' % (sys.getsizeof(code_section.SizeOfRawData) / code_section.PointerToRawData)
	
	# Get the EP, raw size and virtual address of the code
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point
	raw_size = pe.sections[0].SizeOfRawData #Raw Size
	ep_va = ep + pe.OPTIONAL_HEADER.ImageBase #EP VA
	
	#Start disassembly at the EP: pentru a extrage instructiuni se porneste de la PointerToRawData
	raw_text_start = section.PointerToRawData
	offset = ep

	f = open('opcodes.txt', 'a')
	# Loop until the end of the .text section
	while offset < (offset + raw_size):
		# Get the first instruction
		i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
		
		# Print a string representation if the instruction	
		opcodes = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset)
		#print opcodes
		try:
			f.write(pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_va + offset))
			f.write('\n')
		except:
			pass
		if not i:
			break
		# Go to the next instruction
		offset += i.length
		
		#f.close()
		
		#clean opcode:
		#1. remove instructions (ex. nop)
		to_remove='nop'
		newlist= [i for i in opcodes.split() if i!=to_remove]
		clean_opcode = '\n'.join(newlist)
		
		#2. replace inc and sub with add
		last_clean_opcode = replace_opcodes(clean_opcode)
					
		with open('opcodes_chrome.txt','a') as outfile:
			outfile.write(last_clean_opcode)

		
if __name__ == '__main__':
	extract_info()
	main('chrome.exe')
	#ngrams
	with open('opcodes_chrome.txt', 'r') as infile:
			n = [i for i in infile.read().split()]
			n = str(n)
	print ngrams(n)

	#jaccard similarity	
	print('Jaccard similarity: %s') %(jaccard_set())
