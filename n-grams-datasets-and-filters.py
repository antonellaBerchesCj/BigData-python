#!/usr/bin/env python

import sqlite3
import glob
import hashlib
import pefile
import distorm3
import pydasm
import sys
import binascii

freq = {}

def create_table1():
    try:
        c.execute('''CREATE TABLE Homeworks (Hash,Assign,Student,Ngrams)''')
    except:
        print('Error! Cannot create the database connection.')

# def select(verbose=True):
#     sql = 'SELECT * FROM Homeworks'
#     recs = c.execute(sql)
#     if verbose:
#         for row in recs:
#             print(row)


def hash_file(file_path):
    '''
    MD5 file hash --> https://www.pythoncentral.io/hashing-files-with-python/
    '''
    hasher = hashlib.md5()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()


def extract_opcodes(section, file_path, instr):
    '''
    Extract opcodes from the file section
    sample: https://github.com/gdabah/distorm/blob/master/python/distorm3/sample.py
    '''
    # iterable = distorm3.DecodeGenerator(offset, code, options.dt)
    iterable = distorm3.DecodeGenerator(section.PointerToRawData, open(file_path, 'rb').read(), distorm3.Decode32Bits)
    # print(next(iterable))
    for (offset, size, instruction, hexdump) in iterable:
        # print('%.8x: %-32s %s' % (offset, hexdump, instruction))
        if section.SizeOfRawData - section.PointerToRawData < offset + size:
            if instruction != 'INT 3' and instruction != 'NOP':
                instruction = (instruction.replace('INC', 'ADD')).replace('SUB', 'ADD');
                instr.append(instruction.split(' ')[0])


def create_ngrams(instr_list):
    '''
    Create ngrams from an instruction list
    return: sorted list with file n-grams

    https://docs.python.org/2/library/binascii.html
    '''
    ngrams_nr = 10
    ngrams_list = []
    for i in range(0, len(instr_list) - ngrams_nr):
        word_ngram = ''
        for j in range(i, i + ngrams_nr):
            word_ngram = word_ngram + instr_list[j]
        # Compute CRC-32, the 32-bit checksum of data, starting with an initial crc
        ngrams_list.append(binascii.crc32(word_ngram) &0xffffffff);
    # print('Number of ' + str(ngrams_nr) + '-grams: ' + str(len(ngrams_list)))
    return sorted(ngrams_list)
    

def get_ngrams(file_path):
    '''
    Get ngrams from 0x60000020 section - this section contains code that can be read and executed.
    '''
    pe =  pefile.PE(file_path)
    instr_list = []
    for section in pe.sections:
        if '0x60000020' in hex(section.Characteristics):
            extract_opcodes(section, file_path, instr_list)
    return instr_list


def insert_to_db1(conn, files):
    '''
    Insert values into features_raw.db
    '''
    for file in files:
        filename = file.split('/')[2]
        info = filename.split('_')
        assign = info[0]
        student = info[1].split('.exe')[0]
        hashFile = hash_file(file)
        ngrams = ', '.join(str(e) for e in create_ngrams(get_ngrams(file)));
        c.execute('''INSERT INTO Homeworks (Hash, Assign, Student, Ngrams) VALUES (?, ?, ?, ?)''', (hashFile, assign, student, ngrams));
        conn.commit()

def create_table2():
    try:
        c2.execute('''CREATE TABLE Homeworks (Hash,Assign,Student,Ngrams)''')
    except:
        print('Error! Cannot create the database connection.')


def insert_to_db2(conn, allFiles, dict):
    '''
    Insert values into features.db
    '''
    for file in files:
        filename = file.split('/')[2]
        info = filename.split('_')
        assign = info[0]
        student = info[1].split('.exe')[0]
        hashFile = hash_file(file)
        ngrams_val = ''
        ngrams = create_ngrams(get_ngrams(file))
        for n in ngrams:
            if n in dict:
                if int(dict[n]) > 30:
                    n = ''
                else:
                    n = str(n) + ', '

            ngrams_val = ngrams_val + str(n)
        # conn2.execute('''DROP TABLE if exists Homeworks''')
        # conn2.execute('''CREATE TABLE Homeworks (Hash,Assign,Student,Ngrams)''')
        conn.execute('''INSERT INTO Homeworks (Hash, Assign, Student, Ngrams) VALUES (?, ?, ?, ?)''', (hashFile, assign, student, ngrams_val));
        conn.commit()


def ngrams_frequency(conn):
    '''
    Get ngrams frequency from table data and return it as a dictionary
    '''
    freq = {}
    table_ngrams = conn.execute('''SELECT Ngrams FROM Homeworks''')
    ngrams = table_ngrams.fetchall()
    for ngr in ngrams:
        lista = set(ngr[0].split(','))
        for i in lista:
            i = int(i)
            if i not in freq:
                freq[i] = 0
            freq[i] = freq[i] + 1
    return freq

def similarity(n1, n2):
    '''
    Jaccard similarity
    '''
    intersection = set.intersection(*[set(n1), set(n2)])
    reunion = set.union(*[set(n1), set(n2)])
    similarity_value = float(len(intersection)) / len(reunion)
    # print('Similarity between files is:  %s' % str(similarity_value))
    return similarity_value

def similarity1(db, h1, h2):
    '''
    Determine similarity between twi=o hashes
    '''
    conn = sqlite3.connect(db)
    n1 = conn.execute('''SELECT Ngrams FROM Homeworks WHERE Hash = (?)''' , [h1])
    n2 = conn.execute('''SELECT Ngrams FROM Homeworks WHERE Hash = (?)''' , [h2] )
    print('Similarity between hashes: %s' % similarity(n1.fetchone()[0].split(','),n2.fetchone()[0].split(',')))

def similarity2(db, s1, s2, assign):
    '''
    Determine similarity between two id students given the assignment
    '''
    conn = sqlite3.connect(db)
    n1 = conn.execute('''SELECT Ngrams FROM Homeworks WHERE Student = (?) AND Assign = (?)''' , [s1, assign])
    n2 = conn.execute('''SELECT Ngrams FROM Homeworks WHERE Student = (?) AND Assign = (?)''' , [s2, assign] )
    n1_val = n1.fetchone()
    n2_val = n2.fetchone()
    if n1_val is None:
        # print('1st student does not exist in the DB!')
        return 0
    if n2_val is None:
        # print('2nd student does not exist in the DB!') 
        return 0
    print('Similarity between two students: %s' % similarity(n1_val[0].split(','), n2_val[0].split(',')))
    return similarity(n1_val[0].split(','), n2_val[0].split(','))

# ex. 4
def det_similarity(data):
    for i in range(0, len(data)):
        for j in range(i+1, len(data)):
            if i != j:
                s1 = data[i][2]
                s2 = data[j][2]
                assign = data[i][1]
                info = str(s1 + '_' + s2 + '_' + assign)
                similarity_val = similarity2('features.db', assign, s1, s2)
                freq[info] = similarity_val

def top500_similar_pairs(conn):
    '''
    Top500 most similar pairs of assigns (in the two databases)
    '''
    assigns = conn.execute('''SELECT DISTINCT (Assign) FROM Homeworks''')
    assigns_val = assigns.fetchall()
    for assign in assigns_val:
        ngrams_table = conn.execute('''SELECT * FROM Homeworks WHERE Assign = (?)''',[assign[0]])
        ngrams_val = ngrams_table.fetchall()
        det_similarity(ngrams_val)
    # print(sorted(freq.iteritems(), key = lambda(k,v):(v,k), reverse=True)[:500])
    with open('top500.txt', 'w') as file:
        file.write(str(sorted(freq.iteritems(), key=lambda(k,v):(v,k), reverse=True)[:500]))
    file.close()

# ---------- global
conn = sqlite3.connect(r'features_raw.db')
# c = conn.cursor()
# create_table1()#
#  # select()
# files = glob.glob('homeworks2/binaries/*.exe')
# insert_to_db1(conn, files)


# conn2 = sqlite3.connect(r'features.db')
# c2 = conn2.cursor()
# create_table2()
# insert_to_db2(conn2, files, ngrams_frequency(conn))
# c.close()
# c2.close()

similarity1('features_raw.db','1194be6388162e12ea1a53ce0f3bfa4d','c95dea40d097fd020b4798d23eb1fb05')
similarity2('features_raw.db', 's0009', 's0013', 'a02')
top500_similar_pairs(conn)
