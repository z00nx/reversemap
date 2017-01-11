#!/usr/bin/env python
# Purpose: Analyse SQL injection attempts in web server logs
# Execution: python reversemap.py [-h] [[-f FILE] [-o OUTPUT] | [-i]]
# Changelog:
# TODO: Add python3 compatibility
# TODO: Recursive deobfuscation
# TODO: Add deobfuscation for other obfuscation techniques
# TODO: Write a proper NCSA Common log format parser
# TODO: Pretty print the SQL statements
# TODO: Implement logic to automatically analyse SQL statements - https://pypi.python.org/pypi/format-sql/
# TODO: Support IIS and other web server/proxy logs formats

from __future__ import print_function
from builtins import input
import urllib
import re
import argparse
import readline

parser = argparse.ArgumentParser(description='Analyse SQL injection attempts in web server logs')
parser.add_argument('-f', '--file', type=argparse.FileType('r'), help='Input file to process')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), help='Output file to write to')
parser.add_argument('-i', '--interactive', action='store_true', help='Run interactively')
args = parser.parse_args()

banner = '''
  _______ _  _____ _______ ___ __ _  ___ ____ 
 / __/ -_) |/ / -_) __(_-</ -_)  ' \/ _ `/ _ \\
/_/  \__/|___/\__/_/ /___/\__/_/_/_/\_,_/ .__/
                                       /_/    
'''

def deobfuscate(input):
    sqlkeywords = ['SELECT ', 'DISTINCT ', 'FROM ', 'WHERE ', 'CAST\(', 'CONVERT\(', 'ORDER ', 'BY ', 'AS ', 'ON ', 'JOIN ', '@@VERSION', ' ASC', ' LIKE ', ' TOP ', ' AND ', ' DESC', ' SQ ', 'UNION ', 'CHAR\(', 'VERSION\(\)', 'ALL ']
    decodedurl = urllib.unquote_plus(input)
    # Remove SQL comments
    decodedurl = decodedurl.replace('/**/', '')

    # Replace all sql keywords which maybe case obfuscated
    for sqlkeyword in sqlkeywords:
        unescapedsqlkeyword = sqlkeyword.replace('\\', '')
        decodedurl = re.sub(sqlkeyword, unescapedsqlkeyword, decodedurl, count=0, flags=re.IGNORECASE)

    # Extract all char encoded entries, decode and replace the original entry
    chars = re.findall(r'(CHAR\((\d{1,3}(,\d{1,3})*)\)\+?)', decodedurl)
    for char in chars:
        decodedchar = ''
        for encodedchar in char[1].split(','):
            decodedchar += chr(int(encodedchar))
        decodedurl = decodedurl.replace(char[0], decodedchar)

    # Extract all cast obfuscated entries, decode and replace the original entry
    casts = re.findall(r'(CAST\(0x((?:[0-9a-fA-F]{2})*) AS char\))', decodedurl, flags=re.IGNORECASE)
    for cast in casts:
        decodedurl = decodedurl.replace(cast[0], cast[1].decode('hex'))
    '''
    # Extract all substrings entries, decode and replace the original entry
    substrings = re.findall(r'(SUBSTRING\(\(?([^,]+)\)?,(\d+),(\d+)\))', decodedurl, flags=re.IGNORECASE)
    for substring in substrings:
        (encodedsubstring, expression, start, length) = substring
        start = int(start) - 1
        length = int(length)
        decodedsubstring = expression[start:length]
        decodedurl = decodedurl.replace(encodedsubstring, decodedsubstring)
    '''

    return(decodedurl)

if __name__ == "__main__":
    print(banner)
    if args.interactive and args.file is not None and args.output is not None:
        parser.print_help()
    elif args.interactive:
        while True:
            try:
                line = input('REVERSEMAP> ')
            except EOFError:
                break
            if line == 'quit':
                break
            deobfuscatedline = deobfuscate(line)
            print("DEOBFUSCATED> %s" % deobfuscatedline)
    elif args.file is not None and args.output is not None:
        for index, log in enumerate(args.file):
            print("\rProcessing line %s of %s and writing to %s" % (index, args.file.name, args.output.name), end="")
            try:
                webserverhit = log.split('"')[1]
            except IndexError:
                pass
            url = webserverhit.split()[1]
            deobfuscated = deobfuscate(url)
            args.output.write(deobfuscated + '\n')
    else:
        parser.print_help()
