#!/usr/bin/python
# Author: Deron K. Asbery Holmes
# Usage: IP Checker


# get regex and sys for script input
import re, sys

def block(address, block):
    # cast supplied ip address hex string as an integer for range comparison
    convert_addr = int(''.join([ '%02x' % int(x) for x in address.split('.') ]), 16)
    # parse out network and cidr into separate vars
    net, cidr = block.split('/')
    # cast network address hex string as an integer, base 16 for range comparison
    convert_block = int(''.join([ '%02x' % int(x) for x in net.split('.') ]), 16)
    # shift max bits by the difference of the cidr, then combine for mask
    mask = (0xffffffff << (32 - int(cidr))) & 0xffffffff

    if (convert_addr & mask) == (convert_block & mask):
        return True
    else:
        return False

def blockRange(address, first, last):
    convert_addr = int(''.join([ '%02x' % int(x) for x in address.split('.') ]), 16)
    # First block and Last blocks to create a range: creates vars of network address portion and cidr at the delimiter
    first_block, cidr1 = first.split('/')
    last_block, cidr2 = last.split('/')

    # on the assumption that the range of networks contain the same cidr bits
    cidr = cidr2

    # convert both network address strings into hex, cast them as int's with base 16
    converted_block1 = int(''.join([ '%02x' % int(x) for x in first_block.split('.') ]), 16)
    converted_block2 = int(''.join([ '%02x' % int(x) for x in last_block.split('.') ]), 16)
    # shift max bits by the difference of the cidr, then combine for mask
    mask = (0xffffffff << (32 - int(cidr))) & 0xffffffff

    if int(convert_addr & mask) in range(int(converted_block1 & mask), int(converted_block2 & mask)+1):
        return True
    else:
        return False

try:
    #supplied command line address
    addr = sys.argv[1]
    # check for proper octets
    if not re.search(r'(?:1?\d\d?|2[0-4]\d|25[0-5])\.(?:1?\d\d?|2[0-4]\d|25[0-5])\.(?:1?\d\d?|2[0-4]\d|25[0-5])\.(?:1?\d\d?|2[0-4]\d|25[0-5])$', addr):
        print('invalid ip')
    else:
        try:
            # take in the target file as an input
            target_file = 'input.txt'
            #open target file for reading
            file_contents = open(target_file, 'r')
        except IOError as err:
            exit('Exiting...could not open the file named: %s' % f0)
            #iterate over file, append to new list for further operations

    # create a regex to distinguish ranges during iteration
    pattern = re.compile(r'\-')

    with open('input.txt') as contents:
        networks = [network.strip('\n') for network in contents]

    found = False

    # iterate over the list from the file checking for pattern
    for ip_block in networks:
        if re.findall(pattern, ip_block):
            low,high = ip_block.split('-')
            if blockRange(addr, low, high):
                print ip_block
                found = True
        else:
            if block(addr, ip_block):
                print ip_block
                found = True

    if found == False:
        print "not found"

    contents.close()
except IndexError as e:
    print "Please supply an argument."
