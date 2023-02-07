import os
import sys
import pytz
import base64
import datetime
import random
from random import randrange
from libs.srvloc_globals import *
from libs.srvloc_log import printd, printe


def randomizeIP(iplist):
    ''' function to randomize ips to scan'''
#    orig_list = iplist
    # run 1
    random.shuffle(iplist)

    # run 2
    random.shuffle(iplist)
    return iplist


def generateIP():
    blockOne = randrange(0, 255, 1)
    blockTwo = randrange(0, 255, 1)
    blockThree = randrange(0, 255, 1)
    blockFour = randrange(0, 255, 1)
    if blockOne == 10:
        return generateIP()
    elif blockOne == 172:
        return generateIP()
    elif blockOne == 192:
        return generateIP()
    else:
        d = str(blockOne) + '.' + str(blockTwo) + '.' + \
            str(blockThree) + '.' + str(blockFour)

        return d


def console_size():
    height, witdh = os.popen('stty size', 'r').read().split()

    return (int(witdh), int(height))


def generate_randomIP(q, count):
    i = 0
    count = int(count)
    # print 'cnt', count
    while i != count:
        ip = generateIP()
        check_ip = [ip]
        ip = check_blacklist(check_ip)
        if len(ip) > 0:
            q.put(ip[0])
            i += 1
        else:
            print('{0} BLACKLISTED.'.format(ip))

    print('gen %d' % (q.qsize()))
    return


def timefield_rfc3339():
    '''
    implementing timestamp like rfc3339
    '''
    d = datetime.datetime.utcnow()
    d_with_timezone = d.replace(tzinfo=pytz.UTC)
    timestamp = d_with_timezone.isoformat()
    return timestamp


def timedict_rfc3339():
    '''
    implementing timestamp like rfc3339
    '''
    d = datetime.datetime.utcnow()
    d_with_timezone = d.replace(tzinfo=pytz.UTC)
    timestamp = d_with_timezone.isoformat()
    return {'timestamp': timestamp}


def ascii_check(rec):
    '''check if banner has non-ascii values
    '''
    # yes, this is a bool now
    ascii_bool = False

    data = rec
    # print(rec)
    # poor mans clause for checking if ascii or not
    try:
        if type(rec) != int:
            ascii_test = data.decode('ascii')
            ascii_bool = True
        else:
            return rec

    except UnicodeDecodeError as e:
        ascii_bool = False

    # its not ascii, so base64 encoding
    if ascii_bool == False:
        rec = base64.b64encode(data)

    return(rec)


def clean_line(line):
    line = line.rstrip('\r')
    line = line.rstrip('\n')
    return line


def check_file_exists(fname):

    try:
        stat = os.stat(fname)

    except FileNotFoundError as e:
        print(repr(e))
        return False

    return True


def check_file_readable(fname):
    try:
        fr = open(fname, 'r', 1)

    except PermissionError as e:
        print(repr(e))
        return False
    except Exception as e:
        print(repr(e))
        return False

    return True


def create_hostlist(args):
    #ret = check_file_exists(args.hostlist)

    # if not ret:
    #	return False
    fr = open(args.hostlist, 'r', 1)

    for line in fr.readlines():
        cline = clean_line(line)
        rQ.put(cline)
    rQ.put('')
    # req_queue.put('EOF')


def check_blacklist(whites):
    # def check_blacklist(blacks, whites):
    '''
    '''
    fr = open('supply/blacklist.txt', 'r')
    bips = fr.readlines()
    white_len = len(whites)
    blacklisted = []
    for black in bips:
        black = clean_line(black)
        try:
            whites.index(black)
            whites.remove(black)
            blacklisted.append(black)
            print('BLACKLISTED {0}'.format(black))
        except ValueError as e:
            pass
    white_len_after = len(whites)
    #print('Whitelist: {0}/{1}'.format(white_len, white_len_after))
    return whites
