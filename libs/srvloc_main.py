import os
import sys
import json
import time
import socket
import threading
import argparse

from libs.srvloc_globals import q, rQ, __tool_author__, __tool_version__, __tool_date__, jout_Queue
from libs.srvloc_proto_v1 import *
from libs.srvloc_proto_v2 import *

from libs.srvloc_helper import randomizeIP, generate_randomIP, clean_line, check_blacklist
from libs.srvloc_log import printd, printe

from libs.srvloc_fortune import rnd_fck


def parser_main():
    parser_desc = 'service location protocol {0} by {1} in {2}'.format(
        __tool_version__, __tool_author__, __tool_date__)
    prog_desc = 'slpscan.py'
    parser = argparse.ArgumentParser(prog=prog_desc, description=parser_desc)
    parser.add_argument("-l", "--host", action="store",
                        required=False, help='host to check version', dest='host')
    parser.add_argument("-L", "--hostlist", action="store",
                        required=False, help='hostlist to check', dest='hostlist')
    parser.add_argument("-p", "--port", action="store", required=False,
                        default=427, help='slp port (default:427)', dest='port')
    parser.add_argument("-t", "--threads", action="store", required=False,
                        default=50, help='how many threads', dest='thrCnt', type=int)
    parser.add_argument("-m", "--slp-mode", action="store", required=False, default='',
                        help='what attack mode to choose, ? for list', dest='slp_mode')
    parser.add_argument("-P", "--probe-mode", action="store", required=False, default=False,
                        help='what probe to send, ? for list', dest='probe_mode')
    parser.add_argument("-d", "--packet-delay", action="store", required=False, type=float,
                        help='set the delay(in seconds) a packet is sent, delay is per thread (1s and 10 threads, each second 10 threads are working)',
                             dest='pkt_delay')

    parser.add_argument("-T", "--timeout", action="store", required=False,
                        default=5, help='timeout of socket recv', dest='timeout')
    parser.add_argument("-o", "--outfile", action="store",
                        required=False, help='outfile in txt format', dest='outfile')
    parser.add_argument("-oj", "--outfile-json", action="store",
                        required=False, help='outfile in json format', dest='outfile_json')

    parser.add_argument("-r", "--unrandom", action="store", required=False,
                        help='disable random targetlist', dest='unrandom')
    parser.add_argument("-R", "--randomIP", action="store", required=False,
                        help='generate random ips on the fly', dest='randomip')

    args = parser.parse_args()
    return args


SLP_SVC_REQ = 0x1
SLP_SVC_REPLY = 0x2
SLP_ATTR_REQ = 0x6
SLP_ATTR_REPLY = 0x7
SLP_SVC_TYPE_REQ = 0x9
SLP_SVC_TYPE_REPLY = 0xa

# FIXME build other structure for modes


def choose_slp_mode(args):
    lsize = 70
    modes = {1: {'name': '{0:<30} {1:<15} {2:<30}'.format('SLPv1 Modes', 'Operation', 'Description'), 'Operation': '', 'Description': '', 'Method': ''},
             # 2: {'name': '-'*lsize, 'Operation': '', 'Description': '', 'Method': ''},
             # !!!!!!
             21: {'name': 'svc_req_v1', 'Operation': SLP_SVC_REQ, 'Description': '', 'Method': build_slp_svc_req_v1()},
             22: {'name': 'svc_reply_v1', 'Operation': SLP_SVC_REPLY, 'Description': '', 'Method': build_slp_reply_v1()},
             26: {'name': 'svc_attr_req_v1', 'Operation': SLP_ATTR_REQ, 'Description': '', 'Method': build_svc_attr_req_v1()},
             27: {'name': 'svc_attr_reply_v1', 'Operation': SLP_ATTR_REPLY, 'Description': '', 'Method': build_slp_attr_reply_v1()},
             29: {'name': 'svc_type_req_v1', 'Operation': SLP_SVC_TYPE_REQ, 'Description': '', 'Method': build_slp_svc_type_req_v1()},
             30: {'name': 'svc_type_reply_v1', 'Operation': SLP_SVC_TYPE_REPLY, 'Description': '', 'Method': build_slp_type_reply_v1()},

             38: {'name': '{0:<30} {1:<15} {2:<30}'.format('SLPv2 Modes', 'Operation', 'Description'), 'Operation': '', 'Description': '', 'Method': ''},

             40: {'name': 'svc_req_v2', 'Operation': SLP_SVC_REQ, 'Description': '', 'Method': build_slp_svc_req_v2()},
             41: {'name': 'svc_reply_v2', 'Operation': SLP_SVC_REPLY, 'Description': '', 'Method': build_slp_reply_v2()},
             45: {'name': 'svc_attr_req_v2', 'Operation': SLP_ATTR_REQ, 'Description': '', 'Method': build_slp_attr_req_v2()},
             46: {'name': 'svc_attr_reply_v2', 'Operation': SLP_ATTR_REPLY, 'Description': '', 'Method': build_slp_attr_reply_v2()},
             48: {'name': 'svc_type_req_v2', 'Operation': SLP_SVC_TYPE_REQ, 'Description': '', 'Method': build_slp_svc_type_req_v2()},
             49: {'name': 'svc_type_reply_v2', 'Operation': SLP_SVC_TYPE_REPLY, 'Description': '', 'Method': build_slp_type_reply_v2()},
             }

    slp_mode = args.slp_mode

    if slp_mode == '?':
        print()
        for k in modes.keys():
            # print(modes[k])
            name = modes[k]['name']
            operation = modes[k]['Operation']
            desc = modes[k]['Description']
            if name.startswith('SLPv'):
                print('-'*lsize)
            print('{0:<30} {1:<15} {2:<30}'.format(name, operation, desc))
            if name.startswith('SLPv'):
                print('-'*lsize)
        print()
        sys.exit()
    else:
        for k in modes.keys():
            if slp_mode == modes[k]['name']:
                pkt = modes[k]['Method']

                return pkt

    print('Unknown mode use -m? for showing supported modes')
    sys.exit()


def make_request(host, port, args, pkt):
    human = []
    timeout = args.timeout
    slp_mode = args.slp_mode
    probe_mode = args.probe_mode
    pkt_delay = args.pkt_delay

    if pkt_delay:
        time.sleep(pkt_delay)
    try:
        # build up socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # we want to have a timeout
        s.settimeout(timeout)
        s.connect((host, port))

        # send the discovery packet
        s.send(pkt)

        # getting the data of the connection
        rec = s.recv(4096)
        data_dict = {'target': host+':' +
                     str(port), 'reply_pkt': rec, 'pkt': pkt}
        hdata = '%s:%d' % (host, port)
        hdump = '%s' % (repr(rec))

        # place stuff in one of the queues
        human.append(hdata)
        human.append(hdump)
        # human.append(reply_dict)
        rQ.put(human)

    except socket.timeout:
        printe('%s timeout' % host)
    except socket.error:
        printe('%s refused' % host)


def run_mainthreads(args, pkt):

    # wanna have a c00kie?!
    fck = rnd_fck()
    printd(fck)

    if args.outfile:
        fw = open(args.outfile, 'w')

    if args.outfile_json:
        fwj = open(args.outfile_json, 'w')

    if args.host:
        host = args.host
        print('Hostmode: %s' % host)
        line = clean_line(host)

        bl = [host]
        wh = check_blacklist(bl)
        if len(wh) == 1:
            q.put(line)
        else:
            # print('{0} Blacklisted!!!'.format(host))
            sys.exit()

    elif args.hostlist:
        ipL = []
        hostlist = args.hostlist
        print('Hostlistmode')
        fr = open(hostlist, 'r')
        rBuf = fr.readlines()
        for l in rBuf:
            l = clean_line(l)
            ipL.append(l)
        if not args.unrandom:
            iplist = randomizeIP(ipL)
        else:
            iplist = ipL

        iplist = check_blacklist(iplist)

        list = [q.put(query) for query in iplist]

    elif args.randomip:
        randIP = int(args.randomip)
        print('RandomIPs: %d' % (randIP))

    else:
        print('Unknown or no mode choosen. cya')
        sys.exit()

    if not args.randomip:
        print('Targets: %d' % (q.qsize()))
    else:
        # lets start the thread for generating randomIPs
        printd('Starting random thread:')
        randIPThread = threading.Thread(
            target=generate_randomIP, args=(q, args.randomip))
        randIPThread.daemon = True
        randIPThread.start()
        # FIXME
        # quick fix so we do not miss the threading loop
        # better would be a counter in the loop itself
        time.sleep(5)

    port = int(args.port)
    thrCnt = args.thrCnt

    thrList = []

    printd('Starting loop')
    while True:
        if len(thrList) < thrCnt and q.qsize() > 0:
            newthread = threading.Thread(target=make_request, args=(
                q.get(), port, args, pkt))
            newthread.daemon = True
            newthread.start()
            thrList.append(newthread)

        for entry in thrList:
            if entry.is_alive() == False:
                entry.join()
                thrList.remove(entry)
                time.sleep(0.1)

        if rQ.qsize() > 0:

            pout = rQ.get()
            pp = '%s' % (pout)
            print('[RAW] ', pp)
            print()
            if args.outfile:
                fw.write(pp + '\n')

        if jout_Queue.qsize() > 0:
            jdata = jout_Queue.get()
            print(jdata)

            if args.outfile_json:
                fwj.write(jdata + '\n')
        if q.qsize() == 0 and len(thrList) == 0:
            break


def print_slp_modes():

    data = '''
		Supported modes:

		* slp_type_request
			requesting the supported ressources at the remote device
		'''

    print(data)
