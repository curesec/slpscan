#!/usr/bin/env python

import os
import sys
import time

from libs.srvloc_proto_v1 import CRAFT_AUTO_LEN
from libs.srvloc_main import print_slp_modes, parser_main, run_mainthreads, choose_slp_mode
from libs.srvloc_globals import *
from libs.srvloc_log import printe, printd
from libs.srvloc_probes import open_probe_file, print_probes, probe_packet


def run(args):

    fname = 'libs/srvloc_probes.json'
    slp_mode = args.slp_mode
    global CRAFT_AUTO_LEN

    if args.probe_mode:
        jprobes = open_probe_file(fname)
        if args.probe_mode == '?' or args.probe_mode == 'help':
            print_probes(jprobes)
            sys.exit()

        else:
            pkt = probe_packet(jprobes, args.probe_mode)

    else:
        pkt = choose_slp_mode(args)

    print('PKT: ', pkt)
    run_mainthreads(args, pkt)


def main():
    args = parser_main()
    run(args)

if __name__ == "__main__":
    main()
