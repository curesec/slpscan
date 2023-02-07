import queue

global jout_Queue
jout_Queue = queue.Queue()

global rQ
rQ = queue.Queue()

global q
q = queue.Queue()

__tool_version__ = '0.3.7'
__tool_author__ = 'Marco Lux'
__tool_date__ = 'published 2023'

SLP_SVC_REQ = 0x1
SLP_SVC_REPLY = 0x2
SLP_ATTR_REQ = 0x6
SLP_ATTR_REPLY = 0x7
SLP_SVC_TYPE_REQ = 0x9
SLP_SVC_TYPE_REPLY = 0xa


# basic v1 pkt
req_dict_v1 = {'slp_ver': 1,
               'slp_func': SLP_ATTR_REQ,
               'slp_pkt_len': 0,
               'slp_flags': 0,
               'slp_dialect': 0,
               'slp_lang': 0x656e,
               'slp_enc': 3,
               'slp_transx': 0x29A}

# basic v2 pkt
req_dict_v2 = {'slp_ver': 2,
               'slp_func': SLP_SVC_TYPE_REQ,
               'slp_pkt_len': 0,
               'slp_flags': 0,
               'slp_next_offset': 0,
               'slp_xid': 0x666,
               'slpintroduction_lang_tag_len': 2,
               'slp_lang_tag': 0x656e}
