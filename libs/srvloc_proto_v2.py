import struct
import random
from libs.srvloc_log import printd

SLP_SVC_REQ = 0x1
SLP_SVC_REPLY = 0x2
SLP_ATTR_REQ = 0x6
SLP_ATTR_REPLY = 0x7
SLP_SVC_TYPE_REQ = 0x9
SLP_SVC_TYPE_REPLY = 0xa

SLP_TRANSX_RAND = True
SLP_XID_RAND = True
CRAFT_AUTO_LEN = True
DEBUG_PROTO = True

#####################
###### SLP v2 #######
#####################


def build_slp_base_v2(slp_ver=2, slp_func=0, slp_pkt_len=0, slp_flags=0, slp_next_offset=0, slp_xid=0x299, slp_ltag_len=2, slp_ltag=0x656e):

    if SLP_XID_RAND:
        slp_xid = random.randint(1, 65535)

    # basic pkt structure v2
    pkt = struct.pack('>BBBHHBHHHH', slp_ver, slp_func, 0, slp_pkt_len,
                      slp_flags, 0, slp_next_offset, slp_xid, slp_ltag_len, slp_ltag)

    return pkt


def compute_len_v2(pkt):

    pkt_len = len(pkt)

    pkt_byte_len = struct.pack('>bH', 0, pkt_len)
    pkt = pkt[:2] + pkt_byte_len + pkt[5:]

    return pkt


#########SLP_SVC_REQ = 0x1
def build_slp_svc_req_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_REQ)
    pkt2 = _slp_svc_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_req_v2(slp_prev_res_list=0, slp_svc_type_len=0, slp_svc_type=b'service:wbem', slp_scope_len=7, slp_scope=b'default'):
    '''
    '''

    pkt2 = struct.pack('>HH'+str(slp_svc_type_len)+'sH'+str(slp_scope_len)+'sHH', slp_prev_res_list,
                       slp_svc_type_len, slp_svc_type, slp_scope_len, slp_scope, 0, 0)

    return pkt2
##########

#######SLP_SVC_REPLY = 0x2


def build_slp_reply_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_REPLY)
    pkt2 = _slp_svc_reply_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_reply_v2(err_code=0, num_urls=1, reserved=0, url_lifetime=667, url_len=12, urls=b'service:wbem', num_auths=0):
    '''
    '''

    pkt2 = struct.pack('>HHBHH'+str(url_len)+'sB', err_code,
                       num_urls, reserved, url_lifetime, url_len, urls, 0)

    return pkt2

######SLP_ATTR_REQ = 0x6


def build_slp_attr_req_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_ATTR_REQ)
    pkt2 = _slp_attr_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_attr_req_v2(slp_prev_res_list=0, slp_svc_url_len=12, slp_svc_url=b'service:wbem', slp_scope_len=0, slp_scope=b'', slp_tag_len=0, slp_tag=b''):

    pkt2 = struct.pack('>HH'+str(slp_svc_url_len)+'sH'+str(slp_scope_len)+'sH'+str(slp_tag_len)+'sH', slp_prev_res_list,
                       slp_svc_url_len, slp_svc_url, slp_scope_len, slp_scope, slp_tag_len, slp_tag, 0)

    return pkt2
#######################


######SLP_ATTR_REPLY = 0x7
def build_slp_attr_reply_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_ATTR_REPLY)
    pkt2 = _slp_attr_reply_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_attr_reply_v2(err_code=4, attr_list_len=0, attr_list=b'', attr_auths=4):

    pkt2 = struct.pack('>HH' + str(attr_list_len) + 'sB',
                       err_code,
                       attr_list_len,
                       attr_list,
                       attr_auths
                       )

    return pkt2
##########

#####SLP_SVC_TYPE_REQ = 0x9
def build_slp_svc_type_req_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_TYPE_REQ)
    pkt2 = _slp_svc_type_req_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_svc_type_req_v2(slp_prev_res_list=0, slp_all=65535, slp_scope=b'default', slp_scope_len=7):

    pkt2 = struct.pack('>HHH'+str(slp_scope_len)+'s', slp_prev_res_list,
                       slp_all, slp_scope_len, slp_scope)

    return pkt2
########################


#####SLP_SVC_TYPE_REPLY = 0xa
def build_slp_type_reply_v2():
    pkt1 = build_slp_base_v2(slp_func=SLP_SVC_TYPE_REPLY)
    pkt2 = _slp_type_reply_v2()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v2(pkt)

    return pkt_rdy


def _slp_type_reply_v2(err_code=0, svc_type_list_len=31, svc_type_list=b'service:Windows:wbem:http:https'):

    pkt2 = struct.pack('>HH' + str(svc_type_list_len) + 's',
                       err_code,
                       svc_type_list_len,
                       svc_type_list
                       )

    return pkt2
###########################
