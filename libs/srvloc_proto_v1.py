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
###### SLP v1 #######
#####################


def build_slp_base_v1(slp_ver=1, slp_func=0, slp_pkt_len=0, slp_flags=0, slp_dialect=0, slp_lang=0x656e, slp_enc=3, slp_transx=0x29A):
    '''
    this method is used for building up what i call the *base* part of the SLPv1 specification. Base parameters are all parameters part
    of every valid SLPv1 packet. 

    Returns: pkt - a ready base packet, WARNING this packet is missing the function part and also pkt_len is not computed yet
    '''
   # print(slp_ver)
    if SLP_TRANSX_RAND:
        slp_transx = random.randint(1, 65535)

    # basic pkt structure v1
    pkt = struct.pack('>BBHBBHHH', slp_ver, slp_func, slp_pkt_len,
                      slp_flags, slp_dialect, slp_lang, slp_enc, slp_transx)

    printd(pkt)
    return pkt


def compute_len_v1(pkt):
    '''
    This method is used for computing the overall length of a complete SLPv1 packet. It's default usage is being called at the end of 
    packet building process.

    Params: pkt - a ready pkt without correct pkt_len, usually 0 (zero)
    Returns: pkt - a ready pkt with correct pkt_len
    '''
    pkt_len = len(pkt)

    pkt_byte_len = struct.pack('>H', pkt_len)
    pkt = pkt[:2]+pkt_byte_len+pkt[4:]
    return pkt


########SLP_SVC_REQ = 0x1
def build_slp_svc_req_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_SVC_REQ)
    pkt2 = _slp_svc_req_v1()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_svc_req_v1(slp_prev_res_list_len=1, slp_resp_list=b'A', slp_pred_len=1, slp_pred=b'B'):
    '''
    '''

    pkt2 = struct.pack('>H' + str(slp_prev_res_list_len) + 'sH' + str(slp_pred_len) + 's',
                       slp_prev_res_list_len,
                       slp_resp_list,
                       slp_pred_len,
                       slp_pred
                       )

    return pkt2

########################################################################################################################################

###### SLP_SVC_REPLY = 0x2


def build_slp_reply_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_SVC_REPLY)
    pkt2 = _slp_svc_reply_v1()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_svc_reply_v1(err_code=0, num_urls=1, url_lifetime=667, url_len=12, urls=b'service:wbem', num_auths=0):
    '''
    '''

    #url_len = len(urls)
    pkt2 = struct.pack('>HHHH'+str(url_len)+'sB', err_code,
                       num_urls, url_lifetime, url_len, urls, 0)

    return pkt2
########################################################################################################################################

#############SLP_ATTR_REQ = 0x6
def build_svc_attr_req_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_ATTR_REQ)
    pkt2 = _slp_attr_req_v1()
    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_attr_req_v1(slp_prev_res_list=0, slp_url_len=8, slp_svc_url=b'service:', slp_scope_len=0, slp_attr_len=0):

    # attr request structure
    pkt2 = struct.pack('>HH'+str(slp_url_len)+'sHH', slp_prev_res_list,
                       slp_url_len, slp_svc_url, slp_scope_len, slp_attr_len)

    return pkt2

########################################################################################################################################

#########SLP_ATTR_REPLY = 0x7
def build_slp_attr_reply_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_ATTR_REPLY)
    pkt2 = _slp_attr_reply_v1()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_attr_reply_v1(err_code=0, attr_list_len=9, attr_list=b'attribute', attr_auths=0):

    pkt2 = struct.pack('>HH' + str(attr_list_len) + 'sB',
                       err_code,
                       attr_list_len,
                       attr_list,
                       attr_auths
                       )

    return pkt2
########################################################################################################################################


##################SLP_SVC_TYPE_REQ = 0x9


def build_slp_svc_type_req_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_SVC_TYPE_REQ)
    pkt2 = _slp_svc_type_req_v1()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_svc_type_req_v1(slp_prev_res_list=0, slp_all=65535, slp_scope=b'default'):

    slp_scope_len = len(slp_scope)
    pkt2 = struct.pack('>HHH'+str(slp_scope_len)+'s', slp_prev_res_list,
                       slp_all, slp_scope_len, slp_scope)

    return pkt2
########################################################################################################################################

########SLP_SVC_TYPE_REPLY = 0xa


def build_slp_type_reply_v1():
    pkt1 = build_slp_base_v1(slp_func=SLP_SVC_TYPE_REPLY)
    pkt2 = _slp_type_reply_v1()

    pkt = pkt1+pkt2
    pkt_rdy = compute_len_v1(pkt)

    return pkt_rdy


def _slp_type_reply_v1(err_code=0, svc_type_count=1, svc_type_list_len=31, svc_type_list=b'service:Windows:wbem:http:https'):

    pkt2 = struct.pack('>HHH' + str(svc_type_list_len) + 's',
                       err_code,
                       svc_type_count,
                       svc_type_list_len,
                       svc_type_list
                       )

    return pkt2
########################################################################################################################################
