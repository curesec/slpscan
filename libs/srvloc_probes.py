import json
from libs.srvloc_proto_v1 import build_slp_base_v1,  compute_len_v1,  _slp_attr_req_v1, _slp_svc_req_v1, \
    _slp_svc_reply_v1, _slp_attr_reply_v1, _slp_type_reply_v1, _slp_svc_type_req_v1


from libs.srvloc_proto_v2 import _slp_svc_req_v2, _slp_svc_reply_v2, _slp_svc_type_req_v2, _slp_attr_req_v2,_slp_attr_reply_v2, _slp_type_reply_v2, compute_len_v2, build_slp_base_v2
    

from libs.srvloc_helper import console_size

fname = 'srvloc_probes.json'

SLP_SVC_REQ = 0x1
SLP_SVC_REPLY = 0x2
SLP_ATTR_REQ = 0x6
SLP_ATTR_REPLY = 0x7
SLP_SVC_TYPE_REQ = 0x9
SLP_SVC_TYPE_REPLY = 0xa


def open_probe_file(fname):
    fr = open(fname, 'r')
    jprobes = json.loads(fr.read())
    fr.close()
    return jprobes


def print_probes(jprobes):
    width, heigth = console_size()
    # 30% name
    # 40% brief
    # 15% devices
    # yeah i need to substract max width len as well ...
    name_res = 0.30
    brief_res = 0.40
    dev_res = 0.15
    tab_vert_res = 0.90
    width = width * 0.90
    name_space = int(width * name_res)
    brief_space = int(width * brief_res)
    dev_space = int(width * dev_res)
    max_table_vert = int(width * tab_vert_res)

    print('{0: <{1}}| {2: <{3}}| {4: <{5}}'.format(
        'SLP Request', name_space, 'Brief', brief_space, 'Devices', dev_space))

    print('-'*(max_table_vert))
    for k in jprobes.keys():
        name = jprobes[k]['name']
        desc = jprobes[k]['brief']
        devices = jprobes[k]['devices']
        str_devices = ",".join(devices)
        print('{0: <{1}}| {2: <{3}}| {4: <{5}}'.format(
            name, name_space, desc, brief_space, str_devices, dev_space))


def probe_packet(jprobes, pname):
    # print('123')
    for k in jprobes.keys():
        name = jprobes[k]['name']
        if pname == name:
#            print('Found probe')
            base = jprobes[k]['probe']['base']
            data = jprobes[k]['probe']['data']
            slp_ver = jprobes[k]['probe']['base']['slp_ver']
            slp_func = jprobes[k]['probe']['base']['slp_func']

            if slp_ver == 1:
                slp_ver, slp_func, slp_pkt_len, slp_flags, slp_dialect, slp_lang, slp_enc, slp_transx = jprobes[k]['probe']['base'].values(
                )
                pkt1 = build_slp_base_v1(
                    slp_ver, slp_func, slp_pkt_len, slp_flags, slp_dialect, slp_lang, slp_enc, slp_transx)

                if slp_func == SLP_SVC_REQ:
                    slp_prev_res_list_len, slp_rest_list, slp_pred_len, slp_pred = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_svc_req_v1(
                        slp_prev_res_list_len, slp_rest_list.encode(), slp_pred_len, slp_pred.encode())

                elif slp_func == SLP_SVC_REPLY:
                    err_code, num_urls, url_lifetime, url_len, urls, num_auths = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_svc_reply_v1(
                        err_code, num_urls, url_lifetime, url_len, urls.encode(), num_auths)

                elif slp_func == SLP_ATTR_REQ:
                    slp_prev_res_list, slp_svc_len, slp_svc_url, slp_scope_len, slp_attr_len = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_attr_req_v1(
                        slp_prev_res_list, slp_svc_len, slp_svc_url.encode(), slp_scope_len, slp_attr_len)

                elif slp_func == SLP_ATTR_REPLY:
                    err_code, attr_list_len, attr_list, attr_auths = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_attr_reply_v1(
                        err_code, attr_list_len, attr_list.encode(), attr_auths)
                elif slp_func == SLP_SVC_TYPE_REQ:
                    slp_prev_res_list, slp_all, slp_scope = jprobes[k]['probe']['data'].values(
                    )

                    pkt2 = _slp_svc_type_req_v1(
                        slp_prev_res_list, slp_all, slp_scope.encode())

                elif slp_func == SLP_SVC_TYPE_REPLY:
                    err_code, svc_type_count, svc_type_list_len, svc_type_list = jprobes[k]['probe']['data'].values(
                    )

                    pkt2 = _slp_type_reply_v1(
                        err_code, svc_type_count, svc_type_list_len, svc_type_list.encode())

                else:

                    print('{0} function not yet supported.'.format(slp_func))

                    return False

                pkt = pkt1 + pkt2
                pkt_rdy = compute_len_v1(pkt)

            elif slp_ver == 2:
                slp_ver, slp_func, slp_pkt_len, slp_flags, slp_next_offset, slp_xid, slp_ltag_len, slp_ltag = jprobes[k]['probe']['base'].values(
                )

                pkt1 = build_slp_base_v2(
                    slp_ver, slp_func, slp_pkt_len, slp_flags, slp_next_offset, slp_xid, slp_ltag_len, slp_ltag)

                if slp_func == SLP_SVC_REQ:
                    slp_prev_res_list, slp_svc_type_len, slp_svc_type, slp_scope_len, slp_scope = jprobes[k]['probe']['data'].values(
                    )

                    pkt2 = _slp_svc_req_v2(
                        slp_prev_res_list, slp_svc_type_len, slp_svc_type.encode(), slp_scope_len, slp_scope.encode())

                elif slp_func == SLP_SVC_REPLY:
                    err_code, num_urls, reserved, url_lifetime, url_len, urls, num_auths = jprobes[k]['probe']['data'].values(
                    )

                    pkt2 = _slp_svc_reply_v2(
                        err_code, num_urls, reserved, url_lifetime, url_len, urls.encode(), num_auths)

                elif slp_func == SLP_SVC_ACK:
                    err_code = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_svc_ack_v2(
                        err_code)

                elif slp_func == SLP_ATTR_REQ:
                    slp_prev_res_list, slp_svc_url_len, slp_svc_url,  slp_scope_len, slp_scope, slp_tag_len, slp_tag = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_attr_req_v2(
                        slp_prev_res_list, slp_svc_url_len, slp_svc_url.encode(),  slp_scope_len, slp_scope.encode(), slp_tag_len, slp_tag.encode())

                elif slp_func == SLP_ATTR_REPLY:
                    err_code, attr_list_len, attr_list, attr_auths = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_attr_reply_v2(
                        err_code, attr_list_len, attr_list.encode(), attr_auths)
                elif slp_func == SLP_SVC_TYPE_REQ:
                    slp_prev_res_list, slp_all, slp_scope, slp_scope_len = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_svc_type_req_v2(
                        slp_prev_res_list, slp_all, slp_scope.encode(), slp_scope_len)

                elif slp_func == SLP_SVC_TYPE_REPLY:
                    err_code, svc_type_list_len, svc_type_list = jprobes[k]['probe']['data'].values(
                    )
                    pkt2 = _slp_type_reply_v2(
                        err_code, svc_type_list_len, svc_type_list.encode())

                else:
                    print('{0} function not yet supported.'.format(slp_func))

                pkt = pkt1 + pkt2
                pkt_rdy = compute_len_v2(pkt)
#                print('* SLP_SVC_REQ implemented')

            else:
                print('Not supported version {0}'.format(slp_ver))
                return False

    print(base)
    print(data)

    return pkt_rdy
