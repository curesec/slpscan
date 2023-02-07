import struct


def parse_slp_reply(data_dict):
    '''
    Attribute Reply
    Version | Function | PktLen | Flags | Dialect | Lang | Encoding | TransactionID | Error Code | Attribute List Len | Attribdata
       1b		1b			2b	   1b	   1b	     2b		  2b			 2b			 2b			      2b
    '''

    reply_pkt = data_dict['reply_pkt']
    slp_ver, slp_func, slp_pkt_len, slp_flags, slp_dialect, slp_lang, slp_enc, slp_transx,\
        slp_err, slp_attr_list = struct.unpack(
            '>BBHBBHHHHH', reply_pkt[:16])
    reply_dict = {'slp_ver': slp_ver,
                  'slp_func': slp_func,
                  'slp_pkt_len': slp_pkt_len,
                  'slp_flags': slp_flags,
                  'slp_dialect': slp_dialect,
                  'slp_lang': slp_lang,
                  'slp_enc': slp_enc,
                  'slp_transx': slp_transx,
                  'slp_err': slp_err,
                  'slp_attr_list': slp_attr_list}

    # FIXME FIXME
    #  ... disabling parsing for now
   # print(reply_dict)
    attr_data = reply_pkt[16:]
    # print(attr_data)
    s_attr_data = attr_data.split(b'(')
    print(s_attr_data)
    s_attr_data.remove(b'')
    hwdata = s_attr_data
    hw_dict = {}
    for item in hwdata:
        item = item.decode()
        item = item.rstrip(')')
        key_a, val_a = item.split('=')
        hw_dict[key_a] = val_a

    #hwdata = hwdata.decode()
    shwdata = hwdata.split('(')
    #hw_dict = {}
    # shwdata.remove('')
    print('-'*80)
    print(hwdata)
    print(hw_dict)
    print('-'*80)
    for b in shwdata:
        b = b.rstrip(')')
        b = b.split('=')

        key_b = b[0]
        val_b = b[1]
        hw_dict[key_b] = val_b
        print(b)
        if key_b == 'x-hp-p1':

            hw_dict[key_b] = {}
        ['x-hp-p1', 'MFG:Hewlett-Packard']

    s_attr_data.remove(b')')
    print(s_attr_data)
    for entry in s_attr_data:
        ee = entry.decode()
        ee = ee.split(':')
#        print(ee)
        hw_dict[ee[0]] = ee[1]

    return hw_dict
