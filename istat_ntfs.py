# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import datetime
import struct

def as_le_unsigned(b):

    table = {1: 'B', 2: 'H', 4: 'L', 8: 'Q'}

    return struct.unpack('<' + table[len(b)], b)[0]

def as_signed_le(bs):
    if len(bs) <= 0 or len(bs) > 8:
        raise ValueError()

    signed_format = {1: 'b', 2: 'h', 4: 'l', 8: 'q'}

    fill = b'\xFF' if ((bs[-1] & 0x80) >> 7) == 1 else b'\x00'

    while len(bs) not in signed_format:
        bs = bs + fill

    return struct.unpack('<' + signed_format[len(bs)], bs)[0]


def istat_ntfs(f, address, sector_size=512, offset=0):
    data = f.read()[offset*sector_size:]
    bps = as_signed_le(data[11:13]) #bytes per sector
    spc = data[13] # Sectors per cluster
    bpc = spc*bps #bytes per cluster
    record = as_signed_le(data[0x40:0x41])
    mft_cluster = as_signed_le(data[48:56])
    #cpi = data[68] # clusters per index
    mft_offset = bpc*mft_cluster
    
    if(record > 0):
        record *= bpc
    else:
        record = 2**(abs(record))
    
    mft = data[mft_offset + (address*record):]
    logfile_sequence = as_le_unsigned(mft[0x8:0x10])
    sequence = as_le_unsigned(mft[16:18])
    links = as_le_unsigned(mft[18:20])
    
    result = []
    
    content_offset = as_le_unsigned(mft[20:21])
    content = mft[content_offset:]
    atr_val = ''
    cre_time = ''
    mod_time = ''
    mtf_time = ''
    acc_time = ''
    
    f_atr_val = ''
    name_str = ''
    parent = ''
    f_sequence = ''
    allo_size = ''
    act_size = ''
    f_cre_time = ''
    f_mod_time = ''
    f_mtf_time = ''
    f_acc_time = ''
    owner_id = 0
    prev = ''
    cur = content
    count = 0
    attribute_len = 0
    f_attribute_len = 0
    d_attribute_len = 0
    res = "Non-Resident"
    f_res = "Non-Resident"
    d_res = "Non-Resident"
    found = False
    f_found = False
    d_found = False
    while(not(prev == cur or count == 2)): #STANDARD INFO
        found = True
        nxt = content[4]
        if(content[0] == 0x10):
            if(content[8] == 0):
                res = "Resident"
            attribute_len = as_le_unsigned(content[16:18])
            attribute_offset = as_le_unsigned(content[20:22])
            attribute = as_le_unsigned(content[attribute_offset:][32:36])
            cre_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][:8])[0])
            mod_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][8:16])[0])
            mtf_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][16:24])[0])
            acc_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][24:32])[0])
    
            #Attribute Checking
            if(not(attribute & 0b1 == 0)):
                atr_val += "Read Only, "
            if(not(attribute & 0b10 == 0)):
                atr_val += "Hidden, "
            if(not(attribute & 0b100 == 0)):
                atr_val += "System, "
            if(not(attribute & 0b100000 == 0)):
                atr_val += "Archive, "
            if(not(attribute & 0b1000000 == 0)):
                atr_val += "Device, "
            if(not(attribute & 0b10000000 == 0)):
                atr_val += "Normal, "
            if(attribute_len > 48):
                owner_id = as_le_unsigned(content[48:52])
            atr_val = atr_val[:len(atr_val)-2]
            prev = content
            content = content[nxt:]
            cur = content
            count = 0
            if(res == "Non-Resident"):
                attribute_len = as_le_unsigned(content[48:56])
        elif(content[0] == 0x30): #FILE
            f_found = True
            
            if(content[8] == 0):
                f_res = "Resident"
            
            f_attribute_len = as_le_unsigned(content[16:18])
            attribute_offset = as_le_unsigned(content[20:22])
            attribute = as_le_unsigned(content[attribute_offset:][56:60])
            
            name = content[66+attribute_offset:67+attribute_offset + content[64 + attribute_offset]*2-1]
            for n in name:
                if(not(n==0)):
                    name_str += hex(n)
                name_str = name_str.replace("0x",'')
            name_str = ''.join(chr(int(name_str[i:i+2], 16)) for i in range(0, len(name_str), 2))
        
            allo_size = as_le_unsigned(content[attribute_offset+40:attribute_offset+48])
            act_size = as_le_unsigned(content[attribute_offset+48:attribute_offset+56])
        
            f_cre_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][8:16])[0])
            f_mod_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][16:24])[0])
            f_mtf_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][24:32])[0])
            f_acc_time = into_localtime_string(struct.unpack('<Q', content[attribute_offset:][32:40])[0])
            
            parent = content[attribute_offset]
            f_sequence = content[6+attribute_offset]
            
            #Attribute Checking
            if(not(attribute & 0b1 == 0)):
                f_atr_val += "Read Only, "
            if(not(attribute & 0b10 == 0)):
                f_atr_val += "Hidden, "
            if(not(attribute & 0b100 == 0)):
                f_atr_val += "System, "
            if(not(attribute & 0b100000 == 0)):
                f_atr_val += "Archive, "
            if(not(attribute & 0b1000000 == 0)):
                f_atr_val += "Device, "
            if(not(attribute & 0b10000000 == 0)):
                f_atr_val += "Normal, "
            f_atr_val = atr_val[:len(f_atr_val)-2]
            prev = content
            content = content[nxt:]
            cur = content
            count = 0
            if(f_res == "Non-Resident"):
                f_attribute_len = as_le_unsigned(content[48:56])
        elif(content[0] == 0x80): #DATA
            d_found = True
            if(content[8] == 0):
                d_res = "Resident"
            attribute_offset = as_le_unsigned(content[20:22])
            
            d_attribute_len = as_le_unsigned(content[16:18])
            if(d_res == "Non-Resident"):
                d_attribute_len = as_le_unsigned(content[48:56])
            break
        
        elif((found and f_found) and (not d_found)):
            nxt2 = as_le_unsigned(content[4:5])
            content = content[nxt2:]
            count = 0
        count += 1

    result.append("MFT Entry Header Values:")
    result.append("Entry: " + str(address) + "        " + "Sequence: " + str(sequence))
    result.append("$LogFile Sequence Number: " + str(logfile_sequence))
    result.append("Allocated File")
    result.append("Links: " + str(links))
    result.append('')
    result.append("$STANDARD_INFORMATION Attribute Values:" )
    result.append("Flags: " + atr_val)
    result.append("Owner ID: " + str(owner_id))
    result.append("Created:\t" + str(cre_time))
    result.append("File Modified:\t" + str(mod_time))
    result.append("MFT Modified:\t" + str(mtf_time))
    result.append("Accessed:\t" + str(acc_time))
    result.append('')
    result.append("$FILE_NAME Attribute Values:")
    result.append("Flags: " + f_atr_val)
    result.append("Name: " + name_str)
    result.append("Parent MFT Entry: " + str(parent) + " \tSequence: " + str(f_sequence))
    result.append("Allocated Size: " + str(allo_size) + "   \tActual Size: " + str(act_size))
    result.append("Created:\t" + str(f_cre_time))
    result.append("File Modified:\t" + str(f_mod_time))
    result.append("MFT Modified:\t" + str(f_mtf_time))
    result.append("Accessed:\t" + str(f_acc_time))
    result.append('')
    result.append("Attributes:")
    if(res == "Resident"):
        result.append("Type: $STANDARD_INFORMATION (16-0)   Name: N/A   " + res + "   size: " + str(attribute_len))
    else:
        result.append("Type: $STANDARD_INFORMATION (16-0)   Name: N/A   " + res + "   size: " + str(attribute_len) + "  init_size: " + str(attribute_len))
    if(f_res == "Resident"):
        result.append("Type: $FILE_NAME (48-3)   Name: N/A   " + f_res + "   size: " + str(f_attribute_len))
    else:
        result.append("Type: $FILE_NAME (48-3)   Name: N/A   " + f_res + "   size: " + str(f_attribute_len) + "  init_size: " + str(f_attribute_len))
    if(d_res == "Resident"):
        result.append("Type: $DATA (128-2)   Name: N/A   " + d_res + "   size: " + str(d_attribute_len))
    else:
        result.append("Type: $DATA (128-2)   Name: N/A   " + d_res + "   size: " + str(d_attribute_len) + "  init_size: " + str(d_attribute_len))
        data_lst = []
        prev = 0
        run_lst = ''
        content = content[content[32]:]
        while(content[0] != 0):
            r_start = as_signed_le(content[2:4])
            r_len = content[1]
            r_start += prev
            prev = r_start
            while(r_len >= 1):
                if(len(data_lst) == 8):
                    run_lst = ''
                    for i in data_lst:
                        run_lst += str(i) + ' '
                    result.append(run_lst)
                    data_lst = []
                data_lst.append(r_start)
                r_start += 1
                r_len -= 1

            run_lst = ''
            for i in data_lst:
                run_lst += str(i) + ' '
            content = content[4:]

            result.append(run_lst)
        
    return result

def into_localtime_string(windows_timestamp):
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp 
    :return: an istat-compatible string representation of this time in EDT
    """
    dt = datetime.datetime.fromtimestamp((windows_timestamp - 116444736000000000) / 10000000)
    hms = dt.strftime('%Y-%m-%d %H:%M:%S')
    fraction = windows_timestamp % 10000000
    return hms + '.' + str(fraction) + '00 (EDT)'



if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Display details of a meta-data structure (i.e. inode).')
    parser.add_argument('-o', type=int, default=0, metavar='imgoffset',
                        help='The offset of the file system in the image (in sectors)')
    parser.add_argument('-b', type=int, default=512, metavar='dev_sector_size',
                        help='The size (in bytes) of the device sectors')
    parser.add_argument('image', help='Path to an NTFS raw (dd) image')
    parser.add_argument('address', type=int, help='Meta-data number to display stats on')
    args = parser.parse_args()
    with open(args.image, 'rb') as f:
        result = istat_ntfs(f, args.address, args.b, args.o)
        for line in result:
            print(line.strip())