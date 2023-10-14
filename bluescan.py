#!/usr/bin/python
# -*- coding: utf-8 -*-
# pip2 install PySocks
# on windows, must install win_inet_pton also : pip2 install win_inet_pton

from ctypes import *
import os
import socket
import traceback
try:
    import socks
except:
    os.system('pip2 install PySocks')
    try:
        os.system('pip2 install win_inet_pton')
    except:
        pass
finally:
    import socket
import struct
import logging
import Queue
import sys
import thread
import time
import argparse
from datetime import datetime

q_in = Queue.Queue(maxsize=1000)

class GetLog(object):
    logger = None
    @classmethod
    def get_log(cls, filename, print_lever, file_lever):
        logs_path = filename
        if cls.logger is None:
            cls.logger = logging.getLogger(__name__)
            cls.logger.setLevel(logging.INFO)
            fmt = '%(asctime)s: %(message)s'
            datefmt = '%Y-%m-%d %H:%M:%S'
            format = logging.Formatter(fmt, datefmt=datefmt)

            file_handler = logging.FileHandler(os.path.dirname(os.path.abspath(__file__))+'/'+filename)

            file_handler.setLevel(file_lever)  
            file_handler.setFormatter(format)

            console = logging.StreamHandler()
            console.setLevel(print_lever)
            console.setFormatter(format)

            cls.logger.addHandler(file_handler)
            cls.logger.addHandler(console)
        return cls.logger

log = GetLog.get_log(filename='cache.dat', print_lever=logging.INFO, file_lever=logging.CRITICAL)


class SMB_HEADER(Structure):
    """SMB Header decoder.
    """

    _pack_ = 1  # Alignment

    _fields_ = [
        ("server_component", c_uint32),
        ("smb_command", c_uint8),
        ("error_class", c_uint8),
        ("reserved1", c_uint8),
        ("error_code", c_uint16),
        ("flags", c_uint8),
        ("flags2", c_uint16),
        ("process_id_high", c_uint16),
        ("signature", c_uint64),
        ("reserved2", c_uint16),
        ("tree_id", c_uint16),
        ("process_id", c_uint16),
        ("user_id", c_uint16),
        ("multiplex_id", c_uint16)
    ]

    def __new__(self, buffer=None):
        return self.from_buffer_copy(buffer)

    def __init__(self, buffer):
        log.debug("server_component : %04x" % self.server_component)
        log.debug("smb_command      : %01x" % self.smb_command)
        log.debug("error_class      : %01x" % self.error_class)
        log.debug("error_code       : %02x" % self.error_code)
        log.debug("flags            : %01x" % self.flags)
        log.debug("flags2           : %02x" % self.flags2)
        log.debug("process_id_high  : %02x" % self.process_id_high)
        log.debug("signature        : %08x" % self.signature)
        log.debug("reserved2        : %02x" % self.reserved2)
        log.debug("tree_id          : %02x" % self.tree_id)
        log.debug("process_id       : %02x" % self.process_id)
        log.debug("user_id          : %02x" % self.user_id)
        log.debug("multiplex_id     : %02x" % self.multiplex_id)


def generate_smb_proto_payload(*protos):
    """Generate SMB Protocol. Pakcet protos in order.
    """
    hexdata = []
    for proto in protos:
        hexdata.extend(proto)
    return "".join(hexdata)


def calculate_doublepulsar_xor_key(s):
    """Calaculate Doublepulsar Xor Key
    """
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x


def negotiate_proto_request():
    """Generate a negotiate_proto_request packet.
    """
    log.debug("generate negotiate request")
    netbios = [
        '\x00',            # 'Message_Type'
        '\x00\x00\x54'     # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x72',              # 'smb_command': Negotiate Protocol
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x28',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      '\x00\x00',          # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    negotiate_proto_request = [
      '\x00',              # 'word_count'
      '\x31\x00',          # 'byte_count'

      # Requested Dialects
      '\x02',              # 'dialet_buffer_format'
      '\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',   # 'dialet_name': LANMAN1.0

      '\x02',              # 'dialet_buffer_format'
      '\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',   # 'dialet_name': LM1.2X002

      '\x02',              # 'dialet_buffer_format'
      '\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',  # 'dialet_name3': NT LANMAN 1.0

      '\x02',              # 'dialet_buffer_format'
      '\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'   # 'dialet_name4': NT LM 0.12
    ]

    return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
    """Generate session setuo andx request.
    """
    log.debug("generate session setup andx request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x63'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x73',              # 'smb_command': Session Setup AndX
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x20',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      '\x00\x00',          # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    session_setup_andx_request = [
      '\x0D',              # Word Count
      '\xFF',              # AndXCommand: No further command
      '\x00',              # Reserved
      '\x00\x00',          # AndXOffset
      '\xDF\xFF',          # Max Buffer
      '\x02\x00',          # Max Mpx Count
      '\x01\x00',          # VC Number
      '\x00\x00\x00\x00',  # Session Key
      '\x00\x00',          # ANSI Password Length
      '\x00\x00',          # Unicode Password Length
      '\x00\x00\x00\x00',  # Reserved
      '\x40\x00\x00\x00',  # Capabilities
      '\x26\x00',          # Byte Count
      '\x00',              # Account
      '\x2e\x00',          # Primary Domain
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',    # Native OS: Windows 2000 2195
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',        # Native OS: Windows 2000 5.0
    ]

    return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
    """Generate tree connect andx request.
    """
    log.debug("generate tree connect andx request")

    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x47'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x75',              # 'smb_command': Tree Connect AndX
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x07\x60',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      '\x00\x00',          # 'tree_id'
      '\x2F\x4B',          # 'process_id'
      userid,              # 'user_id'
      '\xC5\x5E'           # 'multiplex_id'
    ]

    ipc = "\\\\{}\IPC$\x00".format(ip)
    log.debug("Connecting to {} with UID = {}".format(ipc, userid))

    tree_connect_andx_request = [
      '\x04',              # Word Count
      '\xFF',              # AndXCommand: No further commands
      '\x00',              # Reserved
      '\x00\x00',          # AndXOffset
      '\x00\x00',          # Flags
      '\x01\x00',          # Password Length
      '\x1C\x00',          # Byte Count
      '\x00',              # Password
      ipc.encode(),        # \\xxx.xxx.xxx.xxx\IPC$
      '\x3f\x3f\x3f\x3f\x3f\x00'   # Service
    ]

    length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))
    # netbios[1] = '\x00' + struct.pack('>H', length)
    netbios[1] = struct.pack(">L", length)[-3:]

    return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):
    """Generate tran2 request
    """
    log.debug("generate peeknamedpipe request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x4a'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x25',              # 'smb_command': Trans2
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x01\x28',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    tran_request = [
      '\x10',              # Word Count
      '\x00\x00',          # Total Parameter Count
      '\x00\x00',          # Total Data Count
      '\xff\xff',          # Max Parameter Count
      '\xff\xff',          # Max Data Count
      '\x00',              # Max Setup Count
      '\x00',              # Reserved
      '\x00\x00',          # Flags
      '\x00\x00\x00\x00',  # Timeout: Return immediately
      '\x00\x00',          # Reversed
      '\x00\x00',          # Parameter Count
      '\x4a\x00',          # Parameter Offset
      '\x00\x00',          # Data Count
      '\x4a\x00',          # Data Offset
      '\x02',              # Setup Count
      '\x00',              # Reversed
      '\x23\x00',          # SMB Pipe Protocol: Function: PeekNamedPipe (0x0023)
      '\x00\x00',          # SMB Pipe Protocol: FID
      '\x07\x00',
      '\x5c\x50\x49\x50\x45\x5c\x00'  # \PIPE\
    ]

    return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
    """Generate trans2 request.
    """
    log.debug("generate tran2 request")
    netbios = [
      '\x00',              # 'Message_Type'
      '\x00\x00\x4f'       # 'Length'
    ]

    smb_header = [
      '\xFF\x53\x4D\x42',  # 'server_component': .SMB
      '\x32',              # 'smb_command': Trans2
      '\x00\x00\x00\x00',  # 'nt_status'
      '\x18',              # 'flags'
      '\x07\xc0',          # 'flags2'
      '\x00\x00',          # 'process_id_high'
      '\x00\x00\x00\x00\x00\x00\x00\x00',  # 'signature'
      '\x00\x00',          # 'reserved'
      treeid,
      processid,
      userid,
      multiplex_id
    ]

    trans2_request = [
      '\x0f',              # Word Count
      '\x0c\x00',          # Total Parameter Count
      '\x00\x00',          # Total Data Count
      '\x01\x00',          # Max Parameter Count
      '\x00\x00',          # Max Data Count
      '\x00',              # Max Setup Count
      '\x00',              # Reserved
      '\x00\x00',          # Flags
      '\xa6\xd9\xa4\x00',  # Timeout: 3 hours, 3.622 seconds
      '\x00\x00',          # Reversed
      '\x0c\x00',          # Parameter Count
      '\x42\x00',          # Parameter Offset
      '\x00\x00',          # Data Count
      '\x4e\x00',          # Data Offset
      '\x01',              # Setup Count
      '\x00',              # Reserved
      '\x0e\x00',          # subcommand: SESSION_SETUP
      '\x00\x00',          # Byte Count
      '\x0c\x00' + '\x00' * 12
    ]

    return generate_smb_proto_payload(netbios, smb_header, trans2_request)


    
    
def check(ip, port=445, timeout=2.0):
    """Check v exists.
    """
    try:
        buffersize = 1024

        # Send smb request based on socket.
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(args.t)
        try:
            client.connect((ip, port))
        except:
            if args.nb:
                nbtscan(ip)
            else:
                # log.info("[ ] [{}] err: {}".format(ip, 'close'))
                pass
            return

        # SMB - Negotiate Protocol Request
        # raw_proto = negotiate_proto_request()
        raw_proto = '\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        
        try:
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)
        except:
            nbtscan(ip)
            return

        payload2 = b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'
        client.send(payload2)
        tcp_response = client.recv(buffersize)
        nbt_info = get_info(tcp_response)
        

        
        # SMB - Session Setup AndX Request
        #raw_proto = session_setup_andx_request()
        raw_proto = '\x00\x00\x00\x88\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0d\xff\x00\x88\x00\x04\x11\x0a\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00'
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        
        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SMB_HEADER(smb_header)

        user_id = struct.pack('<H', smb.user_id)

        # parse native_os from Session Setup Andx Response
        session_setup_andx_response = tcp_response[36:]
        #print session_setup_andx_response[10:]
        
        native_os = session_setup_andx_response[9:].split('\x00')[0]
        
        # SMB - Tree Connect AndX Request
        #raw_proto = tree_connect_andx_request(ip, user_id)
        
        raw_proto = '\x00\x00\x00\x58\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe' + user_id + '\x40\x00\x04\xff\x00\x58\x00\x08\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x2e\x00\x39\x00\x39\x00\x2e\x00\x35\x00\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f\x3f\x00'
        
        #print len(raw_proto)
        client.send(raw_proto)
        
        nb_name = 'None'
        dns_name = 'None'
        nbt_domain_name = 'None'
        os_info = native_os
        if nbt_info and nbt_info.get('os_info') != None:
            os_info = nbt_info.get('os_info')
        if nbt_info and nbt_info.get('nbt_name') != None:
            nb_name = nbt_info['nbt_name']
        if nbt_info and nbt_info.get('dns_name') != None:
            dns_name = nbt_info['dns_name']
        if nbt_info and nbt_info.get('nbt_domain_name') != None:
            nbt_domain_name = nbt_info['nbt_domain_name']
        
        if nbt_info == None:
            nb_record = nbtscan(ip, False)
            if nb_record:
                nbt_domain_name, nb_name = nb_record.split('\\')
        if nbt_domain_name == nb_name:
            nbt_domain_name = 'WORKGROUP'
            dns_name = 'None'
        try:
            tcp_response = client.recv(buffersize)
        except:
            log.critical("[ ] [{}] {}\\{}  {}  ({})".format(ip, nbt_domain_name, nb_name, dns_name, os_info))
            return

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]   # SMB Header: 32 bytes
        smb = SMB_HEADER(smb_header)

        tree_id = struct.pack('<H', smb.tree_id)
        process_id = struct.pack('<H', smb.process_id)
        user_id = struct.pack('<H', smb.user_id)
        multiplex_id = struct.pack('<H', smb.multiplex_id)

        # SMB - PeekNamedPipe Request
        raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
        client.send(raw_proto)
        tcp_response = client.recv(buffersize)

        netbios = tcp_response[:4]
        smb_header = tcp_response[4:36]
        smb = SMB_HEADER(smb_header)

        # nt_status = smb_header[5:9]
        nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)

        # 0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
        # 0xC0000008 - STATUS_INVALID_HANDLE
        # 0xC0000022 - STATUS_ACCESS_DENIED


        netcard_info = oxid_scan(ip)
        if nt_status == '\x05\x02\x00\xc0':
            '''
                b'\x01\x00':'nbt_name',
                b'\x02\x00':'nbt_domain_name',
                b'\x03\x00':'dns_name',
                b'\x04\x00':'dns_domain_name',
            }
            '''
            
            log.critical("[+] [{}] {}\\{}  {}  ({}) multIP:{}".format(ip, nbt_domain_name, nb_name, dns_name, os_info, netcard_info)) #  

            # vulnerable to MS17-010, check for DoublePulsar infection
            raw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
            client.send(raw_proto)
            tcp_response = client.recv(buffersize)

            netbios = tcp_response[:4]
            smb_header = tcp_response[4:36]
            smb = SMB_HEADER(smb_header)

            if smb.multiplex_id == 0x0051:
                key = calculate_doublepulsar_xor_key(smb.signature)
                log.critical("{} INFECTED with DoublePulsar! - XOR Key: {}".format(ip, key))
        elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
            log.critical("[ ] [{}] {}\\{}  {}  ({}) multIP:{}".format(ip, nbt_domain_name, nb_name, dns_name, os_info, netcard_info)) #  
            # log.critical("[ ] [{}] {}".format(ip, native_os))
        else:
            # log.critical("[ ] [{}] {}".format(ip, native_os))
            log.critical("[ ] [{}] {}\\{}  {}  ({}) multIP:{}".format(ip, nbt_domain_name, nb_name, dns_name, os_info, netcard_info)) #  

    except Exception as e:
        # log.info("[ ] [{}] Exception: {}".format(ip, str(e)))
        pass
    finally:
        client.close()



def cidr_to_ip(cidr):
    ip, prefix = cidr.split('/')
    prefix = int(prefix)
    
    subnet_mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
    
    network_address = ip_int & subnet_mask
    
    broadcast_address = network_address | (~subnet_mask & 0xFFFFFFFF)
    
    
    for i in range(network_address + 1, broadcast_address):
        q_in.put(socket.inet_ntoa(struct.pack('!I', i)))
    
UNIQUE_NAMES = {
    b'\x00': 'Workstation Service',
    b'\x03': 'Messenger Service',
    b'\x06': 'RAS Server Service',
    b'\x1F': 'NetDDE Service',
    b'\x20': 'Server Service',
    b'\x21': 'RAS Client Service',
    b'\xBE': 'Network Monitor Agent',
    b'\xBF': 'Network Monitor Application',
    b'\x03': 'Messenger Service',
    b'\x1D': 'Master Browser',
    b'\x1B': 'Domain Master Browser',
}
GROUP_NAMES = {
    b'\x00': 'Domain Name',
    b'\x1C': 'Domain Controllers',
    b'\x1E': 'Browser Service Elections',
    # Master Browser
}

NetBIOS_ITEM_TYPE = {
    b'\x01\x00':'nbt_name',
    b'\x02\x00':'nbt_domain_name',
    b'\x03\x00':'dns_name',
    b'\x04\x00':'dns_domain_name',
}



def get_info(ret):
    try:
        msg = ''
        length = ord(ret[43:44]) + ord(ret[44:45]) * 256
        
        os_version = ret[47 + length:]
        os_version = os_version.replace(b'\x00\x00', b'|').replace(b'\x00', b'').decode('UTF-8', errors='ignore') 
        if os_version[-1] == '|':
            os_version = os_version[0:-1]

        start = ret.find(b'NTLMSSP')

        length = ord(ret[start + 40:start + 41]) + ord(ret[start + 41:start + 42]) * 256 
        offset = ord(ret[start + 44:start + 45])
        
        # 8 bit 
        # print('Major Version: %d' % ord(ret[start + 48:start + 49]))
        msg += 'Major Version: %d' % ord(ret[start + 48:start + 49]) + '\n'
        # print('Minor Version: %d' % ord(ret[start + 49:start + 50]))
        msg += 'Minor Version: %d' % ord(ret[start + 49:start + 50]) + '\n'
        # print('Bulid Number: %d' %    (ord(ret[start + 50:start + 51]) + 256 * ord(ret[start + 51:start + 52])))
        msg += 'Bulid Number: %d' %  (ord(ret[start + 50:start + 51]) + 256 * ord(ret[start + 51:start + 52])) + '\n'
        msg += 'NTLM Current Revision: %d' % (ord(ret[start + 55:start + 56]) ) + '\n' 

        index = start + offset

        '''
        GROUP_NAMES = {
            b'\x00': 'Domain Name',
            b'\x1C': 'Domain Controllers',
            b'\x1E': 'Browser Service Elections',
            # Master Browser
        }

        NetBIOS_ITEM_TYPE = {
            b'\x01\x00':'NetBIOS computer name',
            b'\x02\x00':'NetBIOS domain name',
            b'\x03\x00':'DNS computer name',
            b'\x04\x00':'DNS domain name',
            b'\x05\x00':'DNS tree name',
            # b'\x06\x00':'',
            b'\x07\x00':'Time stamp',
        }
        '''
        res = {'os_info': os_version}
        while index < start + offset + length:
            item_type = ret[index:index + 2]
            item_length = ord(ret[index + 2:index +3]) + ord(ret[index + 3:index +4]) * 256  
            item_content = ret[index + 4: index + 4 + item_length].replace(b'\x00', b'')
            if item_type == b'\x07\x00':
                pass
            
            elif item_type in NetBIOS_ITEM_TYPE:
                res[NetBIOS_ITEM_TYPE[item_type]] = item_content.decode(errors='ignore')
            elif item_type == b'\x00\x00':  #  end
                break
            else:
                pass
            index +=  4 + item_length
        return res
    except Exception as e:
        # traceback.print_exc()
        # print(ret)
        pass

def checkfile_own(path):
    try:
        file = open(path,'r')
        for i in file.readlines():
            i = i.strip()
            q_in.put(i)
        file.close()
    except Exception as e:
        print(e)


def nbns_name(addr):
    msg = ''
    data = b'ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(args.t)
        s.sendto(data, (addr, 137))
        rep = s.recv(2000)
        if isinstance(rep, str):
            rep = bytes(rep)

        num = ord(rep[56:57].decode()) #  num of the answer
        data = rep[57:]  # start of the answer

        group, unique = '', ''
        msg += '--------------------------' + '\n'
        for i in range(num):
            name = data[18 * i:18 *i + 15].decode()
            flag_bit = bytes(data[18 * i + 15:18 *i + 16])
            if flag_bit in GROUP_NAMES and flag_bit != b'\x00':  # G TODO
                msg += '%s\t%s\t%s' % (name, 'G', GROUP_NAMES[flag_bit]) + '\n'
                pass
            elif flag_bit in UNIQUE_NAMES and flag_bit != b'\x00':  # U 
                msg += '%s\t%s\t%s' % (name, 'U', UNIQUE_NAMES[flag_bit]) + '\n'
                pass
            elif flag_bit in b'\x00':
                name_flags = data[18 * i + 16:18 *i + 18]
                if ord(name_flags[0:1])>=128:
                    group = name.strip()
                    msg += '%s\t%s\t%s' % (name, 'G', GROUP_NAMES[flag_bit]) + '\n'
                else:
                    unique = name
                    msg += '%s\t%s\t%s' % (name, 'U', UNIQUE_NAMES[flag_bit]) + '\n'
            else:
                msg += '%s\t-\t-' % name + '\n'
                pass
        msg += '--------------------------' + '\n'
        msg = '%s\\%s' % (group, unique) + '\n' + msg
        return { 'group':group, 'unique':unique, 'msg':msg }
    
    except Exception as e:
        # print('Fail to Connect to UDP 137')
        # log.info("[ ] [{}] err: {}".format(addr, str(e)))
        return False


def netbios_encode(src):  
    src = src.ljust(16,"\x20")
    names = []
    for c in src:
        char_ord = ord(c)
        high_4_bits = char_ord >> 4
        low_4_bits = char_ord & 0x0f
        names.append(high_4_bits)
        names.append(low_4_bits)
    
    res = b''
    for name in names:
        res += chr(0x41 + name).encode()
    return res


def nbtscan(addr, is_write=True):
    try:
        nbns_result = nbns_name(addr)
        if not nbns_result:
            return
        elif not nbns_result['unique']:
            return
        nbt_name = nbns_result['msg'].split('\n')[0].strip()
        netcard_info = oxid_scan(addr)
        if is_write:
            log.critical("[ ] [{}] {} multIP:{}".format(addr, nbt_name, netcard_info))
        return nbt_name
    except Exception as e:
        # log.info("[ ] [{}] Exception: {}".format(addr, str(e)))
        pass



def oxid_scan(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(args.t)
        sock.connect((ip,135))
        buffer_v1 = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
        buffer_v2 = "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
        sock.send(buffer_v1)
        packet = sock.recv(1024)
        sock.send(buffer_v2)
        packet = sock.recv(4096)
        packet_v2 = packet[42:]
        packet_v2_end = packet_v2.find("\x09\x00\xff\xff\x00\x00")
        packet_v2 = packet_v2[:packet_v2_end]
        hostname_list = packet_v2.split("\x00\x00")
        result = []
        # print("[*] " + ip)
        for h in hostname_list:
            h = h.replace('\x07\x00','')
            h = h.replace('\x00','')
            if h == '':
                continue
            result.append(h)
        # print result
        if len(result) > 2:
            result = result[1:]
            return ",".join(result)
        else:
            return 'None'
    except Exception as e:
        traceback.print_exc()
        return 'None'
    finally:
        sock.close()




def consumer_exp():
    while True:
        try:
            ip = q_in.get(True, 3)
        except:
            break
        check(ip)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-ip", type=str, help="ip or cidr", nargs='?',)
    parser.add_argument("-f", type=str, help="ip file", nargs='?')
    parser.add_argument("-t", type=float, help="timeout", nargs='?', default=6.0)
    parser.add_argument("-n", type=int, help="thread number", nargs='?', default=45)
    parser.add_argument("-p", type=str, help="proxy. http://x.x.x.x:xx or socks5://x.x.x.x:xx", nargs='?', default='')
    parser.add_argument("-nb", '--nb', help="start nb", action='store_true')

    args = parser.parse_args()
    if args.f is None and args.ip is None:
        parser.print_help()
        sys.exit(1)
    if args.f and args.ip:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.p:
            ip_port = args.p.split('//')[1]
            p_ip, p_port = ip_port.split(':')
            p_port = int(p_port)
            if 'socks5://' in args.p or 'http://' in args.p:
                p_type = None
                if 'socks5' in args.p:  
                    p_type = socks.SOCKS5
                else: 
                    p_type = socks.HTTP
                socks.set_default_proxy(p_type, addr=p_ip, port=p_port)
                socket.socket = socks.socksocket
    except:
      pass
    
    
    if args.f:
        try:
            thread.start_new_thread(checkfile_own, (args.f, ))
        except Exception as e:
            print("Error t")
    if args.ip:
        if '/' not in args.ip:
            q_in.put(args.ip)
        else:
            try:
                thread.start_new_thread(cidr_to_ip, (args.ip, ))
            except Exception as e:
                print("Error t")

    for thread_id in range(0, args.n):
        try:
            thread.start_new_thread(consumer_exp, ())
        except Exception as e:
            print("Error t")

    while True:
        time.sleep(1)
        if q_in.empty():
            time.sleep(args.t)
            break
        

