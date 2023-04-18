#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep
from enum import Enum

import grpc

from addRules import *

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

DEFAULT_QFI = 0
APP_ID_UNKNOWN = 0
DEFAULT_SESSION_METER_IDX = 0
DEFAULT_APP_METER_IDX = 0

class InterfaceType(Enum):
    UNKNOWN = 0
    ACESS = 1
    CORE = 2

class Direction(Enum):
    UNKNOWN = 0
    UPLINK = 1
    DOWNLINK = 2
    OTHER = 3

class Slice(Enum):
    DEFAULT = 0

class TrafficClass(Enum):
    BEST_EFFORT = 0
    CONTROL = 1
    REAL_TIME = 2
    ELASTIC = 3





def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        print("tables here")
        #print(response)
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name, end=' ')
            for m in entry.match:
                print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print('->', action_name, end=' ')
            for p in action.params:
                print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                print('%r' % p.value, end=' ')
            print()

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    ret = []
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))
            ret.append(counter.data.byte_count)
    
    return ret 
    

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


def writeRules(p4info_helper, sw):

    # my station MAC
    writeMyStationRules(p4info_helper, sw, dst_mac="4e:97:ec:04:c7:f9")
    writeMyStationRules(p4info_helper, sw, dst_mac="ae:20:97:b1:d8:3a")

    # uplink 
    writeRoute_v4Rules(p4info_helper, sw, dst_ip_addr="172.16.4.1", mask=32,
                      src_mac="ae:20:97:b1:d8:3a", dst_mac="08:00:00:00:02:22", egress_port=2)


    writeInterfaceRules(p4info_helper, sw, dst_ip_addr="172.16.1.254", matching_bits=32,
                      src_iface=InterfaceType.ACESS.value, direction=Direction.UPLINK.value, slice_id=Slice.DEFAULT.value)

    writeSessionsUplinkRules(p4info_helper, sw, n3_address="172.16.1.254", teid=1, session_meter_idx=0)

    writeTerminationUplinkRules(p4info_helper, sw, ue_address="192.168.0.1", app_id=0,
                     ctr_idx=0, tc=TrafficClass.BEST_EFFORT.value, app_meter_idx=0)
    
    # downlink 
    writeRoute_v4Rules(p4info_helper, sw, dst_ip_addr="172.16.1.99", mask=32,
                      src_mac="08:00:00:00:02:22", dst_mac="ae:20:97:b1:d8:3a", egress_port=1)
    
    writeInterfaceRules(p4info_helper, sw, dst_ip_addr="192.168.0.1", matching_bits=32,
                      src_iface=InterfaceType.CORE.value, direction=Direction.DOWNLINK.value, slice_id=Slice.DEFAULT.value)

    writeSessionsDownlinkRules(p4info_helper, sw, ue_address="192.168.0.1", session_meter_idx=1, tunnel_peer_id=2)

    writeTunnelPeersRules(p4info_helper, sw, tunnel_peer_id=2, src_addr="172.16.1.254",
                     dst_addr="172.16.1.99", sport=2152)


    #rule dictionary
    rule = {
        "action": "forward",
        "ue_address": "192.168.0.1",
        "app_id": 0,
        "ctr_idx": 1,
        "teid": 2,
        "qfi": 1,
        "tc": TrafficClass.BEST_EFFORT.value,
        "app_meter_idx": 1
    }

    # rule = {
    #     "action": "drop",
    #     "ue_address": "192.168.0.1",
    #     "app_id": 0,
    #     "ctr_idx": 1
    # }
    writeTerminationDownlinkRules(p4info_helper, sw, rule=rule)



def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")

        print(s1.client_stub)
        writeRules(p4info_helper, s1)


        # TODO Uncomment the following two lines to read table entries from s1 and s2
        readTableRules(p4info_helper, s1)

        # Print the tunnel counters every 2 seconds

        terminateDownlink = False
        threshold = 10 * 1024 #10Kb

        while True:
            sleep(2)
            print('\n----- Reading tunnel counters -----')
            # 1 is downlink counter
            transmitted_bytes = printCounter(p4info_helper, s1, "PreQosPipe.pre_qos_counter", 1)
            if (not terminateDownlink) and transmitted_bytes[0] > threshold:
                #terminate downlink, simulate billing-related termination 
                # delete rule 
                rule = {
                    "action": "forward",
                    "ue_address": "192.168.0.1",
                    "app_id": 0,
                    "ctr_idx": 1,
                    "teid": 2,
                    "qfi": 1,
                    "tc": TrafficClass.BEST_EFFORT.value,
                    "app_meter_idx": 1
                }
                writeTerminationDownlinkRules(p4info_helper, s1, rule=rule, delete=True)
                print("Billing related downlink termination")
                terminateDownlink = True

            # 0 is uplink counter, assigned in main 


    except KeyboardInterrupt:
        print(" Shutting down.")
        ShutdownAllSwitchConnections()
    except grpc.RpcError as e:
        printGrpcError(e)
        ShutdownAllSwitchConnections()








if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/main.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/main.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
