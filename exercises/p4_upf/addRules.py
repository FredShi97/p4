import os
import sys


# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def writeRoute_v4Rules(p4info_helper, sw, dst_ip_addr, mask,
                     src_mac, dst_mac, egress_port):

    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.Routing.routes_v4",
        match_fields={
            "dst_prefix": (dst_ip_addr, mask)
        },
        action_name="PreQosPipe.Routing.route",
        action_params=
        {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "egress_port": egress_port
        })

    #print(table_entry)
    sw.WriteTableEntry(table_entry)
    print(f"install route rule: dst_prefix:{dst_ip_addr}/{mask}, \
    action param: src_mac: {src_mac}, dst_mac: {dst_mac}, egress_port: {egress_port}")



def writeMyStationRules(p4info_helper, sw, dst_mac):

    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.my_station",
        match_fields={
            "dst_mac": dst_mac
        },
        action_name="NoAction",
        action_params=None)
    sw.WriteTableEntry(table_entry)

    print(f"install my station rule: dst_mac:{dst_mac}")


def writeInterfaceRules(p4info_helper, sw, dst_ip_addr, matching_bits, src_iface,
                     direction, slice_id):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.interfaces",
        match_fields={
            "ipv4_dst_prefix": (dst_ip_addr, matching_bits)
        },
        action_name="PreQosPipe.set_source_iface",
        action_params={
            "src_iface": src_iface,
            "direction": direction,
            "slice_id": slice_id
        })

    sw.WriteTableEntry(table_entry)

    print(f"install interface rule: src_iface:{src_iface}, \
    direction: {direction}, slice_id: {slice_id}")



def writeSessionsUplinkRules(p4info_helper, sw, n3_address, teid, session_meter_idx):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.sessions_uplink",
        match_fields={
            "n3_address": n3_address,
            "teid": teid,

        },

        #TODO: add other actions
        action_name="PreQosPipe.set_session_uplink",
        action_params={
            "session_meter_idx": session_meter_idx,
        })
    sw.WriteTableEntry(table_entry)

    print(f"install session uplink rule: n3_address:{n3_address}, \
    teid: {teid}, action param: session meter index: {session_meter_idx}")


def writeSessionsDownlinkRules(p4info_helper, sw, ue_address, session_meter_idx,
                     tunnel_peer_id):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.sessions_downlink",
        match_fields={
            "ue_address": ue_address,
            "session_meter_idx": session_meter_idx
        },
        action_name="PreQosPipe.set_session_downlink",
        action_params={
            "tunnel_peer_id": tunnel_peer_id,
            "session_meter_idx": session_meter_idx
        })
    sw.WriteTableEntry(table_entry)

    print(f"install session downlink rule: ue_address:{ue_address}, \
    session_meter_idx: {session_meter_idx}, action param: tunnel_peer_id: {tunnel_peer_id}")


def writeTunnelPeersRules(p4info_helper, sw, tunnel_peer_id, src_addr,
                     dst_addr, sport):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.tunnel_peers",
        match_fields={
            "tunnel_peer_id": tunnel_peer_id
        },
        action_name="PreQosPipe.load_tunnel_param",
        action_params={
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "sport": sport
        })
    sw.WriteTableEntry(table_entry)

    print(f"install tunnel peers rule: tunnel_peer_id:{tunnel_peer_id}, \
    action param: src_addr: {src_addr}, dst_addr: {dst_addr}, sport: {sport}")


def writeTerminationUplinkRules(p4info_helper, sw, ue_address, app_id,
                     ctr_idx, tc, app_meter_idx):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.terminations_uplink",
        match_fields={
            "ue_address": ue_address,
            "app_id": app_id,

        },
        # TODO: add other actions
        action_name="PreQosPipe.uplink_term_fwd",
        action_params={
            "ctr_idx": ctr_idx,
            "tc": tc,
            "app_meter_idx": app_meter_idx,

        })
    sw.WriteTableEntry(table_entry)

    print(f"install termination uplink rule: ue_address:{ue_address}, app_id: {app_id}, \
    action param: ctr_idx: {ctr_idx}, tc: {tc}, app_meter_idx: {app_meter_idx}")

def writeTerminationDownlinkRules(p4info_helper, sw, ue_address, app_id,
                     ctr_idx, teid, qfi, tc, app_meter_idx):
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="PreQosPipe.terminations_downlink",
        match_fields={
            "ue_address": ue_address,
            "app_id": app_id
        },
        action_name="PreQosPipe.downlink_term_fwd",
        action_params={
            "ctr_idx": ctr_idx,
            "teid": teid,
            "qfi": qfi,
            "tc": tc,
            "app_meter_idx": app_meter_idx
        })
    sw.WriteTableEntry(table_entry)

    print(f"install termination uplink rule: ue_address:{ue_address}, app_id: {app_id}, \
    action param: ctr_idx: {ctr_idx}, teid: {teid}, qfi: {qfi}, tc: {tc}, app_meter_idx: {app_meter_idx}")
