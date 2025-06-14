#!/usr/bin/env python

import binascii
from scapy.all import rdpcap


def is_mac_gloabl(mac):
    macbytes = binascii.unhexlify(mac.replace(':', ''))

    first_byte = macbytes[0]

    bit = (first_byte >> 1) & 1

    if bit == 1:
        return False

    return True


def is_signal_good(rssi):
    if rssi >= -80:
        return True
    return False


def main():
    """Starts the script"""
    packets = rdpcap("./data.pcap")

    local_cnt = 0
    good_rssi_cnt = 0

    for p in packets:
        timestamp = p.time

        radio_tap = p.getlayer("RadioTap")
        rssi = radio_tap.dBm_AntSignal

        src = radio_tap.addr2
        is_global = is_mac_gloabl(src)
        is_rssi_good = is_signal_good(rssi)

        # print(f"{src}, {timestamp}, {rssi} {'good' if is_rssi_good else 'bad'}, {'global' if is_global else 'local'}")

        if is_rssi_good:
            good_rssi_cnt += 1

        if is_global:
            local_cnt += 1

    global_cnt = len(packets) - local_cnt
    print(f"Local: {local_cnt}\nGlobal: {global_cnt}")
    print(f"Good Signal: {good_rssi_cnt}")


if __name__ == "__main__":
    main()
