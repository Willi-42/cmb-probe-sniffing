#!/usr/bin/env python

import binascii
from scapy.all import rdpcap


def check_mac(mac):

    macbytes = binascii.unhexlify(mac.replace(':', ''))

    first_byte = macbytes[0]

    bit = (first_byte >> 1) & 1

    if bit == 1:
        print("local")
    elif bit == 0:
        print("global")


def main():
    """Starts the script"""
    packets = rdpcap("./outfile.pcap")

    for p in packets:
        timestamp = p.time

        radio_tap = p.getlayer("RadioTap")
        rssi = radio_tap.dBm_AntSignal

        src = radio_tap.addr2

        print(f"{src}, {timestamp}, {rssi}")

        check_mac(src)


if __name__ == "__main__":
    main()
