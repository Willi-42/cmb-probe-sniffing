#!/usr/bin/env python

import binascii
from scapy.all import rdpcap
import pandas as pd


def is_mac_local(mac):
    """0 -> false, 1 -> true"""
    macbytes = binascii.unhexlify(mac.replace(':', ''))

    first_byte = macbytes[0]

    bit = (first_byte >> 1) & 1

    # use int instead of boolean -> easier to plot
    return bit


def is_signal_good(rssi):
    if rssi >= -80:
        return True
    return False


def get_raw_data(file):
    packets = rdpcap(file)

    data = pd.DataFrame(
        columns=['timestamp', 'rssi', 'rssi_good', 'local'])

    for i, p in enumerate(packets):
        timestamp = int(p.time * 1000)

        radio_tap = p.getlayer("RadioTap")
        rssi = radio_tap.dBm_AntSignal

        src = radio_tap.addr2
        is_local = is_mac_local(src)
        is_rssi_good = is_signal_good(rssi)

        data.loc[i] = [timestamp, rssi, is_rssi_good, is_local]

        # print(f"{src}, {timestamp}, {rssi} {is_rssi_good else}, {is_global}")

    basetime = data['timestamp'][0]
    data['time'] = pd.to_datetime(data['timestamp'] - basetime, unit='ms')

    return data


def get_filtered_data(file):
    data = get_raw_data(file)

    return data.loc[data["rssi"] > -80]


def main():
    """Starts the script"""
    data = get_raw_data("./data.pcap")

    value_cnts = data['local'].value_counts()
    global_cnt = value_cnts[0]
    local_cnt = value_cnts[1]

    total_good_rssi = data['rssi_good'].sum()

    print(f"Local: {local_cnt}\nGlobal: {global_cnt}")
    print(f"Good Signal: {total_good_rssi}")


if __name__ == "__main__":
    main()
