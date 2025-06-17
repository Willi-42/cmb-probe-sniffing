#!/usr/bin/env python

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import datetime as dt
import pandas as pd
from eval import parse_data


def save_graph(ax, fig, image_name, legend, yname):
    """Save plot to disc"""
    ax.legend(legend)
    ax.set_ylabel(yname)
    ax.set_xlabel('Time')
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%M:%S"))
    ax.grid(axis='y')

    fig.tight_layout()
    fig.savefig(image_name, bbox_inches='tight')
    plt.close()


def main():
    """Starts the script"""

    data = parse_data("./data.pcap")

    data['global'] = 1 - data['local']  # add global column

    print(data)

    # groupe data to 1s
    basetime = data['timestamp'][0]
    data['time'] = pd.to_datetime(data['timestamp'] - basetime, unit='ms')

    grouped = data.groupby(pd.Grouper(key='time', freq='1s')).sum()

    # draw graph
    legend = []
    image_name = "./plot.png"

    fig, ax = plt.subplots(dpi=300)

    ax.plot(grouped.index, grouped['local'], linestyle='-')
    legend.append("local")

    ax.plot(grouped.index, grouped['global'], linestyle='-')
    legend.append("global")

    save_graph(ax, fig, image_name, legend, 'Mac')


if __name__ == "__main__":
    main()
