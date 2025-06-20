#!/usr/bin/env python

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

from eval import get_filtered_data, get_raw_data


def save_graph(ax, fig, image_name, legend, yname):
    """Save plot to disc"""
    ax.legend(legend)
    ax.set_ylabel(yname)
    ax.set_xlabel("Time")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%M:%S"))
    ax.grid(axis="y")

    fig.tight_layout()
    fig.savefig(image_name, bbox_inches="tight")
    plt.close()


def plot_local_global_chart(file):
    data = get_filtered_data(file)

    data["global"] = 1 - data["local"]  # add global column

    # groupe data to 1s
    grouped = data.groupby(pd.Grouper(key="time", freq="10s")).sum()

    # draw graph
    legend = []
    image_name = "./plot.png"

    fig, ax = plt.subplots(dpi=300)

    ax.stackplot(grouped.index, grouped["local"], linestyle="-")
    legend.append("local")

    ax.stackplot(grouped.index, grouped["global"], linestyle="-")
    legend.append("global")

    save_graph(ax, fig, image_name, legend, "Mac")


def plot_rssi(file):
    data = get_raw_data(file)

    # draw graph
    legend = []
    image_name = "./plot_rssi.png"

    fig, ax = plt.subplots(dpi=300)

    ax.ecdf(data["rssi"], linestyle="-")
    legend.append("RSSI")

    # ax.legend(legend)
    ax.set_ylabel("distribution")
    ax.set_xlabel("RSSI")
    ax.grid(axis="y")
    fig.tight_layout()
    fig.savefig(image_name, bbox_inches="tight")
    plt.close()


def main():
    """Starts the script"""

    file = "./data.pcap"

    plot_local_global_chart(file)
    plot_rssi(file)


if __name__ == "__main__":
    main()
