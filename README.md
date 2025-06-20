# cmb-probe-sniffing

## Tasks and Questions

Reduce noise:
- remove packets with low rssi and only capture probe frames
- is this enough for Quesiton 3

## How to
Install `tshark`.

Set execution bit of `run_capture.sh`

```shell
sudo chmod u+x run_capture.sh
```
Check interface name of wlan adapter:

```shell
iwconfig
```
Update `INTERFACE_NAME` in the script.

Then `./run_capture.sh`. If it complains about access rights, check [this link](https://askubuntu.com/questions/748941/im-not-able-to-use-wireshark-couldnt-run-usr-bin-dumpcap-in-child-process).