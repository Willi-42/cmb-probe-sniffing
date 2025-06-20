INTERFACE_NAME="wlx24050fe5804b"
DURATION_SEC=100

# setup interface
sudo ip link set $INTERFACE_NAME down
sudo iwconfig $INTERFACE_NAME mode monitor
sudo ip link set $INTERFACE_NAME up

# sniff
tshark -i $INTERFACE_NAME -a duration:$DURATION_SEC -f "wlan type mgt subtype probe-req" -w data.pcap

# reset interface
sudo ip link set $INTERFACE_NAME down
sudo iwconfig $INTERFACE_NAME mode managed
sudo ip link set $INTERFACE_NAME up
