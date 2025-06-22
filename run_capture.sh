INTERFACE_NAME_1="wlx24050fe57a7d"
INTERFACE_NAME_2="wlx24050fe588e9"
DURATION_SEC=100

# setup interface
sudo ip link set $INTERFACE_NAME_1 down
sudo iwconfig $INTERFACE_NAME_1 mode monitor
sudo ip link set $INTERFACE_NAME_1 up

sudo ip link set $INTERFACE_NAME_2 down
sudo iwconfig $INTERFACE_NAME_2 mode monitor
sudo ip link set $INTERFACE_NAME_2 up


sudo iw $INTERFACE_NAME_1 set channel 1
sudo iw $INTERFACE_NAME_2 set channel 11


# sudo iw $INTERFACE_NAME_1 info
# sudo iw $INTERFACE_NAME_2 info


# sniff
tshark -f "wlan type mgt subtype probe-req" -i $INTERFACE_NAME_2 -i $INTERFACE_NAME_1 -a duration:$DURATION_SEC  -w data.pcap 

# reset interface
sudo ip link set $INTERFACE_NAME_1 down
sudo iwconfig $INTERFACE_NAME_1 mode managed
sudo ip link set $INTERFACE_NAME_1 up

sudo ip link set $INTERFACE_NAME_2 down
sudo iwconfig $INTERFACE_NAME_2 mode managed
sudo ip link set $INTERFACE_NAME_2 up