#!/bin/bash

# Enhanced capture script for café environment data collection
# Person 2: Semi-dynamic crowd environment analysis

# Configuration
INTERFACE_NAME_1="wlx24050fe588e9"
INTERFACE_NAME_2="wlx24050fe57a7d"
DEFAULT_DURATION=300  # 5 minutes default
OUTPUT_DIR="./cafe_data"
CHANNELS_SET1=(1 6 11)  # Common 2.4GHz channels
CHANNELS_SET2=(36 40 44 48)  # 5GHz channels (if supported)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[SETUP]${NC} $1"
}

# Function to check if interface exists
check_interface() {
    local interface=$1
    if ! ip link show "$interface" &> /dev/null; then
        print_error "Interface $interface not found!"
        echo "Available interfaces:"
        ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'
        return 1
    fi
    return 0
}

# Function to setup monitor mode
setup_monitor_mode() {
    local interface=$1
    local channel=$2
    
    print_header "Setting up $interface on channel $channel"
    
    # Take interface down
    sudo ip link set "$interface" down
    if [ $? -ne 0 ]; then
        print_error "Failed to bring down $interface"
        return 1
    fi
    
    # Set monitor mode
    sudo iwconfig "$interface" mode monitor
    if [ $? -ne 0 ]; then
        print_error "Failed to set monitor mode on $interface"
        return 1
    fi
    
    # Bring interface up
    sudo ip link set "$interface" up
    if [ $? -ne 0 ]; then
        print_error "Failed to bring up $interface"
        return 1
    fi
    
    # Set channel
    sudo iw "$interface" set channel "$channel"
    if [ $? -ne 0 ]; then
        print_warning "Failed to set channel $channel on $interface (might not be supported)"
    fi
    
    print_status "$interface configured successfully"
    return 0
}

# Function to reset interface to managed mode
reset_interface() {
    local interface=$1
    
    print_header "Resetting $interface to managed mode"
    
    sudo ip link set "$interface" down
    sudo iwconfig "$interface" mode managed
    sudo ip link set "$interface" up
    
    print_status "$interface reset to managed mode"
}

# Function to create output directory with metadata
setup_output_dir() {
    local session_id=$1
    local location=$2
    local occupancy=$3
    local notes=$4
    
    local session_dir="$OUTPUT_DIR/session_${session_id}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$session_dir"
    
    # Create metadata file
    cat > "$session_dir/metadata.txt" << EOF
Session ID: $session_id
Date: $(date)
Location Type: Café/Restaurant (Semi-dynamic crowd)
Estimated Occupancy: $occupancy
Peak/Off-peak: $([[ $(date +%H) -ge 11 && $(date +%H) -le 14 || $(date +%H) -ge 17 && $(date +%H) -le 20 ]] && echo "Peak" || echo "Off-peak")
Weather: $(curl -s "wttr.in/?format=%C+%t" 2>/dev/null || echo "Unknown")
Additional Notes: $notes
Interfaces Used: $INTERFACE_NAME_1, $INTERFACE_NAME_2
Channels: Multiple (scanning)
Filter: Probe requests only
EOF
    
    echo "$session_dir"
}

# Fixed channel hopping capture function
channel_hopping_capture() {
    local duration=$1
    local output_file=$2
    local hop_interval=10  # seconds per channel
    
    print_status "Starting channel hopping capture for ${duration}s"
    print_status "This will automatically stop after $duration seconds"
    
    # Calculate how many channel cycles we can do
    local total_channels=${#CHANNELS_SET1[@]}
    local cycles=$((duration / (total_channels * hop_interval)))
    
    if [ $cycles -eq 0 ]; then
        cycles=1
        hop_interval=$((duration / total_channels))
    fi
    
    print_status "Will capture $hop_interval seconds per channel for $cycles cycles"
    
    # Start tshark in background
    sudo tshark -f "wlan type mgt subtype probe-req" \
                -i "$INTERFACE_NAME_1" -i "$INTERFACE_NAME_2" \
                -w "$output_file" &
    
    local tshark_pid=$!
    local elapsed=0
    
    # Channel hopping with countdown
    for ((cycle=1; cycle<=cycles; cycle++)); do
        print_status "Channel hopping cycle $cycle/$cycles"
        
        for channel in "${CHANNELS_SET1[@]}"; do
            # Check if we've reached the duration limit
            if [ $elapsed -ge $duration ]; then
                break 2
            fi
            
            # Check if tshark is still running
            if ! kill -0 $tshark_pid 2>/dev/null; then
                break 2
            fi
            
            print_status "Switching to channel $channel (${elapsed}s/${duration}s elapsed)"
            sudo iw "$INTERFACE_NAME_1" set channel "$channel" 2>/dev/null
            sudo iw "$INTERFACE_NAME_2" set channel "$channel" 2>/dev/null
            
            # Sleep in 1-second increments to track time better
            for ((j=0; j<hop_interval && elapsed<duration; j++)); do
                sleep 1
                ((elapsed++))
                
                # Show remaining time every 10 seconds
                if [ $((elapsed % 10)) -eq 0 ]; then
                    local remaining=$((duration - elapsed))
                    printf "\r[INFO] Capture progress: %d seconds remaining..." "$remaining"
                fi
                
                # Check if tshark died
                if ! kill -0 $tshark_pid 2>/dev/null; then
                    break 3
                fi
            done
        done
    done
    
    # Ensure tshark is stopped
    if kill -0 $tshark_pid 2>/dev/null; then
        print_status "\nStopping capture..."
        # Kill tshark aggressively
        sudo kill -TERM $tshark_pid 2>/dev/null
        sleep 2
        sudo kill -KILL $tshark_pid 2>/dev/null
        sudo pkill -f "tshark.*$(basename "$output_file")" 2>/dev/null
    fi
    
    # Brief pause for cleanup
    sleep 2
    echo  # New line
    
    # Wait for any remaining tshark processes to finish
    wait $tshark_pid 2>/dev/null
    
    # Check if file was created
    if [ -f "$output_file" ]; then
        return 0
    else
        return 1
    fi
}

# Function to run a single capture session
run_capture_session() {
    local session_id=$1
    local duration=$2
    local location="$3"
    local occupancy="$4"
    local notes="$5"
    
    print_header "Starting capture session: $session_id"
    
    # Setup output directory
    local session_dir=$(setup_output_dir "$session_id" "$location" "$occupancy" "$notes")
    local output_file="$session_dir/data.pcap"
    
    print_status "Output directory: $session_dir"
    print_status "Capture duration: ${duration}s"
    print_status "Estimated occupancy: $occupancy people"
    
    # Perform capture with channel hopping
    if channel_hopping_capture "$duration" "$output_file"; then
        print_status "Capture completed successfully"
        
        # Quick analysis
        local packet_count=$(tshark -r "$output_file" -T fields -e frame.number 2>/dev/null | wc -l)
        print_status "Captured $packet_count probe request frames"
        
        # Save quick stats
        echo "Packet Count: $packet_count" >> "$session_dir/metadata.txt"
        echo "Capture Rate: $(echo "scale=2; $packet_count / $duration" | bc -l) packets/second" >> "$session_dir/metadata.txt"
        
        echo "$session_dir"
    else
        print_error "Capture failed!"
        return 1
    fi
}

# Fixed background noise function (corrected order)
assess_background_noise() {
    local duration=60  # 1 minute
    
    print_header "Assessing background noise (${duration}s)"
    print_status "Please ensure no personal devices are active nearby"
    print_status "This will automatically stop after $duration seconds"
    
    local noise_dir="$OUTPUT_DIR/background_noise_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$noise_dir"
    
    # Start capture in background
    sudo tshark -f "wlan type mgt subtype probe-req" \
                -i "$INTERFACE_NAME_1" -i "$INTERFACE_NAME_2" \
                -w "$noise_dir/background.pcap" &
    local tshark_pid=$!
    
    # Show progress countdown
    for ((i=duration; i>=1; i--)); do
        printf "\r[INFO] Background noise capture: %d seconds remaining..." "$i"
        sleep 1
        
        # Check if tshark is still running
        if ! kill -0 $tshark_pid 2>/dev/null; then
            break
        fi
    done
    
    # Ensure tshark is stopped
    if kill -0 $tshark_pid 2>/dev/null; then
        print_status "\nStopping capture..."
        # Kill tshark aggressively
        sudo kill -TERM $tshark_pid 2>/dev/null
        sleep 2
        sudo kill -KILL $tshark_pid 2>/dev/null
        sudo pkill -f "tshark.*background.pcap" 2>/dev/null
    fi
    
    # Brief pause for cleanup
    sleep 2
    echo  # New line after progress
    
    # Check if capture was successful
    if [ -f "$noise_dir/background.pcap" ]; then
        local noise_packets=$(tshark -r "$noise_dir/background.pcap" -T fields -e frame.number 2>/dev/null | wc -l)
        print_status "Background noise: $noise_packets packets in ${duration}s"
        
        # Create noise profile
        cat > "$noise_dir/noise_profile.txt" << EOF
Background Noise Assessment
Date: $(date)
Duration: ${duration}s
Packet Count: $noise_packets
Rate: $(echo "scale=2; $noise_packets / $duration" | bc -l) packets/second
Location: Pre-measurement assessment
EOF
        
        echo "$noise_dir"
    else
        print_error "Background noise assessment failed - no data captured"
        return 1
    fi
}


# Main script logic
main() {
    print_header "Café Environment Wi-Fi Probe Capture Script"
    print_status "Person 2: Semi-dynamic crowd environment analysis"
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        print_error "This script requires root privileges. Please run with sudo."
        exit 1
    fi
    
    # Check for required tools
    for tool in tshark iwconfig iw bc curl; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "Required tool '$tool' is not installed"
            exit 1
        fi
    done
    
    # Check interfaces
    if ! check_interface "$INTERFACE_NAME_1" || ! check_interface "$INTERFACE_NAME_2"; then
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Setup interfaces
    if ! setup_monitor_mode "$INTERFACE_NAME_1" 1; then
        exit 1
    fi
    
    if ! setup_monitor_mode "$INTERFACE_NAME_2" 6; then
        exit 1
    fi
    
    # Show interface status
    print_status "Interface status:"
    sudo iw "$INTERFACE_NAME_1" info | grep -E "(Interface|type|channel)"
    sudo iw "$INTERFACE_NAME_2" info | grep -E "(Interface|type|channel)"
    
    # Interactive mode
    while true; do
        echo
        print_header "Capture Options:"
        echo "1. Assess background noise"
        echo "2. Quick capture (5 min)"
        echo "3. Standard capture (10 min)"
        echo "4. Extended capture (20 min)"
        echo "5. Custom capture"
        echo "6. Exit and reset interfaces"
        echo
        read -p "Select option [1-6]: " choice
        
        case $choice in
            1)
                assess_background_noise
                ;;
            2)
                read -p "Enter location description: " location
                read -p "Enter estimated occupancy: " occupancy
                read -p "Enter additional notes: " notes
                run_capture_session "quick" 300 "$location" "$occupancy" "$notes"
                ;;
            3)
                read -p "Enter location description: " location
                read -p "Enter estimated occupancy: " occupancy
                read -p "Enter additional notes: " notes
                run_capture_session "standard" 600 "$location" "$occupancy" "$notes"
                ;;
            4)
                read -p "Enter location description: " location
                read -p "Enter estimated occupancy: " occupancy
                read -p "Enter additional notes: " notes
                run_capture_session "extended" 1200 "$location" "$occupancy" "$notes"
                ;;
            5)
                read -p "Enter session ID: " session_id
                read -p "Enter duration (seconds): " duration
                read -p "Enter location description: " location
                read -p "Enter estimated occupancy: " occupancy
                read -p "Enter additional notes: " notes
                run_capture_session "$session_id" "$duration" "$location" "$occupancy" "$notes"
                ;;
            6)
                break
                ;;
            *)
                print_warning "Invalid option. Please select 1-6."
                ;;
        esac
    done
    
    # Reset interfaces
    reset_interface "$INTERFACE_NAME_1"
    reset_interface "$INTERFACE_NAME_2"
    
    print_status "Capture sessions completed. Data saved in: $OUTPUT_DIR"
    print_status "Use the analysis script to process your captured data."
}

# Trap to ensure interfaces are reset on exit
trap 'reset_interface "$INTERFACE_NAME_1"; reset_interface "$INTERFACE_NAME_2"' EXIT

# Run main function
main "$@"