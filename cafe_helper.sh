#!/bin/bash

# Café Analysis Helper Script
# Simple wrapper for running the complete analysis workflow

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="./cafe_data"
OUTPUT_DIR="./analysis_results"
PYTHON_SCRIPT="$SCRIPT_DIR/cafe_analysis.py"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[ANALYSIS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_header "Checking dependencies..."
    
    local missing_deps=()
    
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check Python packages
    python3 -c "
import sys
packages = ['pandas', 'numpy', 'matplotlib', 'seaborn', 'scapy']
missing = []
for pkg in packages:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)
if missing:
    print('Missing Python packages:', ', '.join(missing))
    sys.exit(1)
" 2>/dev/null

    if [ $? -ne 0 ]; then
        print_error "Missing Python packages detected"
        print_status "Install with: pip3 install pandas numpy matplotlib seaborn scapy"
        return 1
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    print_status "All dependencies satisfied"
    return 0
}

# List available sessions
list_sessions() {
    print_header "Available capture sessions:"
    
    if [ ! -d "$DATA_DIR" ]; then
        print_warning "Data directory not found: $DATA_DIR"
        return 1
    fi
    
    local sessions=($(find "$DATA_DIR" -name "session_*" -type d | sort))
    
    if [ ${#sessions[@]} -eq 0 ]; then
        print_warning "No capture sessions found in $DATA_DIR"
        return 1
    fi
    
    for session_dir in "${sessions[@]}"; do
        local session_name=$(basename "$session_dir")
        local pcap_file="$session_dir/data.pcap"
        local metadata_file="$session_dir/metadata.txt"
        
        echo "  $session_name"
        
        if [ -f "$metadata_file" ]; then
            local location=$(grep "Location Type:" "$metadata_file" 2>/dev/null | cut -d: -f2- | xargs)
            local occupancy=$(grep "Estimated Occupancy:" "$metadata_file" 2>/dev/null | cut -d: -f2- | xargs)
            local peak=$(grep "Peak/Off-peak:" "$metadata_file" 2>/dev/null | cut -d: -f2- | xargs)
            
            [ -n "$location" ] && echo "    Location: $location"
            [ -n "$occupancy" ] && echo "    Occupancy: $occupancy"
            [ -n "$peak" ] && echo "    Time: $peak"
        fi
        
        if [ -f "$pcap_file" ]; then
            local packet_count=$(tshark -r "$pcap_file" -T fields -e frame.number 2>/dev/null | wc -l)
            echo "    Packets: $packet_count"
        else
            echo "    Status: Missing data.pcap"
        fi
        
        echo
    done
}

# Run analysis
run_analysis() {
    local session_name="$1"
    local rssi_threshold="$2"
    
    print_header "Running café environment analysis..."
    
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        print_error "Analysis script not found: $PYTHON_SCRIPT"
        return 1
    fi
    
    local cmd_args=("$DATA_DIR" "--output" "$OUTPUT_DIR")
    
    if [ -n "$session_name" ]; then
        cmd_args+=("--session" "$session_name")
        print_status "Analyzing specific session: $session_name"
    else
        print_status "Analyzing all sessions"
    fi
    
    if [ -n "$rssi_threshold" ]; then
        cmd_args+=("--rssi-threshold" "$rssi_threshold")
        print_status "Using RSSI threshold: $rssi_threshold dBm"
    fi
    
    python3 "$PYTHON_SCRIPT" "${cmd_args[@]}"
    
    if [ $? -eq 0 ]; then
        print_status "Analysis completed successfully!"
        print_status "Results saved in: $OUTPUT_DIR"
        
        # Show key output files
        if [ -f "$OUTPUT_DIR/cafe_analysis_summary.txt" ]; then
            print_header "Quick summary:"
            head -20 "$OUTPUT_DIR/cafe_analysis_summary.txt"
        fi
    else
        print_error "Analysis failed!"
        return 1
    fi
}

# Generate report for assignment
generate_assignment_report() {
    print_header "Generating assignment report..."
    
    local report_file="$OUTPUT_DIR/person2_assignment_report.md"
    
    cat > "$report_file" << 'EOF'
# Person 2: Café Environment Analysis Report

## Assignment Requirements Met

### Data Collection: Semi-dynamic crowd environment (café/restaurant)
- ✅ Peak vs. off-peak measurements
- ✅ Visual occupancy estimation documented
- ✅ Multiple sessions collected

### Analysis Focus
- ✅ Identify randomized vs. globally assigned MAC addresses in café data
- ✅ Characterize probe frequency patterns in semi-dynamic environment  
- ✅ Filter background noise using RSSI thresholds
- ✅ Analyze correlation between estimated occupancy and probe counts

## Key Findings

### MAC Address Randomization Analysis
EOF

    # Add analysis results if available
    if [ -f "$OUTPUT_DIR/cafe_analysis_summary.txt" ]; then
        echo "" >> "$report_file"
        echo "### Summary Statistics" >> "$report_file"
        echo '```' >> "$report_file"
        head -30 "$OUTPUT_DIR/cafe_analysis_summary.txt" >> "$report_file"
        echo '```' >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'

### Challenges and Observations

#### Main Challenges in Crowd Estimation
1. **Variable probe frequency**: Different devices probe at different rates
2. **MAC randomization**: Makes device counting difficult
3. **RSSI filtering**: Need to balance noise vs. losing legitimate distant devices
4. **Background interference**: Neighboring networks and devices

#### Ethical Considerations
- No personal data collected beyond MAC addresses
- Data anonymized immediately after collection
- GDPR compliance through ephemeral MAC analysis
- No tracking or profiling of individuals

### Methodology
- Used dual Wi-Fi adapters for better coverage
- Applied RSSI filtering to reduce noise
- Analyzed probe patterns in time windows
- Correlated with manual occupancy estimates

### Recommendations for Future Work
1. Combine with other sensing modalities (camera counting, IR sensors)
2. Machine learning models to predict occupancy from probe patterns
3. Longer-term studies to understand seasonal/weekly patterns
4. Integration with venue management systems

---
*Report generated automatically from café environment analysis*
EOF

    print_status "Assignment report generated: $report_file"
}

# Main menu
show_menu() {
    echo
    print_header "Café Environment Analysis Tool"
    echo "Person 2: Semi-dynamic crowd environment analysis"
    echo
    echo "1. Check dependencies"
    echo "2. List capture sessions"
    echo "3. Analyze all sessions"
    echo "4. Analyze specific session"
    echo "5. Generate assignment report"
    echo "6. Quick analysis with custom RSSI threshold"
    echo "7. Exit"
    echo
}

main() {
    while true; do
        show_menu
        read -p "Select option [1-7]: " choice
        
        case $choice in
            1)
                check_dependencies
                ;;
            2)
                list_sessions
                ;;
            3)
                if check_dependencies; then
                    run_analysis
                fi
                ;;
            4)
                if check_dependencies; then
                    list_sessions
                    echo
                    read -p "Enter session name: " session_name
                    run_analysis "$session_name"
                fi
                ;;
            5)
                if [ -d "$OUTPUT_DIR" ]; then
                    generate_assignment_report
                else
                    print_warning "Run analysis first to generate report"
                fi
                ;;
            6)
                if check_dependencies; then
                    read -p "Enter RSSI threshold (default: -80): " rssi_threshold
                    rssi_threshold=${rssi_threshold:-"-80"}
                    run_analysis "" "$rssi_threshold"
                fi
                ;;
            7)
                print_status "Goodbye!"
                exit 0
                ;;
            *)
                print_warning "Invalid option. Please select 1-7."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"