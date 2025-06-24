#!/usr/bin/env python3

"""
Comprehensive Café Environment Analysis Script
Person 2: Semi-dynamic crowd environment analysis

This script analyzes Wi-Fi probe request data collected in café environments,
focusing on MAC address randomization patterns, probe frequency analysis,
and correlation with occupancy estimates.
"""

import os
import glob
import json
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import seaborn as sns
from scapy.all import rdpcap
import binascii
import warnings
warnings.filterwarnings('ignore')

# Configuration
RSSI_THRESHOLDS = {
    'strong': -50,    # Very close devices
    'medium': -70,    # Nearby devices  
    'weak': -80,      # Distant devices
    'background': -90 # Background noise threshold
}

# OUI database for vendor identification (partial list)
COMMON_OUIS = {
    '00:1B:63': 'Apple',
    '00:25:00': 'Apple', 
    '28:CD:C1': 'Apple',
    'AC:DE:48': 'Apple',
    '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',
    'BC:5F:F4': 'Samsung',
    '28:6E:D4': 'Samsung',
    '2C:54:91': 'Samsung',
    '00:1A:11': 'Google',
    'DA:A1:19': 'Google'
}

class ProbeAnalyzer:
    """Comprehensive analysis of Wi-Fi probe requests for café environment"""
    
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.sessions = {}
        self.background_noise = None
        
    def is_mac_randomized(self, mac):
        """
        Determine if MAC address is randomized
        Returns: 0 for global, 1 for local (randomized)
        """
        try:
            mac_bytes = binascii.unhexlify(mac.replace(":", ""))
            first_byte = mac_bytes[0]
            # Check locally administered bit (bit 1 of first byte)
            return (first_byte >> 1) & 1
        except:
            return -1  # Invalid MAC
    
    def get_vendor_from_mac(self, mac):
        """Get vendor from MAC address OUI"""
        oui = mac[:8].upper()
        return COMMON_OUIS.get(oui, 'Unknown')
    
    def categorize_rssi(self, rssi):
        """Categorize RSSI strength"""
        if rssi >= RSSI_THRESHOLDS['strong']:
            return 'strong'
        elif rssi >= RSSI_THRESHOLDS['medium']:
            return 'medium'
        elif rssi >= RSSI_THRESHOLDS['weak']:
            return 'weak'
        else:
            return 'background'
    
    def load_session_metadata(self, session_dir):
        """Load metadata from session directory"""
        metadata_file = os.path.join(session_dir, 'metadata.txt')
        metadata = {}
        
        if os.path.exists(metadata_file):
            with open(metadata_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        metadata[key.strip()] = value.strip()
        
        return metadata
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze a single PCAP file and return structured data"""
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading {pcap_file}: {e}")
            return None
        
        data = []
        
        for i, packet in enumerate(packets):
            try:
                # Extract timestamp
                timestamp = int(packet.time * 1000)
                
                # Get RadioTap layer
                if packet.haslayer('RadioTap'):
                    radiotap = packet.getlayer('RadioTap')
                    
                    # Extract RSSI
                    rssi = getattr(radiotap, 'dBm_AntSignal', None)
                    if rssi is None:
                        continue
                    
                    # Extract source MAC
                    src_mac = getattr(radiotap, 'addr2', None)
                    if src_mac is None:
                        continue
                    
                    # Additional RadioTap fields
                    channel = getattr(radiotap, 'Channel', None)
                    rate = getattr(radiotap, 'Rate', None)
                    
                    # Analyze MAC address
                    is_randomized = self.is_mac_randomized(src_mac)
                    vendor = self.get_vendor_from_mac(src_mac)
                    rssi_category = self.categorize_rssi(rssi)
                    
                    data.append({
                        'timestamp': timestamp,
                        'mac_address': src_mac,
                        'rssi': rssi,
                        'rssi_category': rssi_category,
                        'is_randomized': is_randomized,
                        'vendor': vendor,
                        'channel': channel,
                        'rate': rate
                    })
                    
            except Exception as e:
                continue
        
        if not data:
            return None
        
        df = pd.DataFrame(data)
        
        # Convert timestamp to datetime
        base_time = df['timestamp'].min()
        df['datetime'] = pd.to_datetime(df['timestamp'] - base_time, unit='ms')
        df['relative_time_sec'] = (df['timestamp'] - base_time) / 1000
        
        return df
    
    def load_all_sessions(self):
        """Load all capture sessions from data directory"""
        session_dirs = glob.glob(os.path.join(self.data_dir, 'session_*'))
        
        for session_dir in session_dirs:
            session_name = os.path.basename(session_dir)
            pcap_file = os.path.join(session_dir, 'data.pcap')
            
            if not os.path.exists(pcap_file):
                print(f"Warning: No data.pcap found in {session_dir}")
                continue
            
            print(f"Loading session: {session_name}")
            
            # Load metadata
            metadata = self.load_session_metadata(session_dir)
            
            # Analyze PCAP
            df = self.analyze_pcap_file(pcap_file)
            
            if df is not None:
                self.sessions[session_name] = {
                    'data': df,
                    'metadata': metadata,
                    'path': session_dir
                }
                print(f"  Loaded {len(df)} probe requests")
            else:
                print(f"  Failed to load data from {pcap_file}")
        
        # Load background noise if available
        noise_dirs = glob.glob(os.path.join(self.data_dir, 'background_noise_*'))
        if noise_dirs:
            latest_noise = max(noise_dirs, key=os.path.getctime)
            noise_pcap = os.path.join(latest_noise, 'background.pcap')
            if os.path.exists(noise_pcap):
                self.background_noise = self.analyze_pcap_file(noise_pcap)
                if self.background_noise is not None:
                    print(f"Loaded background noise: {len(self.background_noise)} packets")
                else:
                    print(f"Warning: Could not load background noise from {noise_pcap}")
    
    def filter_by_rssi(self, df, threshold=RSSI_THRESHOLDS['weak']):
        """Filter data by RSSI threshold"""
        return df[df['rssi'] >= threshold].copy()
    
    def analyze_mac_randomization(self, df):
        """Analyze MAC address randomization patterns"""
        total_packets = len(df)
        randomized_packets = len(df[df['is_randomized'] == 1])
        global_packets = len(df[df['is_randomized'] == 0])
        
        unique_macs = df['mac_address'].nunique()
        unique_randomized = df[df['is_randomized'] == 1]['mac_address'].nunique()
        unique_global = df[df['is_randomized'] == 0]['mac_address'].nunique()
        
        return {
            'total_packets': total_packets,
            'randomized_packets': randomized_packets,
            'global_packets': global_packets,
            'randomized_percentage': (randomized_packets / total_packets) * 100,
            'unique_macs': unique_macs,
            'unique_randomized': unique_randomized,
            'unique_global': unique_global,
            'randomization_ratio': unique_randomized / unique_global if unique_global > 0 else float('inf')
        }
    
    def analyze_probe_patterns(self, df, window_size='10S'):
        """Analyze probe request patterns over time"""
        df_copy = df.copy()
        df_copy.set_index('datetime', inplace=True)
        
        # Group by time windows
        patterns = {
            'total_per_window': df_copy.resample(window_size).size(),
            'unique_macs_per_window': df_copy.resample(window_size)['mac_address'].nunique(),
            'randomized_per_window': df_copy[df_copy['is_randomized'] == 1].resample(window_size).size(),
            'global_per_window': df_copy[df_copy['is_randomized'] == 0].resample(window_size).size(),
            'avg_rssi_per_window': df_copy.resample(window_size)['rssi'].mean()
        }
        
        return patterns
    
    def analyze_vendor_distribution(self, df):
        """Analyze device vendor distribution"""
        global_macs = df[df['is_randomized'] == 0]
        vendor_counts = global_macs['vendor'].value_counts()
        
        return {
            'vendor_distribution': vendor_counts.to_dict(),
            'total_identifiable_devices': len(global_macs['mac_address'].unique()),
            'vendor_diversity': vendor_counts.nunique()
        }
    
    def generate_session_report(self, session_name):
        """Generate comprehensive report for a single session"""
        if session_name not in self.sessions:
            return None
        
        session = self.sessions[session_name]
        df = session['data']
        metadata = session['metadata']
        
        # Basic statistics
        basic_stats = {
            'total_packets': len(df),
            'duration_minutes': df['relative_time_sec'].max() / 60,
            'unique_devices': df['mac_address'].nunique(),
            'avg_rssi': df['rssi'].mean(),
            'rssi_range': (df['rssi'].min(), df['rssi'].max())
        }
        
        # Filter by RSSI threshold
        filtered_df = self.filter_by_rssi(df)
        
        # MAC randomization analysis
        mac_analysis = self.analyze_mac_randomization(filtered_df)
        
        # Probe patterns
        probe_patterns = self.analyze_probe_patterns(filtered_df)
        
        # Vendor analysis
        vendor_analysis = self.analyze_vendor_distribution(filtered_df)
        
        # RSSI distribution
        rssi_dist = filtered_df['rssi_category'].value_counts().to_dict()
        
        return {
            'session_name': session_name,
            'metadata': metadata,
            'basic_stats': basic_stats,
            'mac_randomization': mac_analysis,
            'probe_patterns': probe_patterns,
            'vendor_analysis': vendor_analysis,
            'rssi_distribution': rssi_dist,
            'filtered_data': filtered_df
        }
    
    def create_visualizations(self, session_name, output_dir):
        """Create comprehensive visualizations for a session"""
        report = self.generate_session_report(session_name)
        if not report:
            return
        
        df = report['filtered_data']
        session_output_dir = os.path.join(output_dir, f"analysis_{session_name}")
        os.makedirs(session_output_dir, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # 1. Timeline plot of probe requests
        fig, axes = plt.subplots(3, 1, figsize=(15, 12))
        
        # Total probes over time
        patterns = report['probe_patterns']
        axes[0].plot(patterns['total_per_window'].index, patterns['total_per_window'].values, 
                    marker='o', linewidth=2, markersize=4)
        axes[0].set_title('Probe Requests Over Time (10-second windows)')
        axes[0].set_ylabel('Probe Count')
        axes[0].grid(True, alpha=0.3)
        
        # Randomized vs Global MACs
        axes[1].plot(patterns['randomized_per_window'].index, patterns['randomized_per_window'].values, 
                    label='Randomized', marker='o', linewidth=2, markersize=3)
        axes[1].plot(patterns['global_per_window'].index, patterns['global_per_window'].values, 
                    label='Global', marker='s', linewidth=2, markersize=3)
        axes[1].set_title('Randomized vs Global MAC Addresses Over Time')
        axes[1].set_ylabel('Probe Count')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        # Average RSSI over time
        axes[2].plot(patterns['avg_rssi_per_window'].index, patterns['avg_rssi_per_window'].values, 
                    color='red', marker='d', linewidth=2, markersize=3)
        axes[2].set_title('Average RSSI Over Time')
        axes[2].set_ylabel('RSSI (dBm)')
        axes[2].set_xlabel('Time')
        axes[2].grid(True, alpha=0.3)
        
        # Format x-axis
        for ax in axes:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            ax.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(os.path.join(session_output_dir, 'timeline_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. MAC Address Analysis
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # MAC type distribution
        mac_data = [report['mac_randomization']['global_packets'], 
                   report['mac_randomization']['randomized_packets']]
        axes[0,0].pie(mac_data, labels=['Global MACs', 'Randomized MACs'], autopct='%1.1f%%', 
                     colors=['skyblue', 'lightcoral'])
        axes[0,0].set_title('MAC Address Type Distribution')
        
        # RSSI distribution
        rssi_cats = list(report['rssi_distribution'].keys())
        rssi_counts = list(report['rssi_distribution'].values())
        axes[0,1].bar(rssi_cats, rssi_counts, color=['red', 'orange', 'yellow', 'green'])
        axes[0,1].set_title('RSSI Strength Distribution')
        axes[0,1].set_ylabel('Packet Count')
        axes[0,1].tick_params(axis='x', rotation=45)
        
        # Vendor distribution (only for global MACs)
        vendor_dist = report['vendor_analysis']['vendor_distribution']
        if vendor_dist:
            vendors = list(vendor_dist.keys())[:10]  # Top 10
            counts = [vendor_dist[v] for v in vendors]
            axes[1,0].bar(vendors, counts)
            axes[1,0].set_title('Device Vendor Distribution (Global MACs)')
            axes[1,0].set_ylabel('Device Count')
            axes[1,0].tick_params(axis='x', rotation=45)
        
        # RSSI vs Time scatter
        scatter_df = df.sample(min(1000, len(df)))  # Sample for performance
        scatter = axes[1,1].scatter(scatter_df['relative_time_sec'], scatter_df['rssi'], 
                                   c=scatter_df['is_randomized'], cmap='coolwarm', alpha=0.6)
        axes[1,1].set_title('RSSI vs Time (Color: MAC Type)')
        axes[1,1].set_xlabel('Time (seconds)')
        axes[1,1].set_ylabel('RSSI (dBm)')
        plt.colorbar(scatter, ax=axes[1,1], label='Randomized (0=Global, 1=Random)')
        
        plt.tight_layout()
        plt.savefig(os.path.join(session_output_dir, 'mac_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Occupancy Correlation Analysis
        estimated_occupancy = report['metadata'].get('Estimated Occupancy', '0')
        try:
            occupancy_num = int(estimated_occupancy.split()[0])
        except:
            occupancy_num = 0
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Unique devices over time
        axes[0,0].plot(patterns['unique_macs_per_window'].index, 
                      patterns['unique_macs_per_window'].values, 
                      marker='o', linewidth=2, color='purple')
        axes[0,0].set_title(f'Unique Devices Over Time\n(Estimated Occupancy: {occupancy_num})')
        axes[0,0].set_ylabel('Unique MAC Addresses')
        axes[0,0].grid(True, alpha=0.3)
        axes[0,0].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        
        # Probe rate vs estimated occupancy
        total_probes = patterns['total_per_window'].sum()
        duration_hours = df['relative_time_sec'].max() / 3600
        probe_rate = total_probes / duration_hours if duration_hours > 0 else 0
        
        axes[0,1].bar(['Estimated\nOccupancy', 'Unique\nDevices', 'Probe Rate\n(per hour)'], 
                     [occupancy_num, df['mac_address'].nunique(), probe_rate/10])  # Scale probe rate
        axes[0,1].set_title('Occupancy vs Device Metrics')
        axes[0,1].set_ylabel('Count')
        
        # Device persistence (how long devices stay visible)
        device_appearances = df['mac_address'].value_counts()
        axes[1,0].hist(device_appearances.values, bins=20, alpha=0.7, color='green')
        axes[1,0].set_title('Device Persistence Distribution')
        axes[1,0].set_xlabel('Number of Probe Requests per Device')
        axes[1,0].set_ylabel('Number of Devices')
        axes[1,0].grid(True, alpha=0.3)
        
        # Time-based heatmap
        df_copy = df.copy()
        df_copy['minute'] = df_copy['datetime'].dt.minute
        df_copy['second_bin'] = df_copy['datetime'].dt.second // 10 * 10
        
        heatmap_data = df_copy.groupby(['minute', 'second_bin']).size().unstack(fill_value=0)
        if not heatmap_data.empty:
            sns.heatmap(heatmap_data, ax=axes[1,1], cmap='YlOrRd', cbar_kws={'label': 'Probe Count'})
            axes[1,1].set_title('Probe Activity Heatmap\n(Minutes vs 10-second bins)')
            axes[1,1].set_xlabel('Second Bin')
            axes[1,1].set_ylabel('Minute')
        
        plt.tight_layout()
        plt.savefig(os.path.join(session_output_dir, 'occupancy_analysis.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Visualizations saved to: {session_output_dir}")
    
    def generate_summary_report(self, output_file):
        """Generate comprehensive summary report for all sessions"""
        
        summary = {
            'analysis_date': datetime.now().isoformat(),
            'total_sessions': len(self.sessions),
            'sessions': {}
        }
        
        overall_stats = {
            'total_packets': 0,
            'total_unique_devices': 0,
            'total_randomized': 0,
            'total_global': 0,
            'avg_rssi': [],
            'all_vendors': Counter()
        }
        
        for session_name, session_data in self.sessions.items():
            report = self.generate_session_report(session_name)
            if not report:
                continue
            
            # Add to overall stats
            overall_stats['total_packets'] += report['basic_stats']['total_packets']
            overall_stats['total_unique_devices'] += report['basic_stats']['unique_devices']
            overall_stats['total_randomized'] += report['mac_randomization']['randomized_packets']
            overall_stats['total_global'] += report['mac_randomization']['global_packets']
            overall_stats['avg_rssi'].append(report['basic_stats']['avg_rssi'])
            
            for vendor, count in report['vendor_analysis']['vendor_distribution'].items():
                overall_stats['all_vendors'][vendor] += count
            
            # Session summary
            session_summary = {
                'metadata': report['metadata'],
                'duration_minutes': round(report['basic_stats']['duration_minutes'], 2),
                'total_packets': report['basic_stats']['total_packets'],
                'unique_devices': report['basic_stats']['unique_devices'],
                'randomization_percentage': round(report['mac_randomization']['randomized_percentage'], 2),
                'avg_rssi': round(report['basic_stats']['avg_rssi'], 2),
                'vendor_diversity': report['vendor_analysis']['vendor_diversity'],
                'probe_rate_per_minute': round(report['basic_stats']['total_packets'] / 
                                             max(report['basic_stats']['duration_minutes'], 1), 2)
            }
            
            summary['sessions'][session_name] = session_summary
        
        # Calculate overall statistics
        if overall_stats['avg_rssi']:
            summary['overall_statistics'] = {
                'total_packets_all_sessions': overall_stats['total_packets'],
                'average_rssi_all_sessions': round(np.mean(overall_stats['avg_rssi']), 2),
                'randomization_percentage_overall': round(
                    (overall_stats['total_randomized'] / 
                     max(overall_stats['total_packets'], 1)) * 100, 2),
                'top_vendors': dict(overall_stats['all_vendors'].most_common(10)),
                'sessions_analyzed': len(self.sessions)
            }
        
        # Save to JSON
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        # Also create a readable text report
        text_report = output_file.replace('.json', '.txt')
        with open(text_report, 'w') as f:
            f.write("CAFÉ ENVIRONMENT ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Analysis Date: {summary['analysis_date']}\n")
            f.write(f"Total Sessions Analyzed: {summary['total_sessions']}\n\n")
            
            if 'overall_statistics' in summary:
                f.write("OVERALL STATISTICS\n")
                f.write("-" * 20 + "\n")
                stats = summary['overall_statistics']
                f.write(f"Total Probe Requests: {stats['total_packets_all_sessions']:,}\n")
                f.write(f"Average RSSI: {stats['average_rssi_all_sessions']} dBm\n")
                f.write(f"MAC Randomization Rate: {stats['randomization_percentage_overall']}%\n")
                f.write(f"Sessions Analyzed: {stats['sessions_analyzed']}\n\n")
                
                f.write("TOP DEVICE VENDORS (Global MACs only)\n")
                f.write("-" * 35 + "\n")
                for vendor, count in stats['top_vendors'].items():
                    f.write(f"{vendor}: {count} devices\n")
                f.write("\n")
            
            f.write("SESSION DETAILS\n")
            f.write("-" * 15 + "\n")
            
            for session_name, session in summary['sessions'].items():
                f.write(f"\nSession: {session_name}\n")
                f.write(f"Location: {session['metadata'].get('Location Type', 'N/A')}\n")
                f.write(f"Estimated Occupancy: {session['metadata'].get('Estimated Occupancy', 'N/A')}\n")
                f.write(f"Peak/Off-peak: {session['metadata'].get('Peak/Off-peak', 'N/A')}\n")
                f.write(f"Duration: {session['duration_minutes']} minutes\n")
                f.write(f"Total Probes: {session['total_packets']:,}\n")
                f.write(f"Unique Devices: {session['unique_devices']}\n")
                f.write(f"Randomization Rate: {session['randomization_percentage']}%\n")
                f.write(f"Average RSSI: {session['avg_rssi']} dBm\n")
                f.write(f"Probe Rate: {session['probe_rate_per_minute']} probes/minute\n")
                f.write(f"Vendor Diversity: {session['vendor_diversity']} different vendors\n")
        
        return summary
    
    def compare_peak_vs_offpeak(self):
        """Compare peak vs off-peak sessions"""
        peak_sessions = []
        offpeak_sessions = []
        
        for session_name, session_data in self.sessions.items():
            metadata = session_data['metadata']
            peak_status = metadata.get('Peak/Off-peak', '').lower()
            
            report = self.generate_session_report(session_name)
            if not report:
                continue
            
            session_metrics = {
                'name': session_name,
                'probe_rate': report['basic_stats']['total_packets'] / max(report['basic_stats']['duration_minutes'], 1),
                'unique_devices': report['basic_stats']['unique_devices'],
                'randomization_rate': report['mac_randomization']['randomized_percentage'],
                'avg_rssi': report['basic_stats']['avg_rssi'],
                'occupancy': metadata.get('Estimated Occupancy', '0')
            }
            
            if 'peak' in peak_status:
                peak_sessions.append(session_metrics)
            elif 'off-peak' in peak_status:
                offpeak_sessions.append(session_metrics)
        
        return {
            'peak_sessions': peak_sessions,
            'offpeak_sessions': offpeak_sessions
        }

def main():
    parser = argparse.ArgumentParser(description='Analyze café environment Wi-Fi probe data')
    parser.add_argument('data_dir', help='Directory containing capture sessions')
    parser.add_argument('--output', '-o', default='./analysis_output', 
                       help='Output directory for analysis results')
    parser.add_argument('--session', '-s', help='Analyze specific session only')
    parser.add_argument('--rssi-threshold', '-r', type=int, default=-80,
                       help='RSSI threshold for filtering (default: -80)')
    parser.add_argument('--no-plots', action='store_true', 
                       help='Skip generating plots')
    
    args = parser.parse_args()
    
    # Update RSSI threshold
    RSSI_THRESHOLDS['weak'] = args.rssi_threshold
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Initialize analyzer
    analyzer = ProbeAnalyzer(args.data_dir)
    print("Loading capture sessions...")
    analyzer.load_all_sessions()
    
    if not analyzer.sessions:
        print("No valid sessions found!")
        return
    
    print(f"Loaded {len(analyzer.sessions)} sessions")
    
    # Analyze specific session or all sessions
    if args.session:
        if args.session in analyzer.sessions:
            print(f"Analyzing session: {args.session}")
            if not args.no_plots:
                analyzer.create_visualizations(args.session, args.output)
        else:
            print(f"Session '{args.session}' not found!")
            print("Available sessions:", list(analyzer.sessions.keys()))
    else:
        # Analyze all sessions
        print("Analyzing all sessions...")
        
        if not args.no_plots:
            for session_name in analyzer.sessions:
                print(f"Creating visualizations for: {session_name}")
                analyzer.create_visualizations(session_name, args.output)
        
        # Generate summary report
        print("Generating summary report...")
        summary_file = os.path.join(args.output, 'cafe_analysis_summary.json')
        analyzer.generate_summary_report(summary_file)
        print(f"Summary report saved to: {summary_file}")
        
        # Peak vs off-peak comparison
        comparison = analyzer.compare_peak_vs_offpeak()
        if comparison['peak_sessions'] or comparison['offpeak_sessions']:
            comparison_file = os.path.join(args.output, 'peak_offpeak_comparison.json')
            with open(comparison_file, 'w') as f:
                json.dump(comparison, f, indent=2, default=str)
            print(f"Peak/off-peak comparison saved to: {comparison_file}")
    
    print(f"\nAnalysis complete! Results saved in: {args.output}")
    print("\nKey findings summary:")
    
    # Quick summary
    total_packets = sum(len(s['data']) for s in analyzer.sessions.values())
    total_sessions = len(analyzer.sessions)
    
    if total_sessions > 0:
        avg_randomization = np.mean([
            analyzer.analyze_mac_randomization(
                analyzer.filter_by_rssi(s['data'])
            )['randomized_percentage'] 
            for s in analyzer.sessions.values()
        ])
        
        print(f"- {total_sessions} sessions analyzed")
        print(f"- {total_packets:,} total probe requests captured")
        print(f"- {avg_randomization:.1f}% average MAC randomization rate")
        print(f"- Analysis results and visualizations in: {args.output}")

if __name__ == "__main__":
    main()