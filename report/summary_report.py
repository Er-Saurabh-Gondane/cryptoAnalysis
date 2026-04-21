"""
Summary report generator for IoT crypto project.
Generates comprehensive PDF and HTML reports with:
- Executive summary
- Performance analysis
- Security analysis
- Attack resistance results
- Recommendations
"""

import os
import sys
import json
import base64
from datetime import datetime
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import seaborn as sns
import glob

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SummaryReport:
    """Generate comprehensive summary reports."""

    def __init__(self, output_dir: str = "../results/reports"):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.output_dir = os.path.join(self.project_root, "results", "reports")
        self.graphs_dir = os.path.join(self.project_root, "results", "graphs")
        self.attacks_dir = os.path.join(self.project_root, "results", "attacks")
        self.benchmarks_dir = os.path.join(self.project_root, "results", "benchmarks")
        
        # Create directories if they don't exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.graphs_dir, exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        sns.set_palette("husl")
        
        print(f"📁 Report directory: {self.output_dir}")
        print(f"📁 Graphs directory: {self.graphs_dir}")

    def find_latest_benchmark(self) -> Optional[str]:
        """Find the most recent benchmark CSV file."""
        # Check benchmarks directory first
        if os.path.exists(self.benchmarks_dir):
            csv_files = glob.glob(os.path.join(self.benchmarks_dir, "benchmark_results_*.csv"))
            if csv_files:
                latest = max(csv_files, key=os.path.getctime)
                print(f"✅ Found benchmark: {os.path.basename(latest)}")
                return latest
        
        # Check main results directory
        results_dir = os.path.join(self.project_root, "results")
        csv_files = glob.glob(os.path.join(results_dir, "benchmark_results_*.csv"))
        if csv_files:
            latest = max(csv_files, key=os.path.getctime)
            print(f"✅ Found benchmark in main results: {os.path.basename(latest)}")
            return latest
        
        print("⚠️ No benchmark files found")
        return None

    def find_latest_attacks(self) -> Optional[str]:
        """Find the most recent attack analysis JSON file."""
        if os.path.exists(self.attacks_dir):
            json_files = glob.glob(os.path.join(self.attacks_dir, "attack_analysis_*.json"))
            if json_files:
                latest = max(json_files, key=os.path.getctime)
                print(f"✅ Found attacks: {os.path.basename(latest)}")
                return latest
        print("⚠️ No attack analysis files found")
        return None

    def load_all_data(self) -> Dict[str, Any]:
        """Load all result data from previous runs."""
        data = {
            'benchmark': None,
            'attacks': None,
            'summary': {}
        }
        
        print("\n" + "=" * 60)
        print("📂 LOADING PROJECT DATA")
        print("=" * 60)
        
        # Load benchmark data
        bench_file = self.find_latest_benchmark()
        if bench_file:
            try:
                df = pd.read_csv(bench_file)
                data['benchmark'] = df
                print(f"   Records: {len(df)}")
                print(f"   Ciphers: {df['cipher'].nunique()}")
                print(f"   Data sizes: {sorted(df['data_size_bytes'].unique())}")
            except Exception as e:
                print(f"   Error loading benchmark: {e}")
        
        # Load attack data
        attack_file = self.find_latest_attacks()
        if attack_file:
            try:
                with open(attack_file, 'r') as f:
                    data['attacks'] = json.load(f)
                print(f"   Attack tests: {len(data['attacks'].get('summary_rows', []))}")
            except Exception as e:
                print(f"   Error loading attacks: {e}")
        
        return data

    def generate_performance_charts(self, df: pd.DataFrame) -> Dict[str, str]:
        """Generate performance comparison charts and return paths."""
        chart_paths = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if df is None or df.empty:
            print("⚠️ No benchmark data for charts")
            return chart_paths
        
        print("\n📊 Generating performance charts...")
        
        # 1. Encryption Time Comparison
        try:
            plt.figure(figsize=(12, 6))
            pivot = df.pivot_table(
                values='encryption_time_ms',
                index='data_size_bytes',
                columns='cipher',
                aggfunc='mean'
            )
            pivot.plot(marker='o', linewidth=2)
            plt.xlabel('Data Size (bytes)')
            plt.ylabel('Encryption Time (ms)')
            plt.title('Encryption Time Comparison')
            plt.grid(True, alpha=0.3)
            plt.legend(bbox_to_anchor=(1.05, 1))
            plt.tight_layout()
            
            path = os.path.join(self.graphs_dir, f"encryption_time_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['encryption_time'] = path
            plt.close()
            print(f"  ✅ Encryption time chart saved")
        except Exception as e:
            print(f"  ❌ Error creating encryption time chart: {e}")
        
        # 2. Decryption Time Comparison
        try:
            plt.figure(figsize=(12, 6))
            pivot = df.pivot_table(
                values='decryption_time_ms',
                index='data_size_bytes',
                columns='cipher',
                aggfunc='mean'
            )
            pivot.plot(marker='s', linewidth=2)
            plt.xlabel('Data Size (bytes)')
            plt.ylabel('Decryption Time (ms)')
            plt.title('Decryption Time Comparison')
            plt.grid(True, alpha=0.3)
            plt.legend(bbox_to_anchor=(1.05, 1))
            plt.tight_layout()
            
            path = os.path.join(self.graphs_dir, f"decryption_time_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['decryption_time'] = path
            plt.close()
            print(f"  ✅ Decryption time chart saved")
        except Exception as e:
            print(f"  ❌ Error creating decryption time chart: {e}")
        
        # 3. Throughput Comparison
        try:
            plt.figure(figsize=(10, 6))
            throughput = df.groupby('cipher')['throughput_mbps'].mean().sort_values(ascending=False)
            bars = plt.bar(range(len(throughput)), throughput.values)
            plt.xticks(range(len(throughput)), throughput.index, rotation=45)
            plt.ylabel('Throughput (MB/s)')
            plt.title('Average Encryption Throughput')
            
            for bar, val in zip(bars, throughput.values):
                plt.text(bar.get_x() + bar.get_width()/2, val + 0.1, f'{val:.2f}', 
                        ha='center', va='bottom')
            
            plt.tight_layout()
            path = os.path.join(self.graphs_dir, f"throughput_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['throughput'] = path
            plt.close()
            print(f"  ✅ Throughput chart saved")
        except Exception as e:
            print(f"  ❌ Error creating throughput chart: {e}")
        
        # 4. Memory Usage
        try:
            plt.figure(figsize=(10, 6))
            memory = df.groupby('cipher')['memory_peak_kb'].mean().sort_values()
            bars = plt.bar(range(len(memory)), memory.values)
            plt.xticks(range(len(memory)), memory.index, rotation=45)
            plt.ylabel('Peak Memory (KB)')
            plt.title('Memory Usage Comparison')
            
            for bar, val in zip(bars, memory.values):
                plt.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}', ha='center')
            
            plt.tight_layout()
            path = os.path.join(self.graphs_dir, f"memory_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['memory'] = path
            plt.close()
            print(f"  ✅ Memory chart saved")
        except Exception as e:
            print(f"  ❌ Error creating memory chart: {e}")
        
        # 5. CPU Usage
        try:
            plt.figure(figsize=(10, 6))
            cpu = df.groupby('cipher')['process_cpu_util_percent'].mean().sort_values()
            bars = plt.bar(range(len(cpu)), cpu.values)
            plt.xticks(range(len(cpu)), cpu.index, rotation=45)
            plt.ylabel('CPU Utilization (%)')
            plt.title('CPU Usage Comparison')
            
            for bar, val in zip(bars, cpu.values):
                plt.text(bar.get_x() + bar.get_width()/2, val + 1, f'{val:.1f}%', ha='center')
            
            plt.tight_layout()
            path = os.path.join(self.graphs_dir, f"cpu_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['cpu'] = path
            plt.close()
            print(f"  ✅ CPU chart saved")
        except Exception as e:
            print(f"  ❌ Error creating CPU chart: {e}")
        
        # 6. Latency vs Response Time
        try:
            plt.figure(figsize=(12, 6))
            latency_df = df.groupby('cipher')[['latency_time_ms', 'response_time_ms']].mean()
            latency_df.plot(kind='bar', figsize=(12, 6))
            plt.ylabel('Time (ms)')
            plt.title('Latency vs Response Time by Algorithm')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            path = os.path.join(self.graphs_dir, f"latency_{timestamp}.png")
            plt.savefig(path, dpi=300, bbox_inches='tight')
            chart_paths['latency'] = path
            plt.close()
            print(f"  ✅ Latency chart saved")
        except Exception as e:
            print(f"  ❌ Error creating latency chart: {e}")
        
        return chart_paths

    def generate_html_report(self, data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
        
        # Create performance table
        perf_table_html = ""
        if data['benchmark'] is not None and not data['benchmark'].empty:
            try:
                perf_df = data['benchmark'].groupby('cipher').agg({
                    'encryption_time_ms': 'mean',
                    'decryption_time_ms': 'mean',
                    'throughput_mbps': 'mean',
                    'memory_peak_kb': 'mean',
                    'process_cpu_util_percent': 'mean',
                    'latency_time_ms': 'mean',
                    'response_time_ms': 'mean'
                }).round(3)
                
                perf_df.columns = ['Enc Time (ms)', 'Dec Time (ms)', 'Throughput (MB/s)', 
                                  'Memory (KB)', 'CPU (%)', 'Latency (ms)', 'Response (ms)']
                perf_table_html = perf_df.to_html(classes='table table-striped')
                
                # Add summary stats
                summary_stats = {
                    'Total Measurements': len(data['benchmark']),
                    'Data Sizes Tested': sorted(data['benchmark']['data_size_bytes'].unique()).tolist(),
                    'Algorithms Tested': data['benchmark']['cipher'].nunique()
                }
            except Exception as e:
                perf_table_html = f"<p class='error'>Error processing benchmark data: {e}</p>"
                summary_stats = {}
        else:
            perf_table_html = "<p class='warning'>⚠️ No benchmark data available. Run benchmarks first with: python main.py --benchmark</p>"
            summary_stats = {}
        
        # Attack results
        attack_summary = ""
        if data['attacks'] and 'summary_rows' in data['attacks']:
            try:
                attack_df = pd.DataFrame(data['attacks']['summary_rows'])
                attack_summary = attack_df.to_html(classes='table table-bordered')
            except Exception as e:
                attack_summary = f"<p class='error'>Error processing attack data: {e}</p>"
        else:
            attack_summary = "<p class='warning'>⚠️ No attack data available</p>"
        
        # Convert charts to base64 for embedding
        chart_html = ""
        for name, path in charts.items():
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        img_data = base64.b64encode(f.read()).decode()
                    chart_html += f'<div class="chart"><h3>{name.replace("_", " ").title()}</h3>'
                    chart_html += f'<img src="data:image/png;base64,{img_data}" style="width:100%; max-width:800px;"></div>'
                except Exception as e:
                    chart_html += f'<div class="chart"><h3>{name.replace("_", " ").title()}</h3><p class="error">Error loading chart: {e}</p></div>'
        
        # If no charts generated, show message
        if not chart_html:
            chart_html = "<p class='warning'>No charts available. Run benchmarks first.</p>"
        
        # Summary stats HTML
        summary_html = "<div class='summary-stats'>"
        if summary_stats:
            summary_html += "<h3>Benchmark Summary</h3>"
            summary_html += f"<p><strong>Total Measurements:</strong> {summary_stats['Total Measurements']}</p>"
            summary_html += f"<p><strong>Data Sizes Tested:</strong> {summary_stats['Data Sizes Tested']}</p>"
            summary_html += f"<p><strong>Algorithms Tested:</strong> {summary_stats['Algorithms Tested']}</p>"
        summary_html += "</div>"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IoT Crypto Project - Summary Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #34495e; margin-top: 30px; }}
                .table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background-color: white; }}
                .table th {{ background-color: #3498db; color: white; padding: 12px; text-align: left; }}
                .table td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
                .table-striped tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .chart {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: white; }}
                .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .summary-stats {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .footer {{ margin-top: 50px; color: #7f8c8d; font-size: 0.9em; text-align: center; }}
                .warning {{ color: #e67e22; background-color: #fde3a7; padding: 10px; border-radius: 5px; }}
                .error {{ color: #c0392b; background-color: #f2dede; padding: 10px; border-radius: 5px; }}
                .badge {{ display: inline-block; padding: 3px 7px; border-radius: 3px; color: white; font-size: 0.8em; }}
                .badge-success {{ background-color: #27ae60; }}
                .badge-warning {{ background-color: #f39c12; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 IoT Cryptography Project - Summary Report</h1>
                <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="summary">
                    <h2>📊 Executive Summary</h2>
                    <p>This report presents a comprehensive analysis of lightweight cryptographic algorithms
                    for IoT devices, including performance benchmarks, security metrics, and attack resistance.</p>
                </div>
                
                <h2>📈 Performance Analysis</h2>
                {summary_html}
                {perf_table_html}
                
                <h2>🛡️ Attack Analysis</h2>
                {attack_summary}
                
                <h2>📊 Visualization Charts</h2>
                {chart_html}
                
                <div class="footer">
                    <p>IoT Crypto Project - Academic Research</p>
                    <p>Generated by IoT Cryptography Project Pipeline</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n✅ HTML report generated: {html_path}")
        return html_path

    def generate_pdf_report(self, data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Generate PDF report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = os.path.join(self.output_dir, f"report_{timestamp}.pdf")
        
        try:
            with PdfPages(pdf_path) as pdf:
                # Title page
                plt.figure(figsize=(8.5, 11))
                plt.text(0.5, 0.7, 'IoT Cryptography Project', 
                        fontsize=24, ha='center', transform=plt.gcf().transFigure)
                plt.text(0.5, 0.6, 'Performance & Security Analysis', 
                        fontsize=18, ha='center', transform=plt.gcf().transFigure)
                plt.text(0.5, 0.4, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 
                        fontsize=12, ha='center', transform=plt.gcf().transFigure)
                plt.axis('off')
                pdf.savefig()
                plt.close()
                
                # Performance charts
                for name, path in charts.items():
                    if os.path.exists(path):
                        try:
                            img = plt.imread(path)
                            plt.figure(figsize=(10, 6))
                            plt.imshow(img)
                            plt.axis('off')
                            plt.title(name.replace('_', ' ').title())
                            pdf.savefig()
                            plt.close()
                        except Exception as e:
                            print(f"  Warning: Could not add {name} to PDF: {e}")
                
                # Attack results table
                if data['attacks'] and 'summary_rows' in data['attacks']:
                    try:
                        plt.figure(figsize=(10, 4))
                        plt.axis('off')
                        attack_df = pd.DataFrame(data['attacks']['summary_rows'])
                        plt.table(cellText=attack_df.values,
                                 colLabels=attack_df.columns,
                                 cellLoc='center', 
                                 loc='center',
                                 bbox=[0, 0, 1, 1])
                        plt.title('Attack Analysis Results', y=1.1)
                        pdf.savefig()
                        plt.close()
                    except Exception as e:
                        print(f"  Warning: Could not add attack table to PDF: {e}")
            
            print(f"✅ PDF report generated: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            print(f"❌ Error generating PDF: {e}")
            return None

    def generate_report(self) -> Dict[str, str]:
        """Generate complete report suite."""
        print("\n" + "=" * 80)
        print("📑 GENERATING COMPREHENSIVE REPORT")
        print("=" * 80)
        
        # Load all data
        data = self.load_all_data()
        
        # Generate charts
        charts = {}
        if data['benchmark'] is not None:
            print("\n📊 Generating charts...")
            charts = self.generate_performance_charts(data['benchmark'])
            print(f"   Generated {len(charts)} charts")
        else:
            print("\n⚠️ No benchmark data available for charts")
        
        # Generate HTML report
        print("\n🌐 Generating HTML report...")
        html_path = self.generate_html_report(data, charts)
        
        # Generate PDF report
        print("\n📄 Generating PDF report...")
        pdf_path = self.generate_pdf_report(data, charts)
        
        result = {
            'html': html_path,
            'pdf': pdf_path,
            'charts': charts,
            'data_loaded': {
                'benchmark': data['benchmark'] is not None,
                'attacks': data['attacks'] is not None,
                'charts': len(charts)
            }
        }
        
        return result


if __name__ == "__main__":
    print("=" * 80)
    print("📑 IoT CRYPTOGRAPHY PROJECT - REPORT GENERATOR")
    print("=" * 80)
    
    report = SummaryReport()
    paths = report.generate_report()
    
    print("\n" + "=" * 80)
    print("✅ REPORT GENERATION COMPLETE")
    print("=" * 80)
    print(f"📁 Reports saved in: {report.output_dir}")
    print(f"  • HTML: {paths['html']}")
    if paths['pdf']:
        print(f"  • PDF: {paths['pdf']}")
    print(f"  • Charts generated: {paths['data_loaded']['charts']}")
    
    # Open the HTML report in browser
    try:
        import webbrowser
        webbrowser.open(f"file://{paths['html']}")
        print("\n🌐 Report opened in browser")
    except:
        pass