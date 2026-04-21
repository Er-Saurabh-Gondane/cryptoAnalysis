"""
Advanced statistical analysis for cryptographic algorithm benchmarks.
Provides:
- Descriptive statistics
- Comparative statistics (t-tests, ANOVA)
- Correlation analysis
- Trend analysis
- Outlier detection
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import f_oneway, pearsonr, spearmanr
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder for numpy types"""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)


class CryptoStatistics:
    """Advanced statistical analysis for crypto benchmarks."""

    def __init__(self, output_dir: str = "../results/statistics"):
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = {}

    def load_benchmark_data(self, csv_path: Optional[str] = None) -> pd.DataFrame:
        """Load benchmark data from CSV."""
        if csv_path and os.path.exists(csv_path):
            return pd.read_csv(csv_path)
        
        # Try to find latest benchmark file
        results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        if os.path.exists(results_dir):
            csv_files = [f for f in os.listdir(results_dir) if f.startswith("benchmark_results_") and f.endswith(".csv")]
            if csv_files:
                latest = max(csv_files)
                csv_path = os.path.join(results_dir, latest)
                print(f"Loading latest benchmark: {latest}")
                return pd.read_csv(csv_path)
        
        raise FileNotFoundError("No benchmark data found. Run evaluation/benchmark.py first.")

    def _convert_to_python_types(self, obj: Any) -> Any:
        """Recursively convert numpy types to Python native types."""
        if isinstance(obj, dict):
            return {k: self._convert_to_python_types(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_python_types(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._convert_to_python_types(item) for item in obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, pd.Series):
            return obj.tolist()
        elif isinstance(obj, pd.DataFrame):
            return obj.to_dict('records')
        return obj

    def descriptive_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculate descriptive statistics for each cipher."""
        metrics = [
            'encryption_time_ms', 'decryption_time_ms', 
            'throughput_mbps', 'memory_peak_kb', 'process_cpu_util_percent'
        ]
        
        stats_list = []
        for cipher in df['cipher'].unique():
            cipher_data = df[df['cipher'] == cipher]
            
            for metric in metrics:
                if metric in cipher_data.columns:
                    data = cipher_data[metric].dropna()
                    if len(data) > 0:
                        try:
                            stats_list.append({
                                'cipher': cipher,
                                'metric': metric,
                                'mean': float(np.mean(data)),
                                'median': float(np.median(data)),
                                'std': float(np.std(data)),
                                'variance': float(np.var(data)),
                                'min': float(np.min(data)),
                                'max': float(np.max(data)),
                                'range': float(np.max(data) - np.min(data)),
                                'q1': float(np.percentile(data, 25)),
                                'q3': float(np.percentile(data, 75)),
                                'iqr': float(np.percentile(data, 75) - np.percentile(data, 25)),
                                'skewness': float(stats.skew(data)) if len(data) > 2 else 0.0,
                                'kurtosis': float(stats.kurtosis(data)) if len(data) > 2 else 0.0,
                                'cv': float((np.std(data) / np.mean(data) * 100)) if np.mean(data) != 0 else 0.0,
                            })
                        except Exception as e:
                            print(f"Warning: Could not calculate stats for {cipher} - {metric}: {e}")
        
        return pd.DataFrame(stats_list)

    def comparative_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Perform comparative statistical tests between algorithms."""
        results = {}
        
        # Metrics to compare
        metrics = ['encryption_time_ms', 'throughput_mbps', 'memory_peak_kb']
        
        for metric in metrics:
            if metric not in df.columns:
                continue
            
            # Prepare data for ANOVA
            groups = []
            group_names = []
            for cipher in df['cipher'].unique():
                data = df[df['cipher'] == cipher][metric].dropna()
                if len(data) > 0:
                    groups.append(data)
                    group_names.append(cipher)
            
            # One-way ANOVA
            if len(groups) >= 2:
                try:
                    f_stat, p_value = f_oneway(*groups)
                    results[metric] = {
                        'test': 'One-way ANOVA',
                        'f_statistic': float(f_stat),
                        'p_value': float(p_value),
                        'significant': bool(p_value < 0.05),
                        'groups': group_names,
                        'interpretation': 'Significant differences exist' if p_value < 0.05 else 'No significant differences'
                    }
                    
                    # Post-hoc pairwise t-tests
                    pairwise = []
                    for i in range(len(groups)):
                        for j in range(i+1, len(groups)):
                            try:
                                t_stat, p_val = stats.ttest_ind(groups[i], groups[j])
                                pairwise.append({
                                    'group1': group_names[i],
                                    'group2': group_names[j],
                                    't_statistic': float(t_stat),
                                    'p_value': float(p_val),
                                    'significant': bool(p_val < 0.05)
                                })
                            except Exception as e:
                                print(f"Warning: Could not compute t-test for {group_names[i]} vs {group_names[j]}: {e}")
                    results[metric]['pairwise'] = pairwise
                except Exception as e:
                    print(f"Warning: Could not compute ANOVA for {metric}: {e}")
        
        return results

    def correlation_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze correlations between different metrics."""
        # Select numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        correlation_matrix = df[numeric_cols].corr()
        
        # Convert to dict with Python types
        corr_dict = {}
        for col in correlation_matrix.columns:
            corr_dict[col] = {str(k): float(v) for k, v in correlation_matrix[col].items()}
        
        # Find strong correlations
        strong_correlations = []
        for i in range(len(correlation_matrix.columns)):
            for j in range(i+1, len(correlation_matrix.columns)):
                col1 = correlation_matrix.columns[i]
                col2 = correlation_matrix.columns[j]
                corr = correlation_matrix.iloc[i, j]
                if abs(corr) > 0.7:  # Strong correlation threshold
                    strong_correlations.append({
                        'variable1': str(col1),
                        'variable2': str(col2),
                        'correlation': float(corr),
                        'strength': 'strong positive' if corr > 0 else 'strong negative'
                    })
        
        # Pearson correlation for specific pairs
        specific_correlations = {}
        pairs = [
            ('encryption_time_ms', 'decryption_time_ms'),
            ('throughput_mbps', 'memory_peak_kb'),
            ('process_cpu_util_percent', 'encryption_time_ms')
        ]
        
        for col1, col2 in pairs:
            if col1 in df.columns and col2 in df.columns:
                data = df[[col1, col2]].dropna()
                if len(data) > 0:
                    try:
                        pearson_r, pearson_p = pearsonr(data[col1], data[col2])
                        spearman_r, spearman_p = spearmanr(data[col1], data[col2])
                        specific_correlations[f"{col1}_vs_{col2}"] = {
                            'pearson': {'r': float(pearson_r), 'p_value': float(pearson_p)},
                            'spearman': {'rho': float(spearman_r), 'p_value': float(spearman_p)},
                            'interpretation': self._interpret_correlation(pearson_r)
                        }
                    except Exception as e:
                        print(f"Warning: Could not compute correlation for {col1} vs {col2}: {e}")
        
        return {
            'correlation_matrix': corr_dict,
            'strong_correlations': strong_correlations,
            'specific_correlations': specific_correlations
        }

    def _interpret_correlation(self, r: float) -> str:
        """Interpret correlation coefficient."""
        r = abs(r)
        if r > 0.9:
            return "Very strong correlation"
        elif r > 0.7:
            return "Strong correlation"
        elif r > 0.5:
            return "Moderate correlation"
        elif r > 0.3:
            return "Weak correlation"
        else:
            return "Very weak or no correlation"

    def trend_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze trends across different data sizes."""
        trends = {}
        
        for cipher in df['cipher'].unique():
            cipher_data = df[df['cipher'] == cipher].sort_values('data_size_bytes')
            
            if len(cipher_data) < 3:
                continue
            
            try:
                # Analyze scaling behavior
                sizes = cipher_data['data_size_bytes'].values.astype(float)
                times = cipher_data['encryption_time_ms'].values
                
                # Fit linear and quadratic models
                linear_coeffs = np.polyfit(sizes, times, 1)
                quad_coeffs = np.polyfit(sizes, times, 2)
                
                # Calculate R-squared for linear fit
                linear_pred = np.polyval(linear_coeffs, sizes)
                ss_res = np.sum((times - linear_pred) ** 2)
                ss_tot = np.sum((times - np.mean(times)) ** 2)
                r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
                
                trends[cipher] = {
                    'linear_trend': {
                        'slope': float(linear_coeffs[0]),
                        'intercept': float(linear_coeffs[1]),
                        'r_squared': float(r_squared),
                        'interpretation': f"Time increases by {linear_coeffs[0]:.4f}ms per byte"
                    },
                    'quadratic_trend': {
                        'a': float(quad_coeffs[0]),
                        'b': float(quad_coeffs[1]),
                        'c': float(quad_coeffs[2])
                    },
                    'scaling_factor': self._calculate_scaling_factor(cipher_data)
                }
            except Exception as e:
                print(f"Warning: Could not compute trend for {cipher}: {e}")
        
        return trends

    def _calculate_scaling_factor(self, data: pd.DataFrame) -> str:
        """Calculate approximate scaling factor."""
        if len(data) < 2:
            return "Insufficient data"
        
        try:
            sizes = data['data_size_bytes'].values
            times = data['encryption_time_ms'].values
            
            # Calculate ratio of time increase to size increase
            time_ratio = times[-1] / times[0]
            size_ratio = sizes[-1] / sizes[0]
            
            scaling = time_ratio / size_ratio
            
            if scaling < 0.5:
                return "Sub-linear scaling (very efficient)"
            elif scaling < 0.8:
                return "Near-linear scaling (efficient)"
            elif scaling < 1.2:
                return "Linear scaling (expected)"
            elif scaling < 2:
                return "Super-linear scaling (less efficient)"
            else:
                return "Exponential scaling (inefficient)"
        except Exception:
            return "Could not calculate"

    def outlier_detection(self, df: pd.DataFrame, method: str = 'iqr') -> Dict[str, Any]:
        """Detect outliers in the data."""
        outliers = {}
        
        metrics = ['encryption_time_ms', 'decryption_time_ms', 'throughput_mbps', 'memory_peak_kb']
        
        for cipher in df['cipher'].unique():
            cipher_data = df[df['cipher'] == cipher]
            cipher_outliers = {}
            
            for metric in metrics:
                if metric not in cipher_data.columns:
                    continue
                
                data = cipher_data[metric].dropna()
                
                if method == 'iqr':
                    # IQR method
                    q1 = np.percentile(data, 25)
                    q3 = np.percentile(data, 75)
                    iqr = q3 - q1
                    lower_bound = q1 - 1.5 * iqr
                    upper_bound = q3 + 1.5 * iqr
                    
                    outlier_indices = cipher_data[(cipher_data[metric] < lower_bound) | 
                                                 (cipher_data[metric] > upper_bound)].index.tolist()
                    
                    cipher_outliers[metric] = {
                        'count': len(outlier_indices),
                        'indices': [int(i) for i in outlier_indices],
                        'lower_bound': float(lower_bound),
                        'upper_bound': float(upper_bound),
                        'values': [float(v) for v in cipher_data.loc[outlier_indices, metric].tolist()] if outlier_indices else []
                    }
                    
                elif method == 'zscore':
                    # Z-score method
                    z_scores = np.abs(stats.zscore(data))
                    outlier_indices = np.where(z_scores > 3)[0]
                    
                    cipher_outliers[metric] = {
                        'count': len(outlier_indices),
                        'indices': [int(i) for i in outlier_indices],
                        'z_scores': [float(z) for z in z_scores[outlier_indices]] if len(outlier_indices) > 0 else []
                    }
            
            outliers[cipher] = cipher_outliers
        
        return outliers

    def confidence_intervals(self, df: pd.DataFrame, confidence: float = 0.95) -> pd.DataFrame:
        """Calculate confidence intervals for metrics."""
        results = []
        
        metrics = ['encryption_time_ms', 'decryption_time_ms', 'throughput_mbps']
        
        for cipher in df['cipher'].unique():
            for metric in metrics:
                if metric not in df.columns:
                    continue
                
                data = df[df['cipher'] == cipher][metric].dropna()
                if len(data) < 2:
                    continue
                
                mean = float(np.mean(data))
                std = float(np.std(data))
                sem = float(stats.sem(data))
                
                # Calculate confidence interval
                ci = stats.t.interval(confidence, len(data)-1, loc=mean, scale=sem)
                
                results.append({
                    'cipher': cipher,
                    'metric': metric,
                    'mean': mean,
                    'std': std,
                    'ci_lower': float(ci[0]),
                    'ci_upper': float(ci[1]),
                    'ci_width': float(ci[1] - ci[0]),
                    'relative_ci_width': float((ci[1] - ci[0]) / mean * 100) if mean != 0 else 0
                })
        
        return pd.DataFrame(results)

    def run_comprehensive_analysis(self, df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """Run all statistical analyses."""
        if df is None:
            df = self.load_benchmark_data()
        
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE STATISTICAL ANALYSIS")
        print("=" * 80)
        
        print("\n1. Computing descriptive statistics...")
        descriptive = self.descriptive_statistics(df)
        
        print("2. Performing comparative tests...")
        comparative = self.comparative_statistics(df)
        
        print("3. Analyzing correlations...")
        correlations = self.correlation_analysis(df)
        
        print("4. Analyzing trends...")
        trends = self.trend_analysis(df)
        
        print("5. Detecting outliers...")
        outliers = self.outlier_detection(df)
        
        print("6. Calculating confidence intervals...")
        confidence = self.confidence_intervals(df)
        
        # Convert all results to Python native types for JSON serialization
        results = {
            'timestamp': datetime.now().isoformat(),
            'data_shape': {'rows': int(len(df)), 'columns': int(len(df.columns))},
            'descriptive_statistics': self._convert_to_python_types(descriptive.to_dict('records')),
            'comparative_statistics': self._convert_to_python_types(comparative),
            'correlation_analysis': self._convert_to_python_types(correlations),
            'trend_analysis': self._convert_to_python_types(trends),
            'outlier_detection': self._convert_to_python_types(outliers),
            'confidence_intervals': self._convert_to_python_types(confidence.to_dict('records'))
        }
        
        self.results = results
        self._save_results(results)
        
        return results

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save statistical analysis results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON with custom encoder
        json_path = os.path.join(self.output_dir, f"statistics_{timestamp}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, cls=NumpyEncoder)
        
        # Save CSV for descriptive stats
        if 'descriptive_statistics' in results and results['descriptive_statistics']:
            df_desc = pd.DataFrame(results['descriptive_statistics'])
            csv_path = os.path.join(self.output_dir, f"descriptive_stats_{timestamp}.csv")
            df_desc.to_csv(csv_path, index=False)
        
        # Save CSV for confidence intervals
        if 'confidence_intervals' in results and results['confidence_intervals']:
            df_ci = pd.DataFrame(results['confidence_intervals'])
            ci_path = os.path.join(self.output_dir, f"confidence_intervals_{timestamp}.csv")
            df_ci.to_csv(ci_path, index=False)
        
        print(f"\n✅ Statistical analysis saved to: {self.output_dir}")

    def print_summary(self) -> None:
        """Print summary of statistical analysis."""
        if not self.results:
            print("No results to display. Run analysis first.")
            return
        
        print("\n" + "=" * 80)
        print("📈 STATISTICAL ANALYSIS SUMMARY")
        print("=" * 80)
        
        print(f"\nData: {self.results['data_shape']['rows']} observations, "
              f"{self.results['data_shape']['columns']} variables")
        
        print("\n🔍 Significant Findings:")
        
        # Comparative statistics
        if 'comparative_statistics' in self.results:
            for metric, comp in self.results['comparative_statistics'].items():
                if comp.get('significant', False):
                    print(f"  • {metric}: Significant differences between algorithms "
                          f"(F={comp['f_statistic']:.2f}, p={comp['p_value']:.4f})")
        
        # Strong correlations
        if 'correlation_analysis' in self.results:
            strong = self.results['correlation_analysis'].get('strong_correlations', [])
            for corr in strong[:3]:  # Show top 3
                print(f"  • {corr['variable1']} vs {corr['variable2']}: "
                      f"{corr['strength']} (r={corr['correlation']:.2f})")
        
        # Outliers
        total_outliers = 0
        for cipher, metrics in self.results['outlier_detection'].items():
            for metric, data in metrics.items():
                total_outliers += data.get('count', 0)
        print(f"  • Detected {total_outliers} outliers across all algorithms")
        
        print(f"\n📁 Detailed results saved in: {self.output_dir}")


if __name__ == "__main__":
    stats = CryptoStatistics()
    try:
        results = stats.run_comprehensive_analysis()
        stats.print_summary()
    except Exception as e:
        print(f"Error running statistical analysis: {e}")