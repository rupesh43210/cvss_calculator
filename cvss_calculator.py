import math
import logging
from enum import Enum
from typing import Dict, Optional, Any

class CVSSVersion(Enum):
    V31 = "3.1"
    V40 = "4.0"

class CVSSCalculator:
    # CVSS v3.1 Metric Value Constants
    METRICS_V31 = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
        'AC': {'L': 0.77, 'H': 0.44},  # Attack Complexity
        'PR': {  # Privilege Required
            'N': {'U': 0.85, 'C': 0.85},  # Unchanged scope
            'L': {'U': 0.62, 'C': 0.68},  # Changed scope
            'H': {'U': 0.27, 'C': 0.50}
        },
        'UI': {'N': 0.85, 'R': 0.62},  # User Interaction
        'CIA': {'H': 0.56, 'L': 0.22, 'N': 0},  # Impact metrics
        'E': {'X': 1.0, 'H': 1.0, 'F': 0.97, 'P': 0.94, 'U': 0.91},  # Exploit Code Maturity
        'RL': {'X': 1.0, 'O': 0.95, 'T': 0.96, 'W': 0.97, 'U': 1.0},  # Remediation Level
        'RC': {'X': 1.0, 'C': 1.0, 'R': 0.96, 'U': 0.92},  # Report Confidence
        'IMPACT_WEIGHTS': {'H': 1.0, 'M': 1.0, 'L': 0.5}  # Impact Weights
    }

    # CVSS v4.0 Metric Value Constants
    METRICS_V40 = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'AT': {'N': 0.85, 'P': 0.55},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'UI': {'N': 0.85, 'P': 0.62, 'A': 0.45},
        'VC': {'H': 0.56, 'L': 0.22, 'N': 0},
        'VI': {'H': 0.56, 'L': 0.22, 'N': 0},
        'VA': {'H': 0.56, 'L': 0.22, 'N': 0},
        'SC': {'H': 0.56, 'L': 0.22, 'N': 0},
        'SI': {'H': 0.56, 'L': 0.22, 'N': 0},
        'SA': {'H': 0.56, 'L': 0.22, 'N': 0},
        'E': {'X': 1.0, 'A': 1.0, 'P': 0.94, 'U': 0.91},
        'CR': {'X': 1.0, 'H': 1.5, 'M': 1.0, 'L': 0.5},
        'IR': {'X': 1.0, 'H': 1.5, 'M': 1.0, 'L': 0.5},
        'AR': {'X': 1.0, 'H': 1.5, 'M': 1.0, 'L': 0.5}
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.last_impact_score = 0.0
        self.last_exploitability_score = 0.0

    @staticmethod
    def round_up(number: float) -> float:
        """Round up to 1 decimal place"""
        return math.ceil(number * 10) / 10

    def detect_version(self, vector_string: str) -> CVSSVersion:
        """Detect CVSS version from vector string"""
        if vector_string.startswith('CVSS:4.0'):
            return CVSSVersion.V40
        elif vector_string.startswith('CVSS:3.1'):
            return CVSSVersion.V31
        else:
            raise ValueError("Unsupported CVSS version")

    def parse_vector(self, vector_string: str) -> Dict[str, str]:
        """Parse CVSS vector string into dictionary"""
        try:
            # Remove version prefix
            if vector_string.startswith('CVSS:'):
                vector_string = vector_string.split('/', 1)[1]

            metrics = {}
            for metric in vector_string.split('/'):
                if metric:
                    key, value = metric.split(':')
                    metrics[key] = value
            return metrics

        except Exception as e:
            raise ValueError(f"Invalid vector string format: {str(e)}")

    @staticmethod
    def get_v31_severity(score: float) -> str:
        """Get CVSS v3.1 severity rating"""
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"

    @staticmethod
    def get_v40_severity(score: float) -> str:
        """Get CVSS v4.0 severity rating"""
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
        
    def calculate_v31_scores(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """Calculate all CVSS v3.1 scores"""
        try:
            # Calculate Base Score
            base_score = self.calculate_v31_base_score(metrics)
            
            # Calculate Temporal Score if applicable
            temporal_score = None
            if any(m in metrics for m in ['E', 'RL', 'RC']):
                temporal_score = self.calculate_v31_temporal_score(base_score, metrics)
            
            # Calculate Environmental Score if applicable
            environmental_score = None
            if any(m in metrics for m in ['CR', 'IR', 'AR', 'M']):
                environmental_score = self.calculate_v31_environmental_score(metrics)
            
            return {
                'version': '3.1',
                'vector_string': self.create_v31_vector_string(metrics),
                'base_score': base_score,
                'base_severity': self.get_v31_severity(base_score),
                'temporal_score': temporal_score,
                'temporal_severity': self.get_v31_severity(temporal_score) if temporal_score else None,
                'environmental_score': environmental_score,
                'environmental_severity': self.get_v31_severity(environmental_score) if environmental_score else None,
                'impact_score': self.last_impact_score,
                'exploitability_score': self.last_exploitability_score
            }
            
        except Exception as e:
            self.logger.error(f"Error in v3.1 score calculation: {str(e)}")
            raise

    def calculate_v31_base_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 Base Score"""
        # Calculate Impact
        isc_base = self.calculate_v31_isc_base(metrics)
        impact_sub = self.calculate_v31_impact_sub(isc_base, metrics['S'])
        self.last_impact_score = impact_sub
        
        # Calculate Exploitability
        exploit_sub = self.calculate_v31_exploitability(metrics)
        self.last_exploitability_score = exploit_sub
        
        # Calculate Base Score
        if impact_sub <= 0:
            return 0.0
        
        if metrics['S'] == 'C':  # Scope Changed
            return self.round_up(min(1.08 * (impact_sub + exploit_sub), 10.0))
        else:  # Scope Unchanged
            return self.round_up(min(impact_sub + exploit_sub, 10.0))

    def calculate_v31_isc_base(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 ISC Base Score"""
        impact_conf = self.METRICS_V31['CIA'][metrics['C']]
        impact_integ = self.METRICS_V31['CIA'][metrics['I']]
        impact_avail = self.METRICS_V31['CIA'][metrics['A']]
        
        return 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail))

    def calculate_v31_impact_sub(self, isc_base: float, scope: str) -> float:
        """Calculate CVSS v3.1 Impact Sub Score"""
        if scope == 'U':  # Unchanged
            return 6.42 * isc_base
        else:  # Changed
            return 7.52 * (isc_base - 0.029) - 3.25 * pow((isc_base - 0.02), 15)

    def calculate_v31_exploitability(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 Exploitability Sub Score"""
        attack_vector = self.METRICS_V31['AV'][metrics['AV']]
        attack_complexity = self.METRICS_V31['AC'][metrics['AC']]
        privilege_required = self.METRICS_V31['PR'][metrics['PR']][metrics['S']]
        user_interaction = self.METRICS_V31['UI'][metrics['UI']]
        
        return 8.22 * attack_vector * attack_complexity * privilege_required * user_interaction

    def calculate_v31_temporal_score(self, base_score: float, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 Temporal Score"""
        exploit_code = self.METRICS_V31['E'].get(metrics.get('E', 'X'), 1.0)
        remediation_level = self.METRICS_V31['RL'].get(metrics.get('RL', 'X'), 1.0)
        report_confidence = self.METRICS_V31['RC'].get(metrics.get('RC', 'X'), 1.0)
        
        return self.round_up(base_score * exploit_code * remediation_level * report_confidence)

    def calculate_v31_environmental_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 Environmental Score"""
        # Get modified base metrics
        modified_metrics = self.get_modified_metrics_v31(metrics)
        
        # Calculate Modified Impact Sub Score
        modified_isc = self.calculate_v31_modified_isc(modified_metrics, metrics)
        modified_impact = self.calculate_v31_modified_impact(modified_isc, modified_metrics['MS'])
        
        if modified_impact <= 0:
            return 0.0
        
        # Calculate Modified Exploitability Sub Score
        modified_exploit = self.calculate_v31_modified_exploitability(modified_metrics)
        
        # Calculate Environmental Score
        if modified_metrics['MS'] == 'C':  # Modified Scope Changed
            score = self.round_up(min(1.08 * (modified_impact + modified_exploit), 10.0))
        else:  # Modified Scope Unchanged
            score = self.round_up(min(modified_impact + modified_exploit, 10.0))
            
        # Apply temporal metrics if present
        temporal_metrics = {
            'E': metrics.get('E', 'X'),
            'RL': metrics.get('RL', 'X'),
            'RC': metrics.get('RC', 'X')
        }
        
        return self.round_up(score * 
                           self.METRICS_V31['E'][temporal_metrics['E']] * 
                           self.METRICS_V31['RL'][temporal_metrics['RL']] * 
                           self.METRICS_V31['RC'][temporal_metrics['RC']])

    def calculate_v31_modified_isc(self, modified_metrics: Dict[str, str], 
                                 metrics: Dict[str, str]) -> float:
        """Calculate Modified Impact Sub Score Coefficient"""
        # Get requirement factors
        cr = self.METRICS_V31['IMPACT_WEIGHTS'][metrics.get('CR', 'M')]
        ir = self.METRICS_V31['IMPACT_WEIGHTS'][metrics.get('IR', 'M')]
        ar = self.METRICS_V31['IMPACT_WEIGHTS'][metrics.get('AR', 'M')]
        
        # Calculate modified impact values
        mod_conf = self.METRICS_V31['CIA'][modified_metrics['MC']] * cr
        mod_integ = self.METRICS_V31['CIA'][modified_metrics['MI']] * ir
        mod_avail = self.METRICS_V31['CIA'][modified_metrics['MA']] * ar
        
        return min(0.915, 1 - ((1 - mod_conf) * (1 - mod_integ) * (1 - mod_avail)))

    def calculate_v31_modified_impact(self, misc: float, modified_scope: str) -> float:
        """Calculate Modified Impact Sub Score"""
        if modified_scope == 'U':  # Unchanged
            return 6.42 * misc
        else:  # Changed
            return 7.52 * (misc - 0.029) - 3.25 * pow(misc * 0.9731 - 0.02, 13)

    def calculate_v31_modified_exploitability(self, modified_metrics: Dict[str, str]) -> float:
        """Calculate Modified Exploitability Sub Score"""
        mod_av = self.METRICS_V31['AV'][modified_metrics['MAV']]
        mod_ac = self.METRICS_V31['AC'][modified_metrics['MAC']]
        mod_pr = self.METRICS_V31['PR'][modified_metrics['MPR']][modified_metrics['MS']]
        mod_ui = self.METRICS_V31['UI'][modified_metrics['MUI']]
        
        return 8.22 * mod_av * mod_ac * mod_pr * mod_ui

    def create_v31_vector_string(self, metrics: Dict[str, str]) -> str:
        """Create CVSS v3.1 vector string from metrics"""
        # Define metric groups
        base_metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        temporal_metrics = ['E', 'RL', 'RC']
        environmental_metrics = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA']
        
        vector_parts = ['CVSS:3.1']
        
        # Add base metrics
        for metric in base_metrics:
            if metric in metrics:
                vector_parts.append(f"{metric}:{metrics[metric]}")
        
        # Add temporal metrics
        for metric in temporal_metrics:
            if metric in metrics:
                vector_parts.append(f"{metric}:{metrics[metric]}")
        
        # Add environmental metrics
        for metric in environmental_metrics:
            if metric in metrics:
                vector_parts.append(f"{metric}:{metrics[metric]}")
        
        return '/'.join(vector_parts)
    
    def calculate_v40_scores(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """Calculate all CVSS v4.0 scores"""
        try:
            # Calculate Base Score
            base_score = self.calculate_v40_base_score(metrics)
            
            # Calculate Threat Score if applicable
            threat_score = None
            if 'E' in metrics:
                threat_score = self.calculate_v40_threat_score(base_score, metrics)
            
            # Calculate Environmental Score if applicable
            environmental_score = None
            if any(m in metrics for m in ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA']):
                environmental_score = self.calculate_v40_environmental_score(metrics)
            
            # Calculate Supplemental Score if applicable
            supplemental_scores = None
            if any(m in metrics for m in ['S', 'AU', 'R', 'U']):
                supplemental_scores = self.calculate_v40_supplemental_scores(metrics)
            
            return {
                'version': '4.0',
                'vector_string': self.create_v40_vector_string(metrics),
                'base_score': base_score,
                'base_severity': self.get_v40_severity(base_score),
                'threat_score': threat_score,
                'threat_severity': self.get_v40_severity(threat_score) if threat_score else None,
                'environmental_score': environmental_score,
                'environmental_severity': self.get_v40_severity(environmental_score) if environmental_score else None,
                'supplemental_scores': supplemental_scores
            }
            
        except Exception as e:
            self.logger.error(f"Error in v4.0 score calculation: {str(e)}")
            raise

    def calculate_v40_base_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Base Score"""
        # Calculate Vulnerable System Impact
        vs_impact = self.calculate_v40_vulnerable_system_impact(metrics)
        
        # Calculate Subsequent System Impact
        ss_impact = self.calculate_v40_subsequent_system_impact(metrics)
        
        # Calculate Exploitability
        exploit_score = self.calculate_v40_exploitability(metrics)
        
        # Calculate Base Score
        if vs_impact == 0 and ss_impact == 0:
            return 0.0
            
        return self.round_up(min(exploit_score + vs_impact + ss_impact, 10.0))

    def calculate_v40_vulnerable_system_impact(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Vulnerable System Impact"""
        vc = self.METRICS_V40['VC'][metrics['VC']]
        vi = self.METRICS_V40['VI'][metrics['VI']]
        va = self.METRICS_V40['VA'][metrics['VA']]
        
        return max(vc, vi, va)

    def calculate_v40_subsequent_system_impact(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Subsequent System Impact"""
        sc = self.METRICS_V40['SC'][metrics['SC']]
        si = self.METRICS_V40['SI'][metrics['SI']]
        sa = self.METRICS_V40['SA'][metrics['SA']]
        
        return max(sc, si, sa)

    def calculate_v40_exploitability(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Exploitability Score"""
        av = self.METRICS_V40['AV'][metrics['AV']]
        ac = self.METRICS_V40['AC'][metrics['AC']]
        at = self.METRICS_V40['AT'][metrics['AT']]
        pr = self.METRICS_V40['PR'][metrics['PR']]
        ui = self.METRICS_V40['UI'][metrics['UI']]
        
        return 8.22 * av * ac * at * pr * ui

    def calculate_v40_threat_score(self, base_score: float, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Threat Score"""
        exploit_maturity = self.METRICS_V40['E'].get(metrics.get('E', 'X'), 1.0)
        return self.round_up(base_score * exploit_maturity)

    def calculate_v40_environmental_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v4.0 Environmental Score"""
        # Get modified base metrics
        modified_metrics = self.get_modified_metrics_v40(metrics)
        
        # Calculate Modified Base Score
        modified_base = self.calculate_v40_base_score(modified_metrics)
        
        # Apply Environmental Metrics
        cr = float(self.METRICS_V40['CR'].get(metrics.get('CR', 'X'), 1.0))
        ir = float(self.METRICS_V40['IR'].get(metrics.get('IR', 'X'), 1.0))
        ar = float(self.METRICS_V40['AR'].get(metrics.get('AR', 'X'), 1.0))
        
        return self.round_up(min(modified_base * max(cr, ir, ar), 10.0))

    def calculate_v40_supplemental_scores(self, metrics: Dict[str, str]) -> Dict[str, Any]:
        """Calculate CVSS v4.0 Supplemental Scores"""
        return {
            'safety': metrics.get('S', 'X'),
            'automation': metrics.get('AU', 'X'),
            'recovery': metrics.get('R', 'X'),
            'value_density': metrics.get('U', 'X')
        }

    def create_v40_vector_string(self, metrics: Dict[str, str]) -> str:
        """Create CVSS v4.0 vector string from metrics"""
        # Define metric groups
        base_metrics = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']
        threat_metrics = ['E']
        environmental_metrics = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA']
        supplemental_metrics = ['S', 'AU', 'R', 'U']
        
        vector_parts = ['CVSS:4.0']
        
        # Add all metric types
        for metric_list in [base_metrics, threat_metrics, environmental_metrics, supplemental_metrics]:
            for metric in metric_list:
                if metric in metrics:
                    vector_parts.append(f"{metric}:{metrics[metric]}")
        
        return '/'.join(vector_parts)

    def get_modified_metrics_v40(self, metrics: Dict[str, str]) -> Dict[str, str]:
        """Get modified metrics for v4.0 environmental score calculation"""
        modified = {}
        metric_mappings = {
            'AV': 'MAV', 'AC': 'MAC', 'AT': 'MAT', 'PR': 'MPR', 'UI': 'MUI',
            'VC': 'MVC', 'VI': 'MVI', 'VA': 'MVA'
        }
        
        for base, modified_name in metric_mappings.items():
            modified[base] = metrics.get(modified_name, metrics.get(base))
            
        return modified

    def calculate_score(self, vector_string: str) -> Dict[str, Any]:
        """Main method to calculate CVSS scores"""
        try:
            # Detect version and calculate appropriate scores
            version = self.detect_version(vector_string)
            metrics = self.parse_vector(vector_string)
            
            if version == CVSSVersion.V31:
                return self.calculate_v31_scores(metrics)
            else:
                return self.calculate_v40_scores(metrics)
                
        except Exception as e:
            self.logger.error(f"Error calculating CVSS score: {str(e)}")
            return {
                'error': str(e),
                'vector_string': vector_string
            }

if __name__ == "__main__":
    # Test the calculator
    calculator = CVSSCalculator()
    
    # Test vectors
    test_vectors = [
        # CVSS v3.1 test vectors
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Should be 9.8
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:T/RC:C",  # With temporal
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/CR:H/IR:M/AR:M",  # With environmental
        
        # CVSS v4.0 test vectors
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # Should be 10.0
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/E:A",  # With threat
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/CR:H/IR:M/AR:M"  # With environmental
    ]
    
    for vector in test_vectors:
        print(f"\nTesting vector: {vector}")
        result = calculator.calculate_score(vector)
        
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Version: {result['version']}")
            print(f"Base Score: {result['base_score']} ({result['base_severity']})")
            
            if result['temporal_score']:
                print(f"Temporal Score: {result['temporal_score']} ({result['temporal_severity']})")
                
            if result['environmental_score']:
                print(f"Environmental Score: {result['environmental_score']} ({result['environmental_severity']})")
                
            if result.get('supplemental_scores'):
                print("Supplemental Scores:", result['supplemental_scores'])
