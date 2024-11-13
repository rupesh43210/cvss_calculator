import math
import logging

class CVSSCalculator:
    # CVSS v3.1 Metric Value Constants
    METRICS = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
        'AC': {'L': 0.77, 'H': 0.44},  # Attack Complexity
        'PR': {  # Privilege Required
            'N': {'U': 0.85, 'C': 0.85},  # Unchanged scope
            'L': {'U': 0.62, 'C': 0.68},  # Changed scope
            'H': {'U': 0.27, 'C': 0.50}
        },
        'UI': {'N': 0.85, 'R': 0.62},  # User Interaction
        'CIA': {'H': 0.56, 'L': 0.22, 'N': 0},  # Impact metrics (C, I, A)
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def round_up(number):
        """Round up to 1 decimal place"""
        return math.ceil(number * 10) / 10

    def calculate_score(self, vector_string):
        """Main method to calculate CVSS scores"""
        try:
            # Calculate base score
            base_score = self.calculate_base_score(vector_string)
            
            # Get severity rating
            severity = self.get_severity(base_score)
            
            # Calculate temporal score if temporal metrics present
            metrics = self.parse_vector(vector_string)
            temporal_score = None
            if any(m in metrics for m in ['E', 'RL', 'RC']):
                temporal_score = self.calculate_temporal_score(base_score, metrics)
            
            return {
                'vector_string': vector_string,
                'base_score': base_score,
                'temporal_score': temporal_score,
                'severity': severity,
                'impact_score': self.last_impact_score,
                'exploitability_score': self.last_exploitability_score
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating CVSS score: {str(e)}")
            return {
                'error': f"Error calculating CVSS score: {str(e)}",
                'vector_string': vector_string
            }

    def calculate_base_score(self, vector_string):
        """Calculate CVSS Base Score from vector string"""
        metrics = self.parse_vector(vector_string)
        
        # Calculate Impact Sub Score (ISC)
        isc_base = self.calculate_isc_base(metrics)
        impact_sub = self.calculate_impact_sub(isc_base, metrics['S'])
        self.last_impact_score = impact_sub
        
        # Calculate Exploitability Sub Score
        exploit_sub = self.calculate_exploitability(metrics)
        self.last_exploitability_score = exploit_sub
        
        # Calculate Base Score
        if impact_sub <= 0:
            return 0.0
        else:
            if metrics['S'] == 'U':  # Scope Unchanged
                return self.round_up(min((impact_sub + exploit_sub), 10.0))
            else:  # Scope Changed
                return self.round_up(min((1.08 * (impact_sub + exploit_sub)), 10.0))

    def parse_vector(self, vector_string):
        """Parse CVSS v3.1 vector string into dictionary"""
        try:
            if vector_string.startswith('CVSS:3.1/'):
                vector_string = vector_string[9:]

            metrics = {}
            for metric in vector_string.split('/'):
                if metric:
                    key, value = metric.split(':')
                    metrics[key] = value
            
            # Validate required metrics
            required_metrics = {'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'}
            if not required_metrics.issubset(metrics.keys()):
                missing = required_metrics - metrics.keys()
                raise ValueError(f"Missing required metrics: {missing}")
                
            return metrics
            
        except Exception as e:
            raise ValueError(f"Invalid vector string format: {str(e)}")

    def calculate_isc_base(self, metrics):
        """Calculate ISCBase"""
        try:
            impact_conf = self.METRICS['CIA'][metrics['C']]
            impact_integ = self.METRICS['CIA'][metrics['I']]
            impact_avail = self.METRICS['CIA'][metrics['A']]
            
            isc_base = 1 - ((1 - impact_conf) * (1 - impact_integ) * (1 - impact_avail))
            return isc_base
            
        except KeyError as e:
            raise ValueError(f"Invalid impact metric value: {str(e)}")

    def calculate_impact_sub(self, isc_base, scope):
        """Calculate Impact sub score"""
        try:
            if scope == 'U':  # Unchanged
                return 6.42 * isc_base
            else:  # Changed
                return 7.52 * (isc_base - 0.029) - 3.25 * pow((isc_base - 0.02), 15)
                
        except Exception as e:
            raise ValueError(f"Error calculating impact sub score: {str(e)}")

    def calculate_exploitability(self, metrics):
        """Calculate Exploitability sub score"""
        try:
            attack_vector = self.METRICS['AV'][metrics['AV']]
            attack_complexity = self.METRICS['AC'][metrics['AC']]
            privilege_required = self.METRICS['PR'][metrics['PR']][metrics['S']]
            user_interaction = self.METRICS['UI'][metrics['UI']]
            
            return 8.22 * attack_vector * attack_complexity * privilege_required * user_interaction
            
        except KeyError as e:
            raise ValueError(f"Invalid exploitability metric value: {str(e)}")

    def calculate_temporal_score(self, base_score, metrics):
        """Calculate CVSS Temporal Score"""
        try:
            # Get temporal metrics with defaults
            exploit_code = self.get_temporal_value(metrics.get('E', 'X'))
            remediation_level = self.get_temporal_value(metrics.get('RL', 'X'))
            report_confidence = self.get_temporal_value(metrics.get('RC', 'X'))
            
            temporal_score = base_score * exploit_code * remediation_level * report_confidence
            return self.round_up(temporal_score)
            
        except Exception as e:
            self.logger.error(f"Error calculating temporal score: {str(e)}")
            return None

    @staticmethod
    def get_temporal_value(metric):
        """Get values for temporal metrics"""
        temporal_values = {
            # Exploit Code Maturity (E)
            'X': 1.0, 'H': 1.0, 'F': 0.97, 'P': 0.94, 'U': 0.91,
            # Remediation Level (RL)
            'O': 0.95, 'T': 0.96, 'W': 0.97, 'U': 1.0,
            # Report Confidence (RC)
            'C': 1.0, 'R': 0.96, 'U': 0.92
        }
        return temporal_values.get(metric, 1.0)

    @staticmethod
    def get_severity(score):
        """Get qualitative severity rating"""
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

    def validate_vector_string(self, vector_string):
        """Validate CVSS vector string format"""
        try:
            # Check prefix
            if not vector_string.startswith('CVSS:3.1/'):
                raise ValueError("Vector string must start with 'CVSS:3.1/'")
            
            # Parse and validate metrics
            metrics = self.parse_vector(vector_string)
            
            # Validate metric values
            self.validate_metric_values(metrics)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Vector string validation failed: {str(e)}")
            return False

    def validate_metric_values(self, metrics):
        """Validate individual metric values"""
        valid_values = {
            'AV': ['N', 'A', 'L', 'P'],
            'AC': ['L', 'H'],
            'PR': ['N', 'L', 'H'],
            'UI': ['N', 'R'],
            'S': ['U', 'C'],
            'C': ['H', 'L', 'N'],
            'I': ['H', 'L', 'N'],
            'A': ['H', 'L', 'N']
        }
        
        for metric, value in metrics.items():
            if metric in valid_values and value not in valid_values[metric]:
                raise ValueError(f"Invalid value '{value}' for metric '{metric}'")

if __name__ == "__main__":
    # Test the calculator
    calculator = CVSSCalculator()
    test_vectors = [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Should be 9.8
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",  # Should be 5.3
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H"   # Should be 9.0
    ]
    
    for vector in test_vectors:
        result = calculator.calculate_score(vector)
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"\nVector: {vector}")
            print(f"Base Score: {result['base_score']}")
            print(f"Severity: {result['severity']}")
            print(f"Impact Score: {result['impact_score']}")
            print(f"Exploitability Score: {result['exploitability_score']}")
            if result['temporal_score']:
                print(f"Temporal Score: {result['temporal_score']}")