import spacy
from collections import defaultdict
import logging

class VectorGenerator:
    def __init__(self):
        # Load NLP model
        try:
            self.nlp = spacy.load("en_core_web_md")
        except OSError:
            logging.info("Downloading spaCy model...")
            spacy.cli.download("en_core_web_md")
            self.nlp = spacy.load("en_core_web_md")

        # CVSS metric rules
        self.metric_rules = {
            'AV': {  # Attack Vector
                'keywords': {
                    'N': ['internet', 'remote', 'network', 'web', 'online', 'external', 'internet-facing'],
                    'A': ['adjacent', 'local network', 'lan', 'neighbor', 'neighbouring'],
                    'L': ['local', 'physical access', 'locally', 'system access'],
                    'P': ['physical', 'hardware', 'device', 'physically']
                },
                'default': 'N'
            },
            'AC': {  # Attack Complexity
                'keywords': {
                    'L': ['simple', 'easily', 'straightforward', 'common', 'known vulnerability'],
                    'H': ['complex', 'difficult', 'sophisticated', 'chain', 'multiple steps']
                },
                'default': 'L'
            },
            'PR': {  # Privileges Required
                'keywords': {
                    'N': ['unauthenticated', 'no authentication', 'anonymous', 'without login'],
                    'L': ['authenticated', 'basic user', 'normal user', 'user account'],
                    'H': ['administrative', 'admin', 'privileged', 'root', 'system level']
                },
                'default': 'N'
            },
            'UI': {  # User Interaction
                'keywords': {
                    'N': ['automatic', 'without user', 'no interaction', 'automated'],
                    'R': ['user action', 'click', 'download', 'user interaction', 'manual']
                },
                'default': 'N'
            },
            'S': {  # Scope
                'keywords': {
                    'U': ['single system', 'same system', 'unchanged', 'contained'],
                    'C': ['multiple systems', 'spread', 'other systems', 'changed', 'escalate']
                },
                'default': 'U'
            },
            'C': {  # Confidentiality
                'keywords': {
                    'H': ['sensitive data', 'credentials', 'passwords', 'full access', 'all data'],
                    'L': ['limited information', 'partial disclosure', 'minor'],
                    'N': ['no confidentiality', 'no data disclosure']
                },
                'default': 'L'
            },
            'I': {  # Integrity
                'keywords': {
                    'H': ['modify all', 'complete corruption', 'full control'],
                    'L': ['minor modification', 'partial modification', 'slight changes'],
                    'N': ['no integrity', 'read only', 'no modification']
                },
                'default': 'L'
            },
            'A': {  # Availability
                'keywords': {
                    'H': ['crash', 'denial of service', 'dos', 'shutdown', 'unavailable'],
                    'L': ['degraded', 'intermittent', 'reduced performance'],
                    'N': ['no availability', 'no impact on availability']
                },
                'default': 'L'
            }
        }

    def generate_vector(self, threat_desc):
        """Generate CVSS vector string from threat description"""
        if not threat_desc or not isinstance(threat_desc, str):
            return None

        # Process text with spaCy
        doc = self.nlp(threat_desc.lower())
        
        # Score each metric
        metric_scores = self.score_metrics(doc)
        
        # Determine final metrics
        final_metrics = self.determine_final_metrics(metric_scores)
        
        # Generate vector string
        return self.create_vector_string(final_metrics)

    def score_metrics(self, doc):
        """Score each metric based on threat description"""
        metric_scores = defaultdict(lambda: defaultdict(float))
        
        for metric, rules in self.metric_rules.items():
            for value, keywords in rules['keywords'].items():
                score = 0
                for keyword in keywords:
                    # Direct keyword matching
                    if keyword in doc.text:
                        score += 1
                    
                    # Semantic similarity
                    keyword_doc = self.nlp(keyword)
                    for chunk in doc.noun_chunks:
                        similarity = keyword_doc.similarity(chunk)
                        if similarity > 0.7:
                            score += similarity
                
                metric_scores[metric][value] = score
        
        return metric_scores

    def determine_final_metrics(self, metric_scores):
        """Determine final metrics based on scores"""
        final_metrics = {}
        for metric, scores in metric_scores.items():
            if scores:
                max_score_value = max(scores.items(), key=lambda x: x[1])[0]
                final_metrics[metric] = max_score_value
            else:
                final_metrics[metric] = self.metric_rules[metric]['default']
        
        return final_metrics

    def create_vector_string(self, metrics):
        """Create CVSS v3.1 vector string"""
        vector_parts = [
            f"AV:{metrics['AV']}", f"AC:{metrics['AC']}", 
            f"PR:{metrics['PR']}", f"UI:{metrics['UI']}", 
            f"S:{metrics['S']}", f"C:{metrics['C']}", 
            f"I:{metrics['I']}", f"A:{metrics['A']}"
        ]
        return "CVSS:3.1/" + '/'.join(vector_parts)