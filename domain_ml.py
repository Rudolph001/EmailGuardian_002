
import re
import math
import sqlite3
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from models import get_db
from utils import extract_domain
import pickle
import os

logger = logging.getLogger(__name__)

# Common free email providers
FREE_MAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com', 'live.com',
    'msn.com', 'rediffmail.com', 'zoho.com', 'fastmail.com', 'gmx.com',
    'mail.ru', 'qq.com', '163.com', '126.com', 'sina.com'
}

# Common TLD categories
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.ru', '.su', '.cn', '.cc', '.biz', '.info',
    '.click', '.download', '.loan', '.win', '.top', '.site', '.online',
    '.website', '.space', '.xyz', '.club', '.party', '.stream'
}

TRUSTED_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int'
}

def calculate_entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0
    
    counts = {}
    for char in s.lower():
        counts[char] = counts.get(char, 0) + 1
    
    entropy = 0
    length = len(s)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

def calculate_edit_distance(s1, s2):
    """Calculate Levenshtein distance between two strings"""
    if not s1 or not s2:
        return max(len(s1), len(s2))
    
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def extract_domain_features(domain, internal_domains=None):
    """Extract features from a domain name"""
    if not domain:
        return np.zeros(15)  # Return zero vector if no domain
    
    if internal_domains is None:
        try:
            from config import INTERNAL_DOMAINS
            internal_domains = INTERNAL_DOMAINS
        except ImportError:
            internal_domains = set()  # Fallback if config not available
    
    features = []
    
    # Basic domain properties
    features.append(len(domain))  # Domain length
    features.append(domain.count('.'))  # Number of dots/subdomains
    features.append(calculate_entropy(domain))  # Entropy/randomness
    
    # TLD analysis
    if '.' in domain:
        tld = '.' + domain.split('.')[-1]
        features.append(1 if tld in SUSPICIOUS_TLDS else 0)  # Suspicious TLD
        features.append(1 if tld in TRUSTED_TLDS else 0)  # Trusted TLD
    else:
        features.extend([0, 0])  # No TLD
    
    # Character analysis
    digit_count = sum(1 for c in domain if c.isdigit())
    features.append(digit_count / len(domain))  # Digit ratio
    
    hyphen_count = domain.count('-')
    features.append(hyphen_count / len(domain))  # Hyphen ratio
    
    # Vowel/consonant ratio (randomness indicator)
    vowels = 'aeiou'
    vowel_count = sum(1 for c in domain.lower() if c in vowels)
    consonant_count = sum(1 for c in domain.lower() if c.isalpha() and c not in vowels)
    vowel_ratio = vowel_count / max(vowel_count + consonant_count, 1)
    features.append(vowel_ratio)
    
    # Free email provider check
    features.append(1 if domain in FREE_MAIL_PROVIDERS else 0)
    
    # Internal domain check
    features.append(1 if domain in internal_domains else 0)
    
    # Lookalike detection (minimum edit distance to internal domains)
    min_edit_distance = float('inf')
    for internal_domain in internal_domains:
        distance = calculate_edit_distance(domain, internal_domain)
        # Normalize by length to get similarity ratio
        normalized_distance = distance / max(len(domain), len(internal_domain))
        min_edit_distance = min(min_edit_distance, normalized_distance)
    
    features.append(min_edit_distance if min_edit_distance != float('inf') else 1.0)
    
    # Subdomain analysis
    parts = domain.split('.')
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2])
        features.append(len(subdomain))  # Subdomain length
        features.append(calculate_entropy(subdomain))  # Subdomain entropy
    else:
        features.extend([0, 0])  # No subdomain
    
    # Common suspicious patterns
    suspicious_patterns = [
        r'secure', r'login', r'account', r'verify', r'update', r'support',
        r'admin', r'service', r'bank', r'pay', r'mail', r'office'
    ]
    
    pattern_matches = sum(1 for pattern in suspicious_patterns 
                         if re.search(pattern, domain.lower()))
    features.append(pattern_matches)
    
    return np.array(features, dtype=float)

class DomainClassifier:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'domain_length', 'subdomain_count', 'entropy', 'suspicious_tld',
            'trusted_tld', 'digit_ratio', 'hyphen_ratio', 'vowel_ratio',
            'is_freemail', 'is_internal', 'min_edit_distance_internal',
            'subdomain_length', 'subdomain_entropy', 'suspicious_pattern_matches'
        ]
        self.label_mapping = {
            0: 'internal',
            1: 'freemail', 
            2: 'partner',
            3: 'suspicious'
        }
        
    def prepare_training_data(self):
        """Prepare training data from existing events and manual labels"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get all unique recipient domains from events
            cursor.execute("""
                SELECT DISTINCT email FROM recipients
                WHERE email IS NOT NULL AND email != ''
            """)
            
            emails = cursor.fetchall()
            domains = list(set(extract_domain(email[0]) for email in emails if email[0]))
            
            # Create domain labels table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_labels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    label INTEGER NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Auto-label some obvious ones
            auto_labels = []
            try:
                from config import INTERNAL_DOMAINS
            except ImportError:
                INTERNAL_DOMAINS = set()
            
            for domain in domains:
                if domain and len(domain) > 0:  # Ensure domain is valid
                    if domain in INTERNAL_DOMAINS:
                        auto_labels.append((domain, 0, 1.0))  # Internal
                    elif domain in FREE_MAIL_PROVIDERS:
                        auto_labels.append((domain, 1, 1.0))  # Freemail
                    elif any(tld in domain for tld in SUSPICIOUS_TLDS):
                        auto_labels.append((domain, 3, 0.8))  # Suspicious (lower confidence)
            
            # Insert auto-labels
            cursor.executemany("""
                INSERT OR IGNORE INTO domain_labels (domain, label, confidence)
                VALUES (?, ?, ?)
            """, auto_labels)
            
            conn.commit()
            
            # Get labeled domains for training
            cursor.execute("""
                SELECT domain, label FROM domain_labels
                WHERE confidence >= 0.7
            """)
            
            labeled_data = cursor.fetchall()
            
            if len(labeled_data) < 10:
                logger.warning("Insufficient labeled data for domain classification training")
                return None, None
                
            X = []
            y = []
            
            for domain, label in labeled_data:
                if domain and len(domain) > 0:  # Validate domain
                    try:
                        features = extract_domain_features(domain)
                        if len(features) == 15:  # Ensure we have all features
                            X.append(features)
                            y.append(label)
                    except Exception as e:
                        logger.warning(f"Error extracting features for domain {domain}: {e}")
                        continue
            
            return np.array(X), np.array(y)
    
    def train(self):
        """Train the domain classifier"""
        try:
            X, y = self.prepare_training_data()
            
            if X is None:
                logger.info("Auto-generating initial training data...")
                return self._generate_synthetic_training_data()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest (better for this type of problem)
            self.model = RandomForestClassifier(
                n_estimators=100, 
                random_state=42,
                class_weight='balanced'
            )
            
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            logger.info("Domain Classifier Performance:")
            logger.info(classification_report(y_test, y_pred, 
                                            target_names=list(self.label_mapping.values())))
            
            return True
            
        except Exception as e:
            logger.error(f"Domain classifier training failed: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    def _generate_synthetic_training_data(self):
        """Generate synthetic training data for initial model"""
        synthetic_data = []
        
        # Internal domains (from config)
        try:
            from config import INTERNAL_DOMAINS
            for domain in INTERNAL_DOMAINS:
                synthetic_data.append((domain, 0))
        except ImportError:
            # Add some default internal domains if config is unavailable
            default_internal = ['company.com', 'organization.org']
            for domain in default_internal:
                synthetic_data.append((domain, 0))
        
        # Free email providers
        for domain in list(FREE_MAIL_PROVIDERS)[:20]:  # Limit to 20
            synthetic_data.append((domain, 1))
        
        # Generate some suspicious domains
        suspicious_domains = [
            'secure-bank-login.tk', 'verify-account.ml', 'paypal-security.ga',
            'microsoft-support.cf', 'apple-id-verify.click', 'bank-update.biz',
            'admin-portal123.site', 'login-secure999.space'
        ]
        for domain in suspicious_domains:
            synthetic_data.append((domain, 3))
        
        # Generate partner domains (simulate)
        partner_domains = [
            'partner1.com', 'vendor2.net', 'supplier3.org', 'client4.com'
        ]
        for domain in partner_domains:
            synthetic_data.append((domain, 2))
        
        X = []
        y = []
        
        for domain, label in synthetic_data:
            features = extract_domain_features(domain)
            X.append(features)
            y.append(label)
        
        X = np.array(X)
        y = np.array(y)
        
        # Train on synthetic data
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=50, 
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_scaled, y)
        
        logger.info("Domain classifier trained on synthetic data")
        return True
    
    def classify_domain(self, domain):
        """Classify a domain"""
        if not self.model:
            return {'label': 'unknown', 'confidence': 0.0, 'features': {}}
        
        try:
            features = extract_domain_features(domain)
            features_scaled = self.scaler.transform([features])
            
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = max(probabilities)
            
            # Feature importance for interpretability
            feature_importance = {}
            if hasattr(self.model, 'feature_importances_'):
                for i, importance in enumerate(self.model.feature_importances_):
                    if importance > 0.01:  # Only show important features
                        feature_importance[self.feature_names[i]] = {
                            'value': float(features[i]),
                            'importance': float(importance)
                        }
            
            return {
                'label': self.label_mapping[prediction],
                'confidence': float(confidence),
                'probabilities': {
                    self.label_mapping[i]: float(prob) 
                    for i, prob in enumerate(probabilities)
                },
                'features': feature_importance
            }
            
        except Exception as e:
            logger.error(f"Domain classification failed for {domain}: {e}")
            return {'label': 'unknown', 'confidence': 0.0, 'features': {}}
    
    def save_model(self, filepath='domain_classifier.pkl'):
        """Save the trained model"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'label_mapping': self.label_mapping
            }
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Domain classifier saved to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save domain classifier: {e}")
            return False
    
    def load_model(self, filepath='domain_classifier.pkl'):
        """Load a saved model"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.feature_names = model_data['feature_names']
                self.label_mapping = model_data['label_mapping']
                
                logger.info(f"Domain classifier loaded from {filepath}")
                return True
            else:
                logger.warning(f"Domain classifier file {filepath} not found")
                return False
        except Exception as e:
            logger.error(f"Failed to load domain classifier: {e}")
            return False

# Global instance
domain_classifier = DomainClassifier()

def train_domain_classifier():
    """Train and save the domain classifier"""
    success = domain_classifier.train()
    if success:
        domain_classifier.save_model()
    return success

def classify_event_domains(event_id):
    """Classify all domains in an event"""
    try:
        # Load model if not already loaded
        if not domain_classifier.model:
            domain_classifier.load_model()
            if not domain_classifier.model:
                logger.warning("Domain classifier not available")
                return []
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT email FROM recipients WHERE event_id = ?", (event_id,))
            emails = cursor.fetchall()
        
        domain_classifications = []
        
        for email_row in emails:
            email = email_row[0]
            domain = extract_domain(email)
            
            if domain:
                classification = domain_classifier.classify_domain(domain)
                classification['email'] = email
                classification['domain'] = domain
                domain_classifications.append(classification)
        
        return domain_classifications
        
    except Exception as e:
        logger.error(f"Error classifying domains for event {event_id}: {e}")
        return []

def get_domain_risk_score(domain_classifications):
    """Calculate risk score based on domain classifications"""
    if not domain_classifications:
        return 0.0
    
    risk_weights = {
        'internal': 0.0,
        'freemail': 0.2,
        'partner': 0.1,
        'suspicious': 0.8,
        'unknown': 0.3
    }
    
    total_risk = 0.0
    total_weight = 0.0
    
    for classification in domain_classifications:
        label = classification.get('label', 'unknown')
        confidence = classification.get('confidence', 0.5)
        
        risk = risk_weights.get(label, 0.3)
        weight = confidence
        
        total_risk += risk * weight
        total_weight += weight
    
    return total_risk / max(total_weight, 1.0)
