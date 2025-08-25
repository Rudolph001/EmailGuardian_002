import sqlite3
import logging
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from models import get_db
from utils import calculate_heuristic_score
from config import ML_MODEL_VERSION

logger = logging.getLogger(__name__)

def extract_features_for_ml(event_data):
    """Extract features for ML model from event data"""
    features = {}
    
    # Count features
    features['num_recipients'] = len(event_data.get('recipients', []))
    features['num_attachments'] = len(event_data.get('attachments', []))
    features['num_policies'] = len(event_data.get('policies', []))
    
    # Boolean features
    features['is_leaver'] = int(event_data.get('leaver', 0))
    features['is_internal_to_external'] = int(event_data.get('is_internal_to_external', 0))
    features['has_termination_date'] = 1 if event_data.get('termination_date') else 0
    
    # Subject length
    subject = event_data.get('subject', '')
    features['subject_length'] = len(subject)
    features['subject_has_urgent'] = 1 if 'urgent' in subject.lower() else 0
    features['subject_has_confidential'] = 1 if 'confidential' in subject.lower() else 0
    
    # Time features (if available)
    time_month = event_data.get('time_month', '')
    if time_month:
        try:
            month_num = int(time_month)
            features['month'] = month_num
        except (ValueError, TypeError):
            features['month'] = 0
    else:
        features['month'] = 0
    
    return features

def prepare_training_data():
    """Prepare training data from labeled events"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get events with labels
        cursor.execute("""
            SELECT e.*, 
                   GROUP_CONCAT(r.email) as recipients,
                   GROUP_CONCAT(a.filename) as attachments,
                   GROUP_CONCAT(p.policy_name) as policies
            FROM events e
            LEFT JOIN recipients r ON e.id = r.event_id
            LEFT JOIN attachments a ON e.id = a.event_id  
            LEFT JOIN policies p ON e.id = p.event_id
            WHERE e.final_outcome IS NOT NULL AND e.final_outcome != ''
            GROUP BY e.id
        """)
        
        events = cursor.fetchall()
        
        if len(events) < 10:
            logger.warning("Not enough labeled data for ML training")
            return None, None, None
        
        X_features = []
        X_subjects = []
        y = []
        
        for event in events:
            # Prepare event data
            event_data = {
                'recipients': event['recipients'].split(',') if event['recipients'] else [],
                'attachments': event['attachments'].split(',') if event['attachments'] else [],
                'policies': event['policies'].split(',') if event['policies'] else [],
                'leaver': event['leaver'],
                'is_internal_to_external': event['is_internal_to_external'],
                'termination_date': event['termination_date'],
                'subject': event['subject'] or '',
                'time_month': event['time_month']
            }
            
            # Extract features
            features = extract_features_for_ml(event_data)
            X_features.append(list(features.values()))
            X_subjects.append(event['subject'] or '')
            
            # Create label (simple binary classification)
            outcome = event['final_outcome'].lower()
            if outcome in ['risky', 'block', 'escalate', 'suspicious']:
                y.append(1)
            else:
                y.append(0)
        
        if len(set(y)) < 2:
            logger.warning("Training data has only one class")
            return None, None, None
            
        return np.array(X_features), X_subjects, np.array(y)

def train_ml_model():
    """Train a supervised ML model if enough labeled data exists"""
    try:
        X_features, X_subjects, y = prepare_training_data()
        
        if X_features is None:
            logger.info("Insufficient labeled data for ML training, using heuristic model")
            return None
        
        # Split data
        X_feat_train, X_feat_test, X_subj_train, X_subj_test, y_train, y_test = train_test_split(
            X_features, X_subjects, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Vectorize subjects
        vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        X_subj_train_vec = vectorizer.fit_transform(X_subj_train)
        X_subj_test_vec = vectorizer.transform(X_subj_test)
        
        # Combine features
        X_train_combined = np.hstack([X_feat_train, X_subj_train_vec.toarray()])
        X_test_combined = np.hstack([X_feat_test, X_subj_test_vec.toarray()])
        
        # Train model
        model = LogisticRegression(random_state=42, max_iter=1000)
        model.fit(X_train_combined, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test_combined)
        logger.info("ML Model Performance:")
        logger.info(classification_report(y_test, y_pred))
        
        return {
            'model': model,
            'vectorizer': vectorizer,
            'feature_names': list(extract_features_for_ml({}).keys())
        }
        
    except Exception as e:
        logger.error(f"ML training failed: {e}")
        return None

def score_event_with_ml(event_data, ml_model=None):
    """Score an event using ML model or heuristic fallback"""
    if ml_model is None:
        # Use heuristic scoring
        return calculate_heuristic_score(event_data)
    
    try:
        # Extract features
        features = extract_features_for_ml(event_data)
        X_features = np.array([list(features.values())])
        
        # Vectorize subject
        subject = event_data.get('subject', '')
        X_subject = ml_model['vectorizer'].transform([subject])
        
        # Combine features
        X_combined = np.hstack([X_features, X_subject.toarray()])
        
        # Predict probability
        prob = ml_model['model'].predict_proba(X_combined)[0][1]
        
        return min(max(prob, 0.0), 1.0)
        
    except Exception as e:
        logger.warning(f"ML scoring failed, using heuristic: {e}")
        return calculate_heuristic_score(event_data)

def rescore_all_events():
    """Rescore all events in database"""
    try:
        # Try to train ML model
        ml_model = train_ml_model()
        model_version = "ml_v1" if ml_model else "heuristic_v1"
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get all events
            cursor.execute("""
                SELECT e.id, e.subject, e.leaver, e.is_internal_to_external, 
                       e.termination_date, e.time_month,
                       GROUP_CONCAT(r.email) as recipients,
                       GROUP_CONCAT(a.filename) as attachments,
                       GROUP_CONCAT(p.policy_name) as policies
                FROM events e
                LEFT JOIN recipients r ON e.id = r.event_id
                LEFT JOIN attachments a ON e.id = a.event_id
                LEFT JOIN policies p ON e.id = p.event_id
                GROUP BY e.id
            """)
            
            events = cursor.fetchall()
            logger.info(f"Rescoring {len(events)} events with {model_version}")
            
            for event in events:
                # Prepare event data
                event_data = {
                    'recipients': event['recipients'].split(',') if event['recipients'] else [],
                    'attachments': event['attachments'].split(',') if event['attachments'] else [],
                    'policies': event['policies'].split(',') if event['policies'] else [],
                    'leaver': event['leaver'],
                    'is_internal_to_external': event['is_internal_to_external'],
                    'termination_date': event['termination_date'],
                    'subject': event['subject'] or '',
                    'time_month': event['time_month']
                }
                
                # Calculate score
                score = score_event_with_ml(event_data, ml_model)
                
                # Update database
                cursor.execute("""
                    UPDATE events 
                    SET ml_score = ?, ml_model_version = ?
                    WHERE id = ?
                """, (score, model_version, event['id']))
            
            conn.commit()
            logger.info(f"Rescoring complete: {len(events)} events updated")
            
    except Exception as e:
        logger.error(f"Rescoring failed: {e}")
        raise

# Alias for backward compatibility
rescore_all = rescore_all_events
