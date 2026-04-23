import numpy as np
import pandas as pd
import re
import joblib
import os
import json # Import json for parsing the 'groups' string

# --- Model Loading ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Load models
try:
    anomaly_model = joblib.load(os.path.join(MODELS_DIR, "anomaly_model.joblib"))
    classifier_model = joblib.load(os.path.join(MODELS_DIR, "severity_classifier.joblib"))
    print("ML models loaded successfully.")

    # --- DEBUG: Print expected feature names from the loaded anomaly model ---
    if hasattr(anomaly_model, 'feature_names_in_'):
        print(f"DEBUG: Anomaly model expects features: {anomaly_model.feature_names_in_.tolist()}")
    else:
        print("DEBUG: Anomaly model does not have 'feature_names_in_' attribute.")

except FileNotFoundError as e:
    print(f"ERROR: Could not load ML models. Ensure 'models' directory exists and contains 'anomaly_model.joblib' and 'severity_classifier.joblib'.")
    print(f"Looking for models in: {MODELS_DIR}")
    print(f"Detailed error: {e}")
    anomaly_model = None
    classifier_model = None
except Exception as e:
    print(f"ERROR: An unexpected error occurred while loading models: {e}")
    anomaly_model = None
    classifier_model = None

# Severity labeling based on Wazuh Overview dashboard style
def get_severity_label(prediction: float) -> str:
    pred = int(round(prediction))
    
    if 0 <= pred <= 6:
        return "Low"
    elif 7 <= pred <= 11:
        return "Medium"
    elif 12 <= pred <= 14:
        return "High"
    elif pred >= 15:
        return "Critical"
    else:
        return "Unknown"


def parse_json_string(s):
    """
    Parses a JSON string that might contain an array (like 'groups')
    into a space-separated string.
    """
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            return " ".join(parsed)
        return str(parsed)
    except (json.JSONDecodeError, TypeError):
        # If not a valid JSON string, return it as is or a default
        return str(s)

def clean_text(text: str) -> str:
    """
    Cleans and preprocesses text by removing special characters and extra spaces.
    """
    if not text:
        return ""
    text = re.sub(r"[\r\n\t]", " ", text) # Remove carriage returns, newlines, tabs
    text = re.sub(r"\s+", " ", text)     # Replace multiple spaces with a single space
    return text.strip().lower()          # Trim whitespace and convert to lowercase


def extract_structured_features(alert_source: dict) -> dict:
    """
    Extracts relevant features from a single Wazuh alert's '_source' dictionary.
    This function is designed to match the feature extraction logic used during model training.

    Args:
        alert_source (dict): The '_source' dictionary of a Wazuh alert.

    Returns:
        dict: A dictionary containing the extracted and preprocessed features.
    """
    # Access nested fields defensively
    rule = alert_source.get("rule", {})
    agent = alert_source.get("agent", {})
    decoder = alert_source.get("decoder", {})
    data_section = alert_source.get("data", {})
    data_sca = data_section.get("sca", {}).get("check", {})

    # Prioritize rule description, then SCA check description, then default
    description = rule.get("description") or data_sca.get("description") or "[no description]"
    # Fallback: if full_log is missing, use message field (Wazuh version compatibility)
    full_log = alert_source.get("full_log") or alert_source.get("message") or "[no log]"

    # Process 'groups' field: it's a JSON string of a list, needs parsing
    raw_groups = rule.get("groups", "unknown")
    groups_processed = parse_json_string(raw_groups)

    # Combine description and full_log, then clean and lowercase
    combined_text = clean_text(f"{description} {full_log}")


    # Robust numeric conversions for anomaly detection features
    # These must match the types and names used during training for IsolationForest
    # Ensure pd.to_numeric is applied to a Series before .fillna()
    agent_id = agent.get("id", "0")
    agent_id_value = pd.Series([agent_id]).astype(str).apply(pd.to_numeric, errors="coerce").fillna(0.0).iloc[0]

    firedtimes = rule.get("firedtimes", "0")
    firedtimes_value = pd.Series([firedtimes]).astype(str).apply(pd.to_numeric, errors="coerce").fillna(0.0).iloc[0]

    rule_level = rule.get("level", 0)
    rule_level_value = pd.Series([rule_level]).astype(str).apply(pd.to_numeric, errors="coerce").fillna(0.0).iloc[0]


    extracted_features = {
        # Keys here should consistently use the _numeric suffix as per the training script
        "agent_id_numeric": agent_id_value,
        "rule_level_numeric": rule_level_value,
        "firedtimes": firedtimes_value,
        "groups": groups_processed,
        "decoder_name": decoder.get("name", ""),
        "combined_text": combined_text
    }
    print(f"DEBUG: Extracted features keys: {extracted_features.keys()}")
    return extracted_features


def predict(alert_source: dict) -> dict:

    if anomaly_model is None or classifier_model is None:
        return {
            "error": "ML models not loaded. Cannot perform prediction.",
            "severity_level": -1, # Indicate unknown/error
            "severity_label": "Model Error",
            "is_anomaly": False
        }

    try:
        # Extract features using the updated function that expects _source
        features = extract_structured_features(alert_source)
        # Anomaly detection 
        anomaly_input = pd.DataFrame([{
            "agent_id_numeric": features["agent_id_numeric"],
            "rule_level_numeric": features["rule_level_numeric"],
            "firedtimes": features["firedtimes"]
        }])
        print(f"DEBUG: Anomaly input DataFrame columns: {anomaly_input.columns.tolist()}")
        # IsolationForest predict returns -1 for anomaly, 1 is normal
        raw_anomaly = anomaly_model.predict(anomaly_input)[0]
        is_anomaly = 1 if raw_anomaly == -1 else 0
        features["is_anomaly"] = is_anomaly 
        # Classification
        classifier_input = pd.DataFrame([{
            "combined_text": features["combined_text"],
            "decoder_name": features["decoder_name"],
            "groups": features["groups"],
            "is_anomaly": features["is_anomaly"]
        }])
        print(f"DEBUG: Classifier input DataFrame columns: {classifier_input.columns.tolist()}")
        # Perform classification prediction
        prediction = classifier_model.predict(classifier_input)[0]
        
        # Compute ai_confidence from anomaly score (0.0=normal, 1.0=anomaly)
        ai_confidence = 1.0 if raw_anomaly == -1 else 0.0

        return {
            "severity_level": int(round(prediction)),
            "severity_label": get_severity_label(prediction),
            "is_anomaly": bool(is_anomaly),
            "ai_confidence": float(ai_confidence)
        }

    except Exception as e:
        import traceback
        print(f"Prediction failed for alert: {e}")
        print(traceback.format_exc()) # Print full traceback for debugging
        return {
            "error": f"Prediction failed: {str(e)}",
            "severity_level": -1, # Indicate unknown/error
            "severity_label": "Prediction Error",
            "is_anomaly": False
        }

