"""Test suite for ML models feature extraction and predictions."""

import pytest
from ml_models import extract_structured_features, predict


class TestFeatureExtraction:
    """Test feature extraction with full_log and message fallback."""
    
    def test_extract_with_full_log(self):
        """Test extraction when full_log field is present."""
        alert = {
            "rule": {
                "description": "Test rule",
                "level": 3,
                "firedtimes": 1,
                "groups": '["test"]'
            },
            "agent": {"id": "001"},
            "decoder": {"name": "json"},
            "data": {"sca": {"check": {}}},
            "full_log": "This is the full log content"
        }
        
        features = extract_structured_features(alert)
        
        assert "combined_text" in features
        assert "This is the full log content".lower() in features["combined_text"]
        assert features["agent_id_numeric"] == 1.0
        assert features["rule_level_numeric"] == 3.0
        assert features["firedtimes"] == 1.0
    
    def test_extract_with_message_fallback(self):
        """Test extraction when full_log is missing and message field is used."""
        alert = {
            "rule": {
                "description": "Test rule from message",
                "level": 5,
                "firedtimes": 2,
                "groups": '["security"]'
            },
            "agent": {"id": "002"},
            "decoder": {"name": "syslog"},
            "data": {"sca": {"check": {}}},
            "message": "This is the message field content"
            # Note: no full_log field
        }
        
        features = extract_structured_features(alert)
        
        assert "combined_text" in features
        assert "This is the message field content".lower() in features["combined_text"]
        assert features["agent_id_numeric"] == 2.0
        assert features["rule_level_numeric"] == 5.0
        assert features["firedtimes"] == 2.0
    
    def test_extract_with_no_log_or_message(self):
        """Test extraction when both full_log and message are missing."""
        alert = {
            "rule": {
                "description": "Default rule",
                "level": 2,
                "firedtimes": 0,
                "groups": '[]'
            },
            "agent": {"id": "003"},
            "decoder": {"name": "unknown"},
            "data": {"sca": {"check": {}}}
            # No full_log or message
        }
        
        features = extract_structured_features(alert)
        
        assert "combined_text" in features
        assert "[no log]".lower() in features["combined_text"]
        assert features["agent_id_numeric"] == 3.0
    
    def test_extract_with_nested_groups(self):
        """Test extraction of JSON-encoded groups field."""
        alert = {
            "rule": {
                "description": "Test with groups",
                "level": 4,
                "firedtimes": 1,
                "groups": '["authentication", "network"]'
            },
            "agent": {"id": "004"},
            "decoder": {"name": "auth"},
            "data": {"sca": {"check": {}}},
            "full_log": "Auth attempt"
        }
        
        features = extract_structured_features(alert)
        
        assert "groups" in features
        assert "authentication" in features["groups"]
        assert "network" in features["groups"]


class TestPredictionConfidence:
    """Test that predictions return ai_confidence field."""
    
    def test_predict_returns_confidence(self):
        """Test that predict() returns ai_confidence in result."""
        alert = {
            "rule": {
                "description": "Test prediction",
                "level": 3,
                "firedtimes": 1,
                "groups": '["test"]'
            },
            "agent": {"id": "001"},
            "decoder": {"name": "json"},
            "data": {"sca": {"check": {}}},
            "full_log": "Test log"
        }
        
        result = predict(alert)
        
        # Check required fields exist
        assert "severity_level" in result
        assert "severity_label" in result
        assert "is_anomaly" in result
        assert "ai_confidence" in result
        
        # Verify ai_confidence is float
        assert isinstance(result["ai_confidence"], float)
        
        # ai_confidence should be 0.0 or 1.0 based on anomaly flag
        assert result["ai_confidence"] in (0.0, 1.0)
        
        # If anomaly, confidence should be 1.0
        if result["is_anomaly"]:
            assert result["ai_confidence"] == 1.0
        # If not anomaly, confidence should be 0.0
        else:
            assert result["ai_confidence"] == 0.0
    
    def test_predict_with_message_fallback_confidence(self):
        """Test prediction confidence with message fallback."""
        alert = {
            "rule": {
                "description": "Another test",
                "level": 2,
                "firedtimes": 1,
                "groups": '[]'
            },
            "agent": {"id": "002"},
            "decoder": {"name": "sys"},
            "data": {"sca": {"check": {}}},
            "message": "Alert via message field"
            # No full_log
        }
        
        result = predict(alert)
        
        assert "ai_confidence" in result
        assert isinstance(result["ai_confidence"], float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
