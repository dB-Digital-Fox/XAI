def extract_features(alert: dict) -> dict:
    d = alert.get("data", {})
    r = alert.get("rule", {})
    # Keep features aligned with training/train.py
    return {
        "sentbyte": int(d.get("sentbyte", 0)),
        "rcvdbyte": int(d.get("rcvdbyte", 0)),
        "duration": int(d.get("duration", 0)),
        "rule_level": int(r.get("level", 0)),
        "apprisk_elevated": 1 if str(d.get("apprisk","")).lower() == "elevated" else 0,
        "hour": 0
    }
