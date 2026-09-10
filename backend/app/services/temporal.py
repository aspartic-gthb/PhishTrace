from typing import Tuple, Optional

def analyze_temporal_risk(hour: Optional[int], day: Optional[int], base_risk: float) -> Tuple[float, Optional[str]]:
    """
    Adjusts risk score based on time-of-day and day-of-week heuristics.
    Returns (multiplier, explanation).
    """
    if hour is None or day is None:
        return 1.0, None

    multiplier = 1.0
    reasons = []

    # Late Night (11 PM - 5 AM): Fatigue Vulnerability
    if hour >= 23 or hour < 5:
        multiplier += 0.2
        reasons.append("Unusual late-night activity")

    # Friday Afternoon (4 PM - 8 PM): CEO Fraud / Urgency Window
    # Day 4 = Friday
    if day == 4 and 16 <= hour <= 20:
        multiplier += 0.15
        reasons.append("High-risk window for urgency scams (Friday afternoon)")

    # Weekend (Sat/Sun): Reduced Verification Ability
    # Day 5=Sat, 6=Sun
    if day >= 5:
        multiplier += 0.1
        if base_risk > 0.4:
            reasons.append("Weekend targeting detected")

    if multiplier == 1.0:
        return 1.0, None
        
    explanation = None
    if reasons:
        explanation = f"Temporal Warning: {'; '.join(reasons)}."

    return multiplier, explanation
