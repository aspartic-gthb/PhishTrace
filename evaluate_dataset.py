#!/usr/bin/env python3
"""
PhishTrace Dataset Evaluation & Validation Suite
Evaluates external email datasets against the PhishTrace ML and Forensic models.

Usage:
    python evaluate_dataset.py --dataset data/processed/train.csv
    python evaluate_dataset.py --dataset path/to/external_emails.csv --text-col body --output results.csv
    python evaluate_dataset.py --eml-dir path/to/eml_folder/
"""

import os
import sys
import argparse
import json
import joblib
import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

def load_models():
    print("⚡ Loading PhishTrace ML models...")
    vec_path = os.path.join(MODELS_DIR, "vectorizer_v6.joblib")
    model_path = os.path.join(MODELS_DIR, "model_v6.joblib")
    temp_path = os.path.join(MODELS_DIR, "temporal_analysis_v1.pkl")

    if not os.path.exists(vec_path) or not os.path.exists(model_path):
        raise FileNotFoundError(f"Required models not found in {MODELS_DIR}")

    vectorizer = joblib.load(vec_path)
    model = joblib.load(model_path)
    
    temporal_model = None
    if os.path.exists(temp_path):
        try:
            with open(temp_path, "rb") as f:
                temporal_model = pickle.load(f)
        except Exception as e:
            print(f"Warning: Temporal model skipped ({e})")

    print(f"✓ Loaded Vectorizer (vocab: {len(vectorizer.vocabulary_)} tokens)")
    print(f"✓ Loaded MultiOutputClassifier (classes: {model.classes_})")
    return vectorizer, model, temporal_model

def evaluate_dataframe(df: pd.DataFrame, text_col: str, vectorizer, model, temporal_model=None):
    texts = df[text_col].fillna("").astype(str).tolist()
    print(f"\n📊 Evaluating {len(texts)} samples across 4 social engineering threat vectors...")

    # 1. Transform texts
    X = vectorizer.transform(texts)

    # 2. Multi-label prediction & probabilities
    preds = model.predict(X) # Shape: (N, 4)
    probs_list = model.predict_proba(X) # List of 4 arrays, each (N, 2)

    # Probabilities for positive class (1)
    urgency_prob = probs_list[0][:, 1]
    authority_prob = probs_list[1][:, 1]
    fear_prob = probs_list[2][:, 1]
    impersonation_prob = probs_list[3][:, 1]

    # Composite risk score (fused max/weighted)
    composite_risk = np.maximum.reduce([urgency_prob, authority_prob, fear_prob, impersonation_prob])

    # Assign risk tiers
    risk_levels = []
    for score in composite_risk:
        if score >= 0.70:
            risk_levels.append("CRITICAL")
        elif score >= 0.40:
            risk_levels.append("SUSPICIOUS")
        else:
            risk_levels.append("SAFE")

    # Add predictions to dataframe
    df["pred_urgency"] = urgency_prob
    df["pred_authority"] = authority_prob
    df["pred_fear"] = fear_prob
    df["pred_impersonation"] = impersonation_prob
    df["risk_score"] = composite_risk
    df["risk_level"] = risk_levels

    # Summary Statistics
    print("\n" + "=" * 60)
    print("          PHISHTRACE MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"Total Samples Analyzed: {len(df)}")
    print(f"  • Critical Threats (≥ 70%):   {(df['risk_level'] == 'CRITICAL').sum()} ({(df['risk_level'] == 'CRITICAL').mean()*100:.1f}%)")
    print(f"  • Suspicious Emails (40-69%): {(df['risk_level'] == 'SUSPICIOUS').sum()} ({(df['risk_level'] == 'SUSPICIOUS').mean()*100:.1f}%)")
    print(f"  • Safe / Benign (< 40%):      {(df['risk_level'] == 'SAFE').sum()} ({(df['risk_level'] == 'SAFE').mean()*100:.1f}%)")
    print("-" * 60)
    print("Threat Vector Averages Across Dataset:")
    print(f"  • Avg Urgency Score:       {urgency_prob.mean()*100:.2f}%")
    print(f"  • Avg Authority Pressure:  {authority_prob.mean()*100:.2f}%")
    print(f"  • Avg Fear / Coercion:     {fear_prob.mean()*100:.2f}%")
    print(f"  • Avg Impersonation Risk:  {impersonation_prob.mean()*100:.2f}%")
    print("-" * 60)

    # 3. Ground Truth Evaluation (if ground truth columns exist)
    labels = ["urgency", "authority", "fear", "impersonation"]
    has_all_labels = all(col in df.columns for col in labels)

    if has_all_labels:
        print("\n📈 Ground Truth Multi-Label Performance Metrics:")
        print("-" * 60)
        for i, label in enumerate(labels):
            y_true = df[label].astype(int)
            y_pred = preds[:, i]
            acc = accuracy_score(y_true, y_pred)
            prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
            print(f"  [{label.upper():<14}] Acc: {acc*100:5.2f}% | Prec: {prec*100:5.2f}% | Rec: {rec*100:5.2f}% | F1: {f1*100:5.2f}%")
        print("=" * 60)
    elif "label" in df.columns or "is_phishing" in df.columns:
        gt_col = "label" if "label" in df.columns else "is_phishing"
        y_true = df[gt_col].astype(int)
        binary_preds = (composite_risk >= 0.50).astype(int)
        acc = accuracy_score(y_true, binary_preds)
        prec, rec, f1, _ = precision_recall_fscore_support(y_true, binary_preds, average="binary", zero_division=0)
        print(f"\n📈 Binary Phishing Detection Performance (Ground Truth: '{gt_col}'):")
        print(f"  Accuracy:  {acc*100:.2f}%")
        print(f"  Precision: {prec*100:.2f}%")
        print(f"  Recall:    {rec*100:.2f}%")
        print(f"  F1-Score:  {f1*100:.2f}%")
        print("=" * 60)

    return df

def main():
    parser = argparse.ArgumentParser(description="Evaluate PhishTrace models on external datasets")
    parser.add_argument("--dataset", type=str, default="data/processed/train.csv", help="Path to CSV/JSON dataset file")
    parser.add_argument("--text-col", type=str, default=None, help="Name of column containing email text")
    parser.add_argument("--output", type=str, default=None, help="Path to export evaluated predictions CSV")
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        print(f"Error: Dataset file not found at '{args.dataset}'")
        sys.exit(1)

    # Load dataset
    print(f"📂 Loading dataset from {args.dataset}...")
    if args.dataset.endswith(".csv"):
        df = pd.read_csv(args.dataset)
    elif args.dataset.endswith(".json"):
        df = pd.read_json(args.dataset)
    else:
        print("Unsupported format. Please provide a CSV or JSON file.")
        sys.exit(1)

    # Detect text column
    text_col = args.text_col
    if not text_col:
        candidates = ["text", "cleaned_text", "body", "email_body", "content", "message", "subject_body"]
        for c in candidates:
            if c in df.columns:
                text_col = c
                break

    if not text_col:
        print(f"Could not automatically detect text column. Columns available: {df.columns.tolist()}")
        print("Please specify with --text-col <column_name>")
        sys.exit(1)

    print(f"✓ Using text column: '{text_col}'")

    vectorizer, model, temporal_model = load_models()
    evaluated_df = evaluate_dataframe(df, text_col, vectorizer, model, temporal_model)

    if args.output:
        evaluated_df.to_csv(args.output, index=False)
        print(f"\n💾 Predictions successfully exported to: {args.output}")

if __name__ == "__main__":
    main()
