#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import warnings

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score
from imblearn.over_sampling import SMOTE

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier

warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
def load_dataset(csv_path):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    return df


def prepare_data_for_classification(df):
    target_col = 'TYPE'
    feature_cols = [
        'BYTES', 'BYTES_REV', 'INTERVALS_MEAN',
        'INTERVALS_MAX', 'INTERVALS_STD', 'INTERVALS_25', 'INTERVALS_50', 'INTERVALS_75'
    ]

    missing_features = [col for col in feature_cols if col not in df.columns]
    if missing_features:
        print(f"Error: Missing columns: {missing_features}")
        exit(1)

    X = df[feature_cols].copy()
    y = df[target_col].copy()

    # Label encoding for target and storing inverse mapping
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    label_mapping = dict(zip(le.classes_, range(len(le.classes_))))
    label_mapping_inv = {v: k for k, v in label_mapping.items()}

    # Convert all features to numeric and fill missing values
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_scaled, y_encoded)

    return X_resampled, y_resampled, label_mapping_inv


def train_and_evaluate_model(clf, X, y, label_mapping_inv):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.8, random_state=42, stratify=y
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    accuracies = {}
    for label in np.unique(y_test):
        mask = (y_test == label)
        acc = accuracy_score(y_test[mask], y_pred[mask])
        accuracies[label_mapping_inv[label]] = acc

    overall_accuracy = accuracy_score(y_test, y_pred)
    return accuracies, overall_accuracy


def main():
    csv_path = "data/traffic_dataset.csv"
    df = load_dataset(csv_path)
    X, y, label_mapping_inv = prepare_data_for_classification(df)

    classifiers = {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
        "Support Vector Machine": SVC(class_weight='balanced', probability=True, random_state=42),
        "XGBoost Classifier": XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            max_depth=None,
            n_jobs=-1,
            class_weight='balanced'
        )
    }

    for clf_name, clf in classifiers.items():
        print(f"\n--- {clf_name} ---")
        per_class_acc, overall_acc = train_and_evaluate_model(clf, X, y, label_mapping_inv)
        print("Per-Class Accuracy:")
        for service, acc in per_class_acc.items():
            print(f"  {service}: {acc:.4f}")
        print(f"Overall Model Accuracy: {overall_acc:.4f}")


if __name__ == "__main__":
    main()
