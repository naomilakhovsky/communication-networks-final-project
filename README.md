# Network Traffic Analysis

## Project Overview

This project explores network traffic characteristics, focusing on analyzing encrypted traffic and identifying application usage patterns. The study investigates how different applications such as web browsing, audio streaming, video streaming, and video conferencing generate distinct traffic signatures, even when encrypted. The project utilizes Wireshark for capturing network packets and Python-based scripts for processing and classification.

### Background

Everyday applications generate unique traffic patterns based on factors such as packet size, inter-arrival time, and protocol usage. While encryption prevents direct content inspection, metadata analysis can still reveal user behavior. This project aims to:

- Extract key network features from different applications.
- Compare traffic patterns across various services.
- Develop machine learning models to classify traffic based on encrypted metadata.
- Simulate attacker scenarios and evaluate potential privacy risks.

## Features

- Captures and analyzes traffic from different applications.
- Extracts network characteristics such as packet size, inter-arrival time, and protocol usage.
- Implements Python scripts for automated data processing and visualization.
- Develops machine learning models (Random Forest, SVM, XGBoost) for traffic classification.
- Investigates security risks by simulating an attacker attempting to classify encrypted traffic.

## Python Scripts Overview

- analyze_traffic_1.py – Processes and extracts network features from .pcapng files.
- analyze_traffic_2.py – Generates comparative analysis between different traffic captures.
- traffic_classifier.py – Implements machine learning models for traffic classification.

All scripts are located in the /src/ directory and should be executed from within that directory.

## Security and Privacy Considerations

- The project simulates an attacker trying to infer user activity from encrypted traffic.
- Various mitigation techniques (VPN, padding, randomized traffic patterns) are discussed to prevent traffic fingerprinting.

## Authors

This project was conducted by Eitan Derdiger and Naomi Lakhovsky.
