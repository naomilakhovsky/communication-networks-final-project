# Network Traffic Analysis

## Project Overview

This project explores network traffic characteristics, focusing on analyzing encrypted traffic and identifying application usage patterns. The study investigates how different applications such as web browsing, audio streaming, video streaming, and video conferencing generate distinct traffic signatures, even when encrypted. The project utilizes Wireshark for capturing network packets and Python-based scripts for processing and classification.

### Background

Everyday applications generate unique traffic patterns based on factors such as packet size, inter-arrival time, and protocol usage. While encryption prevents direct content inspection, metadata analysis can still reveal user behavior. This project aims to:

- Extract key network features from different applications.
- Compare traffic patterns across various services.
- Develop machine learning models to classify traffic based on encrypted metadata.
- Simulate attacker scenarios and evaluate potential privacy risks.

### Research Summary (Part 2)

The project includes an in-depth analysis of multiple research papers on encrypted traffic classification. For each paper, the following aspects were examined:

- Main contribution: The core problem the research addresses and its significance.
- Novel techniques: Unique methodologies introduced, such as CNN-based FlowPic classification, early flow statistics, and QUIC padding analysis.
- Key results: Performance metrics and comparisons with existing classification models.
- Insights and impact: How the findings contribute to the broader field of encrypted traffic analysis and privacy concerns.
## Key Research Findings:

#### FlowPic (CNN-based Traffic Classification):
Introduces FlowPic, which converts network traffic into 2D histograms and applies CNNs for classification.
Achieves high accuracy (98.4%) for VPN traffic and performs well even with Tor encryption (85.7%).
Works without requiring deep packet inspection, making it encryption-agnostic and suitable for real-world deployment.
#### hRFTC (Hybrid Random Forest Traffic Classifier for TLS 1.3 & QUIC):
Addresses the challenges of Encrypted ClientHello (ECH) in TLS 1.3, which hides metadata that traditional classifiers rely on.
Uses unencrypted TLS handshake elements + flow-based statistics for classification.
Outperforms previous methods with a 94.6% F-score, even when training data is limited.
#### HTTPS-encrypted Traffic Fingerprinting:
Demonstrates that machine learning can identify a user’s OS, browser, and application based solely on encrypted traffic.
Uses SVM with RBF kernel, reaching 96.06% accuracy.
Highlights privacy risks and the need for defensive techniques like randomization and padding.

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
To run the code, you need to add a directory named "data" inside the project directory (alongside the "src" and "res" directories) and place all the pcapng files inside it.
After that, you can run the Python scripts located in the "src" directory, and the generated plots will be saved in the "res" directory.

## Security and Privacy Considerations

- The project simulates an attacker trying to infer user activity from encrypted traffic.
- Various mitigation techniques (VPN, padding, randomized traffic patterns) are discussed to prevent traffic fingerprinting.

## Authors

This project was conducted by Eitan Derdiger and Naomi Lakhovsky.

