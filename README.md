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

## Python Scripts And Execution Instructions 

- analyze_traffic_1.py – Processes and extracts network features from .pcapng files.
- analyze_traffic_2.py – Generates comparative analysis between different traffic captures.
- traffic_classifier.py – Implements machine learning models for traffic classification.

All scripts are located in the /src/ directory and should be executed from within that directory.
To run the code, you need to add a directory named "data" inside the project directory (alongside the "src" and "res" directories) and place all the pcapng files inside it.
After that, you can run the Python scripts located in the "src" directory, and the generated plots will be saved in the "res" directory.
This script may take longer to run compared to others, as it processes PCAPNG files directly, requiring additional time to read, parse, and analyze the network traffic data.

File Format Explanation:
1. analyze_traffic_1.py
This script processes PCAPNG capture files that contain the following columns:
No.
Time
Source
Destination
Protocol
Length
Info

2. analyze_traffic_2.py
This script processes CSV files that were exported from PCAPNG captures.
The expected columns in the CSV files are:
No.
Time
Source
Destination
Protocol
Length
Info

3. traffic_classifier.py
This script uses a dataset from Kaggle, which was approved by the lecturers in the forum. More details about this dataset can be found later in this document.
The dataset contains the following columns:
TYPE
BYTES
BYTES_REV
INTERVALS_MEAN
INTERVALS_MAX
INTERVALS_STD
INTERVALS_25
INTERVALS_50
INTERVALS_75
The dataset contains additional columns, but the script only uses the ones listed above. Any other columns can be removed without affecting the results.


## Security and Privacy Considerations

- The project simulates an attacker trying to infer user activity from encrypted traffic.
- Various mitigation techniques (VPN, padding, randomized traffic patterns) are discussed to prevent traffic fingerprinting.

#### Authors

This project was conducted by Eitan Derdiger and Naomi Lakhovsky.

