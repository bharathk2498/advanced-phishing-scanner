# Advanced Phishing Scanner

A front-end web application built with vanilla HTML, CSS, and JavaScript to analyze URLs and message content for common indicators of phishing.

## 🛡️ Features

This tool performs a client-side analysis based on a set of common phishing tactics. It does **not** send data to any external server or API.

-   **URL Analysis**:
    -   Checks for insecure **HTTP** connections.
    -   Detects the use of known **URL shorteners** (e.g., bit.ly).
    -   Flags suspicious **Top-Level Domains** (TLDs) like `.vip`, `.xyz`, etc.
    -   Warns if the URL is a raw IP address.
-   **Content Analysis**:
    -   Scans message text for **urgency-creating keywords** (e.g., "suspend," "final notice").
-   **Sender Analysis**:
    -   Compares the **claimed sender** (e.g., "Amazon") against the domain in the URL to spot mismatches.
-   **Risk Assessment**:
    -   Provides a final summary (Low, Medium, High Risk) based on the findings.

## 🚀 How to Use

1.  Clone or download the repository.
2.  Open the `index.html` file in any modern web browser.
3.  Enter the URL, the message content, and the claimed sender into the respective fields.
4.  Click "Analyze Now" to see the report.

## ⚠️ Disclaimer

This is a basic educational tool and not a replacement for a full antivirus or internet security solution. Always exercise caution when clicking on suspicious links.
