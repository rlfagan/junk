import json
import os
import numpy as np
import matplotlib.pyplot as plt

# Paths for report and charts
REPORT_DIR = "reports"
CHARTS_DIR = "charts"
vuln_file = "vulnerability_report.json"

# Ensure output directories exist
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)

# Check if the vulnerability report exists
if not os.path.exists(vuln_file):
    print(f"⚠️ Error: {vuln_file} not found. Ensure the scan runs before generating reports.")
    exit(1)  # Exit the script if the file doesn't exist

# Load the vulnerability report
with open(vuln_file, "r", encoding="utf-8") as file:
    results = json.load(file)

# Ensure there's data in the report
if not results:
    print("⚠️ No vulnerabilities found. Creating a basic summary.")
    results = []

# Extract data safely and replace None with 0.0
for entry in results:
    entry["EPSS_Score"] = entry.get("EPSS_Score", 0.0) if isinstance(entry.get("EPSS_Score"), (int, float)) else 0.0
    entry["CVSS_Score"] = entry.get("CVSS_Score", 0.0) if isinstance(entry.get("CVSS_Score"), (int, float)) else 0.0

# Collecting valid scores for mean calculations
epss_scores = [entry["EPSS_Score"] for entry in results if entry["EPSS_Score"] > 0]
cvss_scores = [entry["CVSS_Score"] for entry in results if entry["CVSS_Score"] > 0]
kev_count = sum(1 for entry in results if entry.get("In_KEV", False))
total_cves = len(results)

# Categorize CVEs by risk
high_risk = [entry for entry in results if entry["EPSS_Score"] >= 0.7]
medium_risk = [entry for entry in results if 0.3 <= entry["EPSS_Score"] < 0.7]
low_risk = [entry for entry in results if entry["EPSS_Score"] < 0.3]

# Handle empty datasets to prevent mean calculation errors
avg_epss = np.mean(epss_scores) if epss_scores else 0.0
avg_cvss = np.mean(cvss_scores) if cvss_scores else 0.0

# Generate charts
plt.figure(figsize=(8, 5))
plt.hist(epss_scores, bins=20, edgecolor="black", alpha=0.75, color="purple")
plt.title("EPSS Score Distribution")
plt.xlabel("EPSS Score")
plt.ylabel("Number of Vulnerabilities")
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.savefig(os.path.join(CHARTS_DIR, "epss_distribution.png"))
plt.close()

plt.figure(figsize=(8, 5))
plt.hist(cvss_scores, bins=10, edgecolor="black", alpha=0.75, color="blue")
plt.title("CVSS Score Distribution")
plt.xlabel("CVSS Score")
plt.ylabel("Number of Vulnerabilities")
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.savefig(os.path.join(CHARTS_DIR, "cvss_distribution.png"))
plt.close()

# Generate markdown report
summary_md = f"""
# 📊 Vulnerability Scan Summary

## 🛡️ Overview
- 🔎 **Total CVEs Scanned:** {total_cves}
- 🛑 **Total KEV CVEs:** {kev_count}
- 📉 **Average EPSS Score:** {avg_epss:.2f}
- 💣 **Average CVSS Score:** {avg_cvss:.1f}

---

## 📈 Charts Summary
![EPSS Score Distribution](charts/epss_distribution.png)
![CVSS Score Distribution](charts/cvss_distribution.png)

---
"""

# Write summary to file
summary_file = os.path.join(REPORT_DIR, "summary.md")
with open(summary_file, "w", encoding="utf-8") as f:
    f.write(summary_md)

print("✅ Markdown report and charts generated in 'reports/' and 'charts/' directories.")
