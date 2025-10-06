import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

class Reporter:
    def __init__(self, outdir="reports"):
        self.outdir = outdir
        os.makedirs(self.outdir, exist_ok=True)
        self.template_file = os.path.join(self.outdir, "template.html")
        self.chart_file = os.path.join(self.outdir, "severity_pie.png")
        self.pdf_report_file = os.path.join(self.outdir, "vuln_report.pdf")
        self.template_html = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>WebScanPro Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #2a4f7a; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .severity-High { color: red; font-weight: bold; }
        .severity-Medium { color: orange; }
        .severity-Low { color: green; }
    </style>
</head>
<body>
    <h1>WebScanPro Report</h1>
    <p><strong>Date:</strong> {{ date }}</p>
    <h2>Findings</h2>
    <img src="{{ chart_file }}" width="200"><br>
    <table>
        <tr>
            <th>Type</th>
            <th>Endpoint</th>
            <th>Severity</th>
            <th>Mitigation</th>
            <th>Param</th>
            <th>Payload/Tested Value</th>
            <th>Evidence</th>
            <th>Username</th>
        </tr>
        {% for f in findings %}
        <tr>
            <td>{{ f.type }}</td>
            <td>{{ f.endpoint }}</td>
            <td class="severity-{{ f.severity }}">{{ f.severity }}</td>
            <td>{{ f.mitigation }}</td>
            <td>{{ f.param }}</td>
            <td>{{ f.payload if f.payload != '-' else f.tested_value }}</td>
            <td>{{ f.evidence }}</td>
            <td>{{ f.username }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

    @staticmethod
    def normalize_vulnerability(vuln):
        keys = [
            "type", "endpoint", "severity", "mitigation",
            "param", "payload", "tested_value", "evidence", "username"
        ]
        return {key: vuln.get(key, "-") for key in keys}

    def generate(self, findings, output_file="scan_report.html"):
        vulnerabilities_norm = [self.normalize_vulnerability(v) for v in findings]

        # Pie chart
        df = pd.DataFrame(vulnerabilities_norm)
        severity_counts = df['severity'].value_counts()
        plt.figure(figsize=(4,4))
        severity_counts.plot.pie(autopct='%1.1f%%', colors=['red', 'orange', 'yellow'])
        plt.title('Severity Distribution')
        plt.ylabel('')
        plt.savefig(self.chart_file)
        plt.close()

        # Write Jinja2 template to file
        with open(self.template_file, "w", encoding="utf-8") as f:
            f.write(self.template_html)

        env = Environment(
            loader=FileSystemLoader(self.outdir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template("template.html")
        html_out = template.render(
            date=datetime.now().strftime('%Y-%m-%d %H:%M'),
            findings=vulnerabilities_norm,
            chart_file=os.path.basename(self.chart_file)
        )

        html_report_file = os.path.join(self.outdir, output_file)
        with open(html_report_file, "w", encoding="utf-8") as f:
            f.write(html_out)

        HTML(html_report_file).write_pdf(self.pdf_report_file)
