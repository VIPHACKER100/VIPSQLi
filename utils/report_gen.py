import os
import logging
from datetime import datetime
from typing import List, Dict, Any

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
except ImportError:
    # Module will be installed via requirements-v2.2.txt
    pass

logger = logging.getLogger(__name__)

class PDFReporter:
    def __init__(self, filename: str):
        self.filename = filename
        self.styles = getSampleStyleSheet()
        self.doc = SimpleDocTemplate(filename, pagesize=letter)
        self.elements = []

    def _add_header(self, title: str):
        header_style = self.styles['Heading1']
        header_style.alignment = 1  # Center
        self.elements.append(Paragraph(title, header_style))
        self.elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        self.elements.append(Spacer(1, 20))

    def _add_summary_table(self, stats: Dict[str, Any]):
        data = [
            ["Metric", "Value"],
            ["Total URLs", stats.get('total', 0)],
            ["Vulnerable", stats.get('vulnerable', 0)],
            ["Safe", stats.get('safe', 0)],
            ["Errors", stats.get('errors', 0)],
            ["WAF Detected", stats.get('waf_detected', 0)],
            ["Elapsed Time", f"{stats.get('elapsed', 0)}s"]
        ]
        
        table = Table(data, colWidths=[150, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        self.elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
        self.elements.append(Spacer(1, 10))
        self.elements.append(table)
        self.elements.append(Spacer(1, 20))

    def _add_results_table(self, results: List[Dict[str, Any]]):
        data = [["URL", "Verdict", "Risk", "Details"]]
        
        for res in results:
            url = res.get('url', '')[:50] + '...' if len(res.get('url', '')) > 50 else res.get('url', '')
            verdict = res.get('verdict', 'SAFE')
            risk = res.get('risk', 'Low')
            details = res.get('details', '')[:40]
            
            row = [url, verdict, risk, details]
            data.append(row)

        table = Table(data, colWidths=[180, 80, 70, 120])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('SIZE', (0, 1), (-1, -1), 8)
        ]))
        
        self.elements.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        self.elements.append(Spacer(1, 10))
        self.elements.append(table)

    def generate(self, stats: Dict[str, Any], results: List[Dict[str, Any]]):
        try:
            self._add_header("VIP SQLi Scanner - Vulnerability Report")
            self._add_summary_table(stats)
            self._add_results_table(results)
            self.doc.build(self.elements)
            logger.info(f"PDF report generated: {self.filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False
