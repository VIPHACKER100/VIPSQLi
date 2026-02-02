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
        self._setup_custom_styles()
        self.doc = SimpleDocTemplate(filename, pagesize=letter)
        self.elements = []
        
        # Cyberpunk Theme Colors
        self.neon_blue = colors.HexColor("#00f2ff")
        self.neon_pink = colors.HexColor("#ff00ff")
        self.obsidian = colors.HexColor("#0b0e14")
        self.dark_grey = colors.HexColor("#161b22")

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CyberTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor("#00f2ff"),
            alignment=1,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='CyberHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor("#ff00ff"),
            spaceBefore=15,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='CyberText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.whitesmoke,
            leading=12
        ))

    def _add_header(self, title: str):
        # Draw a dark background rectangle via a Table (simplest in ReportLab Platypus)
        # Note: True dark background requires drawing on the canvas, but we use tables for layout here.
        self.elements.append(Paragraph(title.upper(), self.styles['CyberTitle']))
        self.elements.append(Paragraph(f"SCAN REPORT // DATA_FETCH_DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['CyberText']))
        self.elements.append(Spacer(1, 20))

    def _get_remediation(self, verdict: str) -> str:
        if verdict == 'VULNERABLE':
            return "IMMEDIATE: Use prepared statements or parameterized queries. Sanitize all user inputs using type-casting or whitelisting."
        elif verdict == 'SUSPICIOUS':
            return "REVIEW: Behavior anomalies detected. Verify input filtering and monitor logs for unusual injection attempts."
        return "N/A: No issues detected."

    def _get_cvss(self, verdict: str) -> str:
        if verdict == 'VULNERABLE': return "8.8 (High)"
        if verdict == 'SUSPICIOUS': return "5.3 (Medium)"
        return "0.0"

    def _add_summary_table(self, stats: Dict[str, Any]):
        data = [
            [Paragraph("<b>METRIC</b>", self.styles['CyberText']), Paragraph("<b>VALUE</b>", self.styles['CyberText'])],
            ["Total Nodes", str(stats.get('total', 0))],
            ["Vulnerabilities", f"{stats.get('vulnerable', 0)} (CRITICAL)"],
            ["Safe nodes", str(stats.get('safe', 0))],
            ["Packet Errors", str(stats.get('errors', 0))],
            ["WAF Bypassed", str(stats.get('waf_detected', 0))],
            ["Scan Runtime", f"{stats.get('elapsed', 0)}s"]
        ]
        
        table = Table(data, colWidths=[150, 150])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.dark_grey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, self.neon_blue),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        self.elements.append(Paragraph("EXECUTIVE_SUMMARY", self.styles['CyberHeader']))
        self.elements.append(table)
        self.elements.append(Spacer(1, 30))

    def _add_results_table(self, results: List[Dict[str, Any]]):
        self.elements.append(Paragraph("THREAT_DETAIL_STREAM", self.styles['CyberHeader']))
        
        for i, res in enumerate(results):
            if i > 50: # Limit PDF size
                self.elements.append(Paragraph("... (truncated for brevity)", self.styles['CyberText']))
                break
                
            url = res.get('url', '')
            verdict = res.get('verdict', 'SAFE')
            cvss = self._get_cvss(verdict)
            remediation = self._get_remediation(verdict)
            
            # Sub-table for each finding
            finding_data = [
                [Paragraph(f"<b>TARGET [{i+1}]</b>", self.styles['CyberText']), Paragraph(url[:70], self.styles['CyberText'])],
                [Paragraph("<b>VERDICT</b>", self.styles['CyberText']), Paragraph(f"<font color='#ff00ff'>{verdict}</font>" if verdict != 'SAFE' else verdict, self.styles['CyberText'])],
                [Paragraph("<b>CVSS_V3</b>", self.styles['CyberText']), cvss],
                [Paragraph("<b>ANALYSIS</b>", self.styles['CyberText']), Paragraph(str(res.get('details', 'N/A')), self.styles['CyberText'])],
                [Paragraph("<b>REMEDIATION</b>", self.styles['CyberText']), Paragraph(remediation, self.styles['CyberText'])]
            ]
            
            st = Table(finding_data, colWidths=[100, 350])
            st.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.neon_blue),
                ('BACKGROUND', (0, 0), (0, -1), self.dark_grey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            self.elements.append(st)
            self.elements.append(Spacer(1, 15))

    def generate(self, stats: Dict[str, Any], results: List[Dict[str, Any]]):
        try:
            # Note: True dark mode background requires a custom template or page canvas drawing.
            # We'll use a clean white page with high-contrast cyber elements.
            self._add_header("VIP SQLi Scanner // Cyber Report")
            self._add_summary_table(stats)
            self._add_results_table(results)
            self.elements.append(Spacer(1, 40))
            self.elements.append(Paragraph("--- [ END_OF_TRANSMISSION ] ---", self.styles['CyberText']))
            
            self.doc.build(self.elements)
            logger.info(f"PDF report generated: {self.filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False
