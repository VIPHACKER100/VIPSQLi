import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
        PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
except ImportError:
    pass

logger = logging.getLogger(__name__)


class EnhancedPDFReporter:
    """Enhanced PDF report generator with better formatting and analysis"""
    
    def __init__(self, filename: str, config: Optional[Dict] = None):
        self.filename = filename
        self.config = config or {}
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # PDF settings
        self.pagesize = A4 if self.config.get('paper_size') == 'A4' else letter
        self.doc = SimpleDocTemplate(
            filename, 
            pagesize=self.pagesize,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        self.elements = []
        
        # Color scheme
        self.theme = self.config.get('theme', 'cyber')
        self._setup_colors()
        
        logger.info(f"PDF Reporter initialized: {filename}, theme={self.theme}")
    
    def _setup_colors(self):
        """Setup color scheme based on theme"""
        if self.theme == 'cyber':
            self.primary_color = colors.HexColor("#00f2ff")
            self.secondary_color = colors.HexColor("#ff00ff")
            self.background_dark = colors.HexColor("#0b0e14")
            self.background_light = colors.HexColor("#161b22")
            self.text_color = colors.whitesmoke
            self.success_color = colors.HexColor("#00ff41")
            self.warning_color = colors.HexColor("#ffaa00")
            self.danger_color = colors.HexColor("#ff0055")
        elif self.theme == 'professional':
            self.primary_color = colors.HexColor("#2563eb")
            self.secondary_color = colors.HexColor("#7c3aed")
            self.background_dark = colors.HexColor("#1e293b")
            self.background_light = colors.HexColor("#334155")
            self.text_color = colors.HexColor("#f1f5f9")
            self.success_color = colors.HexColor("#10b981")
            self.warning_color = colors.HexColor("#f59e0b")
            self.danger_color = colors.HexColor("#ef4444")
        else:  # default
            self.primary_color = colors.blue
            self.secondary_color = colors.purple
            self.background_dark = colors.HexColor("#1a1a1a")
            self.background_light = colors.HexColor("#2a2a2a")
            self.text_color = colors.white
            self.success_color = colors.green
            self.warning_color = colors.orange
            self.danger_color = colors.red
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor("#00f2ff"),
            alignment=TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold',
            leading=32
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor("#ff00ff"),
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor("#ff00ff"),
            borderPadding=8
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor("#00f2ff"),
            spaceBefore=12,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.whitesmoke,
            leading=14,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeText',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor("#00ff41"),
            fontName='Courier',
            leading=11,
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor("#888888"),
            alignment=TA_RIGHT,
            spaceAfter=20
        ))
    
    def _add_header(self, title: str, subtitle: Optional[str] = None):
        """Add report header with metadata"""
        # Title
        self.elements.append(Paragraph(title.upper(), self.styles['ReportTitle']))
        
        # Metadata
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        metadata = f"Generated: {timestamp} | Scanner v3.0"
        if subtitle:
            metadata = f"{subtitle}<br/>{metadata}"
        
        self.elements.append(Paragraph(metadata, self.styles['Metadata']))
        self.elements.append(Spacer(1, 20))
    
    def _add_executive_summary(self, stats: Dict[str, Any]):
        """Add executive summary with key metrics"""
        self.elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        self.elements.append(Spacer(1, 10))
        
        # Calculate additional metrics
        total = stats.get('total', 0)
        vulnerable = stats.get('vulnerable', 0)
        suspicious = stats.get('suspicious', 0)
        safe = stats.get('safe', 0)
        errors = stats.get('errors', 0)
        
        vuln_rate = (vulnerable / total * 100) if total > 0 else 0
        success_rate = ((total - errors) / total * 100) if total > 0 else 0
        
        # Risk assessment
        risk_level = "CRITICAL" if vuln_rate > 10 else "HIGH" if vuln_rate > 5 else "MEDIUM" if vuln_rate > 1 else "LOW"
        risk_color = self.danger_color if vuln_rate > 10 else self.warning_color if vuln_rate > 1 else self.success_color
        
        # Summary table
        data = [
            [Paragraph("<b>METRIC</b>", self.styles['BodyText']), 
             Paragraph("<b>VALUE</b>", self.styles['BodyText']),
             Paragraph("<b>NOTES</b>", self.styles['BodyText'])],
            
            ["Total Targets Scanned", str(total), "Unique endpoints tested"],
            ["Vulnerabilities Found", f"{vulnerable} ({vuln_rate:.1f}%)", "CRITICAL - Immediate action required"],
            ["Suspicious Findings", str(suspicious), "Requires manual review"],
            ["Safe Endpoints", str(safe), "No vulnerabilities detected"],
            ["Scan Errors", str(errors), "Failed requests / timeouts"],
            ["Success Rate", f"{success_rate:.1f}%", "Successful scan completion"],
            ["WAF Detections", str(stats.get('waf_detected', 0)), "WAF/IPS systems identified"],
            ["Scan Duration", f"{stats.get('elapsed', 0):.2f}s", "Total execution time"],
            ["Risk Level", risk_level, "Overall security posture"]
        ]
        
        table = Table(data, colWidths=[2*inch, 1.5*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.background_dark),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.text_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, self.primary_color),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.background_light, None]),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        self.elements.append(table)
        self.elements.append(Spacer(1, 20))
    
    def _add_vulnerability_details(self, results: List[Dict[str, Any]]):
        """Add detailed vulnerability findings"""
        # Filter for vulnerabilities only
        vulnerabilities = [r for r in results if r.get('verdict') in ['VULNERABLE', 'SUSPICIOUS']]
        
        if not vulnerabilities:
            self.elements.append(Paragraph("No vulnerabilities found.", self.styles['BodyText']))
            return
        
        self.elements.append(Paragraph("VULNERABILITY DETAILS", self.styles['SectionHeader']))
        self.elements.append(Spacer(1, 10))
        
        for i, vuln in enumerate(vulnerabilities[:50], 1):  # Limit to top 50
            self._add_single_vulnerability(i, vuln)
    
    def _add_single_vulnerability(self, index: int, vuln: Dict[str, Any]):
        """Add a single vulnerability finding"""
        url = vuln.get('url', 'Unknown')
        verdict = vuln.get('verdict', 'UNKNOWN')
        details = vuln.get('details', 'No details available')
        payload = vuln.get('payload', '')
        response_time = vuln.get('response_time', 0)
        
        # Determine severity
        cvss = self._calculate_cvss(verdict, vuln)
        severity = self._get_severity_from_cvss(cvss)
        severity_color = self._get_severity_color(severity)
        
        # Create finding card
        finding_elements = []
        
        # Header
        header_text = f"<font color='{self.secondary_color.hexval()}'>FINDING #{index}</font> | {severity} | CVSS: {cvss}"
        finding_elements.append(Paragraph(header_text, self.styles['SubHeader']))
        
        # Details table
        details_data = [
            ["Target URL:", Paragraph(url[:100], self.styles['BodyText'])],
            ["Verdict:", f"<font color='{severity_color.hexval()}'>{verdict}</font>"],
            ["Description:", Paragraph(str(details)[:300], self.styles['BodyText'])],
        ]
        
        if payload:
            details_data.append(["Payload Used:", Paragraph(f"<font face='Courier' size='8'>{payload[:150]}</font>", self.styles['BodyText'])])
        
        if response_time:
            details_data.append(["Response Time:", f"{response_time:.3f}s"])
        
        # Remediation
        remediation = self._get_remediation(verdict, vuln)
        details_data.append(["Remediation:", Paragraph(remediation, self.styles['BodyText'])])
        
        # OWASP Reference
        details_data.append(["Reference:", "OWASP Top 10 2021 - A03:2021 Injection"])
        
        details_table = Table(details_data, colWidths=[1.5*inch, 5*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.background_dark),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.text_color),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, self.primary_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        finding_elements.append(details_table)
        finding_elements.append(Spacer(1, 15))
        
        # Keep finding together
        self.elements.append(KeepTogether(finding_elements))
    
    def _add_statistics(self, stats: Dict[str, Any]):
        """Add detailed statistics section"""
        self.elements.append(PageBreak())
        self.elements.append(Paragraph("SCAN STATISTICS", self.styles['SectionHeader']))
        self.elements.append(Spacer(1, 10))
        
        # Performance metrics
        if 'rate_limiter' in stats:
            self.elements.append(Paragraph("Rate Limiting Performance", self.styles['SubHeader']))
            rl_stats = stats['rate_limiter']
            
            rl_data = [
                ["Total Requests", str(rl_stats.get('requests', 0))],
                ["Throttled Requests", str(rl_stats.get('throttled', 0))],
                ["Average Delay", f"{rl_stats.get('avg_delay', 0):.3f}s"],
                ["Error Rate", f"{rl_stats.get('error_rate', 0) * 100:.2f}%"],
            ]
            
            rl_table = Table(rl_data, colWidths=[3*inch, 2*inch])
            rl_table.setStyle(self._get_standard_table_style())
            self.elements.append(rl_table)
            self.elements.append(Spacer(1, 15))
        
        # WAF evasion stats
        if 'waf_evasion' in stats:
            self.elements.append(Paragraph("WAF Evasion Statistics", self.styles['SubHeader']))
            waf_stats = stats['waf_evasion']
            
            waf_data = [
                ["Total Evasions Applied", str(waf_stats.get('total_evasions', 0))],
                ["Techniques Used", ", ".join(waf_stats.get('techniques_used', {}).keys())],
            ]
            
            waf_table = Table(waf_data, colWidths=[3*inch, 2*inch])
            waf_table.setStyle(self._get_standard_table_style())
            self.elements.append(waf_table)
            self.elements.append(Spacer(1, 15))
    
    def _add_recommendations(self, stats: Dict[str, Any]):
        """Add security recommendations"""
        self.elements.append(Paragraph("SECURITY RECOMMENDATIONS", self.styles['SectionHeader']))
        self.elements.append(Spacer(1, 10))
        
        recommendations = [
            ("Immediate Actions", [
                "Implement parameterized queries / prepared statements for all database operations",
                "Deploy input validation with whitelist approach for all user inputs",
                "Enable WAF rules to block common SQL injection patterns",
                "Review and patch all identified vulnerable endpoints within 24-48 hours"
            ]),
            ("Short-term (1-2 weeks)", [
                "Conduct code review of database interaction layer",
                "Implement stored procedures where appropriate",
                "Add input length restrictions and type validation",
                "Enable database query logging for monitoring",
                "Train development team on secure coding practices"
            ]),
            ("Long-term (1-3 months)", [
                "Implement ORM (Object-Relational Mapping) framework",
                "Deploy Database Activity Monitoring (DAM) solution",
                "Establish regular security testing schedule",
                "Implement least privilege principle for database accounts",
                "Set up automated vulnerability scanning in CI/CD pipeline"
            ])
        ]
        
        for title, items in recommendations:
            self.elements.append(Paragraph(title, self.styles['SubHeader']))
            for item in items:
                self.elements.append(Paragraph(f"• {item}", self.styles['BodyText']))
            self.elements.append(Spacer(1, 10))
    
    def _get_standard_table_style(self) -> TableStyle:
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.background_dark),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.text_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, self.primary_color),
            ('PADDING', (0, 0), (-1, -1), 6),
        ])
    
    def _calculate_cvss(self, verdict: str, vuln: Dict) -> float:
        """Calculate CVSS score"""
        if verdict == 'VULNERABLE':
            return 8.8
        elif verdict == 'SUSPICIOUS':
            return 5.3
        return 0.0
    
    def _get_severity_from_cvss(self, cvss: float) -> str:
        """Get severity level from CVSS score"""
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        elif cvss > 0:
            return "LOW"
        return "INFO"
    
    def _get_severity_color(self, severity: str):
        """Get color for severity level"""
        severity_colors = {
            "CRITICAL": self.danger_color,
            "HIGH": colors.HexColor("#ff6b6b"),
            "MEDIUM": self.warning_color,
            "LOW": colors.HexColor("#ffd93d"),
            "INFO": self.text_color
        }
        return severity_colors.get(severity, self.text_color)
    
    def _get_remediation(self, verdict: str, vuln: Dict) -> str:
        """Get remediation advice"""
        if verdict == 'VULNERABLE':
            return ("CRITICAL: This endpoint is vulnerable to SQL injection. "
                   "Immediately implement parameterized queries or prepared statements. "
                   "Use input validation with whitelist approach. "
                   "Consider deploying WAF rules as temporary mitigation.")
        elif verdict == 'SUSPICIOUS':
            return ("WARNING: Suspicious behavior detected. "
                   "Review input validation logic and database query construction. "
                   "Monitor logs for injection attempts. "
                   "Consider implementing additional input sanitization.")
        return "No action required - endpoint appears secure."
    
    def generate(self, stats: Dict[str, Any], results: List[Dict[str, Any]]) -> bool:
        """Generate the complete PDF report"""
        try:
            # Build report sections
            self._add_header(
                "SQL Injection Security Assessment",
                f"Vulnerability Scan Report - {stats.get('total', 0)} Targets"
            )
            
            self._add_executive_summary(stats)
            self._add_vulnerability_details(results)
            self._add_statistics(stats)
            self._add_recommendations(stats)
            
            # Footer
            self.elements.append(Spacer(1, 40))
            footer = f"<para align='center'><font color='#888888'>--- END OF REPORT ---<br/>Confidential - For Internal Use Only</font></para>"
            self.elements.append(Paragraph(footer, self.styles['BodyText']))
            
            # Build PDF
            self.doc.build(self.elements)
            
            logger.info(f"PDF report generated successfully: {self.filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}", exc_info=True)
            return False


class JSONReporter:
    """JSON report generator for machine-readable output"""
    
    def __init__(self, filename: str):
        self.filename = filename
    
    def generate(self, stats: Dict[str, Any], results: List[Dict[str, Any]]) -> bool:
        """Generate JSON report"""
        try:
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'scanner_version': '3.0',
                    'report_format': 'json'
                },
                'summary': stats,
                'findings': results
            }
            
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {self.filename}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return False