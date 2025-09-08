import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import jinja2
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import markdown

class ReportGenerator:
    """DIVYASTRA Report Generation System"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.templates_dir = Path(__file__).parent.parent / 'templates'
        self.templates_dir.mkdir(exist_ok=True)
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.templates_dir))
        )
        self._create_default_templates()

    def _create_default_templates(self):
        """Create default report templates"""
        # Technical Report Template
        technical_template = """# DIVYASTRA Penetration Testing Report

## Executive Summary
Target: {{ data.target }}
Scan Date: {{ data.timestamp | format_date }}
Total Vulnerabilities: {{ data.statistics.vulnerabilities_found }}

### Risk Summary
- Critical: {{ data.statistics.critical }}
- High: {{ data.statistics.high }}
- Medium: {{ data.statistics.medium }}
- Low: {{ data.statistics.low }}

## Reconnaissance Results

### Subdomains Discovered ({{ data.reconnaissance.subdomains|length }})
{% for subdomain in data.reconnaissance.subdomains[:10] %}
- {{ subdomain }}
{% endfor %}

### Open Ports ({{ data.reconnaissance.open_ports|length }})
{% for port in data.reconnaissance.open_ports %}
- {{ port.port }}/{{ port.protocol }} - {{ port.service }}
{% endfor %}

### Technologies Detected ({{ data.reconnaissance.technologies|length }})
{% for tech in data.reconnaissance.technologies %}
- {{ tech.name }} ({{ tech.type }})
{% endfor %}

## Vulnerability Assessment

{% for vuln in data.vulnerabilities[:20] %}
### {{ vuln.id }} - {{ vuln.severity }}
**CVSS Score:** {{ vuln.cvss_score }}
**Published:** {{ vuln.published }}

{{ vuln.description }}

**Affected Systems:**
{% for product in vuln.affected_products %}
- {{ product }}
{% endfor %}

**References:**
{% for ref in vuln.references[:3] %}
- {{ ref }}
{% endfor %}

---
{% endfor %}

## Exploitation Results

{% if data.exploitation_results %}
{% for exploit in data.exploitation_results %}
### {{ exploit.target }} - {{ exploit.exploit_name }}
**Status:** {{ exploit.status }}
**Evidence:** {{ exploit.evidence }}
**Impact:** {{ exploit.impact }}

{% endfor %}
{% endif %}

## Recommendations

### Immediate Actions (Critical/High)
1. Patch all critical vulnerabilities identified
2. Review and harden exposed services
3. Implement network segmentation
4. Enable logging and monitoring

### Medium Term Actions
1. Regular vulnerability assessments
2. Security awareness training
3. Incident response planning
4. Backup and recovery procedures

## Appendix

### Scan Configuration
- Aggression Level: {{ data.scan_config.aggression }}
- Scope: {{ data.scan_config.scope }}
- Duration: {{ data.scan_config.duration }}

### Tools Used
- DIVYASTRA v{{ data.version }}
- Vulnerability Feeds: {{ data.feeds_used|join(', ') }}
"""

        executive_template = """# EXECUTIVE SUMMARY
## Penetration Testing Assessment

**Organization:** {{ data.organization | default('Target Organization') }}
**Assessment Date:** {{ data.timestamp | format_date }}
**Assessor:** DIVYASTRA AI Pentesting Suite

### Overview
This report presents the findings of an automated penetration testing assessment conducted against {{ data.target }}. The assessment identified {{ data.statistics.vulnerabilities_found }} security vulnerabilities across the target infrastructure.

### Risk Rating Summary
| Risk Level | Count | Percentage |
|------------|-------|------------|
| Critical   | {{ data.statistics.critical }} | {{ (data.statistics.critical / data.statistics.vulnerabilities_found * 100) | round(1) }}% |
| High       | {{ data.statistics.high }} | {{ (data.statistics.high / data.statistics.vulnerabilities_found * 100) | round(1) }}% |
| Medium     | {{ data.statistics.medium }} | {{ (data.statistics.medium / data.statistics.vulnerabilities_found * 100) | round(1) }}% |
| Low        | {{ data.statistics.low }} | {{ (data.statistics.low / data.statistics.vulnerabilities_found * 100) | round(1) }}% |

### Key Findings
{% set critical_high = data.statistics.critical + data.statistics.high %}
{% if critical_high > 0 %}
- **{{ critical_high }} critical/high-risk vulnerabilities** require immediate attention
- **{{ data.statistics.medium }} medium-risk vulnerabilities** should be addressed in the next 30 days
- **{{ data.reconnaissance.open_ports|length }} open services** were identified and analyzed
{% endif %}

### Business Impact
{% if data.statistics.critical > 0 %}
**CRITICAL RISK:** {{ data.statistics.critical }} critical vulnerabilities pose immediate threat to business operations
{% elif data.statistics.high > 0 %}
**HIGH RISK:** {{ data.statistics.high }} high-risk vulnerabilities could lead to data breach or service disruption
{% else %}
**MODERATE RISK:** No critical vulnerabilities identified, but {{ data.statistics.medium + data.statistics.low }} issues require attention
{% endif %}

### Recommended Actions
1. **Immediate (0-7 days):** Address all critical vulnerabilities
2. **Short-term (7-30 days):** Remediate high-risk vulnerabilities
3. **Medium-term (30-90 days):** Address medium-risk vulnerabilities and implement security improvements
4. **Ongoing:** Establish regular security assessments and monitoring

### Compliance Impact
{% for framework in data.compliance_frameworks %}
- **{{ framework.upper() }} Compliance:** {{ framework }} requirements may be impacted by identified vulnerabilities
{% endfor %}

**Report prepared by:** DIVYASTRA AI Pentesting Suite v{{ data.version }}
**Contact:** security-team@organization.com
"""

        compliance_template = """# COMPLIANCE ASSESSMENT REPORT

## Regulatory Compliance Analysis

**Target:** {{ data.target }}
**Assessment Date:** {{ data.timestamp | format_date }}
**Frameworks Assessed:** {{ data.compliance_frameworks | join(', ') | upper }}

## Compliance Summary

{% for framework in data.compliance_frameworks %}
### {{ framework.upper() }} Compliance Status

#### Control Assessment
{% if framework == 'nist' %}
- **AC (Access Control):** {{ data.compliance_results.nist.access_control.status }}
- **AU (Audit and Accountability):** {{ data.compliance_results.nist.audit.status }}
- **CM (Configuration Management):** {{ data.compliance_results.nist.config_mgmt.status }}
- **IA (Identification and Authentication):** {{ data.compliance_results.nist.identity_auth.status }}
- **SC (System and Communications Protection):** {{ data.compliance_results.nist.system_comms.status }}
- **SI (System and Information Integrity):** {{ data.compliance_results.nist.system_integrity.status }}
{% endif %}

#### Findings Impact
{% for vuln in data.vulnerabilities %}
{% if vuln.compliance_impact and framework in vuln.compliance_impact %}
- **{{ vuln.id }}:** Impacts {{ vuln.compliance_impact[framework] | join(', ') }}
{% endif %}
{% endfor %}

{% endfor %}

## Audit Trail
All assessment activities have been logged in compliance with audit requirements:
- Scan initiated: {{ data.audit_log.scan_start }}
- Tools used: {{ data.tools_used | join(', ') }}
- No destructive testing performed
- All activities within approved scope

## Remediation Recommendations
{% for framework in data.compliance_frameworks %}
### {{ framework.upper() }} Specific Actions
1. Implement missing security controls
2. Address identified vulnerabilities
3. Update security policies and procedures
4. Conduct regular compliance assessments
{% endfor %}
"""

        # Save templates
        templates = {
            'technical.md': technical_template,
            'executive.md': executive_template,
            'compliance.md': compliance_template
        }
        
        for filename, content in templates.items():
            template_path = self.templates_dir / filename
            if not template_path.exists():
                with open(template_path, 'w') as f:
                    f.write(content)

    def generate_report(self, 
                       data: Dict[str, Any], 
                       format_type: str = 'pdf', 
                       template: str = 'technical',
                       output_path: Optional[str] = None) -> str:
        """Generate comprehensive report"""
        
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"divyastra_report_{data.get('target', 'unknown')}_{timestamp}.{format_type}"
        
        # Prepare data for templating
        report_data = self._prepare_report_data(data)
        
        if format_type.lower() == 'pdf':
            return self._generate_pdf_report(report_data, template, output_path)
        elif format_type.lower() == 'markdown':
            return self._generate_markdown_report(report_data, template, output_path)
        elif format_type.lower() == 'html':
            return self._generate_html_report(report_data, template, output_path)
        elif format_type.lower() == 'json':
            return self._generate_json_report(report_data, output_path)
        elif format_type.lower() == 'sarif':
            return self._generate_sarif_report(report_data, output_path)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")

    def _prepare_report_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare and enrich data for report generation"""
        
        # Add custom filters for Jinja2
        def format_date(timestamp):
            if isinstance(timestamp, int):
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
            return timestamp

        self.jinja_env.filters['format_date'] = format_date
        
        # Enrich data with additional context
        enriched_data = data.copy()
        enriched_data.update({
            'version': '1.0.0',
            'generation_time': datetime.now().isoformat(),
            'compliance_frameworks': self.config.get('reporting', {}).get('compliance_frameworks', ['nist', 'owasp']),
            'organization': self.config.get('reporting', {}).get('organization', 'Target Organization')
        })
        
        return enriched_data

    def _generate_markdown_report(self, data: Dict[str, Any], template: str, output_path: str) -> str:
        """Generate Markdown report"""
        template_file = f"{template}.md"
        
        try:
            template_obj = self.jinja_env.get_template(template_file)
            markdown_content = template_obj.render(data=data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
                
            return output_path
            
        except jinja2.TemplateNotFound:
            raise FileNotFoundError(f"Template {template_file} not found")

    def _generate_html_report(self, data: Dict[str, Any], template: str, output_path: str) -> str:
        """Generate HTML report from Markdown"""
        # First generate markdown
        md_path = output_path.replace('.html', '.md')
        self._generate_markdown_report(data, template, md_path)
        
        # Convert to HTML
        with open(md_path, 'r', encoding='utf-8') as f:
            markdown_content = f.read()
        
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
        
        # Wrap in HTML document
        full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DIVYASTRA Penetration Testing Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_html)
        
        # Clean up temporary markdown file
        os.remove(md_path)
        
        return output_path

    def _generate_pdf_report(self, data: Dict[str, Any], template: str, output_path: str) -> str:
        """Generate PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        # Title
        elements.append(Paragraph("DIVYASTRA Penetration Testing Report", title_style))
        elements.append(Spacer(1, 20))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(f"Target: {data.get('target', 'N/A')}", styles['Normal']))
        elements.append(Paragraph(f"Scan Date: {datetime.fromtimestamp(data.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 12))
        
        # Vulnerability Statistics Table
        if 'statistics' in data:
            stats = data['statistics']
            vuln_data = [
                ['Risk Level', 'Count'],
                ['Critical', str(stats.get('critical', 0))],
                ['High', str(stats.get('high', 0))],
                ['Medium', str(stats.get('medium', 0))],
                ['Low', str(stats.get('low', 0))],
                ['Total', str(stats.get('vulnerabilities_found', 0))]
            ]
            
            vuln_table = Table(vuln_data, colWidths=[2*inch, 1*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(vuln_table)
            elements.append(Spacer(1, 20))
        
        # Top Vulnerabilities
        if 'vulnerabilities' in data and data['vulnerabilities']:
            elements.append(Paragraph("Top Vulnerabilities", heading_style))
            
            for i, vuln in enumerate(data['vulnerabilities'][:10], 1):
                elements.append(Paragraph(f"{i}. {vuln.get('id', 'N/A')} - {vuln.get('severity', 'Unknown')}", styles['Heading3']))
                elements.append(Paragraph(f"CVSS Score: {vuln.get('cvss_score', 0.0)}", styles['Normal']))
                
                # Truncate description for PDF
                description = vuln.get('description', 'No description available')
                if len(description) > 500:
                    description = description[:500] + "..."
                elements.append(Paragraph(description, styles['Normal']))
                elements.append(Spacer(1, 10))
        
        # Build PDF
        doc.build(elements)
        return output_path

    def _generate_json_report(self, data: Dict[str, Any], output_path: str) -> str:
        """Generate JSON report"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return output_path

    def _generate_sarif_report(self, data: Dict[str, Any], output_path: str) -> str:
        """Generate SARIF (Static Analysis Results Interchange Format) report"""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DIVYASTRA",
                            "version": data.get('version', '1.0.0'),
                            "informationUri": "https://github.com/divyastra/divyastra"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Convert vulnerabilities to SARIF format
        for vuln in data.get('vulnerabilities', []):
            sarif_result = {
                "ruleId": vuln.get('id', ''),
                "message": {
                    "text": vuln.get('description', 'No description available')
                },
                "level": self._map_severity_to_sarif(vuln.get('severity', 'info')),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": data.get('target', 'unknown')
                            }
                        }
                    }
                ],
                "properties": {
                    "cvss_score": vuln.get('cvss_score', 0.0),
                    "published": vuln.get('published', ''),
                    "source": vuln.get('source', ''),
                    "references": vuln.get('references', [])
                }
            }
            sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
        
        return output_path

    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map vulnerability severity to SARIF levels"""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note'
        }
        return mapping.get(severity.upper(), 'note')

    def generate_dashboard_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data for web dashboard"""
        return {
            'summary': {
                'target': data.get('target', ''),
                'scan_date': data.get('timestamp', 0),
                'total_vulnerabilities': data.get('statistics', {}).get('vulnerabilities_found', 0),
                'risk_distribution': {
                    'critical': data.get('statistics', {}).get('critical', 0),
                    'high': data.get('statistics', {}).get('high', 0),
                    'medium': data.get('statistics', {}).get('medium', 0),
                    'low': data.get('statistics', {}).get('low', 0)
                }
            },
            'reconnaissance': {
                'subdomains_found': len(data.get('reconnaissance', {}).get('subdomains', [])),
                'ports_open': len(data.get('reconnaissance', {}).get('open_ports', [])),
                'technologies': data.get('reconnaissance', {}).get('technologies', [])
            },
            'top_vulnerabilities': data.get('vulnerabilities', [])[:10],
            'timeline': {
                'scan_start': data.get('scan_start', 0),
                'scan_end': data.get('scan_end', 0),
                'duration': data.get('scan_duration', 0)
            }
        }
