#!/usr/bin/env python3
"""
Generate a comprehensive PDF report for CYBER-SCAN project
Requires: pip install reportlab
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime

def create_pdf_report(filename="CYBER-SCAN_Report.pdf"):
    """Generate comprehensive CYBER-SCAN project report"""
    
    # Create PDF
    doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=colors.HexColor('#00FF41'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#00FF41'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=11,
        alignment=TA_JUSTIFY,
        spaceAfter=8
    )
    
    # Title
    story.append(Paragraph("🔐 CYBER-SCAN", title_style))
    story.append(Paragraph("Advanced AI-Powered Cybersecurity Platform", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    # Report Metadata
    metadata = [
        ['Report Generated:', datetime.now().strftime('%B %d, %Y')],
        ['Repository:', 'sahilbagde6/CYBER-SCAN'],
        ['License:', 'MIT License'],
        ['Status:', 'Active & Public'],
    ]
    
    metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a1a')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Overview Section
    story.append(Paragraph("📋 Project Overview", heading_style))
    overview_text = """
    CYBER-SCAN (SECURITRY v2) is an advanced AI-powered cybersecurity platform designed for security 
    professionals and ethical hackers to perform comprehensive security reconnaissance, threat detection, 
    vulnerability analysis, and intelligent reporting. The platform integrates attack simulation capabilities 
    with real-time threat detection to help users understand, defend, and learn modern security practices.
    """
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Technology Stack
    story.append(Paragraph("💻 Technology Stack", heading_style))
    
    tech_data = [
        ['Component', 'Technology'],
        ['Backend Framework', 'Python + Flask'],
        ['Frontend Framework', 'React.js with JavaScript'],
        ['Database', 'SQLite / SQL Server'],
        ['UI Theme', 'Cyberpunk with Animated Neon Grid'],
        ['Authentication', 'Flask-Login + PBKDF2-SHA256'],
        ['API Rate Limiting', 'Flask-Limiter'],
    ]
    
    tech_table = Table(tech_data, colWidths=[2.5*inch, 3.5*inch])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00FF41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9f9f9')]),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Language Composition
    story.append(Paragraph("📊 Language Composition", heading_style))
    
    lang_data = [
        ['Language', 'Bytes', 'Percentage'],
        ['Python', '49,509 bytes', '51.3%'],
        ['CSS', '25,241 bytes', '26.1%'],
        ['JavaScript', '16,060 bytes', '16.6%'],
        ['HTML', '17,634 bytes', '18.2%'],
    ]
    
    lang_table = Table(lang_data, colWidths=[2*inch, 2*inch, 2*inch])
    lang_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00FF41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(lang_table)
    story.append(Spacer(1, 0.2*inch))
    
    story.append(PageBreak())
    
    # Core Features
    story.append(Paragraph("✨ Core Security Scanners & Features", heading_style))
    
    features_text = """
    <b>1. IP Lookup & DNS Resolution</b><br/>
    Performs DNS resolution and gathers IP information for reconnaissance.<br/><br/>
    
    <b>2. Port Scanning</b><br/>
    Threaded TCP port enumeration to identify open services and potential vulnerabilities.<br/><br/>
    
    <b>3. HTTP Security Headers Analysis</b><br/>
    Detects and analyzes HTTP security headers for compliance and best practices.<br/><br/>
    
    <b>4. Technology Fingerprinting</b><br/>
    Identifies the web technology stack including frameworks, libraries, and platforms.<br/><br/>
    
    <b>5. Subdomain Enumeration</b><br/>
    DNS wordlist brute-force to discover all subdomains of a target domain.<br/><br/>
    
    <b>6. Directory Discovery</b><br/>
    HTTP path enumeration to find hidden directories and endpoints.<br/>
    """
    story.append(Paragraph(features_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Version 2 Enhancements
    story.append(Paragraph("🚀 Version 2 Major Enhancements", heading_style))
    
    enhancements = [
        ['Category', 'Implementation'],
        ['Security', 'PBKDF2-SHA256 hashing, CSRF protection, security headers, SSRF guard'],
        ['Authentication', 'Full login/signup/logout with session management'],
        ['Configuration', 'Environment-based config (Dev/Prod/Testing) via dotenv'],
        ['API', 'RESTful endpoints: /api/scan, /api/history, /api/export'],
        ['Database', 'SQLite with User & Scan tables'],
        ['Logging', 'Rotating file logger + console output'],
        ['Export', 'PDF and JSON report generation'],
        ['Frontend', 'Animated neon grid, shimmer effects, stat pills'],
    ]
    
    enh_table = Table(enhancements, colWidths=[1.8*inch, 4.2*inch])
    enh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00FF41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(enh_table)
    story.append(Spacer(1, 0.2*inch))
    
    story.append(PageBreak())
    
    # API Reference
    story.append(Paragraph("🔌 API Reference", heading_style))
    
    api_endpoints = [
        ['Endpoint', 'Method', 'Purpose'],
        ['/api/scan', 'POST', 'Execute security scan (rate: 12/min)'],
        ['/api/history', 'GET', 'Retrieve user scan history'],
        ['/api/export/<id>/json', 'GET', 'Export scan as JSON'],
        ['/api/export/<id>/pdf', 'GET', 'Export scan as formatted PDF'],
        ['/auth/api/login', 'POST', 'User authentication (rate: 10/min)'],
        ['/auth/api/signup', 'POST', 'User registration (rate: 5/min)'],
    ]
    
    api_table = Table(api_endpoints, colWidths=[2*inch, 1*inch, 3*inch])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00FF41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
    ]))
    story.append(api_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Security Features
    story.append(Paragraph("🔒 Security Implementation", heading_style))
    
    security_text = """
    <b>Password Security:</b> PBKDF2-SHA256 hashing via werkzeug ensures passwords are never stored in plaintext.<br/><br/>
    
    <b>Session Management:</b> HttpOnly, SameSite=Lax cookies with Secure flag in production environments.<br/><br/>
    
    <b>SSRF Protection:</b> Blocks private and reserved IP addresses to prevent internal network scanning.<br/><br/>
    
    <b>CSRF Protection:</b> Enabled on all forms and API endpoints to prevent cross-site request forgery.<br/><br/>
    
    <b>Rate Limiting:</b> 12 scans/minute, 10 logins/minute, 5 signups/minute per IP address.<br/><br/>
    
    <b>Security Headers:</b> X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy added to all responses.<br/><br/>
    
    <b>Input Validation:</b> Comprehensive URL, email, and password validators prevent malicious input.
    """
    story.append(Paragraph(security_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    story.append(PageBreak())
    
    # Project Statistics
    story.append(Paragraph("📈 Project Statistics", heading_style))
    
    stats = [
        ['Metric', 'Value'],
        ['Repository Owner', 'Sahil Bagde'],
        ['Created Date', 'March 31, 2026'],
        ['Stars', '1'],
        ['Forks', '0'],
        ['Open Issues', '0'],
        ['License', 'MIT'],
        ['Repository Size', '49 KB'],
        ['Visibility', 'Public'],
        ['Primary Language', 'Python'],
    ]
    
    stats_table = Table(stats, colWidths=[2.5*inch, 3.5*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00FF41')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Quick Start
    story.append(Paragraph("🚀 Quick Start Guide", heading_style))
    
    quickstart_text = """
    <b>1. Setup Virtual Environment</b><br/>
    python -m venv venv<br/>
    source venv/bin/activate  (Windows: venv\\Scripts\\activate)<br/><br/>
    
    <b>2. Install Dependencies</b><br/>
    pip install -r requirements.txt<br/><br/>
    
    <b>3. Configure Environment</b><br/>
    cp .env.example .env<br/>
    # Edit .env and set a strong SECRET_KEY<br/><br/>
    
    <b>4. Run the Application</b><br/>
    python run.py<br/>
    # Access at http://127.0.0.1:5000
    """
    story.append(Paragraph(quickstart_text, body_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Important Notice
    story.append(Paragraph("⚠️ Important Legal Notice", heading_style))
    
    legal_text = """
    <b>FOR AUTHORIZED USE ONLY.</b> This security reconnaissance toolkit should only be used to scan 
    systems you own or have explicit written permission to test. Unauthorized scanning of computer systems 
    may violate local, state, and federal laws. The author assumes no responsibility for misuse or damage 
    caused by this tool. Always conduct security testing within ethical and legal boundaries.
    """
    story.append(Paragraph(legal_text, body_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Author Information
    story.append(Paragraph("👨‍💻 About the Author", heading_style))
    
    author_text = """
    <b>Sahil Bagde</b><br/>
    Cybersecurity | AI Enthusiast | Ethical Hacker<br/><br/>
    
    Passionate about building intelligent security systems that can simulate, detect, and analyze modern 
    cyber threats. Dedicated to advancing cybersecurity practices through innovative tools and education.<br/><br/>
    
    GitHub: https://github.com/sahilbagde6<br/>
    Repository: https://github.com/sahilbagde6/CYBER-SCAN
    """
    story.append(Paragraph(author_text, body_style))
    
    # Footer
    story.append(Spacer(1, 0.4*inch))
    footer_text = f"Report Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')} | CYBER-SCAN © 2026"
    story.append(Paragraph(footer_text, styles['Normal']))
    
    # Build PDF
    doc.build(story)
    print(f"✅ PDF Report generated successfully: {filename}")

if __name__ == "__main__":
    create_pdf_report()
