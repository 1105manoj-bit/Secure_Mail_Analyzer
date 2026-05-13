"""
Email Parser
Extract headers, body, attachments, and metadata from email files (.eml)
"""

import email
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, List, Optional
import re
import base64
from datetime import datetime


# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh',
    '.msi', '.msp', '.com', '.pif', '.dll', '.reg', '.hta', '.cpl', '.inf',
    '.lnk', '.ps1', '.psm1', '.vbe', '.jar', '.ade', '.adp', '.bas', '.chm',
    '.crt', '.hlp', '.iso', '.lib', '.mdb', '.mde', '.msc', '.ocx', '.shs',
    '.shb', '.sys', '.vb', '.vxd', '.ws', '.xnk'
}


class EmailParser:
    """Parse and extract data from email files"""

    def __init__(self):
        pass

    def parse_file(self, file_path: str) -> Dict:
        """
        Parse an email file (.eml)

        Args:
            file_path: Path to .eml file

        Returns:
            Dict containing parsed email data
        """
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return self._extract_data(msg)

    def parse_string(self, raw_email: str) -> Dict:
        """
        Parse raw email string

        Args:
            raw_email: Raw email content as string

        Returns:
            Dict containing parsed email data
        """
        msg = Parser(policy=policy.default).parsestr(raw_email)
        return self._extract_data(msg)

    def _extract_data(self, msg) -> Dict:
        """Extract all relevant data from a parsed email message"""
        data = {
            'subject': self._decode_header_value(msg.get('subject', '')),
            'from': self._decode_header_value(msg.get('from', '')),
            'to': self._decode_header_value(msg.get('to', '')),
            'cc': self._decode_header_value(msg.get('cc', '')),
            'reply_to': self._decode_header_value(msg.get('reply-to', '')),
            'date': self._parse_date(msg.get('date', '')),
            'message_id': msg.get('message-id', ''),
            'headers': self._extract_all_headers(msg),
            'body': '',
            'html_body': '',
            'attachments': [],
            'urls': [],
            'ip_addresses': [],
            'email_addresses': [],
            'routing_trace': self._extract_routing(msg),
            'has_dangerous_attachments': False,
            'raw_headers': dict(msg.items()),
        }

        # Extract body
        body_text, body_html = self._extract_body(msg)
        data['body'] = body_text
        data['html_body'] = body_html

        # Extract attachments
        data['attachments'] = self._extract_attachments(msg)
        data['has_dangerous_attachments'] = any(
            att['is_dangerous'] for att in data['attachments']
        )

        # Extract URLs from body and HTML
        full_text = body_text + ' ' + body_html
        data['urls'] = self._extract_urls(full_text)

        # Extract IPs from headers
        data['ip_addresses'] = self._extract_ips(str(data['headers']))

        # Extract email addresses from body
        data['email_addresses'] = self._extract_emails(full_text)

        return data

    def _decode_header_value(self, value: str) -> str:
        """Decode encoded header values"""
        if not value:
            return ''
        try:
            decoded_parts = email.header.decode_header(str(value))
            result = []
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    try:
                        result.append(part.decode(charset or 'utf-8', errors='replace'))
                    except Exception:
                        result.append(part.decode('latin-1', errors='replace'))
                else:
                    result.append(str(part))
            return ' '.join(result)
        except Exception:
            return str(value)

    def _parse_date(self, date_str: str) -> str:
        """Parse and normalize email date"""
        if not date_str:
            return ''
        try:
            parsed = email.utils.parsedate_to_datetime(str(date_str))
            return parsed.isoformat()
        except Exception:
            return str(date_str)

    def _extract_all_headers(self, msg) -> Dict:
        """Extract all email headers as a dictionary"""
        headers = {}
        for key, value in msg.items():
            key_lower = key.lower()
            if key_lower in headers:
                if isinstance(headers[key_lower], list):
                    headers[key_lower].append(str(value))
                else:
                    headers[key_lower] = [headers[key_lower], str(value)]
            else:
                headers[key_lower] = str(value)
        return headers

    def _extract_body(self, msg) -> tuple:
        """Extract plain text and HTML body"""
        text_body = ''
        html_body = ''

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                if 'attachment' in content_disposition:
                    continue

                if content_type == 'text/plain':
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                        if payload:
                            text_body += payload.decode(charset, errors='replace')
                    except Exception:
                        pass

                elif content_type == 'text/html':
                    try:
                        charset = part.get_content_charset() or 'utf-8'
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_body += payload.decode(charset, errors='replace')
                            # Also extract plain text from HTML
                            if not text_body:
                                text_body += self._html_to_text(html_body)
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            try:
                charset = msg.get_content_charset() or 'utf-8'
                payload = msg.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(charset, errors='replace')
                    if content_type == 'text/html':
                        html_body = decoded
                        text_body = self._html_to_text(decoded)
                    else:
                        text_body = decoded
            except Exception:
                pass

        return text_body, html_body

    def _html_to_text(self, html: str) -> str:
        """Simple HTML to text conversion"""
        # Remove scripts and styles
        html = re.sub(r'<(script|style)[^>]*>.*?</(script|style)>', '', html, flags=re.DOTALL | re.IGNORECASE)
        # Replace common block elements with newlines
        html = re.sub(r'<(br|p|div|tr|li)[^>]*>', '\n', html, flags=re.IGNORECASE)
        # Remove all remaining tags
        html = re.sub(r'<[^>]+>', '', html)
        # Decode HTML entities
        html = html.replace('&nbsp;', ' ').replace('&amp;', '&').replace(
            '&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
        # Clean up whitespace
        html = re.sub(r'\n\s*\n', '\n\n', html)
        return html.strip()

    def _extract_attachments(self, msg) -> List[Dict]:
        """Extract attachment information"""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get('Content-Disposition', ''))
                if 'attachment' in content_disposition or 'inline' in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        filename = self._decode_header_value(filename)
                        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                        is_dangerous = ext in DANGEROUS_EXTENSIONS

                        attachment = {
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': 0,
                            'is_dangerous': is_dangerous,
                            'extension': ext,
                            'encoding': part.get('Content-Transfer-Encoding', 'none'),
                        }

                        # Get size
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                attachment['size'] = len(payload)
                        except Exception:
                            pass

                        attachments.append(attachment)

        return attachments

    def _extract_routing(self, msg) -> List[Dict]:
        """Extract routing information from Received headers"""
        routing = []
        received_headers = msg.get_all('received', [])

        for header in received_headers:
            hop = {
                'raw': str(header),
                'from': '',
                'by': '',
                'ip': '',
                'timestamp': '',
            }

            # Extract 'from' server
            from_match = re.search(r'from\s+([\w\.\-]+)', str(header), re.IGNORECASE)
            if from_match:
                hop['from'] = from_match.group(1)

            # Extract 'by' server
            by_match = re.search(r'by\s+([\w\.\-]+)', str(header), re.IGNORECASE)
            if by_match:
                hop['by'] = by_match.group(1)

            # Extract IP
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(header))
            if ip_match:
                hop['ip'] = ip_match.group(1)

            # Extract timestamp
            time_match = re.search(
                r';\s*(.+?)(?:\s*\(|$)',
                str(header),
                re.IGNORECASE
            )
            if time_match:
                hop['timestamp'] = time_match.group(1).strip()

            routing.append(hop)

        return list(reversed(routing))  # Show oldest hop first

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]{3,}'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        # Clean URLs
        clean_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;:!?)\]>]+$', '', url)
            if url and url not in clean_urls:
                clean_urls.append(url)
        return clean_urls[:50]  # Limit

    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = list(set(re.findall(ip_pattern, text)))
        return ips[:20]  # Limit

    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'
        emails = list(set(re.findall(email_pattern, text)))
        return emails[:20]  # Limit


if __name__ == '__main__':
    parser = EmailParser()
    print("EmailParser initialized successfully")
    print(f"Dangerous extensions tracked: {len(DANGEROUS_EXTENSIONS)}")
