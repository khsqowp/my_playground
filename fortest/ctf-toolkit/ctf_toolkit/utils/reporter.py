"""Report generation utilities for CTF Toolkit."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


class Reporter:
    """Generate and save scan reports."""

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize reporter.

        Args:
            output_dir: Directory to save reports (defaults to current directory)
        """
        self.output_dir = Path(output_dir) if output_dir else Path.cwd()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_filename(self, prefix: str = "result", extension: str = "json") -> str:
        """Generate timestamped filename."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{extension}"

    def save_json(
        self,
        data: dict[str, Any],
        filename: Optional[str] = None,
        indent: int = 2
    ) -> Path:
        """
        Save data as JSON file.

        Args:
            data: Data to save
            filename: Output filename (auto-generated if not provided)
            indent: JSON indentation

        Returns:
            Path to saved file
        """
        if filename is None:
            filename = self.generate_filename(extension="json")

        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)

        return filepath

    def save_txt(
        self,
        content: str,
        filename: Optional[str] = None
    ) -> Path:
        """
        Save content as text file.

        Args:
            content: Text content to save
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to saved file
        """
        if filename is None:
            filename = self.generate_filename(extension="txt")

        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return filepath

    def generate_scan_report(
        self,
        target_url: str,
        scan_type: str,
        vulnerabilities: list[dict],
        extracted_data: list[str],
        flags: list[str],
        metadata: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Generate a structured scan report.

        Args:
            target_url: Scanned URL
            scan_type: Type of scan performed
            vulnerabilities: List of found vulnerabilities
            extracted_data: Extracted data
            flags: Found flags
            metadata: Additional metadata

        Returns:
            Report dictionary
        """
        return {
            "report_info": {
                "generated_at": datetime.now().isoformat(),
                "tool": "CTF Toolkit",
                "version": "0.1.0",
            },
            "target": {
                "url": target_url,
                "scan_type": scan_type,
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "total_extracted": len(extracted_data),
                "total_flags": len(flags),
                "vulnerability_types": list(set(v.get("type", "unknown") for v in vulnerabilities)),
            },
            "vulnerabilities": vulnerabilities,
            "extracted_data": extracted_data,
            "flags": flags,
            "metadata": metadata or {},
        }

    def format_txt_report(
        self,
        target_url: str,
        scan_type: str,
        vulnerabilities: list[dict],
        extracted_data: list[str],
        flags: list[str],
    ) -> str:
        """
        Format report as human-readable text.

        Args:
            target_url: Scanned URL
            scan_type: Type of scan
            vulnerabilities: Found vulnerabilities
            extracted_data: Extracted data
            flags: Found flags

        Returns:
            Formatted text report
        """
        lines = [
            "=" * 60,
            "CTF TOOLKIT SCAN REPORT",
            "=" * 60,
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target URL: {target_url}",
            f"Scan Type: {scan_type}",
            "",
            "-" * 60,
            "SUMMARY",
            "-" * 60,
            f"Vulnerabilities Found: {len(vulnerabilities)}",
            f"Data Extracted: {len(extracted_data)} items",
            f"Flags Found: {len(flags)}",
            "",
        ]

        if vulnerabilities:
            lines.extend([
                "-" * 60,
                "VULNERABILITIES",
                "-" * 60,
            ])
            for i, vuln in enumerate(vulnerabilities, 1):
                lines.extend([
                    f"\n[{i}] {vuln.get('type', 'Unknown')}",
                    f"    Parameter: {vuln.get('parameter', 'N/A')}",
                    f"    Payload: {vuln.get('payload', 'N/A')}",
                    f"    Evidence: {vuln.get('evidence', 'N/A')[:100]}",
                    f"    Confidence: {vuln.get('confidence', 'N/A')}",
                ])

        if extracted_data:
            lines.extend([
                "",
                "-" * 60,
                "EXTRACTED DATA",
                "-" * 60,
            ])
            for data in extracted_data:
                lines.append(f"  - {data}")

        if flags:
            lines.extend([
                "",
                "-" * 60,
                "FLAGS FOUND",
                "-" * 60,
            ])
            for flag in flags:
                lines.append(f"  >>> {flag}")

        lines.extend([
            "",
            "=" * 60,
            "END OF REPORT",
            "=" * 60,
        ])

        return "\n".join(lines)

    def save_report(
        self,
        target_url: str,
        scan_type: str,
        vulnerabilities: list[dict],
        extracted_data: list[str],
        flags: list[str],
        output_format: str = "json",
        filename: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Path:
        """
        Generate and save report in specified format.

        Args:
            target_url: Scanned URL
            scan_type: Type of scan
            vulnerabilities: Found vulnerabilities
            extracted_data: Extracted data
            flags: Found flags
            output_format: "json" or "txt"
            filename: Output filename
            metadata: Additional metadata

        Returns:
            Path to saved file
        """
        if output_format == "json":
            report = self.generate_scan_report(
                target_url=target_url,
                scan_type=scan_type,
                vulnerabilities=vulnerabilities,
                extracted_data=extracted_data,
                flags=flags,
                metadata=metadata,
            )
            return self.save_json(report, filename)
        else:
            content = self.format_txt_report(
                target_url=target_url,
                scan_type=scan_type,
                vulnerabilities=vulnerabilities,
                extracted_data=extracted_data,
                flags=flags,
            )
            return self.save_txt(content, filename)
