import pefile
import math
import re
import hashlib
from collections import Counter
from typing import Dict, List, Any, Optional
import magic
from app.services.yara.yara_engine import scan_file
from pathlib import Path


class StaticAnalyser:

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_data = None
        self.pe = None
        self.results = {
            'file_info': {},
            'pe_headers': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'entropy': {},
            'strings': {
                'ascii': [],
                'unicode': []
            },
            'yara': {
                'matched': False,
                'rules': []
            },
            'suspicious_indicators': [],
            'risk_score': 0
        }

    def analyse(self) -> Dict[str, Any]:
        try:
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()

            self._analyse_file_info()
            self._analyse_pe_structure()
            self._calculate_entropy()
            self._extract_strings()
            self._detect_suspicious_indicators()
            self._run_yara_scan()
            self._check_digital_signature()
            self._calculate_risk_score()
            return self.results

        except Exception as e:
            self.results["error"] = str(e)
            return self.results

    def _analyse_file_info(self):
        try:
            file_magic = magic.from_file(str(self.file_path))

            self.results['file_info'] = {
                'filename': self.file_path.name,
                'size': len(self.file_data),
                'md5': hashlib.md5(self.file_data).hexdigest(),
                'sha1': hashlib.sha1(self.file_data).hexdigest(),
                'sha256': hashlib.sha256(self.file_data).hexdigest(),
                'file_type': file_magic
            }
        except Exception as e:
            self.results['file_info']['error'] = str(e)

    def _analyse_pe_structure(self):
        try:
            self.pe = pefile.PE(data=self.file_data, fast_load=True)
            self.pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
            ])

            dos_header = {
                'e_magic': hex(self.pe.DOS_HEADER.e_magic),
                'e_lfanew': hex(self.pe.DOS_HEADER.e_lfanew)
            }

            nt_headers = {
                'signature': hex(self.pe.NT_HEADERS.Signature),
                'machine': hex(self.pe.FILE_HEADER.Machine),
                'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
                'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
                'characteristics': hex(self.pe.FILE_HEADER.Characteristics)
            }

            optional_header = {
                'magic': hex(self.pe.OPTIONAL_HEADER.Magic),
                'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
                'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'subsystem': self.pe.OPTIONAL_HEADER.Subsystem,
                'dll_characteristics': hex(self.pe.OPTIONAL_HEADER.DllCharacteristics)
            }

            self.results['pe_headers'] = {
                'dos_header': dos_header,
                'nt_headers': nt_headers,
                'optional_header': optional_header
            }

            self._analyse_sections()
            self._analyse_imports()
            self._analyse_exports()

        except Exception as e:
            self.results['pe_headers']['error'] = str(e)

    def _analyse_sections(self):
        try:
            for section in self.pe.sections:
                section_data = {
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics),
                    'entropy': self._calculate_section_entropy(section)
                }

                if section_data['entropy'] > 7.0:
                    section_data['suspicious'] = 'High entropy (possible packed/encrypted)'

                if section.SizeOfRawData == 0:
                    section_data['suspicious'] = 'Zero raw size'

                self.results['sections'].append(section_data)

        except Exception as e:
            self.results['sections'].append({'error': str(e)})

    def _calculate_section_entropy(self, section) -> float:
        try:
            data = section.get_data()
            if not data:
                return 0.0
            return round(self._entropy_of(data), 2)
        except Exception:
            return 0.0

    def _analyse_imports(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []

                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            functions.append(func_name)

                    self.results['imports'].append({
                        'dll': dll_name,
                        'functions': functions[:50]
                    })
        except Exception as e:
            self.results['imports'].append({'error': str(e)})

    def _analyse_exports(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode('utf-8', errors='ignore')
                        self.results['exports'].append({
                            'name': export_name,
                            'address': hex(exp.address)
                        })
        except Exception:
            pass

    def _entropy_of(self, data: bytes) -> float:
        if not data:
            return 0.0
        data_len = len(data)
        entropy = 0.0
        for count in Counter(data).values():
            p = count / data_len
            entropy -= p * math.log2(p)
        return entropy

    def _calculate_entropy(self):
        try:
            if not self.file_data:
                return
            entropy = self._entropy_of(self.file_data)
            self.results['entropy'] = {
                'overall': round(entropy, 2),
                'interpretation': self._interpret_entropy(entropy)
            }
        except Exception as e:
            self.results['entropy']['error'] = str(e)

    def _interpret_entropy(self, entropy: float) -> str:
        if entropy < 4.0:
            return "Low (likely not packed)"
        elif entropy < 6.0:
            return "Medium (normal executable)"
        elif entropy < 7.5:
            return "High (possibly compressed)"
        else:
            return "Very High (likely packed/encrypted)"

    def _extract_strings(self, min_length: int = 4, max_strings: int = 500):
        try:
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, self.file_data)
            for s in ascii_strings[:max_strings]:
                decoded = s.decode('ascii', errors='ignore')
                if decoded and len(decoded) >= min_length:
                    self.results['strings']['ascii'].append(decoded)

            # UTF-16 LE
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, self.file_data)
            for s in unicode_strings[:max_strings]:
                try:
                    decoded = s.decode('utf-16-le', errors='ignore')
                    if decoded and len(decoded) >= min_length:
                        self.results['strings']['unicode'].append(decoded)
                except:
                    continue

            self.results['strings']['ascii'] = self.results['strings']['ascii'][:max_strings]
            self.results['strings']['unicode'] = self.results['strings']['unicode'][:max_strings]

        except Exception as e:
            self.results['strings']['error'] = str(e)

    def _check_digital_signature(self):
        """
        Verify Authenticode signature via PowerShell.
        HashMismatch/NotTrusted is itself a risk signal and raises the score.
        """
        import subprocess
        sig = {'status': 'NotSigned', 'valid': False, 'publisher': None}
        try:
            path = str(self.file_path)
            ps_cmd = (
                f'$s = Get-AuthenticodeSignature -LiteralPath "{path}"; '
                f'"$($s.Status)|$($s.SignerCertificate.Subject)"'
            )
            out = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if out.returncode == 0 and out.stdout.strip():
                parts = out.stdout.strip().split('|', 1)
                status  = parts[0].strip()
                subject = parts[1].strip() if len(parts) > 1 else ''
                sig['status'] = status
                sig['valid']  = (status == 'Valid')
                for field in subject.split(','):
                    f = field.strip()
                    if f.upper().startswith('CN='):
                        sig['publisher'] = f[3:].strip('"').strip()
                        break
        except Exception:
            pass
        self.results['signature'] = sig

    def _run_yara_scan(self):
        try:
            matches = scan_file(str(self.file_path))
            print("DEBUG YARA MATCHES:", matches)

            self.results['yara'] = {
                'matched': len(matches) > 0,
                'rules': matches
            }

            for match in matches:
                self.results['suspicious_indicators'].append(
                    f"YARA match: {match.get('rule')} "
                    f"({match.get('meta', {}).get('severity', 'low')})"
                )

        except Exception as e:
            self.results['yara']['error'] = str(e)

    def _detect_suspicious_indicators(self):
        """
        Detects high-signal suspicious behaviours.
        Avoids noisy patterns that fire on almost every legitimate file.
        """
        indicators = []

        INJECTION_APIS = {
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'CreateRemoteThreadEx', 'NtUnmapViewOfSection', 'QueueUserAPC',
            'SetThreadContext', 'RtlCreateUserThread',
        }

        SHELL_APIS = {
            'WinExec',
        }

        DOWNLOAD_APIS = {
            'URLDownloadToFileA', 'URLDownloadToFileW',
            'InternetReadFile', 'HttpSendRequestA', 'HttpSendRequestW',
            'WinHttpSendRequest',
        }

        for import_entry in self.results['imports']:
            dll = import_entry.get('dll', '')
            for func in import_entry.get('functions', []):
                fn = func.split('@')[0]
                if fn in INJECTION_APIS:
                    indicators.append(f"Process injection API: {fn} ({dll})")
                elif fn in SHELL_APIS:
                    indicators.append(f"Shell execution API: {fn} ({dll})")
                elif fn in DOWNLOAD_APIS:
                    indicators.append(f"Network download API: {fn} ({dll})")

        for section in self.results['sections']:
            if section.get('entropy', 0) >= 7.5:
                indicators.append(
                    f"Packed section: {section['name']} "
                    f"(entropy {section['entropy']:.2f})"
                )

        CMD_PATTERNS = [
            'powershell -e', 'powershell -enc', 'powershell -w hidden',
            'cmd /c ', 'cmd.exe /c', 'cmd /k ',
            'vssadmin delete', 'bcdedit /set', 'wmic process',
            'regsvr32 /s', 'certutil -decode', 'bitsadmin /transfer',
            'mshta ', 'cscript /nologo', 'wscript /e',
            'rundll32 javascript', 'taskkill /f',
        ]
        seen_strings = set()
        all_strings = (self.results['strings'].get('ascii', []) +
                       self.results['strings'].get('unicode', []))
        for s in all_strings:
            sl = s.lower()
            for pat in CMD_PATTERNS:
                if pat in sl and s[:80] not in seen_strings:
                    indicators.append(f"Command execution string: {s[:80]}")
                    seen_strings.add(s[:80])
                    break

        self.results['suspicious_indicators'] = list(dict.fromkeys(indicators))[:50]

    def _calculate_risk_score(self):
        """
        Score 0-100. YARA is the primary signal.
        Clean executables score 0-20; clear malware 65-100.
        Only extreme entropy (>=7.2) is penalised to avoid false positives.
        """
        score = 0

        yara_pts = 0
        for match in self.results.get('yara', {}).get('rules', []):
            sev = match.get('meta', {}).get('severity', 'low')
            if sev == 'high':
                yara_pts += 30
            elif sev == 'medium':
                yara_pts += 15
            else:
                yara_pts += 5
        score += min(yara_pts, 60)

        entropy = self.results['entropy'].get('overall', 0)
        if entropy >= 7.8:
            score += 6
        elif entropy >= 7.5:
            score += 2

        packed = sum(
            1 for s in self.results['sections']
            if s.get('entropy', 0) >= 7.5
        )
        score += min(packed * 3, 6)

        inds = self.results.get('suspicious_indicators', [])
        inj_count   = sum(1 for i in inds if i.startswith('Process injection'))
        shell_count = sum(1 for i in inds if i.startswith('Shell execution'))
        net_count   = sum(1 for i in inds if i.startswith('Network download'))
        api_pts = inj_count * 4 + shell_count * 2 + net_count * 1
        score += min(api_pts, 15)

        cmd_count = sum(1 for i in inds if i.startswith('Command execution'))
        score += min(cmd_count * 3, 5)

        sig_status = self.results.get('signature', {}).get('status', 'NotSigned')
        if sig_status in ('HashMismatch', 'NotTrusted'):
            score += 20

        self.results['risk_score'] = min(score, 100)


def analyse_file(file_path: str) -> Dict[str, Any]:
    analyser = StaticAnalyser(file_path)
    return analyser.analyse()
