"""
SandBug Static Analysis Module
Performs comprehensive static analysis on executable files
British English version
"""

import pefile
import math
import re
import hashlib
from typing import Dict, List, Any, Optional
import magic
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
            'suspicious_indicators': [],
            'risk_score': 0
        }
        
    def analyse(self) -> Dict[str, Any]:

       #perform complete static analysis
        try:
            # Read file data
            with open(self.file_path, 'rb') as f:
                self.file_data = f.read()
            
            # Perform analysis steps
            self._analyse_file_info()
            self._analyse_pe_structure()
            self._calculate_entropy()
            self._extract_strings()
            self._detect_suspicious_indicators()
            self._calculate_risk_score()
            
            return self.results
            
        except Exception as e:
            self.results['error'] = str(e)
            return self.results
    
    def _analyse_file_info(self):
        #Extract basic file information
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
        """Analyse PE file structure and headers"""
        try:
            self.pe = pefile.PE(data=self.file_data)
            
            #DOS Header
            dos_header = {
                'e_magic': hex(self.pe.DOS_HEADER.e_magic),
                'e_lfanew': hex(self.pe.DOS_HEADER.e_lfanew)
            }
            
            #NT Headers
            nt_headers = {
                'signature': hex(self.pe.NT_HEADERS.Signature),
                'machine': hex(self.pe.FILE_HEADER.Machine),
                'number_of_sections': self.pe.FILE_HEADER.NumberOfSections,
                'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
                'characteristics': hex(self.pe.FILE_HEADER.Characteristics)
            }
            
            #optional Header
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
            
            #analyse sections
            self._analyse_sections()
            
            #analyse imports
            self._analyse_imports()
            
            #analyse exports
            self._analyse_exports()
            
        except Exception as e:
            self.results['pe_headers']['error'] = str(e)
    
    def _analyse_sections(self):
        #analyse PE sections
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
                
                #check for suspicious characteristics
                if section_data['entropy'] > 7.0:
                    section_data['suspicious'] = 'High entropy (possible packed/encrypted)'
                
                if section.SizeOfRawData == 0:
                    section_data['suspicious'] = 'Zero raw size'
                
                self.results['sections'].append(section_data)
                
        except Exception as e:
            self.results['sections'].append({'error': str(e)})
    
    def _calculate_section_entropy(self, section) -> float:
        #calculate entropy for a given section
        try:
            data = section.get_data()
            if not data:
                return 0.0
            
            #calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            #calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count == 0:
                    continue
                probability = float(count) / data_len
                entropy -= probability * math.log2(probability)
            
            return round(entropy, 2)
            
        except Exception:
            return 0.0
    
    def _analyse_imports(self):
        #extract imported DLLs and functions
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
                        'functions': functions[:50]  # Limit to first 50 functions
                    })
        except Exception as e:
            self.results['imports'].append({'error': str(e)})
    
    def _analyse_exports(self):
        #extract exported functions
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
            pass  #many executables don't have exports
    
    def _calculate_entropy(self):
        #calculate overall file entropy
        try:
            if not self.file_data:
                return
            
            #calculate byte frequency
            byte_counts = [0] * 256
            for byte in self.file_data:
                byte_counts[byte] += 1
            
            #calculate entropy
            entropy = 0.0
            data_len = len(self.file_data)
            
            for count in byte_counts:
                if count == 0:
                    continue
                probability = float(count) / data_len
                entropy -= probability * math.log2(probability)
            
            self.results['entropy'] = {
                'overall': round(entropy, 2),
                'interpretation': self._interpret_entropy(entropy)
            }
            
        except Exception as e:
            self.results['entropy']['error'] = str(e)
    
    def _interpret_entropy(self, entropy: float) -> str:
        #interpret entropy value
        if entropy < 4.0:
            return "Low (likely not packed)"
        elif entropy < 6.0:
            return "Medium (normal executable)"
        elif entropy < 7.5:
            return "High (possibly compressed)"
        else:
            return "Very High (likely packed/encrypted)"
    
    def _extract_strings(self, min_length: int = 4, max_strings: int = 500):
        """
        Extract ASCII and Unicode strings from file
        
        Args:
            min_length: Minimum string length to extract
            max_strings: Maximum number of strings to store
        """
        try:
            # ASCII strings pattern
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            ascii_strings = re.findall(ascii_pattern, self.file_data)
            
            # Decode and store ASCII strings
            for s in ascii_strings[:max_strings]:
                decoded = s.decode('ascii', errors='ignore')
                if decoded and len(decoded) >= min_length:
                    self.results['strings']['ascii'].append(decoded)
            
            # Unicode strings pattern (UTF-16 LE)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            unicode_strings = re.findall(unicode_pattern, self.file_data)
            
            # Decode and store Unicode strings
            for s in unicode_strings[:max_strings]:
                try:
                    decoded = s.decode('utf-16-le', errors='ignore')
                    if decoded and len(decoded) >= min_length:
                        self.results['strings']['unicode'].append(decoded)
                except:
                    continue
            
            # Limit total strings stored
            self.results['strings']['ascii'] = self.results['strings']['ascii'][:max_strings]
            self.results['strings']['unicode'] = self.results['strings']['unicode'][:max_strings]
            
        except Exception as e:
            self.results['strings']['error'] = str(e)
    
    def _detect_suspicious_indicators(self):
        #detect suspicious indicators in the file
        indicators = []
        
        # Check for suspicious imports
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress',
            'WinExec', 'ShellExecute', 'RegSetValue', 'RegCreateKey',
            'InternetOpen', 'InternetConnect', 'HttpSendRequest',
            'CryptEncrypt', 'CryptDecrypt'
        ]
        
        for import_entry in self.results['imports']:
            for func in import_entry.get('functions', []):
                if any(api in func for api in suspicious_apis):
                    indicators.append(f"Suspicious API: {func} from {import_entry['dll']}")
        
        # Check for high entropy sections
        for section in self.results['sections']:
            if section.get('entropy', 0) > 7.0:
                indicators.append(f"High entropy section: {section['name']} (entropy: {section['entropy']})")
        
        # Check for suspicious strings
        suspicious_strings = [
            'cmd.exe', 'powershell', 'regedit', 'netsh',
            'taskkill', 'schtasks', 'vssadmin', 'bcdedit',
            'http://', 'https://', '.dll', '.exe'
        ]
        
        all_strings = self.results['strings']['ascii'] + self.results['strings']['unicode']
        for string in all_strings:
            string_lower = string.lower()
            for suspicious in suspicious_strings:
                if suspicious in string_lower:
                    indicators.append(f"Suspicious string: {string[:100]}")
                    break
        
        # Remove duplicates and limit
        self.results['suspicious_indicators'] = list(set(indicators))[:50]
    
    def _calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # High entropy adds risk
        overall_entropy = self.results['entropy'].get('overall', 0)
        if overall_entropy > 7.5:
            score += 30
        elif overall_entropy > 7.0:
            score += 20
        elif overall_entropy > 6.0:
            score += 10
        
        # Suspicious indicators add risk
        indicator_count = len(self.results['suspicious_indicators'])
        score += min(indicator_count * 2, 40)
        
        # High number of imports can indicate complexity
        import_count = len(self.results['imports'])
        if import_count > 20:
            score += 10
        
        # Packed sections add risk
        packed_sections = sum(1 for s in self.results['sections'] if s.get('entropy', 0) > 7.0)
        score += packed_sections * 5
        
        # Cap at 100
        self.results['risk_score'] = min(score, 100)


def analyse_file(file_path: str) -> Dict[str, Any]:
    analyser = StaticAnalyser(file_path)
    return analyser.analyse()