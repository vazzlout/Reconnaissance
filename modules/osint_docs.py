"""
Document Metadata Intelligence Module - OSINT Phase 2
- Document discovery via search engines
- Metadata extraction from PDF, Office docs, images
- EXIF data extraction
- Stealth integration
"""

import asyncio
import aiohttp
import re
import json
import hashlib
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlencode, quote_plus, urlparse
from collections import defaultdict
import io

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class DocumentMetadata:
    """Document metadata result"""
    url: str
    file_type: str
    file_size: int
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    
    # Common metadata
    title: Optional[str] = None
    author: Optional[str] = None
    subject: Optional[str] = None
    keywords: Optional[str] = None
    creator: Optional[str] = None
    producer: Optional[str] = None
    creation_date: Optional[str] = None
    modification_date: Optional[str] = None
    
    # PDF specific
    pdf_version: Optional[str] = None
    page_count: Optional[int] = None
    encrypted: bool = False
    permissions: Optional[str] = None
    
    # Office specific
    application: Optional[str] = None
    app_version: Optional[str] = None
    last_modified_by: Optional[str] = None
    revision_number: Optional[str] = None
    edit_time: Optional[str] = None
    
    # EXIF specific
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    datetime_original: Optional[str] = None
    gps_latitude: Optional[str] = None
    gps_longitude: Optional[str] = None
    gps_altitude: Optional[str] = None
    software: Optional[str] = None
    
    # Custom metadata
    custom_metadata: Dict[str, str] = field(default_factory=dict)
    
    # Source info
    source_url: str = ""
    source_type: str = ""  # search, crawl, direct
    confidence: int = 50


@dataclass
class DocumentIntelConfig:
    """Configuration for document intelligence"""
    # Search settings
    max_results_per_query: int = 50
    max_pages_per_engine: int = 5
    request_delay: float = 2.0
    
    # File types to search
    file_types: List[str] = field(default_factory=lambda: [
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'odt', 'ods', 'odp', 'rtf', 'txt', 'csv',
        'jpg', 'jpeg', 'png', 'tiff', 'tif', 'bmp', 'gif',
        'svg', 'webp', 'heic'
    ])
    
    # Search engines
    use_google: bool = True
    use_bing: bool = True
    use_duckduckgo: bool = True
    
    # Crawl settings
    crawl_website: bool = True
    max_crawl_pages: int = 100
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    
    # Metadata extraction
    extract_pdf: bool = True
    extract_office: bool = True
    extract_exif: bool = True
    extract_custom: bool = True
    
    # Download settings
    download_files: bool = True
    save_to_disk: bool = False
    output_dir: str = "./documents"
    
    # Filters
    min_file_size: int = 1024  # 1KB
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    keywords: List[str] = field(default_factory=list)
    exclude_keywords: List[str] = field(default_factory=list)


class DocumentIntelligence:
    """Document metadata intelligence gatherer"""
    
    def __init__(self, domain: str, config: DocumentIntelConfig,
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.domain = domain.lower()
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        self.found_documents: List[DocumentMetadata] = []
        self.processed_urls: Set[str] = set()
        self.stats = {
            'total_found': 0,
            'by_type': defaultdict(int),
            'by_source': defaultdict(int),
            'total_size': 0,
            'errors': 0
        }
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            connector = aiohttp.TCPConnector(limit=10)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconTool/1.0 DocumentIntelligence)'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _stealth_get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=60, method='GET', **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=60, **kwargs)
            except Exception:
                return None
    
    def _calculate_hashes(self, content: bytes) -> Dict[str, str]:
        """Calculate file hashes"""
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }
    
    def _extract_pdf_metadata(self, content: bytes) -> Dict[str, Any]:
        """Extract metadata from PDF"""
        metadata = {}
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=content, filetype="pdf")
            
            meta = doc.metadata
            if meta:
                metadata.update({
                    'title': meta.get('title'),
                    'author': meta.get('author'),
                    'subject': meta.get('subject'),
                    'keywords': meta.get('keywords'),
                    'creator': meta.get('creator'),
                    'producer': meta.get('producer'),
                    'creation_date': meta.get('creationDate'),
                    'modification_date': meta.get('modDate'),
                })
            
            metadata['pdf_version'] = f"{doc.pdf_version()}"
            metadata['page_count'] = doc.page_count
            metadata['encrypted'] = doc.is_encrypted
            
            if doc.is_encrypted:
                metadata['permissions'] = "encrypted"
            
            doc.close()
        except ImportError:
            metadata['error'] = 'PyMuPDF not installed'
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_office_metadata(self, content: bytes, file_type: str) -> Dict[str, Any]:
        """Extract metadata from Office documents"""
        metadata = {}
        try:
            if file_type in ['docx', 'xlsx', 'pptx']:
                # Use python-docx, openpyxl, python-pptx
                if file_type == 'docx':
                    import docx
                    doc = docx.Document(io.BytesIO(content))
                    core_props = doc.core_properties
                    metadata.update({
                        'title': core_props.title,
                        'author': core_props.author,
                        'subject': core_props.subject,
                        'keywords': core_props.keywords,
                        'creator': core_props.author,
                        'creation_date': str(core_props.created) if core_props.created else None,
                        'modification_date': str(core_props.modified) if core_props.modified else None,
                        'last_modified_by': core_props.last_modified_by,
                        'revision_number': str(core_props.revision) if core_props.revision else None,
                        'edit_time': str(core_props.content_status) if core_props.content_status else None,
                    })
                elif file_type == 'xlsx':
                    import openpyxl
                    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True)
                    props = wb.properties
                    metadata.update({
                        'title': props.title,
                        'author': props.creator,
                        'subject': props.subject,
                        'keywords': props.keywords,
                        'creation_date': str(props.created) if props.created else None,
                        'modification_date': str(props.modified) if props.modified else None,
                        'last_modified_by': props.lastModifiedBy,
                    })
                    wb.close()
                elif file_type == 'pptx':
                    from pptx import Presentation
                    prs = Presentation(io.BytesIO(content))
                    props = prs.core_properties
                    metadata.update({
                        'title': props.title,
                        'author': props.author,
                        'subject': props.subject,
                        'keywords': props.keywords,
                        'creation_date': str(props.created) if props.created else None,
                        'modification_date': str(props.modified) if props.modified else None,
                        'last_modified_by': props.last_modified_by,
                        'revision_number': str(props.revision) if props.revision else None,
                    })
            elif file_type in ['doc', 'xls', 'ppt']:
                # Legacy formats - would need python-docx2txt or similar
                metadata['note'] = 'Legacy format - limited metadata extraction'
        except ImportError:
            metadata['error'] = 'Required library not installed (python-docx, openpyxl, python-pptx)'
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_exif_metadata(self, content: bytes) -> Dict[str, Any]:
        """Extract EXIF metadata from images"""
        metadata = {}
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            img = Image.open(io.BytesIO(content))
            exif_data = img._getexif()
            
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    
                    if tag == 'GPSInfo':
                        gps_data = {}
                        for gps_tag_id, gps_value in value.items():
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_data[gps_tag] = gps_value
                        
                        # Convert GPS coordinates
                        if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
                            lat = self._convert_gps_coordinate(gps_data['GPSLatitude'], gps_data['GPSLatitudeRef'])
                            metadata['gps_latitude'] = str(lat)
                        if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
                            lon = self._convert_gps_coordinate(gps_data['GPSLongitude'], gps_data['GPSLongitudeRef'])
                            metadata['gps_longitude'] = str(lon)
                        if 'GPSAltitude' in gps_data:
                            metadata['gps_altitude'] = str(gps_data['GPSAltitude'])
                    else:
                        metadata[tag.lower().replace(' ', '_')] = str(value)
            
            # Common EXIF fields
            common_fields = {
                'make': 'camera_make',
                'model': 'camera_model',
                'datetime_original': 'datetime_original',
                'software': 'software',
            }
            
            for exif_key, meta_key in common_fields.items():
                if exif_key in metadata:
                    metadata[meta_key] = metadata[exif_key]
                    
        except ImportError:
            metadata['error'] = 'Pillow not installed'
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _convert_gps_coordinate(self, coord: tuple, ref: str) -> float:
        """Convert GPS coordinate to decimal degrees"""
        degrees, minutes, seconds = coord
        decimal = degrees + minutes/60 + seconds/3600
        if ref in ['S', 'W']:
            decimal = -decimal
        return decimal
    
    async def _download_file(self, url: str) -> Optional[bytes]:
        """Download file content"""
        try:
            session = await self._get_session()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=60, method='GET'
                )
            else:
                resp = await session.get(url, timeout=60)
            
            if resp and resp.status == 200:
                content = await resp.read()
                
                # Check file size
                if len(content) > self.config.max_file_size:
                    return None
                if len(content) < self.config.min_file_size:
                    return None
                
                return content
        except Exception as e:
            print(f"[!] Download error for {url}: {e}")
        
        return None
    
    def _process_document(self, url: str, content: bytes, source_type: str) -> Optional[DocumentMetadata]:
        """Process document and extract metadata"""
        # Determine file type from URL
        parsed = urlparse(url)
        path = parsed.path.lower()
        file_type = path.split('.')[-1] if '.' in path else 'unknown'
        
        # Calculate hashes
        hashes = self._calculate_hashes(content)
        
        # Create base metadata
        doc_meta = DocumentMetadata(
            url=url,
            file_type=file_type,
            file_size=len(content),
            hash_md5=hashes['md5'],
            hash_sha1=hashes['sha1'],
            hash_sha256=hashes['sha256'],
            source_url=url,
            source_type=source_type
        )
        
        # Extract metadata based on file type
        extracted_meta = {}
        
        if file_type == 'pdf' and self.config.extract_pdf:
            extracted_meta = self._extract_pdf_metadata(content)
        elif file_type in ['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt'] and self.config.extract_office:
            extracted_meta = self._extract_office_metadata(content, file_type)
        elif file_type in ['jpg', 'jpeg', 'png', 'tiff', 'tif', 'bmp', 'gif'] and self.config.extract_exif:
            extracted_meta = self._extract_exif_metadata(content)
        
        # Apply extracted metadata
        for key, value in extracted_meta.items():
            if hasattr(doc_meta, key) and value:
                setattr(doc_meta, key, value)
            elif value:
                doc_meta.custom_metadata[key] = str(value)
        
        return doc_meta
    
    async def search_documents(self) -> List[DocumentMetadata]:
        """Search for documents via search engines"""
        documents = []
        
        # Build search queries
        queries = []
        for file_type in self.config.file_types:
            queries.append(f'site:{self.domain} filetype:{file_type}')
            if self.config.keywords:
                for kw in self.config.keywords[:3]:  # Limit keywords
                    queries.append(f'site:{self.domain} filetype:{file_type} "{kw}"')
        
        engines = [
            ('duckduckgo', 'https://html.duckduckgo.com/html/', {'q': '{query}'}),
            ('bing', 'https://www.bing.com/search', {'q': '{query}'}),
        ]
        
        for engine_name, base_url, params_template in engines:
            if not getattr(self.config, f'use_{engine_name}', True):
                continue
                
            for query in queries[:20]:  # Limit queries
                try:
                    params = {k: v.format(query=query) for k, v in params_template.items()}
                    
                    session = await self._get_session()
                    if self.stealth_scheduler:
                        resp = await fetch_with_stealth(
                            session, base_url, self.stealth_scheduler,
                            params=params, method='GET'
                        )
                    else:
                        resp = await session.get(base_url, params=params, timeout=30)
                    
                    if resp and resp.status == 200:
                        html = await resp.text()
                        
                        # Extract file URLs
                        file_urls = re.findall(
                            r'href=["\']([^"\']+\.(?:' + '|'.join(self.config.file_types) + r'))["\']',
                            html, re.IGNORECASE
                        )
                        
                        for file_url in file_urls[:10]:  # Limit per query
                            # Normalize URL
                            if file_url.startswith('/'):
                                file_url = urljoin(f"https://{self.domain}", file_url)
                            elif not file_url.startswith('http'):
                                continue
                            
                            if file_url in self.processed_urls:
                                continue
                            self.processed_urls.add(file_url)
                            
                            # Download and process
                            content = await self._download_file(file_url)
                            if content:
                                doc = self._process_document(file_url, content, f'{engine_name}-search')
                                if doc:
                                    self._add_document(doc)
                                    documents.append(doc)
                    
                    if self.stealth_scheduler:
                        await self.stealth_scheduler.wait_before_request()
                        
                except Exception as e:
                    print(f"[!] {engine_name} document search error: {e}")
                    self.stats['errors'] += 1
        
        return documents
    
    async def crawl_website(self) -> List[DocumentMetadata]:
        """Crawl website for documents"""
        if not self.config.crawl_website:
            return []
        
        documents = []
        base_url = f"https://{self.domain}"
        visited = set()
        to_visit = [base_url]
        page_count = 0
        
        while to_visit and page_count < self.config.max_crawl_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                session = await self._get_session()
                if self.stealth_scheduler:
                    resp = await fetch_with_stealth(
                        session, url, self.stealth_scheduler,
                        method='GET'
                    )
                else:
                    resp = await session.get(url, timeout=30)
                
                if resp and resp.status == 200:
                    html = await resp.text()
                    page_count += 1
                    
                    # Find document links
                    doc_links = re.findall(
                        r'href=["\']([^"\']+\.(?:' + '|'.join(self.config.file_types) + r'))["\']',
                        html, re.IGNORECASE
                    )
                    
                    for doc_link in doc_links:
                        # Normalize
                        if doc_link.startswith('/'):
                            doc_link = urljoin(base_url, doc_link)
                        elif not doc_link.startswith('http'):
                            doc_link = urljoin(url, doc_link)
                        
                        if doc_link in self.processed_urls:
                            continue
                        self.processed_urls.add(doc_link)
                        
                        # Download and process
                        content = await self._download_file(doc_link)
                        if content:
                            doc = self._process_document(doc_link, content, 'crawl')
                            if doc:
                                self._add_document(doc)
                                documents.append(doc)
                    
                    # Find more pages to crawl
                    if page_count < self.config.max_crawl_pages:
                        links = re.findall(r'href=["\']([^"\']+)["\']', html)
                        for link in links:
                            if link.startswith('/'):
                                link = urljoin(base_url, link)
                            elif not link.startswith('http'):
                                link = urljoin(url, link)
                            
                            parsed = urlparse(link)
                            if parsed.netloc.endswith(self.domain) or parsed.netloc == self.domain:
                                if link not in visited and link not in to_visit:
                                    to_visit.append(link)
                
                if self.stealth_scheduler:
                    await self.stealth_scheduler.wait_before_request()
                    
            except Exception as e:
                print(f"[!] Crawl error for {url}: {e}")
                self.stats['errors'] += 1
        
        return documents
    
    def _add_document(self, doc: DocumentMetadata):
        """Add document to results"""
        # Check for duplicates by hash
        for existing in self.found_documents:
            if existing.hash_sha256 == doc.hash_sha256:
                return
        
        self.found_documents.append(doc)
        self.stats['total_found'] += 1
        self.stats['by_type'][doc.file_type] += 1
        self.stats['by_source'][doc.source_type] += 1
        self.stats['total_size'] += doc.file_size
    
    async def run(self) -> Dict[str, Any]:
        """Run document intelligence gathering"""
        print(f"[+] Starting document intelligence for {self.domain}")
        
        # Search via search engines
        if any([self.config.use_google, self.config.use_bing, self.config.use_duckduckgo]):
            print(f"[+] Searching for documents via search engines")
            await self.search_documents()
        
        # Crawl website
        if self.config.crawl_website:
            print(f"[+] Crawling website for documents")
            await self.crawl_website()
        
        # Prepare results
        results = {
            'domain': self.domain,
            'stats': self.stats,
            'documents': [
                {
                    'url': d.url,
                    'file_type': d.file_type,
                    'file_size': d.file_size,
                    'hash_md5': d.hash_md5,
                    'hash_sha1': d.hash_sha1,
                    'hash_sha256': d.hash_sha256,
                    'title': d.title,
                    'author': d.author,
                    'subject': d.subject,
                    'keywords': d.keywords,
                    'creator': d.creator,
                    'producer': d.producer,
                    'creation_date': d.creation_date,
                    'modification_date': d.modification_date,
                    'pdf_version': d.pdf_version,
                    'page_count': d.page_count,
                    'encrypted': d.encrypted,
                    'application': d.application,
                    'app_version': d.app_version,
                    'last_modified_by': d.last_modified_by,
                    'revision_number': d.revision_number,
                    'camera_make': d.camera_make,
                    'camera_model': d.camera_model,
                    'datetime_original': d.datetime_original,
                    'gps_latitude': d.gps_latitude,
                    'gps_longitude': d.gps_longitude,
                    'gps_altitude': d.gps_altitude,
                    'software': d.software,
                    'custom_metadata': d.custom_metadata,
                    'source_url': d.source_url,
                    'source_type': d.source_type,
                    'confidence': d.confidence
                }
                for d in self.found_documents
            ]
        }
        
        print(f"[+] Found {self.stats['total_found']} documents")
        print(f"[+] By type: {dict(self.stats['by_type'])}")
        print(f"[+] By source: {dict(self.stats['by_source'])}")
        print(f"[+] Total size: {self.stats['total_size'] / 1024 / 1024:.2f} MB")
        
        return results


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python document_intel.py <domain>")
        return
    
    domain = sys.argv[1]
    config = DocumentIntelConfig()
    intel = DocumentIntelligence(domain, config)
    results = await intel.run()
    await intel.close()
    
    import json
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())