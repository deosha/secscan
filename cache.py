#!/usr/bin/env python3
"""
Intelligent caching system for SecScan
Implements multi-level caching with TTL, offline mode, and smart updates
"""

import json
import hashlib
import time
import os
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

@dataclass
class CacheMetadata:
    """Metadata for cached entries"""
    timestamp: float
    ttl: int
    version: str = "1.0"
    checksum: Optional[str] = None
    source: Optional[str] = None


class CacheManager:
    """Manages multi-level cache for SecScan"""
    
    DEFAULT_CACHE_DIR = Path.home() / ".secscan" / "cache"
    DEFAULT_TTL = 86400  # 24 hours
    VULNDB_TTL = 21600   # 6 hours for vulnerability database
    CACHE_VERSION = "1.0"
    
    def __init__(self, cache_dir: Optional[Path] = None, ttl: Optional[int] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else self.DEFAULT_CACHE_DIR
        self.ttl = ttl if ttl is not None else self.DEFAULT_TTL
        self.lock = threading.Lock()
        
        # Create cache structure
        self.vulndb_dir = self.cache_dir / "vulndb"
        self.scans_dir = self.cache_dir / "scans"
        self.packages_dir = self.cache_dir / "packages"
        
        self._init_cache_dirs()
    
    def _init_cache_dirs(self):
        """Initialize cache directory structure"""
        for dir_path in [
            self.vulndb_dir / "osv",
            self.vulndb_dir / "indexes",
            self.scans_dir,
            self.packages_dir
        ]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_path(self, cache_type: str, *args) -> Path:
        """Get path for cached item"""
        if cache_type == "vuln":
            ecosystem, name, version = args
            return self.vulndb_dir / "osv" / ecosystem / f"{name}_{version}.json"
        elif cache_type == "scan":
            project_hash = args[0]
            return self.scans_dir / project_hash
        elif cache_type == "package":
            ecosystem, name, version = args
            return self.packages_dir / ecosystem / name / f"{version}.json"
        else:
            raise ValueError(f"Unknown cache type: {cache_type}")
    
    def _compute_hash(self, data: Any) -> str:
        """Compute SHA256 hash of data"""
        if isinstance(data, (dict, list)):
            data = json.dumps(data, sort_keys=True)
        elif isinstance(data, Path):
            with open(data, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        
        return hashlib.sha256(str(data).encode()).hexdigest()
    
    def _is_cache_valid(self, metadata: CacheMetadata, ttl_override: Optional[int] = None) -> bool:
        """Check if cached data is still valid"""
        ttl = ttl_override or metadata.ttl
        age = time.time() - metadata.timestamp
        return age < ttl
    
    def get(self, cache_type: str, *args, ttl_override: Optional[int] = None) -> Optional[Any]:
        """Get cached data if valid"""
        cache_path = self._get_cache_path(cache_type, *args)
        metadata_path = cache_path.with_suffix('.meta')
        
        if not cache_path.exists() or not metadata_path.exists():
            return None
        
        try:
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = CacheMetadata(**json.load(f))
            
            # Check if cache is valid
            if not self._is_cache_valid(metadata, ttl_override):
                return None
            
            # Load and verify data
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            # Verify checksum if present
            if metadata.checksum:
                if self._compute_hash(data) != metadata.checksum:
                    # Cache corrupted, remove it
                    cache_path.unlink(missing_ok=True)
                    metadata_path.unlink(missing_ok=True)
                    return None
            
            return data
            
        except (json.JSONDecodeError, KeyError, OSError):
            # Remove corrupted cache
            cache_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            return None
    
    def set(self, cache_type: str, *args, data: Any, ttl_override: Optional[int] = None):
        """Cache data with metadata"""
        cache_path = self._get_cache_path(cache_type, *args)
        metadata_path = cache_path.with_suffix('.meta')
        
        # Ensure directory exists
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create metadata
        metadata = CacheMetadata(
            timestamp=time.time(),
            ttl=ttl_override or self.ttl,
            version=self.CACHE_VERSION,
            checksum=self._compute_hash(data)
        )
        
        with self.lock:
            # Write data
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Write metadata
            with open(metadata_path, 'w') as f:
                json.dump(asdict(metadata), f)
    
    def get_scan_cache(self, manifest_path: Path) -> Optional[Dict[str, Any]]:
        """Get cached scan results for a project"""
        # Compute hash of manifest file
        project_hash = self._compute_hash(manifest_path)
        scan_dir = self.scans_dir / project_hash
        
        if not scan_dir.exists():
            return None
        
        manifest_cache = scan_dir / "manifest.json"
        results_cache = scan_dir / "results.json"
        
        if not manifest_cache.exists() or not results_cache.exists():
            return None
        
        # Check if manifest has changed
        with open(manifest_cache, 'r') as f:
            cached_manifest = json.load(f)
        
        with open(manifest_path, 'r') as f:
            current_manifest = f.read()
        
        if cached_manifest.get('content') != current_manifest:
            # Manifest changed, cache invalid
            shutil.rmtree(scan_dir)
            return None
        
        # Load results
        return self.get("scan", project_hash)
    
    def set_scan_cache(self, manifest_path: Path, results: Dict[str, Any]):
        """Cache scan results for a project"""
        project_hash = self._compute_hash(manifest_path)
        scan_dir = self.scans_dir / project_hash
        scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache manifest content
        with open(manifest_path, 'r') as f:
            manifest_content = f.read()
        
        manifest_cache = scan_dir / "manifest.json"
        with open(manifest_cache, 'w') as f:
            json.dump({
                'path': str(manifest_path),
                'content': manifest_content,
                'timestamp': time.time()
            }, f)
        
        # Cache results
        self.set("scan", project_hash, data=results)
    
    def clear_cache(self, cache_type: Optional[str] = None):
        """Clear cache (all or specific type)"""
        if cache_type == "vulndb":
            shutil.rmtree(self.vulndb_dir, ignore_errors=True)
            self._init_cache_dirs()
        elif cache_type == "scans":
            shutil.rmtree(self.scans_dir, ignore_errors=True)
            self._init_cache_dirs()
        elif cache_type == "packages":
            shutil.rmtree(self.packages_dir, ignore_errors=True)
            self._init_cache_dirs()
        else:
            # Clear all
            shutil.rmtree(self.cache_dir, ignore_errors=True)
            self._init_cache_dirs()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            'cache_dir': str(self.cache_dir),
            'total_size': 0,
            'vulndb': {'count': 0, 'size': 0, 'oldest': None, 'newest': None},
            'scans': {'count': 0, 'size': 0, 'oldest': None, 'newest': None},
            'packages': {'count': 0, 'size': 0, 'oldest': None, 'newest': None}
        }
        
        for cache_type, dir_path in [
            ('vulndb', self.vulndb_dir),
            ('scans', self.scans_dir),
            ('packages', self.packages_dir)
        ]:
            oldest = None
            newest = None
            
            for path in dir_path.rglob('*.json'):
                if path.name.endswith('.meta'):
                    continue
                
                stats[cache_type]['count'] += 1
                size = path.stat().st_size
                stats[cache_type]['size'] += size
                stats['total_size'] += size
                
                # Check metadata for age
                meta_path = path.with_suffix('.meta')
                if meta_path.exists():
                    try:
                        with open(meta_path, 'r') as f:
                            metadata = json.load(f)
                            timestamp = metadata.get('timestamp', 0)
                            
                        if oldest is None or timestamp < oldest:
                            oldest = timestamp
                        if newest is None or timestamp > newest:
                            newest = timestamp
                    except:
                        pass
            
            if oldest:
                stats[cache_type]['oldest'] = datetime.fromtimestamp(oldest).isoformat()
            if newest:
                stats[cache_type]['newest'] = datetime.fromtimestamp(newest).isoformat()
        
        # Convert sizes to human readable
        for key in ['total_size', 'vulndb', 'scans', 'packages']:
            if isinstance(stats[key], dict):
                stats[key]['size_human'] = self._format_size(stats[key]['size'])
            else:
                stats['total_size_human'] = self._format_size(stats['total_size'])
        
        return stats
    
    def _format_size(self, size: int) -> str:
        """Format size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def warm_cache(self, ecosystems: List[str] = None, progress_callback=None):
        """Pre-populate cache with common vulnerability data"""
        if ecosystems is None:
            ecosystems = ["npm", "PyPI", "Go"]
        
        # Common packages to pre-fetch
        common_packages = {
            "npm": ["express", "react", "lodash", "axios", "vue"],
            "PyPI": ["django", "flask", "requests", "numpy", "pandas"],
            "Go": ["github.com/gin-gonic/gin", "github.com/gorilla/mux"]
        }
        
        total = sum(len(pkgs) for pkgs in common_packages.values())
        current = 0
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for ecosystem, packages in common_packages.items():
                if ecosystem not in ecosystems:
                    continue
                
                for package in packages:
                    # Check if already cached
                    if not self.get("package", ecosystem, package, "latest"):
                        future = executor.submit(self._fetch_package_info, ecosystem, package)
                        futures.append((future, package))
            
            for future, package in futures:
                try:
                    future.result(timeout=10)
                    current += 1
                    if progress_callback:
                        progress_callback(current, total, f"Cached {package}")
                except:
                    pass


class CachedOSVClient:
    """OSV client with intelligent caching"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
        self.base_url = "https://api.osv.dev/v1"
    
    def check_vulnerability_raw(self, ecosystem: str, name: str, version: str, 
                          use_cache: bool = True, offline: bool = False) -> Dict[str, Any]:
        """Check vulnerability with caching support"""
        # Try cache first
        if use_cache:
            cached = self.cache.get("vuln", ecosystem, name, version)
            if cached is not None:
                return cached
        
        # Offline mode - return empty if no cache
        if offline:
            return []
        
        # Fetch from API
        query = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/query",
                json=query,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            # Cache the result
            if use_cache:
                self.cache.set("vuln", ecosystem, name, version, 
                             data=data, ttl_override=self.cache.VULNDB_TTL)
            
            return data
            
        except requests.exceptions.RequestException:
            # Try to return stale cache if available
            cached = self.cache.get("vuln", ecosystem, name, version, 
                                  ttl_override=float('inf'))
            return cached if cached else {}
    
    def batch_check(self, packages: List[Tuple[str, str, str]], 
                   use_cache: bool = True, offline: bool = False,
                   progress_callback=None) -> Dict[str, List[Dict[str, Any]]]:
        """Batch check multiple packages with caching"""
        results = {}
        to_fetch = []
        
        # Check cache first
        for ecosystem, name, version in packages:
            key = f"{ecosystem}:{name}@{version}"
            
            if use_cache:
                cached = self.cache.get("vuln", ecosystem, name, version)
                if cached is not None:
                    # Ensure we return the vulns array, not the whole response
                    results[key] = cached.get('vulns', []) if isinstance(cached, dict) else cached
                    continue
            
            if not offline:
                to_fetch.append((ecosystem, name, version))
        
        # Fetch missing data in parallel
        if to_fetch:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {}
                
                for ecosystem, name, version in to_fetch:
                    key = f"{ecosystem}:{name}@{version}"
                    future = executor.submit(
                        self.check_vulnerability_raw, 
                        ecosystem, name, version, use_cache, offline
                    )
                    futures[future] = key
                
                completed = 0
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        data = future.result()
                        results[key] = data.get('vulns', []) if isinstance(data, dict) else []
                        completed += 1
                        if progress_callback:
                            progress_callback(completed, len(to_fetch))
                    except:
                        results[key] = []
        
        return results
    
    def check_vulnerability(self, dependency) -> List[Dict[str, Any]]:
        """Check vulnerability matching OSVClient interface"""
        from secscan import Language
        
        ecosystem_map = {
            Language.JAVASCRIPT: "npm",
            Language.PYTHON: "PyPI",
            Language.GO: "Go"
        }
        
        ecosystem = ecosystem_map.get(dependency.language)
        if not ecosystem:
            return []
        
        data = self.check_vulnerability_raw(
            ecosystem, dependency.name, dependency.version,
            use_cache=True, offline=False
        )
        
        return data.get('vulns', []) if isinstance(data, dict) else []


def format_cache_stats(stats: Dict[str, Any]) -> str:
    """Format cache statistics for display"""
    lines = []
    lines.append("📊 Cache Statistics")
    lines.append("=" * 50)
    lines.append(f"📁 Cache directory: {stats['cache_dir']}")
    lines.append(f"💾 Total size: {stats['total_size_human']}")
    lines.append("")
    
    for cache_type in ['vulndb', 'scans', 'packages']:
        info = stats[cache_type]
        lines.append(f"📦 {cache_type.title()}:")
        lines.append(f"   Files: {info['count']}")
        lines.append(f"   Size: {info['size_human']}")
        if info['oldest']:
            lines.append(f"   Oldest: {info['oldest']}")
        if info['newest']:
            lines.append(f"   Newest: {info['newest']}")
        lines.append("")
    
    return "\n".join(lines)