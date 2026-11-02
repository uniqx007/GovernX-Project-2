"""
GovernX: Cloud Poller - Multi-cloud orchestrator
Manages AWS/Azure polling, scheduling, caching
"""

import schedule
import time
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import threading
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# POLLING CONFIGURATION
# ============================================

@dataclass
class PollingConfig:
    """Configuration for cloud polling"""
    provider: str  # 'aws', 'azure'
    region: str
    interval_hours: int = 1  # Poll every N hours
    cache_duration_hours: int = 1  # Cache validity
    max_retries: int = 3
    retry_wait_seconds: int = 5
    timeout_seconds: int = 300


@dataclass
class PollingResult:
    """Result of a polling operation"""
    provider: str
    region: str
    status: str  # 'success', 'error', 'cached'
    findings_count: int
    resources_count: int
    timestamp: str
    cached_from: Optional[str] = None
    error_message: Optional[str] = None


# ============================================
# CACHE MANAGER
# ============================================

class CacheManager:
    """Manage polling cache"""
    
    def __init__(self, cache_dir: str = './.cache'):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_metadata = {}
        logger.info(f"Cache manager initialized at: {cache_dir}")
    
    def get_cache_key(self, provider: str, region: str) -> str:
        """Generate cache key"""
        return f"{provider}_{region}".lower()
    
    def get_cache_file(self, provider: str, region: str) -> Path:
        """Get cache file path"""
        cache_key = self.get_cache_key(provider, region)
        return self.cache_dir / f"{cache_key}_audit.json"
    
    def get_cache_metadata_file(self, provider: str, region: str) -> Path:
        """Get cache metadata file path"""
        cache_key = self.get_cache_key(provider, region)
        return self.cache_dir / f"{cache_key}_metadata.json"
    
    def is_cache_valid(self, provider: str, region: str, duration_hours: int) -> bool:
        """Check if cache is still valid"""
        metadata_file = self.get_cache_metadata_file(provider, region)
        
        if not metadata_file.exists():
            return False
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            cached_at = datetime.fromisoformat(metadata['timestamp'])
            age_hours = (datetime.now() - cached_at).total_seconds() / 3600
            
            is_valid = age_hours < duration_hours
            logger.info(f"Cache validity check ({provider}/{region}): {is_valid} (age: {age_hours:.1f}h)")
            return is_valid
        
        except Exception as e:
            logger.error(f"Error checking cache validity: {e}")
            return False
    
    def write_cache(self, provider: str, region: str, data: Dict[str, Any]):
        """Write data to cache"""
        try:
            cache_file = self.get_cache_file(provider, region)
            metadata_file = self.get_cache_metadata_file(provider, region)
            
            # Write data
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Write metadata
            metadata = {
                'timestamp': datetime.now().isoformat(),
                'provider': provider,
                'region': region
            }
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Cache written for {provider}/{region}")
        
        except Exception as e:
            logger.error(f"Error writing cache: {e}")
    
    def read_cache(self, provider: str, region: str) -> Optional[Dict[str, Any]]:
        """Read data from cache"""
        try:
            cache_file = self.get_cache_file(provider, region)
            
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Cache hit for {provider}/{region}")
            return data
        
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    def clear_cache(self, provider: str = None, region: str = None):
        """Clear cache"""
        try:
            if provider and region:
                # Clear specific cache
                cache_file = self.get_cache_file(provider, region)
                metadata_file = self.get_cache_metadata_file(provider, region)
                
                cache_file.unlink(missing_ok=True)
                metadata_file.unlink(missing_ok=True)
                logger.info(f"Cleared cache for {provider}/{region}")
            else:
                # Clear all cache
                for file in self.cache_dir.glob('*'):
                    file.unlink()
                logger.info("Cleared all cache")
        
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")


# ============================================
# CLOUD POLLER
# ============================================

class CloudPoller:
    """Orchestrate cloud polling from multiple providers"""
    
    def __init__(self):
        self.cache = CacheManager()
        self.polling_results: List[PollingResult] = []
        self.configs: List[PollingConfig] = []
        self.is_running = False
        
        # Import connectors (will implement in separate files)
        try:
            from aws_connector import AWSConnector
            self.AWSConnector = AWSConnector
        except ImportError:
            logger.warning("AWS connector not available")
            self.AWSConnector = None
        
        logger.info("Cloud poller initialized")
    
    def add_polling_config(self, config: PollingConfig):
        """Add a cloud provider to poll"""
        self.configs.append(config)
        logger.info(f"Added polling config: {config.provider}/{config.region}")
    
    def poll_aws(self, region: str, config: PollingConfig) -> PollingResult:
        """Poll AWS environment"""
        logger.info(f"Polling AWS region: {region}")
        
        try:
            # Check cache first
            if self.cache.is_cache_valid(config.provider, region, config.cache_duration_hours):
                cached_data = self.cache.read_cache(config.provider, region)
                if cached_data:
                    return PollingResult(
                        provider='aws',
                        region=region,
                        status='cached',
                        findings_count=cached_data['summary']['total_findings'],
                        resources_count=cached_data['summary']['resources_scanned'],
                        timestamp=datetime.now().isoformat(),
                        cached_from=cached_data['timestamp']
                    )
            
            # Run audit
            if not self.AWSConnector:
                raise Exception("AWS connector not available")
            
            connector = self.AWSConnector(region=region)
            audit_result = connector.run_full_audit()
            
            # Cache result
            self.cache.write_cache('aws', region, audit_result)
            
            # Return result
            result = PollingResult(
                provider='aws',
                region=region,
                status='success',
                findings_count=audit_result['summary']['total_findings'],
                resources_count=audit_result['summary']['resources_scanned'],
                timestamp=datetime.now().isoformat()
            )
            
            logger.info(f"AWS poll successful: {result.findings_count} findings")
            return result
        
        except Exception as e:
            logger.error(f"AWS poll failed: {e}")
            return PollingResult(
                provider='aws',
                region=region,
                status='error',
                findings_count=0,
                resources_count=0,
                timestamp=datetime.now().isoformat(),
                error_message=str(e)
            )
    
    def poll_azure(self, region: str, config: PollingConfig) -> PollingResult:
        """Poll Azure environment (placeholder)"""
        logger.info(f"Polling Azure region: {region}")
        
        # TODO: Implement Azure connector
        logger.warning("Azure polling not yet implemented")
        
        return PollingResult(
            provider='azure',
            region=region,
            status='error',
            findings_count=0,
            resources_count=0,
            timestamp=datetime.now().isoformat(),
            error_message='Azure polling not implemented'
        )
    
    def poll_provider(self, config: PollingConfig) -> PollingResult:
        """Poll a single provider with retry logic"""
        retries = 0
        
        while retries < config.max_retries:
            try:
                if config.provider.lower() == 'aws':
                    return self.poll_aws(config.region, config)
                elif config.provider.lower() == 'azure':
                    return self.poll_azure(config.region, config)
                else:
                    raise ValueError(f"Unknown provider: {config.provider}")
            
            except Exception as e:
                retries += 1
                if retries < config.max_retries:
                    logger.warning(f"Retry {retries}/{config.max_retries} for {config.provider}/{config.region}")
                    time.sleep(config.retry_wait_seconds)
                else:
                    logger.error(f"Max retries reached for {config.provider}/{config.region}")
                    return PollingResult(
                        provider=config.provider,
                        region=config.region,
                        status='error',
                        findings_count=0,
                        resources_count=0,
                        timestamp=datetime.now().isoformat(),
                        error_message=str(e)
                    )
    
    def run_polling_cycle(self):
        """Run one complete polling cycle for all configured providers"""
        logger.info("=" * 70)
        logger.info(f"STARTING POLLING CYCLE: {datetime.now().isoformat()}")
        logger.info("=" * 70)
        
        self.polling_results.clear()
        
        for config in self.configs:
            result = self.poll_provider(config)
            self.polling_results.append(result)
            
            # Print result
            logger.info(f"  {result.provider.upper()}/{result.region}: {result.status}")
            logger.info(f"    Findings: {result.findings_count}, Resources: {result.resources_count}")
            if result.status == 'cached':
                logger.info(f"    Cached from: {result.cached_from}")
            if result.error_message:
                logger.info(f"    Error: {result.error_message}")
        
        logger.info("=" * 70)
        logger.info(f"POLLING CYCLE COMPLETE")
        logger.info("=" * 70)
        
        return self.polling_results
    
    def schedule_polling(self):
        """Schedule periodic polling"""
        logger.info("Scheduling cloud polling...")
        
        # Schedule jobs for each config
        job_configs = {}
        for config in self.configs:
            job_key = f"{config.provider}_{config.region}"
            schedule.every(config.interval_hours).hours.do(self.run_polling_cycle)
            job_configs[job_key] = config
            logger.info(f"Scheduled {config.provider}/{config.region} every {config.interval_hours} hour(s)")
        
        # Start scheduler
        self.is_running = True
        logger.info("Polling scheduler started")
        
        while self.is_running:
            schedule.run_pending()
            time.sleep(60)  # Check schedule every minute
    
    def start_polling_thread(self):
        """Start polling in background thread"""
        thread = threading.Thread(target=self.schedule_polling, daemon=True)
        thread.start()
        logger.info("Polling started in background thread")
        return thread
    
    def stop_polling(self):
        """Stop the polling scheduler"""
        self.is_running = False
        logger.info("Polling scheduler stopped")
    
    def get_polling_results(self) -> List[PollingResult]:
        """Get latest polling results"""
        return self.polling_results
    
    def export_results_json(self, filepath: str = 'polling_results.json'):
        """Export polling results to JSON"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'results': [asdict(r) for r in self.polling_results],
            'summary': {
                'total_polls': len(self.polling_results),
                'successful': len([r for r in self.polling_results if r.status == 'success']),
                'cached': len([r for r in self.polling_results if r.status == 'cached']),
                'failed': len([r for r in self.polling_results if r.status == 'error']),
                'total_findings': sum(r.findings_count for r in self.polling_results),
                'total_resources': sum(r.resources_count for r in self.polling_results)
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Results exported to: {filepath}")


if __name__ == "__main__":
    # Example usage
    poller = CloudPoller()
    
    # Add AWS regions to poll
    poller.add_polling_config(PollingConfig(
        provider='aws',
        region='us-east-1',
        interval_hours=1,
        cache_duration_hours=1
    ))
    
    poller.add_polling_config(PollingConfig(
        provider='aws',
        region='us-west-2',
        interval_hours=1,
        cache_duration_hours=1
    ))
    
    # Run one polling cycle
    results = poller.run_polling_cycle()
    
    # Export results
    poller.export_results_json('polling_results.json')
    
    # Print summary
    print("\n" + "=" * 70)
    print("POLLING SUMMARY")
    print("=" * 70)
    for result in results:
        status_icon = "[OK]" if result.status == 'success' else "[CACHED]" if result.status == 'cached' else "[ERROR]"
        print(f"{status_icon} {result.provider.upper()}/{result.region}: {result.findings_count} findings, {result.resources_count} resources")
