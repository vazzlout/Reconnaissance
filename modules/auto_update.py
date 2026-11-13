"""
Auto-Update Module
- Check for updates from GitHub repository
- Auto-pull latest changes
- Version comparison
- Dependency update check
- Changelog display
"""

import asyncio
import aiohttp
import subprocess
import json
import re
import os
import sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from packaging import version
from pathlib import Path

from utils import StealthScheduler, fetch_with_stealth


@dataclass
class UpdateInfo:
    """Update information"""
    current_version: str
    latest_version: str
    update_available: bool
    release_url: str
    changelog: str
    published_at: str
    assets: List[Dict] = None


@dataclass
class AutoUpdateConfig:
    """Auto-update configuration"""
    repo_owner: str = "vazzlout"
    repo_name: str = "Reconnaissance"
    current_version: str = "1.0.0"
    check_interval_hours: int = 24
    auto_pull: bool = False
    auto_install_deps: bool = False
    backup_before_update: bool = True
    notify_only: bool = False
    github_token: Optional[str] = None


class AutoUpdater:
    """Auto-update manager"""
    
    def __init__(self, config: AutoUpdateConfig, 
                 stealth_scheduler: Optional[StealthScheduler] = None):
        self.config = config
        self.stealth_scheduler = stealth_scheduler
        self.session: Optional[aiohttp.ClientSession] = None
        self.repo_path = Path(__file__).parent.parent.parent  # Project root
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={'User-Agent': 'ReconTool/1.0 AutoUpdater'}
            )
        return self.session
    
    async def close(self):
        """Close the session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _stealth_get(self, url: str, headers: Dict = None, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request with stealth timing"""
        session = await self._get_session()
        if self.stealth_scheduler:
            return await fetch_with_stealth(
                session, url, self.stealth_scheduler,
                timeout=30, method='GET', headers=headers, **kwargs
            )
        else:
            try:
                return await session.get(url, timeout=30, headers=headers, **kwargs)
            except Exception:
                return None
    
    def get_local_version(self) -> str:
        """Get current local version"""
        # Try to read from VERSION file
        version_file = self.repo_path / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        
        # Try to read from config.yaml
        config_file = self.repo_path / "config.yaml"
        if config_file.exists():
            try:
                import yaml
                with open(config_file) as f:
                    config = yaml.safe_load(f)
                    return config.get('general', {}).get('version', '1.0.0')
            except Exception:
                pass
        
        # Try to get from git tag
        try:
            result = subprocess.run(
                ['git', 'describe', '--tags', '--always'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        return self.config.current_version
    
    def get_git_commit_hash(self) -> str:
        """Get current git commit hash"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()[:8]
        except Exception:
            pass
        return "unknown"
    
    def get_git_branch(self) -> str:
        """Get current git branch"""
        try:
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"
    
    async def check_for_updates(self) -> UpdateInfo:
        """Check for updates from GitHub"""
        current_version = self.get_local_version()
        
        print(f"[+] Checking for updates...")
        print(f"[+] Current version: {current_version}")
        print(f"[+] Current commit: {self.get_git_commit_hash()}")
        print(f"[+] Current branch: {self.get_git_branch()}")
        
        # GitHub API URL for latest release
        url = f"https://api.github.com/repos/{self.config.repo_owner}/{self.config.repo_name}/releases/latest"
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ReconTool/1.0 AutoUpdater'
        }
        
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        
        try:
            session = await self._get_session()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=30, method='GET', headers=headers
                )
            else:
                resp = await session.get(url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                release_data = await resp.json()
                
                latest_version = release_data.get('tag_name', '').lstrip('v')
                release_url = release_data.get('html_url', '')
                changelog = release_data.get('body', 'No changelog available')
                published_at = release_data.get('published_at', '')
                assets = release_data.get('assets', [])
                
                # Compare versions
                try:
                    current_ver = version.parse(current_version.lstrip('v'))
                    latest_ver = version.parse(latest_version.lstrip('v'))
                    update_available = latest_ver > current_ver
                except Exception:
                    # Fallback to string comparison
                    update_available = latest_version != current_version
                
                update_info = UpdateInfo(
                    current_version=current_version,
                    latest_version=latest_version,
                    update_available=update_available,
                    release_url=release_url,
                    changelog=changelog,
                    published_at=published_at,
                    assets=assets
                )
                
                if update_available:
                    print(f"[+] Update available: {current_version} -> {latest_version}")
                    print(f"[+] Release URL: {release_url}")
                    print(f"[+] Published: {published_at}")
                else:
                    print(f"[+] Already up to date: {current_version}")
                
                return update_info
            
            elif resp and resp.status == 404:
                # No releases, check commits
                return await self._check_commits_update()
            
            else:
                print(f"[!] Failed to check updates: HTTP {resp.status if resp else 'Unknown'}")
                return UpdateInfo(
                    current_version=current_version,
                    latest_version=current_version,
                    update_available=False,
                    release_url='',
                    changelog='',
                    published_at=''
                )
                
        except Exception as e:
            print(f"[!] Error checking updates: {e}")
            return UpdateInfo(
                current_version=current_version,
                latest_version=current_version,
                update_available=False,
                release_url='',
                changelog=f'Error: {e}',
                published_at=''
            )
    
    async def _check_commits_update(self) -> UpdateInfo:
        """Check for updates by comparing commits"""
        current_version = self.get_local_version()
        
        # Get latest commit from remote
        url = f"https://api.github.com/repos/{self.config.repo_owner}/{self.config.repo_name}/commits/main"
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ReconTool/1.0 AutoUpdater'
        }
        
        if self.config.github_token:
            headers['Authorization'] = f'token {self.config.github_token}'
        
        try:
            session = await self._get_session()
            
            if self.stealth_scheduler:
                resp = await fetch_with_stealth(
                    session, url, self.stealth_scheduler,
                    timeout=30, method='GET', headers=headers
                )
            else:
                resp = await session.get(url, headers=headers, timeout=30)
            
            if resp and resp.status == 200:
                commit_data = await resp.json()
                latest_sha = commit_data.get('sha', '')[:8]
                commit_message = commit_data.get('commit', {}).get('message', '')
                commit_date = commit_data.get('commit', {}).get('author', {}).get('date', '')
                commit_url = commit_data.get('html_url', '')
                
                # Get local commit
                local_sha = self.get_git_commit_hash()
                
                update_available = latest_sha != local_sha
                
                changelog = f"New commit: {commit_message}\nDate: {commit_date}"
                
                return UpdateInfo(
                    current_version=current_version,
                    latest_version=f"commit-{latest_sha}",
                    update_available=update_available,
                    release_url=commit_url,
                    changelog=changelog,
                    published_at=commit_date
                )
            
        except Exception as e:
            print(f"[!] Error checking commits: {e}")
        
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            update_available=False,
            release_url='',
            changelog='',
            published_at=''
        )
    
    def create_backup(self) -> bool:
        """Create backup before update"""
        if not self.config.backup_before_update:
            return True
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = self.repo_path.parent / f"recon_tool_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Copy project files (excluding .git, venv, __pycache__)
            import shutil
            
            def ignore_patterns(dir, files):
                ignored = []
                for f in files:
                    if f.startswith('.') or f in ['venv', '__pycache__', '*.pyc', '*.pyo', '*.pyd']:
                        ignored.append(f)
                return ignored
            
            shutil.copytree(self.repo_path, backup_dir, ignore=ignore_patterns)
            print(f"[+] Backup created: {backup_dir}")
            return True
            
        except Exception as e:
            print(f"[!] Backup failed: {e}")
            return False
    
    def git_pull(self) -> bool:
        """Pull latest changes from git"""
        try:
            print("[+] Pulling latest changes...")
            
            # Fetch first
            result = subprocess.run(
                ['git', 'fetch', 'origin'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"[!] Git fetch failed: {result.stderr}")
                return False
            
            # Get current branch
            branch = self.get_git_branch()
            
            # Pull
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print("[+] Git pull successful")
                print(result.stdout)
                return True
            else:
                print(f"[!] Git pull failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Git pull error: {e}")
            return False
    
    def install_dependencies(self) -> bool:
        """Install/update dependencies"""
        if not self.config.auto_install_deps:
            return True
        
        try:
            print("[+] Installing/updating dependencies...")
            
            requirements_file = self.repo_path / "requirements.txt"
            if not requirements_file.exists():
                print("[!] requirements.txt not found")
                return False
            
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt', '--upgrade'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("[+] Dependencies updated successfully")
                return True
            else:
                print(f"[!] Dependency installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Dependency installation error: {e}")
            return False
    
    def show_changelog(self, update_info: UpdateInfo):
        """Display changelog"""
        print("\n" + "="*60)
        print(f"CHANGELOG: {update_info.latest_version}")
        print("="*60)
        print(f"Published: {update_info.published_at}")
        print(f"Release URL: {update_info.release_url}")
        print("-"*60)
        print(update_info.changelog)
        print("="*60)
    
    async def run_update(self, force: bool = False) -> bool:
        """Run the update process"""
        print(f"[+] Starting auto-update process...")
        print(f"[+] Repository: {self.config.repo_owner}/{self.config.repo_name}")
        
        # Check for updates
        update_info = await self.check_for_updates()
        
        if not update_info.update_available and not force:
            print("[+] Already up to date!")
            return True
        
        # Show changelog
        self.show_changelog(update_info)
        
        if self.config.notify_only:
            print("[+] Notify only mode - not applying update")
            return True
        
        # Confirm update (unless forced)
        if not force:
            confirm = input("\n[?] Apply update? (y/N): ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("[+] Update cancelled")
                return False
        
        # Create backup
        if not self.create_backup():
            print("[!] Backup failed, aborting update")
            return False
        
        # Pull latest changes
        if not self.git_pull():
            print("[!] Git pull failed")
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            print("[!] Dependency installation failed")
            return False
        
        # Verify update
        new_version = self.get_local_version()
        print(f"\n[+] Update complete!")
        print(f"[+] New version: {self.get_local_version()}")
        print(f"[+] New commit: {self.get_git_commit_hash()}")
        
        return True
    
    async def run_scheduled_check(self):
        """Run scheduled update check"""
        print(f"[+] Running scheduled update check (interval: {self.config.check_interval_hours}h)")
        
        while True:
            try:
                update_info = await self.check_for_updates()
                
                if update_info.update_available:
                    print(f"\n[!] UPDATE AVAILABLE: {update_info.latest_version}")
                    print(f"[+] Run 'python main.py --update' to apply")
                    
                    # Could add notification here (email, webhook, etc.)
                    
            except Exception as e:
                print(f"[!] Scheduled check error: {e}")
            
            # Wait for next check
            await asyncio.sleep(self.config.check_interval_hours * 3600)


async def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Auto-Updater for Recon Tool")
    parser.add_argument("--check", action="store_true", help="Check for updates only")
    parser.add_argument("--update", action="store_true", help="Apply update if available")
    parser.add_argument("--force", action="store_true", help="Force update even if up to date")
    parser.add_argument("--schedule", action="store_true", help="Run scheduled checks")
    parser.add_argument("--interval", type=int, default=24, help="Check interval in hours")
    parser.add_argument("--repo-owner", default="vazzlout", help="GitHub repo owner")
    parser.add_argument("--repo-name", default="Reconnaissance", help="GitHub repo name")
    parser.add_argument("--current-version", default="1.0.0", help="Current version")
    parser.add_argument("--github-token", help="GitHub API token")
    parser.add_argument("--auto-pull", action="store_true", help="Auto pull without confirmation")
    parser.add_argument("--auto-install-deps", action="store_true", help="Auto install dependencies")
    parser.add_argument("--notify-only", action="store_true", help="Only notify, don't apply")
    parser.add_argument("--no-backup", action="store_true", help="Skip backup before update")
    
    args = parser.parse_args()
    
    config = AutoUpdateConfig(
        repo_owner=args.repo_owner,
        repo_name=args.repo_name,
        current_version=args.current_version,
        check_interval_hours=args.interval,
        auto_pull=args.auto_pull,
        auto_install_deps=args.auto_install_deps,
        backup_before_update=not args.no_backup,
        notify_only=args.notify_only,
        github_token=args.github_token
    )
    
    updater = AutoUpdater(config)
    
    try:
        if args.schedule:
            await updater.run_scheduled_check()
        elif args.check:
            update_info = await updater.check_for_updates()
            if update_info.update_available:
                print(f"\n[+] Update available: {update_info.latest_version}")
                updater.show_changelog(update_info)
            else:
                print("[+] Already up to date")
        elif args.update:
            success = await updater.run_update(force=args.force)
            sys.exit(0 if success else 1)
        else:
            # Default: check and show info
            update_info = await updater.check_for_updates()
            if update_info.update_available:
                print(f"\n[+] Update available: {update_info.latest_version}")
                print(f"[+] Run with --update to apply")
            else:
                print("[+] Already up to date")
    finally:
        await updater.close()


if __name__ == "__main__":
    asyncio.run(main())