import os
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
    from jira import JIRA
    from jira.exceptions import JIRAError
except ImportError:
    pass

logger = logging.getLogger(__name__)


class S3Client:
    """Enhanced S3 client with better error handling and features"""
    
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.bucket = config.get('bucket')
        self.region = config.get('region', 'us-east-1')
        self.prefix = config.get('prefix', 'sqli-scanner/')
        self.encryption = config.get('encryption', True)
        self.client = None
        
        if self.enabled and self.bucket:
            try:
                self.client = boto3.client('s3', region_name=self.region)
                logger.info(f"S3 client initialized: bucket={self.bucket}, region={self.region}")
            except NoCredentialsError:
                logger.error("AWS credentials not found. Please configure AWS credentials.")
                self.enabled = False
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")
                self.enabled = False
    
    def upload_file(self, file_path: str, object_name: Optional[str] = None, metadata: Optional[Dict] = None) -> bool:
        """
        Upload file to S3 with optional metadata
        
        Args:
            file_path: Path to file to upload
            object_name: S3 object name (defaults to filename with prefix)
            metadata: Optional metadata dict to attach
            
        Returns:
            True if successful, False otherwise
        """
        if not self.client or not self.enabled:
            logger.debug("S3 client not available, skipping upload")
            return False
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # Generate object name
        if object_name is None:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            object_name = f"{self.prefix}{timestamp}_{filename}"
        
        # Prepare extra args
        extra_args = {}
        if self.encryption:
            extra_args['ServerSideEncryption'] = 'AES256'
        if metadata:
            extra_args['Metadata'] = {k: str(v) for k, v in metadata.items()}
        
        try:
            self.client.upload_file(file_path, self.bucket, object_name, ExtraArgs=extra_args)
            
            # Generate presigned URL for sharing
            url = self.client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket, 'Key': object_name},
                ExpiresIn=3600 * 24 * 7  # 7 days
            )
            
            logger.info(f"Successfully uploaded to s3://{self.bucket}/{object_name}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during S3 upload: {e}")
            return False
    
    def upload_string(self, content: str, object_name: str, content_type: str = 'text/plain') -> bool:
        """Upload string content directly to S3"""
        if not self.client or not self.enabled:
            return False
        
        try:
            extra_args = {'ContentType': content_type}
            if self.encryption:
                extra_args['ServerSideEncryption'] = 'AES256'
            
            self.client.put_object(
                Bucket=self.bucket,
                Key=f"{self.prefix}{object_name}",
                Body=content.encode('utf-8'),
                **extra_args
            )
            
            logger.info(f"Uploaded string content to s3://{self.bucket}/{self.prefix}{object_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload string to S3: {e}")
            return False
    
    def list_files(self, max_keys: int = 100) -> List[str]:
        """List files in bucket with prefix"""
        if not self.client or not self.enabled:
            return []
        
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=self.prefix,
                MaxKeys=max_keys
            )
            
            if 'Contents' in response:
                return [obj['Key'] for obj in response['Contents']]
            return []
            
        except Exception as e:
            logger.error(f"Failed to list S3 objects: {e}")
            return []


class SlackClient:
    """Enhanced Slack client with rich message formatting"""
    
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.token = config.get('token')
        self.channel = config.get('channel')
        self.mention_on_critical = config.get('mention_on_critical', False)
        self.mention_user = config.get('mention_user', '')
        self.client = None
        
        if self.enabled and self.token:
            try:
                self.client = WebClient(token=self.token)
                # Test authentication
                auth_response = self.client.auth_test()
                logger.info(f"Slack client initialized: team={auth_response['team']}")
            except SlackApiError as e:
                logger.error(f"Slack authentication failed: {e.response['error']}")
                self.enabled = False
            except Exception as e:
                logger.error(f"Failed to initialize Slack client: {e}")
                self.enabled = False
    
    def send_scan_summary(self, stats: Dict[str, Any], scan_id: Optional[str] = None) -> bool:
        """Send formatted scan summary to Slack"""
        if not self.client or not self.enabled or not self.channel:
            logger.debug("Slack client not available, skipping notification")
            return False
        
        try:
            # Determine severity
            vuln_count = stats.get('vulnerable', 0)
            total = stats.get('total', 0)
            severity = "🔴 CRITICAL" if vuln_count > 0 else "🟢 CLEAR"
            
            # Build message blocks
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity} SQL Injection Scan Complete",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Total Scanned:*\n{total}"},
                        {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{vuln_count}"},
                        {"type": "mrkdwn", "text": f"*Safe:*\n{stats.get('safe', 0)}"},
                        {"type": "mrkdwn", "text": f"*Errors:*\n{stats.get('errors', 0)}"},
                    ]
                }
            ]
            
            # Add scan details
            if scan_id:
                blocks.append({
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Scan ID: `{scan_id}` | Duration: {stats.get('elapsed', 0):.2f}s"
                        }
                    ]
                })
            
            # Add mention for critical findings
            mention_text = ""
            if self.mention_on_critical and vuln_count > 0 and self.mention_user:
                mention_text = f"<@{self.mention_user}> "
            
            text = f"{mention_text}SQL Injection scan completed: {vuln_count} vulnerabilities found"
            
            response = self.client.chat_postMessage(
                channel=self.channel,
                text=text,
                blocks=blocks
            )
            
            logger.info(f"Slack notification sent: {response['ts']}")
            return True
            
        except SlackApiError as e:
            logger.error(f"Slack message failed: {e.response['error']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Slack message: {e}")
            return False
    
    def send_vulnerability_alert(self, vulnerability: Dict[str, Any]) -> bool:
        """Send alert for individual vulnerability"""
        if not self.client or not self.enabled or not self.channel:
            return False
        
        try:
            url = vulnerability.get('url', 'Unknown')
            verdict = vulnerability.get('verdict', 'Unknown')
            details = vulnerability.get('details', 'No details')
            
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 SQL Injection Vulnerability Detected",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Target:*\n{url[:100]}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{verdict}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Details:*\n{details[:200]}"
                    }
                }
            ]
            
            self.client.chat_postMessage(
                channel=self.channel,
                text=f"Vulnerability found: {url}",
                blocks=blocks
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send vulnerability alert: {e}")
            return False


class JiraClient:
    """Enhanced Jira client with better issue management"""
    
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.server = config.get('server')
        self.email = config.get('email')
        self.api_token = config.get('api_token')
        self.project_key = config.get('project_key')
        self.auto_create = config.get('auto_create_issues', False)
        self.priority_mapping = config.get('priority_mapping', {
            'CRITICAL': 'Highest',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        })
        self.client = None
        
        if self.enabled and all([self.server, self.email, self.api_token]):
            try:
                self.client = JIRA(
                    server=self.server,
                    basic_auth=(self.email, self.api_token)
                )
                # Test connection
                self.client.myself()
                logger.info(f"Jira client initialized: server={self.server}")
            except JIRAError as e:
                logger.error(f"Jira authentication failed: {e.text}")
                self.enabled = False
            except Exception as e:
                logger.error(f"Failed to initialize Jira client: {e}")
                self.enabled = False
    
    def create_vulnerability_issue(self, vulnerability: Dict[str, Any], scan_id: Optional[str] = None) -> Optional[str]:
        """
        Create Jira issue for vulnerability
        
        Returns:
            Issue key if successful, None otherwise
        """
        if not self.client or not self.enabled or not self.project_key:
            logger.debug("Jira client not available, skipping issue creation")
            return None
        
        try:
            url = vulnerability.get('url', 'Unknown')
            verdict = vulnerability.get('verdict', 'UNKNOWN')
            details = vulnerability.get('details', 'No details available')
            payload = vulnerability.get('payload', '')
            
            # Determine priority
            priority = self.priority_mapping.get(verdict, 'Medium')
            
            # Build description
            description = f"""
h2. SQL Injection Vulnerability Detected

*Target URL:* {url}

*Severity:* {verdict}

*Description:* {details}

*Payload Used:* 
{{code}}{payload}{{code}}

h3. Remediation Steps:
# Implement parameterized queries or prepared statements
# Add input validation with whitelist approach
# Review all database interaction code
# Deploy WAF rules as temporary mitigation
# Conduct code review of affected component

h3. References:
* OWASP Top 10 2021 - A03:2021 Injection
* CWE-89: SQL Injection
* https://owasp.org/www-community/attacks/SQL_Injection

---
_Scan ID: {scan_id or 'N/A'}_
_Generated: {datetime.now().isoformat()}_
"""
            
            # Create issue
            new_issue = self.client.create_issue(
                project=self.project_key,
                summary=f"[SQLi] Vulnerability in {url[:80]}",
                description=description,
                issuetype={'name': 'Bug'},
                priority={'name': priority},
                labels=['security', 'sql-injection', 'automated-scan']
            )
            
            issue_key = new_issue.key
            logger.info(f"Created Jira issue: {issue_key}")
            return issue_key
            
        except JIRAError as e:
            logger.error(f"Jira issue creation failed: {e.text}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating Jira issue: {e}")
            return None
    
    def create_scan_summary_issue(self, stats: Dict[str, Any], scan_id: Optional[str] = None) -> Optional[str]:
        """Create summary issue for scan results"""
        if not self.client or not self.enabled:
            return None
        
        try:
            vuln_count = stats.get('vulnerable', 0)
            
            description = f"""
h2. SQL Injection Scan Summary

*Total Targets:* {stats.get('total', 0)}
*Vulnerabilities Found:* {vuln_count}
*Suspicious:* {stats.get('suspicious', 0)}
*Safe:* {stats.get('safe', 0)}
*Errors:* {stats.get('errors', 0)}
*Scan Duration:* {stats.get('elapsed', 0):.2f}s

h3. Next Steps:
* Review individual vulnerability issues
* Prioritize critical findings
* Schedule remediation with development team
* Plan follow-up scan after fixes

---
_Scan ID: {scan_id or 'N/A'}_
_Generated: {datetime.now().isoformat()}_
"""
            
            new_issue = self.client.create_issue(
                project=self.project_key,
                summary=f"SQL Injection Scan Results - {vuln_count} Vulnerabilities",
                description=description,
                issuetype={'name': 'Task'},
                priority={'name': 'High' if vuln_count > 0 else 'Medium'},
                labels=['security-scan', 'sql-injection']
            )
            
            logger.info(f"Created summary Jira issue: {new_issue.key}")
            return new_issue.key
            
        except Exception as e:
            logger.error(f"Failed to create summary issue: {e}")
            return None


class CloudManager:
    """Unified cloud integrations manager"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.s3 = S3Client(config.get('s3', {}))
        self.slack = SlackClient(config.get('slack', {}))
        self.jira = JiraClient(config.get('jira', {}))
        
        # Track sync results
        self.sync_results = {
            's3': False,
            'slack': False,
            'jira': False
        }
    
    def sync_results(self, results_path: str, stats: Dict[str, Any], 
                    results: List[Dict[str, Any]], scan_id: Optional[str] = None) -> Dict[str, bool]:
        """
        Unified method to sync results to all configured cloud services
        
        Args:
            results_path: Path to results file (PDF/JSON)
            stats: Scan statistics
            results: List of vulnerability findings
            scan_id: Optional scan identifier
            
        Returns:
            Dictionary of sync results for each service
        """
        logger.info("Starting cloud sync...")
        
        # 1. Upload to S3
        if self.s3.enabled:
            metadata = {
                'scan_id': scan_id or 'unknown',
                'total': str(stats.get('total', 0)),
                'vulnerable': str(stats.get('vulnerable', 0)),
                'timestamp': datetime.now().isoformat()
            }
            self.sync_results['s3'] = self.s3.upload_file(results_path, metadata=metadata)
        
        # 2. Send Slack notification
        if self.slack.enabled:
            self.sync_results['slack'] = self.slack.send_scan_summary(stats, scan_id)
            
            # Send individual alerts for critical vulnerabilities
            if self.slack.mention_on_critical:
                critical_vulns = [r for r in results if r.get('verdict') == 'VULNERABLE']
                for vuln in critical_vulns[:5]:  # Limit to first 5
                    self.slack.send_vulnerability_alert(vuln)
        
        # 3. Create Jira issues
        if self.jira.enabled and self.jira.auto_create:
            # Create summary issue
            summary_key = self.jira.create_scan_summary_issue(stats, scan_id)
            
            # Create individual issues for vulnerabilities
            vulnerabilities = [r for r in results if r.get('verdict') == 'VULNERABLE']
            issue_count = 0
            for vuln in vulnerabilities[:10]:  # Limit to first 10
                issue_key = self.jira.create_vulnerability_issue(vuln, scan_id)
                if issue_key:
                    issue_count += 1
            
            self.sync_results['jira'] = (summary_key is not None) or (issue_count > 0)
        
        # Log results
        success_count = sum(1 for v in self.sync_results.values() if v)
        logger.info(f"Cloud sync complete: {success_count}/{len(self.sync_results)} services successful")
        
        return self.sync_results.copy()
    
    def get_sync_status(self) -> Dict[str, bool]:
        """Get status of last sync operation"""
        return self.sync_results.copy()