import os
import json
import logging
from typing import Dict, Any, Optional

try:
    import boto3
    from slack_sdk import WebClient
    from jira import JIRA
except ImportError:
    # Modules will be installed via requirements-v2.2.txt
    pass

logger = logging.getLogger(__name__)

class S3Client:
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.bucket = config.get('bucket')
        self.region = config.get('region', 'us-east-1')
        self.client = None
        
        if self.enabled and self.bucket:
            try:
                self.client = boto3.client('s3', region_name=self.region)
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")

    def upload_file(self, file_path: str, object_name: Optional[str] = None):
        if not self.client:
            return False
        
        if object_name is None:
            object_name = os.path.basename(file_path)
            
        try:
            self.client.upload_file(file_path, self.bucket, object_name)
            logger.info(f"Successfully uploaded {file_path} to s3://{self.bucket}/{object_name}")
            return True
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            return False

class SlackClient:
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.token = config.get('token')
        self.channel = config.get('channel')
        self.client = None
        
        if self.enabled and self.token:
            try:
                self.client = WebClient(token=self.token)
            except Exception as e:
                logger.error(f"Failed to initialize Slack client: {e}")

    def send_message(self, text: str, blocks: Optional[list] = None):
        if not self.client or not self.channel:
            return False
            
        try:
            self.client.chat_postMessage(channel=self.channel, text=text, blocks=blocks)
            return True
        except Exception as e:
            logger.error(f"Slack message failed: {e}")
            return False

class JiraClient:
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.server = config.get('server')
        self.email = config.get('email')
        self.api_token = config.get('api_token')
        self.project_key = config.get('project_key')
        self.client = None
        
        if self.enabled and self.server and self.email and self.api_token:
            try:
                self.client = JIRA(server=self.server, basic_auth=(self.email, self.api_token))
            except Exception as e:
                logger.error(f"Failed to initialize Jira client: {e}")

    def create_issue(self, summary: str, description: str, issue_type: str = 'Bug'):
        if not self.client or not self.project_key:
            return None
            
        try:
            new_issue = self.client.create_issue(
                project=self.project_key,
                summary=summary,
                description=description,
                issuetype={'name': issue_type}
            )
            return new_issue.key
        except Exception as e:
            logger.error(f"Jira issue creation failed: {e}")
            return None

class CloudManager:
    def __init__(self, config: Dict):
        self.s3 = S3Client(config.get('s3', {}))
        self.slack = SlackClient(config.get('slack', {}))
        self.jira = JiraClient(config.get('jira', {}))

    def sync_results(self, results_path: str, stats: Dict):
        """Unified method to handle post-scan cloud sync"""
        # 1. Upload to S3
        if self.s3.enabled:
            self.s3.upload_file(results_path)
            
        # 2. Notify Slack
        if self.slack.enabled:
            msg = f"*SQLi Scan Complete*\nTotal: {stats['total']}\nVulnerable: {stats['vulnerable']}\nSafe: {stats['safe']}"
            self.slack.send_message(msg)
            
        # 3. Create Jira issues for criticals (if enabled and specific results found)
        # This could be handled externally or via another method
        pass
