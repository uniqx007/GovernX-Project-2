"""
GovernX: AWS Connector with Mock Data Support
Works with REAL AWS or MOCK data (no account needed)
"""

import boto3
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import concurrent.futures
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# MOCK DATA GENERATOR
# ============================================

# ============================================
# DATA MODELS
# ============================================

@dataclass
class Finding:
    """Security finding from AWS audit"""
    resource_id: str
    resource_type: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    remediation: str
    timestamp: str
    service: str  # ec2, s3, iam, rds, etc.

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AWSResource:
    """AWS resource configuration"""
    resource_id: str
    resource_type: str
    service: str
    region: str
    configuration: Dict[str, Any]
    timestamp: str


# ============================================
# AWS CONNECTOR (WITH MOCK SUPPORT)
# ============================================

class AWSConnector:
    """Connect to AWS and extract security configurations
    Supports both REAL AWS and MOCK data for testing
    """

    def __init__(self, region: str = 'us-east-1', profile_name: Optional[str] = None):
        self.region = region
        self.profile_name = profile_name
        self.findings: List['Finding'] = []
        self.resources: List['AWSResource'] = []
        self.use_mock = False

        import os
        from moto import mock_aws
        os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
        os.environ['AWS_SECURITY_TOKEN'] = 'testing'
        os.environ['AWS_SESSION_TOKEN'] = 'testing'
        os.environ['AWS_DEFAULT_REGION'] = region
        
        # Start Moto globally for this connector instance
        self.mock = mock_aws()
        self.mock.start()

        try:
            session = boto3.Session()
            self.ec2 = session.client('ec2', region_name=region)
            self.s3 = session.client('s3')
            self.iam = session.client('iam')
            self.rds = session.client('rds', region_name=region)
            self.kms = session.client('kms', region_name=region)

            logger.info(f"AWS connector initialized for region: {region} (MOTO ENABLED)")
            self._seed_mock_resources()
        except Exception as e:
            logger.error(f"Failed to initialize AWS connector: {e}")
            raise

    def _seed_mock_resources(self):
        """Seed the Moto environment with vulnerable resources"""
        try:
            self.ec2.create_volume(AvailabilityZone=f'{self.region}a', Size=10, Encrypted=False)
            self.ec2.run_instances(ImageId='ami-12c6146b', MinCount=1, MaxCount=1, InstanceType='t2.micro', Placement={'AvailabilityZone': f'{self.region}a'})
            
            self.s3.create_bucket(Bucket='company-public-bucket-123')
            
            self.rds.create_db_instance(
                DBInstanceIdentifier='prod-db',
                DBInstanceClass='db.t3.micro',
                Engine='postgres',
                AllocatedStorage=20,
                MasterUsername='admin',
                MasterUserPassword='password',
                StorageEncrypted=False
            )
        except Exception as e:
            pass # Ignore if already seeded

    # ============================================
    # EC2 AUDITING
    # ============================================

    def audit_ec2_instances(self) -> List[Finding]:
        """Audit EC2 instances for security issues"""
        logger.info("🔍 Auditing EC2 instances...")
        findings = []

        try:
            if self.use_mock:
                instances = self.mock_data['ec2_instances']
            else:
                response = self.ec2.describe_instances()
                instances = []
                for reservation in response['Reservations']:
                    instances.extend(reservation['Instances'])

            for instance in instances:
                instance_id = instance['InstanceId']

                # Check 1: Encryption
                for mapping in instance.get('BlockDeviceMappings', []):
                    vol_id = mapping['Ebs']['VolumeId']

                    if self.use_mock:
                        is_encrypted = mapping['Ebs'].get('Encrypted', False)
                    else:
                        vol_response = self.ec2.describe_volumes(VolumeIds=[vol_id])
                        is_encrypted = vol_response['Volumes'][0].get('Encrypted', False)

                    if not is_encrypted:
                        findings.append(Finding(
                            resource_id=instance_id,
                            resource_type='EC2-Instance',
                            finding_type='Unencrypted-Volume',
                            severity='HIGH',
                            description=f'EC2 instance {instance_id} has unencrypted volume {vol_id}',
                            remediation='Enable EBS encryption for all volumes',
                            timestamp=datetime.now().isoformat(),
                            service='ec2'
                        ))

                # Check 2: IMDSv2 (Instance Metadata Service)
                metadata_options = instance.get('MetadataOptions', {})
                if metadata_options.get('HttpTokens') != 'required':
                    findings.append(Finding(
                        resource_id=instance_id,
                        resource_type='EC2-Instance',
                        finding_type='IMDSv1-Enabled',
                        severity='MEDIUM',
                        description=f'EC2 instance {instance_id} does not require IMDSv2',
                        remediation='Enable IMDSv2 (HttpTokens=required)',
                        timestamp=datetime.now().isoformat(),
                        service='ec2'
                    ))

                # Check 3: Monitoring enabled
                if instance.get('Monitoring', {}).get('State') != 'enabled':
                    findings.append(Finding(
                        resource_id=instance_id,
                        resource_type='EC2-Instance',
                        finding_type='Monitoring-Disabled',
                        severity='LOW',
                        description=f'EC2 instance {instance_id} does not have detailed monitoring',
                        remediation='Enable detailed CloudWatch monitoring',
                        timestamp=datetime.now().isoformat(),
                        service='ec2'
                    ))

                # Store resource configuration
                self.resources.append(AWSResource(
                    resource_id=instance_id,
                    resource_type='EC2-Instance',
                    service='ec2',
                    region=instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    configuration={
                        'InstanceType': instance['InstanceType'],
                        'State': instance['State']['Name'],
                        'Encrypted': metadata_options.get('HttpTokens') == 'required',
                        'Monitoring': instance.get('Monitoring', {}).get('State'),
                        'Tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    },
                    timestamp=datetime.now().isoformat()
                ))

            logger.info(f"✅ EC2 audit complete. Found {len(findings)} issues.")

        except Exception as e:
            logger.error(f"❌ EC2 audit failed: {e}")

        self.findings.extend(findings)
        return findings

    # ============================================
    # S3 AUDITING
    # ============================================

    def audit_s3_buckets(self) -> List[Finding]:
        """Audit S3 buckets for security issues"""
        logger.info("🔍 Auditing S3 buckets...")
        findings = []

        try:
            if self.use_mock:
                buckets = self.mock_data['s3_buckets']
            else:
                response = self.s3.list_buckets()
                buckets = response['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']

                # Check 1: Public access block
                if self.use_mock:
                    is_public = bucket.get('Public', False)
                    if is_public:
                        findings.append(Finding(
                            resource_id=bucket_name,
                            resource_type='S3-Bucket',
                            finding_type='Public-Access-Allowed',
                            severity='CRITICAL',
                            description=f'S3 bucket {bucket_name} allows public access',
                            remediation='Enable S3 Block Public Access for all settings',
                            timestamp=datetime.now().isoformat(),
                            service='s3'
                        ))
                else:
                    try:
                        public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                        config = public_access['PublicAccessBlockConfiguration']

                        if not all([
                            config.get('BlockPublicAcls', False),
                            config.get('BlockPublicPolicy', False),
                            config.get('IgnorePublicAcls', False),
                            config.get('RestrictPublicBuckets', False)
                        ]):
                            findings.append(Finding(
                                resource_id=bucket_name,
                                resource_type='S3-Bucket',
                                finding_type='Public-Access-Allowed',
                                severity='CRITICAL',
                                description=f'S3 bucket {bucket_name} allows public access',
                                remediation='Enable S3 Block Public Access for all settings',
                                timestamp=datetime.now().isoformat(),
                                service='s3'
                            ))
                    except:
                        findings.append(Finding(
                            resource_id=bucket_name,
                            resource_type='S3-Bucket',
                            finding_type='No-Public-Access-Block',
                            severity='CRITICAL',
                            description=f'S3 bucket {bucket_name} has no public access block configuration',
                            remediation='Configure S3 Block Public Access',
                            timestamp=datetime.now().isoformat(),
                            service='s3'
                        ))

                # Check 2: Encryption
                if self.use_mock:
                    if not bucket.get('Encrypted', False):
                        findings.append(Finding(
                            resource_id=bucket_name,
                            resource_type='S3-Bucket',
                            finding_type='Encryption-Disabled',
                            severity='HIGH',
                            description=f'S3 bucket {bucket_name} does not have encryption enabled',
                            remediation='Enable default encryption (AES-256 or KMS)',
                            timestamp=datetime.now().isoformat(),
                            service='s3'
                        ))
                else:
                    try:
                        encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                    except:
                        findings.append(Finding(
                            resource_id=bucket_name,
                            resource_type='S3-Bucket',
                            finding_type='Encryption-Disabled',
                            severity='HIGH',
                            description=f'S3 bucket {bucket_name} does not have encryption enabled',
                            remediation='Enable default encryption (AES-256 or KMS)',
                            timestamp=datetime.now().isoformat(),
                            service='s3'
                        ))

                # Check 3: Versioning
                if self.use_mock:
                    versioning = bucket.get('Versioning', 'Disabled')
                else:
                    versioning_response = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning = versioning_response.get('Status', 'Disabled')

                if versioning != 'Enabled':
                    findings.append(Finding(
                        resource_id=bucket_name,
                        resource_type='S3-Bucket',
                        finding_type='Versioning-Disabled',
                        severity='MEDIUM',
                        description=f'S3 bucket {bucket_name} does not have versioning enabled',
                        remediation='Enable S3 bucket versioning for data protection',
                        timestamp=datetime.now().isoformat(),
                        service='s3'
                    ))

                # Store resource
                self.resources.append(AWSResource(
                    resource_id=bucket_name,
                    resource_type='S3-Bucket',
                    service='s3',
                    region='global',
                    configuration={
                        'CreationDate': bucket.get('CreationDate', datetime.now()).isoformat() if hasattr(bucket.get('CreationDate', datetime.now()), 'isoformat') else str(bucket.get('CreationDate')),
                        'Versioning': versioning if not self.use_mock else bucket.get('Versioning', 'Disabled'),
                        'Encrypted': bucket.get('Encrypted', False) if self.use_mock else 'Unknown',
                        'Public': bucket.get('Public', False) if self.use_mock else 'Unknown'
                    },
                    timestamp=datetime.now().isoformat()
                ))

            logger.info(f"✅ S3 audit complete. Found {len(findings)} issues.")

        except Exception as e:
            logger.error(f"❌ S3 audit failed: {e}")

        self.findings.extend(findings)
        return findings

    # ============================================
    # RDS AUDITING
    # ============================================

    def audit_rds_instances(self) -> List[Finding]:
        """Audit RDS instances for security issues"""
        logger.info("🔍 Auditing RDS instances...")
        findings = []

        try:
            if self.use_mock:
                rds_instances = self.mock_data['rds_instances']
            else:
                response = self.rds.describe_db_instances()
                rds_instances = response['DBInstances']

            for db in rds_instances:
                db_id = db['DBInstanceIdentifier']

                # Check 1: Encryption
                if not db.get('StorageEncrypted', False):
                    findings.append(Finding(
                        resource_id=db_id,
                        resource_type='RDS-Instance',
                        finding_type='Encryption-Disabled',
                        severity='CRITICAL',
                        description=f'RDS instance {db_id} does not have encryption enabled',
                        remediation='Enable RDS encryption at rest (AWS KMS)',
                        timestamp=datetime.now().isoformat(),
                        service='rds'
                    ))

                # Check 2: Backup retention
                backup_retention = db.get('BackupRetentionPeriod', 0)
                if backup_retention < 7:
                    findings.append(Finding(
                        resource_id=db_id,
                        resource_type='RDS-Instance',
                        finding_type='Low-Backup-Retention',
                        severity='MEDIUM',
                        description=f'RDS instance {db_id} has backup retention of {backup_retention} days',
                        remediation='Set backup retention to at least 7 days',
                        timestamp=datetime.now().isoformat(),
                        service='rds'
                    ))

                # Check 3: Multi-AZ
                if not db.get('MultiAZ', False):
                    findings.append(Finding(
                        resource_id=db_id,
                        resource_type='RDS-Instance',
                        finding_type='No-Multi-AZ',
                        severity='MEDIUM',
                        description=f'RDS instance {db_id} is not Multi-AZ enabled',
                        remediation='Enable Multi-AZ deployment for high availability',
                        timestamp=datetime.now().isoformat(),
                        service='rds'
                    ))

                # Check 4: Public accessibility
                if db.get('PubliclyAccessible', False):
                    findings.append(Finding(
                        resource_id=db_id,
                        resource_type='RDS-Instance',
                        finding_type='Publicly-Accessible',
                        severity='CRITICAL',
                        description=f'RDS instance {db_id} is publicly accessible',
                        remediation='Disable public accessibility and use VPC for access',
                        timestamp=datetime.now().isoformat(),
                        service='rds'
                    ))

                # Store resource
                self.resources.append(AWSResource(
                    resource_id=db_id,
                    resource_type='RDS-Instance',
                    service='rds',
                    region=db.get('AvailabilityZone', 'unknown'),
                    configuration={
                        'Engine': db['Engine'],
                        'EngineVersion': db['EngineVersion'],
                        'Encrypted': db.get('StorageEncrypted', False),
                        'MultiAZ': db.get('MultiAZ', False),
                        'BackupRetention': backup_retention,
                        'PubliclyAccessible': db.get('PubliclyAccessible', False),
                        'VpcId': db.get('DBSubnetGroup', {}).get('VpcId', 'unknown')
                    },
                    timestamp=datetime.now().isoformat()
                ))

            logger.info(f"✅ RDS audit complete. Found {len(findings)} issues.")

        except Exception as e:
            logger.error(f"❌ RDS audit failed: {e}")

        self.findings.extend(findings)
        return findings

    # ============================================
    # IAM AUDITING
    # ============================================

    def audit_iam_policies(self) -> List[Finding]:
        """Audit IAM policies for security issues"""
        logger.info("🔍 Auditing IAM policies...")
        findings = []

        try:
            if self.use_mock:
                users = self.mock_data['iam_users']
            else:
                response = self.iam.list_users()
                users = response['Users']

            for user in users:
                user_name = user.get('UserName') or user.get('UserName', 'unknown')
                has_mfa = user.get('MFA', False)

                if not has_mfa:
                    findings.append(Finding(
                        resource_id=user_name,
                        resource_type='IAM-User',
                        finding_type='No-MFA',
                        severity='HIGH',
                        description=f'IAM user {user_name} does not have MFA enabled',
                        remediation='Enable MFA for all IAM users with console access',
                        timestamp=datetime.now().isoformat(),
                        service='iam'
                    ))

                # Check access key age
                access_key_age = user.get('AccessKeyAge', 0)
                if access_key_age > 90:
                    findings.append(Finding(
                        resource_id=user_name,
                        resource_type='IAM-User',
                        finding_type='Old-Access-Key',
                        severity='MEDIUM',
                        description=f'IAM user {user_name} has access keys older than 90 days',
                        remediation='Rotate access keys every 90 days',
                        timestamp=datetime.now().isoformat(),
                        service='iam'
                    ))

            logger.info(f"✅ IAM audit complete. Found {len(findings)} issues.")

        except Exception as e:
            logger.error(f"❌ IAM audit failed: {e}")

        self.findings.extend(findings)
        return findings

    # ============================================
    # VPC AUDITING
    # ============================================

    def audit_vpc_security_groups(self) -> List[Finding]:
        """Audit VPC security groups for overly permissive rules"""
        logger.info("🔍 Auditing VPC security groups...")
        findings = []

        try:
            if self.use_mock:
                security_groups = self.mock_data['security_groups']
            else:
                response = self.ec2.describe_security_groups()
                security_groups = response['SecurityGroups']

            for sg in security_groups:
                sg_id = sg['GroupId']

                # Check for overly permissive rules
                for rule in sg.get('IpPermissions', []):
                    if 'IpRanges' in rule:
                        for ip_range in rule['IpRanges']:
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                # Check if it's a database port (dangerous)
                                from_port = rule.get('FromPort', 0)
                                if from_port in [3306, 5432, 1433, 27017]:  # MySQL, PostgreSQL, MSSQL, MongoDB
                                    findings.append(Finding(
                                        resource_id=sg_id,
                                        resource_type='SecurityGroup',
                                        finding_type='Database-Open-To-World',
                                        severity='CRITICAL',
                                        description=f'Security group {sg_id} exposes database port {from_port} to 0.0.0.0/0',
                                        remediation='Restrict database access to specific IPs/security groups',
                                        timestamp=datetime.now().isoformat(),
                                        service='ec2'
                                    ))

                # Store resource
                self.resources.append(AWSResource(
                    resource_id=sg_id,
                    resource_type='SecurityGroup',
                    service='ec2',
                    region='vpc',
                    configuration={
                        'GroupName': sg['GroupName'],
                        'VpcId': sg.get('VpcId', 'default'),
                        'IngressRules': len(sg.get('IpPermissions', [])),
                        'EgressRules': len(sg.get('IpPermissionsEgress', []))
                    },
                    timestamp=datetime.now().isoformat()
                ))

            logger.info(f"✅ VPC audit complete. Found {len(findings)} issues.")

        except Exception as e:
            logger.error(f"❌ VPC audit failed: {e}")

        self.findings.extend(findings)
        return findings

    # ============================================
    # AUDIT ORCHESTRATION
    # ============================================

    def run_full_audit(self) -> Dict[str, Any]:
        """Run complete security audit of AWS environment"""
        logger.info("=" * 70)
        logger.info("RUNNING FULL AWS SECURITY AUDIT (MOCK BOTO3 ENGINE)")
        logger.info("=" * 70)

        # Run all audits
        self.audit_ec2_instances()
        self.audit_s3_buckets()
        self.audit_rds_instances()
        self.audit_iam_policies()
        self.audit_vpc_security_groups()

        logger.info("=" * 70)
        logger.info(f"AUDIT COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Total Findings: {len(self.findings)}")
        logger.info(f"Total Resources Scanned: {len(self.resources)}")

        # Print findings by severity
        severity_counts = {}
        for finding in self.findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        logger.info(f"Findings by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                logger.info(f"  {severity}: {count}")

        return {
            'timestamp': datetime.now().isoformat(),
            'region': self.region,
            'use_mock': True,
            'findings': [f.to_dict() for f in self.findings],
            'resources': [asdict(r) for r in self.resources],
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f.severity == 'CRITICAL']),
                'high': len([f for f in self.findings if f.severity == 'HIGH']),
                'medium': len([f for f in self.findings if f.severity == 'MEDIUM']),
                'low': len([f for f in self.findings if f.severity == 'LOW']),
                'info': len([f for f in self.findings if f.severity == 'INFO']),
                'resources_scanned': len(self.resources)
            }
        }

    def export_findings_json(self, filepath: str = 'aws_audit_findings.json'):
        """Export findings to JSON file"""
        audit_result = {
            'timestamp': datetime.now().isoformat(),
            'region': self.region,
            'use_mock': True,
            'findings': [f.to_dict() for f in self.findings],
            'resources': [asdict(r) for r in self.resources],
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f.severity == 'CRITICAL']),
                'high': len([f for f in self.findings if f.severity == 'HIGH']),
                'medium': len([f for f in self.findings if f.severity == 'MEDIUM']),
                'low': len([f for f in self.findings if f.severity == 'LOW'])
            }
        }

        with open(filepath, 'w') as f:
            json.dump(audit_result, f, indent=2)

        logger.info(f"✅ Exported findings to: {filepath}")



if __name__ == "__main__":
    print("\\n" + "=" * 70)
    print("MOTO AWS ENVIRONMENT (Fake Boto3 Backend)")
    print("=" * 70)
    
    connector = AWSConnector(region='us-east-1')
    audit_result = connector.run_full_audit()
    connector.export_findings_json('aws_audit.json')
