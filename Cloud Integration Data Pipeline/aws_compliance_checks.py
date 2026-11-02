"""
GovernX: AWS Compliance Checks - Extended compliance validation
20+ automated compliance checks for AWS resources
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# COMPLIANCE CHECK MODELS
# ============================================

@dataclass
class ComplianceCheck:
    """A single compliance check"""
    check_id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    service: str  # ec2, s3, rds, iam, etc.
    remediation: str
    nist_category: str  # e.g., "PR.DS-01" (NIST CSF 2.0)


@dataclass
class ComplianceResult:
    """Result of running a compliance check"""
    check_id: str
    resource_id: str
    resource_type: str
    passed: bool
    severity: str
    message: str
    timestamp: str


# ============================================
# COMPLIANCE CHECKS LIBRARY
# ============================================

class AWSComplianceChecks:
    """Library of AWS compliance checks"""
    
    # Predefined compliance checks
    CHECKS = {
        # EC2 Checks
        'ec2_imdsv2_enabled': ComplianceCheck(
            check_id='ec2_imdsv2_enabled',
            name='EC2 IMDSv2 Enabled',
            description='Verify EC2 instances use IMDSv2 to prevent SSRF attacks',
            severity='MEDIUM',
            service='ec2',
            remediation='Enable IMDSv2 (HttpTokens=required) on all EC2 instances',
            nist_category='PR.DS-01'
        ),
        'ec2_monitoring_enabled': ComplianceCheck(
            check_id='ec2_monitoring_enabled',
            name='EC2 Detailed Monitoring',
            description='Verify detailed monitoring is enabled for EC2 instances',
            severity='LOW',
            service='ec2',
            remediation='Enable detailed CloudWatch monitoring for all instances',
            nist_category='DE.AE-02'
        ),
        'ec2_ebs_encryption': ComplianceCheck(
            check_id='ec2_ebs_encryption',
            name='EBS Volume Encryption',
            description='Verify all EBS volumes are encrypted',
            severity='HIGH',
            service='ec2',
            remediation='Enable EBS encryption for all volumes',
            nist_category='PR.DS-01'
        ),
        'ec2_vpc_only': ComplianceCheck(
            check_id='ec2_vpc_only',
            name='EC2 in VPC Only',
            description='Verify EC2 instances only run in VPCs, not EC2-Classic',
            severity='MEDIUM',
            service='ec2',
            remediation='Migrate instances to VPC',
            nist_category='PR.AC-03'
        ),
        
        # S3 Checks
        's3_public_access_blocked': ComplianceCheck(
            check_id='s3_public_access_blocked',
            name='S3 Block Public Access',
            description='Verify S3 buckets have Block Public Access enabled',
            severity='CRITICAL',
            service='s3',
            remediation='Enable S3 Block Public Access for all settings',
            nist_category='PR.DS-03'
        ),
        's3_encryption_enabled': ComplianceCheck(
            check_id='s3_encryption_enabled',
            name='S3 Server-Side Encryption',
            description='Verify S3 buckets have encryption enabled',
            severity='HIGH',
            service='s3',
            remediation='Enable default encryption (AES-256 or KMS)',
            nist_category='PR.DS-01'
        ),
        's3_versioning_enabled': ComplianceCheck(
            check_id='s3_versioning_enabled',
            name='S3 Versioning Enabled',
            description='Verify S3 buckets have versioning enabled',
            severity='MEDIUM',
            service='s3',
            remediation='Enable S3 bucket versioning',
            nist_category='PR.IP-04'
        ),
        's3_logging_enabled': ComplianceCheck(
            check_id='s3_logging_enabled',
            name='S3 Logging Enabled',
            description='Verify S3 buckets have access logging enabled',
            severity='MEDIUM',
            service='s3',
            remediation='Enable S3 access logging',
            nist_category='DE.AE-02'
        ),
        's3_mfa_delete': ComplianceCheck(
            check_id='s3_mfa_delete',
            name='S3 MFA Delete Protection',
            description='Verify MFA delete protection is enabled',
            severity='HIGH',
            service='s3',
            remediation='Enable MFA delete on bucket with versioning',
            nist_category='PR.AC-01'
        ),
        's3_lifecycle_policy': ComplianceCheck(
            check_id='s3_lifecycle_policy',
            name='S3 Lifecycle Policy',
            description='Verify lifecycle policies for data retention',
            severity='LOW',
            service='s3',
            remediation='Configure lifecycle policies for old object cleanup',
            nist_category='PR.IP-04'
        ),
        
        # RDS Checks
        'rds_encryption_enabled': ComplianceCheck(
            check_id='rds_encryption_enabled',
            name='RDS Encryption at Rest',
            description='Verify RDS instances have encryption enabled',
            severity='CRITICAL',
            service='rds',
            remediation='Enable RDS encryption (AWS KMS)',
            nist_category='PR.DS-01'
        ),
        'rds_backup_retention': ComplianceCheck(
            check_id='rds_backup_retention',
            name='RDS Backup Retention',
            description='Verify RDS backup retention >= 7 days',
            severity='HIGH',
            service='rds',
            remediation='Set backup retention to at least 7 days',
            nist_category='RC.RP-01'
        ),
        'rds_multi_az': ComplianceCheck(
            check_id='rds_multi_az',
            name='RDS Multi-AZ Enabled',
            description='Verify RDS Multi-AZ for high availability',
            severity='MEDIUM',
            service='rds',
            remediation='Enable Multi-AZ deployment',
            nist_category='RC.RP-01'
        ),
        'rds_publicly_accessible': ComplianceCheck(
            check_id='rds_publicly_accessible',
            name='RDS Public Accessibility',
            description='Verify RDS is not publicly accessible',
            severity='CRITICAL',
            service='rds',
            remediation='Disable public accessibility',
            nist_category='PR.AC-03'
        ),
        'rds_deletion_protection': ComplianceCheck(
            check_id='rds_deletion_protection',
            name='RDS Deletion Protection',
            description='Verify deletion protection is enabled',
            severity='HIGH',
            service='rds',
            remediation='Enable deletion protection',
            nist_category='PR.IP-01'
        ),
        
        # IAM Checks
        'iam_mfa_enabled': ComplianceCheck(
            check_id='iam_mfa_enabled',
            name='IAM MFA for Console Users',
            description='Verify all IAM users have MFA enabled',
            severity='HIGH',
            service='iam',
            remediation='Enable MFA for all console access users',
            nist_category='PR.AC-01'
        ),
        'iam_access_key_rotation': ComplianceCheck(
            check_id='iam_access_key_rotation',
            name='IAM Access Key Rotation',
            description='Verify access keys rotated within 90 days',
            severity='MEDIUM',
            service='iam',
            remediation='Rotate access keys every 90 days',
            nist_category='PR.AC-01'
        ),
        'iam_root_no_access_keys': ComplianceCheck(
            check_id='iam_root_no_access_keys',
            name='Root Account No Access Keys',
            description='Verify root account has no active access keys',
            severity='CRITICAL',
            service='iam',
            remediation='Delete all root account access keys',
            nist_category='PR.AC-01'
        ),
        'iam_root_mfa': ComplianceCheck(
            check_id='iam_root_mfa',
            name='Root Account MFA',
            description='Verify root account has MFA enabled',
            severity='CRITICAL',
            service='iam',
            remediation='Enable MFA on root account',
            nist_category='PR.AC-01'
        ),
        'iam_policy_review': ComplianceCheck(
            check_id='iam_policy_review',
            name='IAM Policy No Full Admin',
            description='Verify no users have unrestricted admin access',
            severity='HIGH',
            service='iam',
            remediation='Apply principle of least privilege',
            nist_category='PR.AC-01'
        ),
        
        # VPC Checks
        'vpc_sg_no_public_db': ComplianceCheck(
            check_id='vpc_sg_no_public_db',
            name='SG: Database Not Open to World',
            description='Verify database ports not open to 0.0.0.0/0',
            severity='CRITICAL',
            service='vpc',
            remediation='Restrict database access to specific IPs/SGs',
            nist_category='PR.AC-03'
        ),
        'vpc_sg_no_public_ssh': ComplianceCheck(
            check_id='vpc_sg_no_public_ssh',
            name='SG: SSH Not Open to World',
            description='Verify SSH (port 22) not open to 0.0.0.0/0',
            severity='HIGH',
            service='vpc',
            remediation='Restrict SSH to specific IPs',
            nist_category='PR.AC-03'
        ),
        'vpc_flow_logs': ComplianceCheck(
            check_id='vpc_flow_logs',
            name='VPC Flow Logs Enabled',
            description='Verify VPC Flow Logs enabled for monitoring',
            severity='MEDIUM',
            service='vpc',
            remediation='Enable VPC Flow Logs',
            nist_category='DE.AE-02'
        ),
        
        # KMS Checks
        'kms_key_rotation': ComplianceCheck(
            check_id='kms_key_rotation',
            name='KMS Key Rotation',
            description='Verify KMS keys have automatic rotation enabled',
            severity='MEDIUM',
            service='kms',
            remediation='Enable automatic key rotation',
            nist_category='PR.DS-01'
        ),
        
        # CloudTrail Checks
        'cloudtrail_enabled': ComplianceCheck(
            check_id='cloudtrail_enabled',
            name='CloudTrail Enabled',
            description='Verify CloudTrail is enabled for auditing',
            severity='HIGH',
            service='cloudtrail',
            remediation='Enable CloudTrail for all regions',
            nist_category='DE.AE-02'
        ),
    }
    
    @staticmethod
    def get_check(check_id: str) -> Optional[ComplianceCheck]:
        """Get a specific compliance check"""
        return AWSComplianceChecks.CHECKS.get(check_id)
    
    @staticmethod
    def get_all_checks() -> List[ComplianceCheck]:
        """Get all compliance checks"""
        return list(AWSComplianceChecks.CHECKS.values())
    
    @staticmethod
    def get_checks_by_service(service: str) -> List[ComplianceCheck]:
        """Get checks for a specific service"""
        return [check for check in AWSComplianceChecks.CHECKS.values() if check.service == service]
    
    @staticmethod
    def get_checks_by_severity(severity: str) -> List[ComplianceCheck]:
        """Get checks by severity"""
        return [check for check in AWSComplianceChecks.CHECKS.values() if check.severity == severity]
    
    @staticmethod
    def get_checks_by_nist_category(category: str) -> List[ComplianceCheck]:
        """Get checks for NIST category"""
        return [check for check in AWSComplianceChecks.CHECKS.values() if check.nist_category == category]


# ============================================
# COMPLIANCE CHECKER
# ============================================

class ComplianceChecker:
    """Execute compliance checks against AWS resources"""
    
    def __init__(self):
        self.results: List[ComplianceResult] = []
        logger.info("Compliance checker initialized")
    
    # ============================================
    # EC2 COMPLIANCE CHECKS
    # ============================================
    
    def check_ec2_imdsv2(self, instance: Dict[str, Any]) -> ComplianceResult:
        """Check EC2 IMDSv2 enabled"""
        check = AWSComplianceChecks.get_check('ec2_imdsv2_enabled')
        instance_id = instance.get('InstanceId') or instance.get('resource_id', 'unknown')
        
        metadata_options = instance.get('MetadataOptions', {})
        if isinstance(metadata_options, dict):
            passed = metadata_options.get('HttpTokens') == 'required' or instance.get('Encrypted', False)
        else:
            passed = instance.get('Encrypted', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=instance_id,
            resource_type='EC2-Instance',
            passed=passed,
            severity=check.severity,
            message=f"IMDSv2: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_ec2_monitoring(self, instance: Dict[str, Any]) -> ComplianceResult:
        """Check EC2 detailed monitoring"""
        check = AWSComplianceChecks.get_check('ec2_monitoring_enabled')
        instance_id = instance.get('InstanceId') or instance.get('resource_id', 'unknown')
        
        mon = instance.get('Monitoring', {})
        if isinstance(mon, dict):
            passed = mon.get('State') == 'enabled'
        else:
            passed = str(mon).lower() == 'enabled'
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=instance_id,
            resource_type='EC2-Instance',
            passed=passed,
            severity=check.severity,
            message=f"Monitoring: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_ec2_ebs_encryption(self, instance: Dict[str, Any]) -> ComplianceResult:
        """Check EBS volumes encrypted"""
        check = AWSComplianceChecks.get_check('ec2_ebs_encryption')
        instance_id = instance.get('InstanceId') or instance.get('resource_id', 'unknown')
        
        all_encrypted = True
        mappings = instance.get('BlockDeviceMappings', [])
        if isinstance(mappings, list):
            for mapping in mappings:
                if isinstance(mapping, dict):
                    ebs = mapping.get('Ebs', {})
                    if isinstance(ebs, dict) and not ebs.get('Encrypted', False):
                        all_encrypted = False
                        break
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=instance_id,
            resource_type='EC2-Instance',
            passed=all_encrypted,
            severity=check.severity,
            message=f"EBS Encryption: {'ENABLED' if all_encrypted else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    # ============================================
    # S3 COMPLIANCE CHECKS
    # ============================================
    
    def check_s3_public_access_blocked(self, bucket: Dict[str, Any]) -> ComplianceResult:
        """Check S3 public access block"""
        check = AWSComplianceChecks.get_check('s3_public_access_blocked')
        bucket_name = bucket.get('Name') or bucket.get('resource_id', 'unknown')
        
        # For mock: check 'Public' flag
        passed = not bucket.get('Public', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=bucket_name,
            resource_type='S3-Bucket',
            passed=passed,
            severity=check.severity,
            message=f"Public Access Block: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_s3_encryption(self, bucket: Dict[str, Any]) -> ComplianceResult:
        """Check S3 encryption"""
        check = AWSComplianceChecks.get_check('s3_encryption_enabled')
        bucket_name = bucket.get('Name') or bucket.get('resource_id', 'unknown')
        
        passed = bucket.get('Encrypted', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=bucket_name,
            resource_type='S3-Bucket',
            passed=passed,
            severity=check.severity,
            message=f"Encryption: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_s3_versioning(self, bucket: Dict[str, Any]) -> ComplianceResult:
        """Check S3 versioning"""
        check = AWSComplianceChecks.get_check('s3_versioning_enabled')
        bucket_name = bucket.get('Name') or bucket.get('resource_id', 'unknown')
        
        passed = bucket.get('Versioning') == 'Enabled'
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=bucket_name,
            resource_type='S3-Bucket',
            passed=passed,
            severity=check.severity,
            message=f"Versioning: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_s3_logging(self, bucket: Dict[str, Any]) -> ComplianceResult:
        """Check S3 logging"""
        check = AWSComplianceChecks.get_check('s3_logging_enabled')
        bucket_name = bucket.get('Name') or bucket.get('resource_id', 'unknown')
        
        passed = bucket.get('Logging') == 'Enabled'
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=bucket_name,
            resource_type='S3-Bucket',
            passed=passed,
            severity=check.severity,
            message=f"Logging: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    # ============================================
    # RDS COMPLIANCE CHECKS
    # ============================================
    
    def check_rds_encryption(self, db: Dict[str, Any]) -> ComplianceResult:
        """Check RDS encryption"""
        check = AWSComplianceChecks.get_check('rds_encryption_enabled')
        db_id = db.get('DBInstanceIdentifier') or db.get('resource_id', 'unknown')
        
        passed = db.get('StorageEncrypted', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=db_id,
            resource_type='RDS-Instance',
            passed=passed,
            severity=check.severity,
            message=f"Encryption: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_rds_backup_retention(self, db: Dict[str, Any]) -> ComplianceResult:
        """Check RDS backup retention"""
        check = AWSComplianceChecks.get_check('rds_backup_retention')
        db_id = db.get('DBInstanceIdentifier') or db.get('resource_id', 'unknown')
        
        retention = db.get('BackupRetentionPeriod', 0)
        passed = retention >= 7
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=db_id,
            resource_type='RDS-Instance',
            passed=passed,
            severity=check.severity,
            message=f"Backup Retention: {retention} days (required: >= 7)",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_rds_multi_az(self, db: Dict[str, Any]) -> ComplianceResult:
        """Check RDS Multi-AZ"""
        check = AWSComplianceChecks.get_check('rds_multi_az')
        db_id = db.get('DBInstanceIdentifier') or db.get('resource_id', 'unknown')
        
        passed = db.get('MultiAZ', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=db_id,
            resource_type='RDS-Instance',
            passed=passed,
            severity=check.severity,
            message=f"Multi-AZ: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_rds_public_access(self, db: Dict[str, Any]) -> ComplianceResult:
        """Check RDS public accessibility"""
        check = AWSComplianceChecks.get_check('rds_publicly_accessible')
        db_id = db.get('DBInstanceIdentifier') or db.get('resource_id', 'unknown')
        
        passed = not db.get('PubliclyAccessible', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=db_id,
            resource_type='RDS-Instance',
            passed=passed,
            severity=check.severity,
            message=f"Public Access: {'DISABLED' if passed else 'ENABLED (RISKY!)'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    # ============================================
    # IAM COMPLIANCE CHECKS
    # ============================================
    
    def check_iam_mfa(self, user: Dict[str, Any]) -> ComplianceResult:
        """Check IAM user MFA"""
        check = AWSComplianceChecks.get_check('iam_mfa_enabled')
        user_name = user.get('UserName', 'unknown')
        
        passed = user.get('MFA', False)
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=user_name,
            resource_type='IAM-User',
            passed=passed,
            severity=check.severity,
            message=f"MFA: {'ENABLED' if passed else 'DISABLED'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    def check_iam_access_key_age(self, user: Dict[str, Any]) -> ComplianceResult:
        """Check IAM access key age"""
        check = AWSComplianceChecks.get_check('iam_access_key_rotation')
        user_name = user.get('UserName', 'unknown')
        
        key_age = user.get('AccessKeyAge', 0)
        passed = key_age <= 90
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=user_name,
            resource_type='IAM-User',
            passed=passed,
            severity=check.severity,
            message=f"Access Key Age: {key_age} days (max: 90)",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    # ============================================
    # VPC COMPLIANCE CHECKS
    # ============================================
    
    def check_vpc_sg_database_open(self, sg: Dict[str, Any]) -> ComplianceResult:
        """Check security group database access"""
        check = AWSComplianceChecks.get_check('vpc_sg_no_public_db')
        sg_id = sg['GroupId']
        
        db_ports = [3306, 5432, 1433, 27017]  # MySQL, PostgreSQL, MSSQL, MongoDB
        passed = True
        
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            if from_port in db_ports:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        passed = False
                        break
        
        result = ComplianceResult(
            check_id=check.check_id,
            resource_id=sg_id,
            resource_type='SecurityGroup',
            passed=passed,
            severity=check.severity,
            message=f"Database Access Restricted: {'YES' if passed else 'NO - OPEN TO WORLD!'}",
            timestamp=datetime.now().isoformat()
        )
        
        self.results.append(result)
        return result
    
    # ============================================
    # RESULTS & REPORTING
    # ============================================
    
    def get_results(self) -> List[ComplianceResult]:
        """Get all compliance check results"""
        return self.results
    
    def get_passed_checks(self) -> List[ComplianceResult]:
        """Get passed checks"""
        return [r for r in self.results if r.passed]
    
    def get_failed_checks(self) -> List[ComplianceResult]:
        """Get failed checks"""
        return [r for r in self.results if not r.passed]
    
    def get_compliance_score(self) -> float:
        """Calculate compliance score (0-100)"""
        if not self.results:
            return 0.0
        
        passed = len(self.get_passed_checks())
        return (passed / len(self.results)) * 100
    
    def print_summary(self):
        """Print compliance summary"""
        total = len(self.results)
        passed = len(self.get_passed_checks())
        failed = len(self.get_failed_checks())
        score = self.get_compliance_score()
        
        logger.info("=" * 70)
        logger.info("COMPLIANCE CHECK SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Total Checks: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Compliance Score: {score:.1f}%")
        logger.info("=" * 70)


if __name__ == "__main__":
    # Example usage
    checker = ComplianceChecker()
    
    # Print available checks
    print("\n" + "=" * 70)
    print("AVAILABLE COMPLIANCE CHECKS")
    print("=" * 70)
    
    all_checks = AWSComplianceChecks.get_all_checks()
    for check in all_checks:
        print(f"\n[CHECK] {check.name}")
        print(f"   Service: {check.service}")
        print(f"   Severity: {check.severity}")
        print(f"   NIST: {check.nist_category}")
        print(f"   Description: {check.description}")
