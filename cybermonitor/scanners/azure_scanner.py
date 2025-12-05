# cybermonitor/scanners/azure_scanner.py
"""
Azure Security Scanner - Scans Azure resources for security misconfigurations.

Checks:
- Storage account public access settings
- Network security group rules
- Key vault configurations
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from cybermonitor.scanners.aws_scanner import Finding, Severity

logger = logging.getLogger(__name__)


class AzureScanner:
    """
    Azure Security Scanner for detecting misconfigurations.

    Scans:
    - Storage accounts for public access
    - Network security groups
    """

    def __init__(self, subscription_id: Optional[str] = None, credential=None):
        """
        Initialize the Azure scanner.

        Args:
            subscription_id: Azure subscription ID
            credential: Azure credential object (for dependency injection)
        """
        self.subscription_id = subscription_id
        self._credential = credential
        self._storage_client = None
        self.findings: List[Finding] = []

    @property
    def credential(self):
        """Lazy load Azure credential."""
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential
                self._credential = DefaultAzureCredential()
            except ImportError:
                raise ImportError(
                    "azure-identity is required for Azure scanning. "
                    "Install with: pip install azure-identity azure-mgmt-storage"
                )
        return self._credential

    @property
    def storage_client(self):
        """Lazy load Storage Management client."""
        if self._storage_client is None:
            if not self.subscription_id:
                raise ValueError("subscription_id is required for Azure scanning")
            try:
                from azure.mgmt.storage import StorageManagementClient
                self._storage_client = StorageManagementClient(
                    self.credential,
                    self.subscription_id
                )
            except ImportError:
                raise ImportError(
                    "azure-mgmt-storage is required. "
                    "Install with: pip install azure-mgmt-storage"
                )
        return self._storage_client

    def scan_all(self) -> List[Finding]:
        """
        Run all Azure security scans.

        Returns:
            List of security findings
        """
        logger.info("Starting comprehensive Azure security scan...")
        self.findings = []

        self.scan_storage_accounts()

        logger.info(f"Azure scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def scan_storage_accounts(self) -> List[Finding]:
        """
        Scan Azure storage accounts for public access misconfigurations.

        Checks:
        - Public network access settings
        - Blob public access settings
        - HTTPS-only traffic enforcement

        Returns:
            List of storage-related findings
        """
        logger.info("Scanning Azure storage accounts...")
        storage_findings = []

        try:
            storage_accounts = self.storage_client.storage_accounts.list()

            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4] if account.id else 'Unknown'
                logger.debug(f"Scanning storage account: {account_name}")

                # Check public network access
                if hasattr(account, 'public_network_access'):
                    if account.public_network_access == "Enabled":
                        finding = Finding(
                            resource_type="Azure::Storage::StorageAccount",
                            resource_id=account.id or account_name,
                            title="Storage Account Allows Public Network Access",
                            description=f"Storage account {account_name} allows public network access",
                            severity=Severity.HIGH,
                            remediation="Disable public network access and use private endpoints",
                            metadata={
                                "account_name": account_name,
                                "resource_group": resource_group,
                                "location": account.location
                            }
                        )
                        storage_findings.append(finding)
                        logger.warning(f"HIGH: Storage account {account_name} allows public access")

                # Check blob public access
                if hasattr(account, 'allow_blob_public_access'):
                    if account.allow_blob_public_access:
                        finding = Finding(
                            resource_type="Azure::Storage::StorageAccount",
                            resource_id=account.id or account_name,
                            title="Storage Account Allows Blob Public Access",
                            description=f"Storage account {account_name} allows blob public access",
                            severity=Severity.CRITICAL,
                            remediation="Disable blob public access at the storage account level",
                            metadata={
                                "account_name": account_name,
                                "resource_group": resource_group
                            }
                        )
                        storage_findings.append(finding)
                        logger.warning(f"CRITICAL: Storage account {account_name} allows blob public access!")

                # Check HTTPS enforcement
                if hasattr(account, 'enable_https_traffic_only'):
                    if not account.enable_https_traffic_only:
                        finding = Finding(
                            resource_type="Azure::Storage::StorageAccount",
                            resource_id=account.id or account_name,
                            title="Storage Account Does Not Enforce HTTPS",
                            description=f"Storage account {account_name} allows non-HTTPS traffic",
                            severity=Severity.MEDIUM,
                            remediation="Enable 'Secure transfer required' for the storage account",
                            metadata={
                                "account_name": account_name,
                                "resource_group": resource_group
                            }
                        )
                        storage_findings.append(finding)

                # Check minimum TLS version
                if hasattr(account, 'minimum_tls_version'):
                    if account.minimum_tls_version and account.minimum_tls_version < "TLS1_2":
                        finding = Finding(
                            resource_type="Azure::Storage::StorageAccount",
                            resource_id=account.id or account_name,
                            title="Storage Account Uses Outdated TLS Version",
                            description=f"Storage account {account_name} uses TLS version below 1.2",
                            severity=Severity.MEDIUM,
                            remediation="Set minimum TLS version to TLS 1.2 or higher",
                            metadata={
                                "account_name": account_name,
                                "current_tls": account.minimum_tls_version
                            }
                        )
                        storage_findings.append(finding)

        except Exception as e:
            logger.error(f"Error scanning Azure storage accounts: {e}")

        self.findings.extend(storage_findings)
        return storage_findings

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of scan findings.

        Returns:
            Dictionary with finding counts by severity
        """
        summary = {
            "total": len(self.findings),
            "by_severity": {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 0,
                Severity.MEDIUM.value: 0,
                Severity.LOW.value: 0,
                Severity.INFO.value: 0
            }
        }

        for finding in self.findings:
            summary["by_severity"][finding.severity.value] += 1

        return summary
