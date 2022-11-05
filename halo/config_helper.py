import os

from halo.utility import Utility


class ConfigHelper(object):
    """
    This class contains all application configuration variables.

    Attributes:
        halo_api_key_id (str): Halo API key ID, sometimes referred to as 'key id'
        halo_api_key_secret (str): Halo API Key Secret associated with halo_api_key_id
        halo_api_hostname (str): Hostname for Halo API
        halo_api_port (str): Halo API port
        halo_api_version (str): Halo API version
        halo_api_auth_url (str): Halo API authentication URL
        halo_api_auth_args (str): Halo API authentication arguments (grant_type)
        halo_api_auth_token (str): Halo API authentication token
        output_directory (str): directory for generated output files.
        halo_group_id (str): Halo Group ID.
        cve_nvd_link_base (str): Base URL of CVE NVD
    """

    def __init__(self):
        self.halo_api_key_id = os.getenv("HALO_API_KEY", "HARDSTOP")
        self.halo_api_key_secret = os.getenv("HALO_API_SECRET_KEY", "HARDSTOP")
        self.halo_api_hostname = os.getenv(
            "HALO_API_HOSTNAME", "https://api.cloudpassage.com")
        self.halo_api_port = os.getenv("HALO_API_PORT", "443")
        self.halo_api_version = os.getenv("HALO_API_VERSION", "v1")
        self.halo_api_auth_url = "oauth/access_token"
        self.halo_api_auth_args = {'grant_type': 'client_credentials'}
        self.halo_api_auth_token = None
        self.output_directory = os.getenv("OUTPUT_DIRECTORY", "/tmp")
        self.halo_group_id = os.getenv("HALO_GROUP_ID", "HARDSTOP")
        self.cve_nvd_link_base = os.getenv("CVE_NVD_LINK_BASE", "http://web.nvd.nist.gov/view/vuln/detail?vulnId=")
        self.table_header_columns = ['OS Type', 'OS Name', 'OS Version', 'Hostname', 'Server Label', 'Reported FQDN',
                    'Connecting IP Address', 'Primary IP Address', 'Connecting IP FQDN', 'CSP Type', 'CSP Instance ID',
                    'CSP Account ID', 'CSP Image ID', 'CSP Kernel ID', 'CSP Private IP', 'CSP Instance Type', 'CSP Availability Zone',
                    'CSP Region', 'CSP Security Groups', 'CSP Instance Tags', 'EC2 Instance ID', 'EC2 Account ID', 'EC2 Image ID',
                    'EC2 Kernel ID', 'EC2 Private IP', 'EC2 Instance Type', 'EC2 Availability Zone', 'EC2 Region', 'EC2 Security Groups',
                    'Server Status', 'Server Group Path', 'Last Scan Time', 'Package Name', 'Package Version', 'Criticality', 'CVE ID',
                    'CVSS Base Score', 'CVSS v2 Attack Vector', 'CVSS v2 Access Complexity', 'CVSS v2 Authentication', 'CVSS v2 Confidentiality Impact',
                    'CVSS v2 Integrity Impact', 'CVSS v2 Availability Impact', 'CVSS v3 Attack Vector', 'CVSS v3 Attack Complexity',
                    'CVSS v3 User Interaction', 'CVSS v3 Confidentiality Impact', 'CVSS v3 Integrity Impact', 'CVSS v3 Availability Impact',
                    'CVSS v3 Privileges Required', 'CVSS v3 Scope', 'CVSS v3 Base Severity', 'CVSS v3 Vector String', 'Remotely Exploitable',
                    'CVE Description', 'CVE NVD Link', 'Vulnerability First Seen', 'Vulnerability Last Seen']

    def sane(self):
        """
        Test to make sure that config items for Halo are set.
        Returns:
            True if everything is OK, False if otherwise
        """

        sanity = True
        template = "Required configuration variable {0} is not set!"
        critical_vars = {"HALO_API_KEY_ID": self.halo_api_key_id,
                         "HALO_API_KEY_SECRET": self.halo_api_key_secret,
                         "HALO_GROUP_ID": self.halo_group_id}
        for name, varval in critical_vars.items():
            if varval == "HARDSTOP":
                sanity = False
                Utility.log_stdout(template.format(name))
        return sanity
