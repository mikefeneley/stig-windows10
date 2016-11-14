import platform

if platform.system() == "Windows":
    from _winreg import *

from windows10_winrm_logger import Windows10WinRMLogger
from winreg_comparator import WinRegComparator


class Windows10WinRMAuditor:
    
    def __init__(self):
        self.comparator = WinRegComparator()
    
    def audit(self):
        """
        Entry function to all WinRM defined requirments by the
        Windows 10 STIG.

        :returns: string -- filename of the log file
        """
        logger = Windows10WinRMLogger()

        result = self.winrm_service_basic_auth_disabled()
        logger.winrm_service_basic_auth_disabled_errmsg(result)

        result = self.winrm_client_basic_auth_disabled()
        logger.winrm_service_basic_auth_disabled_errmsg(result)

        result = self.winrm_runas_disabled()
        logger.winrm_runas_disabled_errmsg(result)

        result = self.winrm_unencrypted_traffic_disabled()
        logger.winrm_unencrypted_traffic_disabled_errmsg(result)

        result = self.winrm_digest_authentication_disabled()
        logger.winrm_digest_authentication_disabled_errmsg(result)

        result = self.winrm_client_unencrypted_traffic_disabled()
        logger.winrm_client_unencrypted_traffic_disabled_errmsg(result)

        filename = logger.get_filename()
        del logger
        return filename

    def winrm_service_basic_auth_disabled(self):
        """
        Check SV-77837r1_rule: The Windows Remote Management (WinRM)
        service must not use Basic authentication.

        Finding ID: V-63347

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_val = "AllowBasic"
        val = 0
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare

    def winrm_client_basic_auth_disabled(self):
        """
        Check SV-77825r1_rule: The Windows Remote Management (WinRM)
        client must not use Basic authentication.

        Finding ID: V-63335

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_val = "AllowBasic"
        val = 0
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare
    
    def winrm_runas_disabled(self):
        """
        Check SV-77865r1_rule: The Windows Remote Management (WinRM) service
        must not store RunAs credentials.

        Finding ID: V-63375

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_val = "DisableRunAs"
        val = 1
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare


    def winrm_unencrypted_traffic_disabled(self):
        """
        Check SV-77859r1_rule: The Windows Remote Management (WinRM) service
        must not allow unencrypted traffic.

        Finding ID: V-63369

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        key_val = "AllowUnencryptedTraffic"
        val = 0
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare

    def winrm_digest_authentication_disabled(self):
        """
        Check SV-77831r1_rule: The Windows Remote Management (WinRM) client
        must not use Digest authentication.

        Finding ID: V-63341

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_val = "AllowDigest"
        val = 0
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare

    def winrm_client_unencrypted_traffic_disabled(self):
        """
        Check SV-77829r1_rule: The Windows Remote Management (WinRM) client must
        not allow unencrypted traffic.

        Finding ID: V-63339

        :returns: int -- True if criteria met, False otherwise
        """
        key = HKEY_LOCAL_MACHINE
        subkey = r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        key_val = "AllowUnencryptedTraffic"
        val = 0
        compare = self.comparator.reg_equals(None, key, subkey, key_val, val)
        return compare



if __name__ == "__main__":
	auditor = Windows10WinRMAuditor()
	auditor.audit()











