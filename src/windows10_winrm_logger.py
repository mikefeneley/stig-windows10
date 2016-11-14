DEFAULT_CONFIG = "Windows10WinRM.txt"

class Windows10WinRMLogger:

    """
    Windows10WinRMLogger writes error messages to the WinRM log file
    for every rule in the WinRM STIG that is violated.
    """
    def __init__(self):
        pass

    def __init__(self, filename=DEFAULT_CONFIG):
        self.filename = filename
        self.log = open(filename, 'w')
        self.log.write("#########################\n\n")
        self.log.write("Windows10 WinRm Audit Findings\n\n")

    def __del__(self):
        print("Write out")
        self.log.write("#########################\n\n")
        self.log.close()

    def get_filename(self):
    	return self.filename

    def winrm_service_basic_auth_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-78287r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) service must not use Basic authentication.\n\n")

    def winrm_client_basic_auth_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-77825r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) client must not use Basic authentication.\n\n")

    def winrm_runas_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-77865r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) service must not store RunAs credentials.\n\n")

    def winrm_unencrypted_traffic_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-77859r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) service must not allow unencrypted traffic.\n\n")

    def winrm_digest_authentication_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-77831r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) client must not use Digest authentication.\n\n")

    def winrm_client_unencrypted_traffic_disabled_errmsg(self, success):
        if not success:
            self.log.write("Check SV-77829r1_rule: ")
            self.log.write(
                "The Windows Remote Management (WinRM) client must not allow unencrypted traffic.\n\n")