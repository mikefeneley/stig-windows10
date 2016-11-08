from _winreg import *

class Windows10SystemAuditor:
	def __init__(self):
		pass
	def audit(self):
		"""
		Entry function to all system defined requirments by the
		Windows 10 STIG.
		"""
		result = self.lan_manager_hash_disabled()
		
		result = self.remote_assistance_disabled()
		
		result = self.windows_installer_elevated_prviliges_disabled()

		result = self.non_volume_autoplay_disabled()

		result = self.annonymous_pipe_access_restricted()

		result = self.drive_autorun_disabled()

		result = self.autorun_commands_disabled()

		result = self.sam_anonymous_enumeration_disabled()

		result = self.sehop_disabled()

		result = self.recovery_console_enabled()

		result = self.lanman_auth_level_set()

		result = self.winrm_service_basic_auth_disabled()

		result = self.winrm_client_basic_auth_disabled()
	def lan_manager_hash_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Lsa", value = "NoLmHash"):
		"""
        Check SV-78287r1_rule: The system must be configured to prevent
        the storage of the LAN Manager hash of passwords.

        Finding ID: V-63797

        :returns: int -- True if criteria met, False otherwise
        """
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63797")
			return False

	def remote_assistance_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", value = "fAllowToGetHelp"):
		"""
        Check SV-78141r1_rule: Solicited Remote Assistance must not be allowed.


        Finding ID: V-63651

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """		
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 0:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63651")
			return False

	def windows_installer_elevated_prviliges_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows\Installer", value = "AlwaysInstallElevated"):
		"""
        Check SV-77815r1_rule: The Windows Installer Always install
        with elevated privileges must be disabled.


        Finding ID: V-63325

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """				

		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 0:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63325")
			return False

	def non_volume_autoplay_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows\Explorer", value = "NoAutoplayfornonVolume"):
		"""
        Check SV-78157r1_rule: Autoplay must be turned off for 
        non-volume devices.

        Finding ID: V-63667

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """				

		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63667")
			return False


	def annonymous_pipe_access_restricted(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters", value = "RestrictNullSessAccess"):
		"""
        Check SV-78249r1_rule: Anonymous access to Named Pipes and 
        Shares must be restricted.


        Finding ID: V-63759

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """				

		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63759")
			return False

	def drive_autorun_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters", value = "RestrictNullSessAccess"):
		"""
        Check SV-78163r1_rule: Autoplay must be disabled for all drives.

        Finding ID: V-63673

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 255:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63673")
			return False


	def autorun_commands_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", value = "NoAutorun"):
		"""
        Check SV-78163r1_rule: The default autorun behavior must be 
        configured to prevent autorun commands.

        Finding ID: V-63671

        :returns: int -- True if criteria met, False otherwise

        NOTE
        	Add registry key in test and verify it queries correctly.
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63671")
			return False

	def sam_anonymous_enumeration_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Lsa", value = "RestrictAnonymousSAM"):
		"""
        Check SV-78235r1_rule: Anonymous enumeration of SAM accounts must not 
        be allowed.


        Finding ID: V-63745

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63745")
			return False

	def sehop_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", value = "DisableExceptionChainValidation"):
		"""
        Check SV-83445r1_rule: Structured Exception Handling Overwrite 
        Protection (SEHOP) must be turned on.


        Finding ID: V-68849

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 0:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-68849")
			return False

	def recovery_console_enabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole", value = "SecurityLevel"):
		"""
        Check SV-78299r1_rule: The Recovery Console option must be set 
        to prevent automatic logon to the system.


        Finding ID: V-63809

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 0:
				disabled = True
			return disabled

		except Exception as e:
			print(e, "V-63809")
			return False


	def lanman_auth_level_set(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Lsa", value = "LmCompatibilityLevel"):
		"""
        Check SV-78291r1_rule: The LanMan authentication level must be 
        set to send NTLMv2 response only, and to refuse LM and NTLM.


        Finding ID: V-63801

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			option_set = False
			if query_val == 5:
				option_set = True
			return option_set

		except Exception as e:
			print(e, "V-63801")
			return False

	def winrm_service_basic_auth_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", value = "AllowBasic"):
		"""
        Check SV-77837r1_rule: The Windows Remote Management (WinRM) 
        service must not use Basic authentication.

        Finding ID: V-63347

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 5:
				option_set = True
			return option_set

		except Exception as e:
			print(e, "V-63347")
			return False

	def annonymous_share_enumeration_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Lsa", value = "RestrictAnonymous"):
		"""
        Check SV-78239r1_rule: Anonymous enumeration of shares must 
        be restricted.

        Finding ID: V-63749

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 1:
				option_set = True
			return option_set

		except Exception as e:
			print(e, "V-63749")
			return False

	def winrm_client_basic_auth_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Client", value = "AllowBasic"):
		"""
        Check SV-77825r1_rule: The Windows Remote Management (WinRM) 
        client must not use Basic authentication.

        Finding ID: V-63335

        :returns: int -- True if criteria met, False otherwise
        """				
		try:
			aReg  = ConnectRegistry(None, hive)
			key = OpenKey(aReg ,  key)
			query = QueryValueEx(key, value)
			query_val = query[0]

			disabled = False
			if query_val == 0:
				option_set = True
			return option_set

		except Exception as e:
			print(e, "V-63335")
			return False

if __name__ == "__main__":
	auditor = Windows10SystemAuditor()
	auditor.audit()