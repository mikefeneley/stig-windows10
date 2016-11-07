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
        Check SV-78249r1_rule: Autoplay must be turned off for 
        non-volume devices.

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

if __name__ == "__main__":
	auditor = Windows10SystemAuditor()
	auditor.audit()