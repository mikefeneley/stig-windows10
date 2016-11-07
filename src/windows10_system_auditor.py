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
	def lan_manager_hash_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SYSTEM\CurrentControlSet\Control\Lsa", value = "NoLmHash"):
		"""
        Check SV-78287r1_rule: The system must be configured to prevent
        the storage of the LAN Manager hash of passwords.

        Finding ID: V-63797

        :returns: int -- True if the deployment path was found, False otherwise
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
			print(e)
			return False

	def remote_assistance_disabled(self, hive=HKEY_LOCAL_MACHINE, key= r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", value = "fAllowToGetHelp"):
		"""
        Check SV-78287r1_rule: The system must be configured to prevent
        the storage of the LAN Manager hash of passwords.

        Finding ID: V-63797

        :returns: int -- True if the deployment path was found, False otherwise

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
			print(e)
			return False


if __name__ == "__main__":
	auditor = Windows10SystemAuditor()
	auditor.audit()