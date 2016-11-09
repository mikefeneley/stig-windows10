from _winreg import *


class WinRegComparator:
	def __init__(self):
		pass

	def reg_equals(self, computer_name=None, key=None, subkey=None, key_val=None, val=-1):
		
		"""
		
        :param hive: The default directory to search for the properties file
        :type direc: string
        :param key: The name of the default properties file
        :type key: string
        :returns: int -- 1 if the file is found, 0 otherwise

		"""
		try:
			aReg  = ConnectRegistry(None, key)
			open_key = OpenKey(aReg ,  subkey)
			query = QueryValueEx(open_key, key_val)
			query_val = query[0]
			equal = False
			if query_val == val:
				equal = True
			return equal
		except Exception as e:
			print(e)
			return False