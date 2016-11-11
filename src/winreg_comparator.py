from _winreg import *


class WinRegComparator:
	def __init__(self):
		pass

	def reg_equals(self, computer_name=None, key=None, subkey=None, key_val=None, val=-1):
		
		"""
		Check if a key with a specific value exists in the windows registry.


        :param computer_name: The computer whose operating system we are checking.
        :type computer_name: 
        :param key: The predefined handle to connect to.
        :type key: predefined key handle constant
        :param subkey: Name of the sub key we want to open
        :type subkey: String
        :param key_val: Value in the subkey we want to query
        :type key_val:	String
        :param val: Value we are checking the registry for
        :type val: int
        :returns: int -- True if the registry value exists and equals val. False otherwise.
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

	def reg_less_than(self, computer_name=None, key=None, subkey=None, key_val=None, val=-1):
		
		"""
		Check if a key with a specific value exists in the windows registry.


        :param computer_name: The computer whose operating system we are checking.
        :type computer_name: 
        :param key: The predefined handle to connect to.
        :type key: predefined key handle constant
        :param subkey: Name of the sub key we want to open
        :type subkey: String
        :param key_val: Value in the subkey we want to query
        :type key_val:	String
        :param val: Value we are checking the registry for
        :type val: int
        :returns: int -- True if the registry value exists and equals val. False otherwise.
		"""
		try:
			aReg  = ConnectRegistry(None, key)
			open_key = OpenKey(aReg ,  subkey)
			query = QueryValueEx(open_key, key_val)
			query_val = query[0]
			equal = False
			if query_val < val:
				equal = True
			return equal
		except Exception as e:
			print(e)
			return False

	def reg_greater_than(self, computer_name=None, key=None, subkey=None, key_val=None, val=-1):
		
		"""
		Check if a key with a specific value exists in the windows registry.


        :param computer_name: The computer whose operating system we are checking.
        :type computer_name: 
        :param key: The predefined handle to connect to.
        :type key: predefined key handle constant
        :param subkey: Name of the sub key we want to open
        :type subkey: String
        :param key_val: Value in the subkey we want to query
        :type key_val:	String
        :param val: Value we are checking the registry for
        :type val: int
        :returns: int -- True if the registry value exists and equals val. False otherwise.
		"""
		try:
			aReg  = ConnectRegistry(None, key)
			open_key = OpenKey(aReg ,  subkey)
			query = QueryValueEx(open_key, key_val)
			query_val = query[0]
			equal = False
			if query_val > val:
				equal = True
			return equal
		except Exception as e:
			print(e)
			return False
