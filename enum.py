# Enum class I wrote for another project

class Enum(object):
	"""This class is the base of all C style Enum classes"""

	@classmethod
	def to_string(cls, val):
		"""Convert a enum value to the string name"""
		for k,v in vars(cls).iteritems():
			if v==val:
				return k
		return "Unknown (%d)" % val

	@classmethod
	def to_string_list(cls, vals, join_on = ", "):
		"""Converts a list of enum values to a string containing their names"""
		strings = []
		for v in vals:
			strings.append(cls.to_string(v))
		return join_on.join(strings)

	@classmethod
	def from_string(cls, key):
		"""Convert a string to one of the enum values"""
		key = key.upper()
		for k, v in vars(cls).iteritems():
			if k.upper()==key:
				return v
		return -1

	@classmethod 
	def is_valid_item(cls, val):
		"""Returns whether or not the value is an item in the enum"""
		for k, v in vars(cls).iteritems():
			if type(v) == int and v == val:
				return True
		return False

	@classmethod
	def get_string_list(cls, join_on = ", "): 
		values = []
		for key, value in vars(cls).iteritems():
			if type(value) == int:
				values.append(key)
		values.sort()
		return join_on.join(values)

	@classmethod
	def define_enum_from_string_list(cls, name, string_list):
		values = {}
		for string in string_list:
			values[string.upper()] = len(values)
		new_enum = type(name, (cls,), values)
		__builtins__[name] = new_enum #probably a better place to put this than builtins, but we want it to be accessible outside this file
		return new_enum

	@classmethod
	def max_value(cls):
		max_value = -1
		for key, value in vars(cls).iteritems():
			if type(value) == int and value > max_value:
				max_value = value
		return max_value

class BitmaskEnum(Enum):
	CombinedValues = []

	@classmethod 
	def to_string(cls, val):
		"""Convert a string to one of the enum values"""
		output = []
		max_shift = 0
		for k,v in vars(cls).iteritems():
			if type(v) == int and k not in cls.CombinedValues and v > max_shift:
				max_shift = v
		for i in range(max_shift+1):
			output.append("-")
		for k,v in vars(cls).iteritems():
			if type(v) == int and k not in cls.CombinedValues and (1 << v) & val != 0:
				output[v] = k
		return "".join(output)

	@classmethod
	def from_string(cls, key):
		key = key.upper()
		val = 0
		for k, v in vars(cls).iteritems():
			if key.find(k) != -1 and k not in cls.CombinedValues:
				val |= (1 << v)
		return val

	@classmethod
	def combine(cls, key, values):
		"""Defines a shortcut combination of two bitmask values into one.
			@key = the new key to define
			@values = The bitmasks to include in the new one
		  Example: BitmaskEnum.combine("AB", [BitmaskEnum.A, BitmaskEnum.B]) creates a value BitmaskEnum.AB that contains both
			values A and B
		"""
		val = 0
		for value in values:
			val |= (1 << value)
		cls.CombinedValues.append(key)
		setattr(cls, key, val)

	@classmethod
	def is_set(cls, bitmask, bit):
		"""Tests if a particular bit is set in a bitmask"""
		return (bitmask & (1 << bit)) != 0


