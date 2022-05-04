import unittest
import json
import sqlite3
import os
from device_module import Device

class TestDevice(unittest.TestCase):

	def setUp(self):
		""" set up the test data and the test method"""
		print("setUp")

		# self.db = os.path.join('device_module/', 'table.db')
		#self.BASE_DIR = os.path.dirname(os.path.abspath(__file__))
		#self.db = os.path.join(self.BASE_DIR, 'table.db')
		self.db = "table.db"
		self.js = os.path.join('device_module/', 'data.json')
		# self.js = "device_module/data.json"
		# self.db = "device_module/table.db"
		self.pyfile = 'python device_module/table.py'
		self.user_id_list = [1, 2]
		self.device_id_list = [3, 5]

		self.p = Device(self.js)

		f = open(self.js) # data.json
		self.data = json.loads(f.read())

		self.p.init(self.db, self.pyfile)
		#dir = 'device_module/'
		#db_name = 'table.db'


	def test_get_device(self):
		""" check the get device fuction"""
		user_id = []
		device_id = []
		role = []

		keys = list(self.data.keys())		
		for key in keys:
			self.p.get_device(key)
			user_id.append(self.p.user_id)
			device_id.append(self.p.device_id)
			role.append(self.p.role)

		message = " The get_device() doesn't work successfully."
		self.assertEqual(user_id, [1, 5, 8, 8], message)
		self.assertEqual(device_id, [3, 4.4, 9, 9], message)
		self.assertEqual(role, ["Patient", "Driver", "Doctor", "Doctor"], message)

	def test_create_device(self):
		# self.p.init(self.db, self.pyfile)
		self.p.control(self.db, self.pyfile)

		conn = sqlite3.connect(self.p.db) # table.db
		cur = conn.cursor()

		# test Users table
		msg1 = "The 'Users' table is not created successfully."
		test_Users = [(1, 'AA', '07/28/99', 'Patient', 'Female'), (2, 'BB', '06/18/99', 'Doctor', 'Male'), (8, 'CC', '02/18/97', 'Doctor', 'Male')]
		Users = []
		for u in cur.execute('SELECT * FROM Users'):
			Users.append(u)
		self.assertEqual(Users, test_Users, msg1)

		# test Devices table
		msg2 = "The 'Devices' table is not created successfully."
		test_Devices = [(3, '00:00:5e:00:53:af', '03/01/22', 1, '1.3.4'), 
					(5, '00:00:44:00:53:ab', '02/01/22', 1, '1.8.9'), 
					(9, '12:00:5e:00:53:af', '12/28/21', 1, '1.4.4')]
		Devices = []
		for d in cur.execute('SELECT * FROM Devices'):
			Devices.append(d)
		self.assertEqual(Devices, test_Devices, msg2)

		# test Measyrements table
		msg3 = "The 'Measurements' table is not created successfully."
		test_Measurements = [(1, 50.2, 164.0, 36.4, 110.0, 75.0, 70.0, 97.0, 7.4), 
							  (2, 63.0, 173.0, 35.7, 113.0, 77.0, 88.0, 96.0, 8.2), 
							  (8, 74.0, 180.0, 36.1, 112.0, 80.0, 70.0, 99.0, 7.3)]
		Measurements = []
		for m in cur.execute('SELECT * FROM Measurements'):
			Measurements.append(m)
		self.assertEqual(Measurements, test_Measurements, msg2)

		# test Assignments table
		msg4 = "The 'Assignments' table is not created successfully."
		test_Assignments = [(3, 1, 5, '03/02/22'), 
							(5, 2, 7, '02/04/22'), 
							(9, 8, 8, '01/02/22')]
		Assignments = []
		for a in cur.execute('SELECT * FROM Assignments'):
			Assignments.append(a)
		self.assertEqual(Assignments, test_Assignments, msg2)       

		# test Storage table
		msg5 = "The 'Storage' table is not created successfully."
		test_Storage = [(1, 1, 3, 'Patient'), 
					(2, 2, 5, 'Doctor'), 
					(3, 8, 9, 'Doctor')]
		Storage = []
		for s in cur.execute('SELECT * FROM Storage'):
			Storage.append(s)
		self.assertEqual(Storage, test_Storage, msg5)


if __name__ == '__main__':
	# js = "device_module/data.json"
	# db = "device_module/table.db"
	# p = Device("data.json")
	# p = Device(js)
	unittest.main()