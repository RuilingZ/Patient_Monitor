import unittest
import json
import sqlite3
import os
from chat_module import Chat

class TestChat(unittest.TestCase):
	def setUp(self):
		""" set up the data of the test file"""
		print("setUp")
		self.p = Chat()

		f = open("test_data.json")
		data = json.loads(f.read())

		self.user_id_list = []
		self.connect_id_list = []
		self.message_type_list = []
		self.content_list = []

		for key in data.keys():
			# user_id = int(data[key]["User_id"])
			# connect_id = int(data[key]["Connect_id"])
			# message_type = data[key]["Message_Type"]
			# content = data[key]["Content"]

			self.user_id_list.append(int(data[key]["User_id"]))
			self.connect_id_list.append(int(data[key]["Connect_id"]))
			self.message_type_list.append(data[key]["Message_Type"])
			self.content_list.append(data[key]["Content"])

	def test_check(self):
		""" test the check() function"""
		res = ["User_5_Records", "User_4_Records", "User_7_Records", "User_2_Records",
				"User4_User5", "User2_User7", "User2_User5"]
		for i in range(len(self.user_id_list)):
			res.append(self.p.check(self.user_id_list[i], self.connect_id_list[i]))

		message = " The check() doesn't work successfully."
		self.assertEqual(res, [True, True, None, True], message)

	def test_create_tables():
		""" test the create_tables() function"""
		tables = []

		for i in range(len(self.user_id_list)):
			self.p.create_tables(self.user_id_list[i], self.connect_id_list[i])

		

if __name__ == '__main__':
	unittest.main()
