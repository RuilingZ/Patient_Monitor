from flask import Flask, redirect, url_for, render_template, request, flash
#from flask_restful import Resource, Api, reqparse
import json
import sqlite3
import os

from sqlalchemy.dialects.mysql import pymysql

from device_module.device_module import Device
from application import application

#application = Flask(__name__)
# api = Api(application)

os.system('python device_module/table.py')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
#db = os.path.join(BASE_DIR, '../device_module/table.db')
db = os.path.join(BASE_DIR, 'table.db')

col_users = ['User_id', 'Name', 'Date_of_Birth', 'Roles', 'Gender']
col_devices = ['Device_id', 'MAC', 'Date_of_Purchase', 'User_id', 'Fir_ver']
col_measurements = ['User_id', 'Weight', 'Height', 'Temperature', 'Systolic_Pressure', 'Diastolic_Pressure', 'Pulse', 'Oximeter', 'Glucometer']
col_assignments = ['Device_id', 'User_id', 'Assigner_id', 'Date_Assigned']
col_storage = ['Premission', 'User_id', 'Device_id', 'Roles']

def insert_data(table, new_data):
	data = tuple(list(new_data[table].values()))

	conn = sqlite3.connect(db) # table.db
	cur = conn.cursor()

	if(table == "Users"):
		sql_statement = 'INSERT INTO Users VALUES (?, ?, ?, ?, ?)'
		cur.executemany(sql_statement, [data])

	elif(table == "Devices"):
		sql_statement = 'INSERT INTO Devices VALUES (?, ?, ?, ?, ?)'
		cur.executemany(sql_statement, [data])

	elif(table == "Measurements"):
		sql_statement = 'INSERT INTO Measurements VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
		cur.executemany(sql_statement, [data])

	elif(table == "Assignments"):
		sql_statement = 'INSERT INTO Assignments VALUES (?, ?, ?, ?)'
		cur.executemany(sql_statement, [data])

	else:
		print("there is something wrong, please check your information")

	conn.commit()
	conn.close

def get_data(table, col):
	con = sqlite3.connect(db)
	con.row_factory = sqlite3.Row
	cur = con.cursor()
	num = 1
	data = {}

	for row in cur.execute(f'SELECT * FROM {table}'):
		dic = {}
		for i in range(len(row)):
			dic[col[i]] = row[i]				
		data[f'number {num} user'] = dic
		num += 1

	con.commit()
	con.close
	return data

@application.route('/index')
def index():
    return render_template('index1.html')

# set as part of the config
SECRET_KEY = 'many random bytes'

# or set directly on the app
application.secret_key = 'many random bytes'

#获取登录参数及处理
@application.route('/login', methods=["POST", "GET"])
def Login():
	#username = request.form.get('username')
	#print("name" + username)
	#password = request.form.get('password')
	#error = None
	if request.method == 'POST':
		if request.form['username'] == 'admin' or request.form['password'] == 'admin':
			#flash('login success', 'success')
			return render_template('index1.html')
		else:
			flash('Wrong username or passport')
			#get_flashed_messages('Wrong username or passport','danger')
			#return redirect(url_for('Login'))
			#return redirect(url_for('index'))
	return render_template('login.html')

@application.route('/register', methods=['GET','post'])
def register():
	if request.method == 'POST':
		if request.form['username'] == 'admin' or request.form['password'] == 'admin' or 1:
			return render_template('index1.html')
	#regname = request.form['username']
	#regpass = request.form['password']
	return render_template('register.html')

@application.route('/logout')
def logout():
    return render_template('index.html')

@application.route("/create", methods=["POST", "GET"])
def Storage():
	if request.method == "POST":
		# user_id = int(request.form['User_id'])
		# device_id = int(request.form['Device_id'])
		# role = request.form['Roles']
		#time = str(datetime.datetime.now())
		new_data = {"Storage":{'User_id': int(request.form['User_id']),
					'Device_id': int(request.form['Device_id']),
					'Roles': request.form['Roles']}}
		new_json = json.dumps(new_data)

		with open('new_json.json', 'w') as outfile:
			json.dump(new_json, outfile)

		p = Device('new_json.json')
		#p.importdb("table.db")
		p.importdb(db)
		p.user_id = int(request.form['User_id'])
		p.device_id = int(request.form['Device_id'])
		p.role = request.form['Roles']
		#p.get_device(0)

		p.check_user_id()
		p.check_device_id()
		p.check_role()
		if ((p.check_user_id() and p.check_device_id() and p.check_role())!=True):
			return "There is something wrong in your infomation, please check it."
		
		conn = sqlite3.connect(db) # table.db
		cur = conn.cursor()
		cur.execute(f'INSERT INTO Storage VALUES ((SELECT MAX(Premission) + 1 FROM Storage),{p.user_id}, {p.device_id}, "{p.role}")')

		conn.commit()
		conn.close

		return new_data
	else:
			data = get_data("Storage", col_storage)
			return render_template("storage.html", data = data)

@application.route("/users", methods=["POST", "GET"])
def Users():
	if request.method == "POST":
		new_data = {"Users":{'User_id': int(request.form['User_id']),
					'Name': request.form['Name'],
					'Date_of_Birth': request.form['Date_of_Birth'],
					'Roles': request.form['Roles'],
					'Gender': request.form['Gender']}}

		insert_data("Users", new_data)

		return new_data
	else:
			data = get_data("Users", col_users)
			return render_template("users.html", data = data)

@application.route("/devices", methods=["POST", "GET"])
def Devices():
	if request.method == "POST":
		new_data = {"Devices":{'Device_id': int(request.form['Device_id']),
					'MAC': request.form['MAC'],
					'Date_of_Purchase': request.form['Date_of_Purchase'],
					'User_id': int(request.form['User_id']),
					'Fir_ver': request.form['Fir_ver']}}

		insert_data("Devices", new_data)

		return new_data
	else:
			data = get_data("Devices", col_devices)
			return render_template("devices.html", data = data)

@application.route("/measurements", methods=["POST", "GET"])
def Measurements():
	if request.method == "POST":
		new_data = {"Measurements":{'User_id': int(request.form['User_id']),
					'Weight': float(request.form['Weight']),
					'Height': float(request.form['Height']),
					'Temperature': float(request.form['Temperature']),
					'Systolic_Pressure': float(request.form['Systolic_Pressure']),
					'Diastolic_Pressure': float(request.form['Diastolic_Pressure']),
					'Pulse': float(request.form['Pulse']),
					'Oximeter': float(request.form['Oximeter']),
					'Glucometer': float(request.form['Glucometer'])}}

		insert_data("Measurements", new_data)

		return new_data
	else:
			data = get_data("Measurements", col_measurements)
			return render_template("measurements.html", data = data)

@application.route("/assignments", methods=["POST", "GET"])
def Assignments():
	if request.method == "POST":
		new_data = {"Assignments":{'Device_id': int(request.form['Device_id']),
					'User_id': int(request.form['User_id']),
					'Assigner_id': int(request.form['Assigner_id']),
					'Date_Assigned': request.form['Date_Assigned'],
					}}

		insert_data("Assignments", new_data)

		return new_data
	else:
			data = get_data("Assignments", col_assignments)
			return render_template("assignments.html", data = data)

# if __name__ == '__main__':
# 	application.run(debug=True)  # run our Flask app