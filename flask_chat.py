from flask import Flask, redirect, url_for, render_template, request
#from flask_restful import Resource, Api, reqparse
import json
import sqlite3
import os
from chat_module.chat_module import Chat
import datetime
import requests
from application import application


	# application = Flask(__name__)
	# api = Api(application)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db = os.path.join(BASE_DIR, 'chat_table.db')

if os.path.exists('chat_table.db'):
	os.remove('chat_table.db')

p = Chat()
p.control('chat_module/dt.json')

col_records = ['Record_Num', 'From_id', 'To_id', 'Message_Type', 'Content', 'Time']
col_connect = ['Record_Times', 'From_id', 'To_id', 'Message_Type', 'Content', 'Time']
co = ['User_id', 'Connect_id', 'Message_Type', 'Content', 'Time']

# @application.route("/chat")
# def chat_home():
#  	return render_template("chat.html")

@application.route("/chat", methods=["POST", "GET"])
def chat():
	if request.method == "POST":
		user_id = int(request.form['User_id'])
		connect_id = int(request.form['Connect_id'])
		message_type = request.form['Message_Type']
		content = request.form['Content']
		#time = str(datetime.datetime.now())
		if(p.check(user_id, connect_id)):
			p.create_tables(user_id, connect_id)
			p.store_data(user_id, connect_id, message_type, content)
			data = {'Records':p.data_rec, 'Connects':p.data_con}
			return data

		else:
			return "things wrong"
	else:
			data = p.table_rec
			return render_template("chat.html", data = data)

# if __name__ == '__main__':
# 	application.run(debug=True)