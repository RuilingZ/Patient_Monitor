from flask import Flask, redirect, url_for, render_template, request
#from flask_restful import Resource, Api, reqparse
import json
import sqlite3
import os
import requests
import datetime

application = Flask(__name__)
#api = Api(application)

@application.route("/")
def home():
	return render_template("index.html")


from flask_chat import *
from flask_device import *


if __name__ == '__main__':
	application.run(debug=True)