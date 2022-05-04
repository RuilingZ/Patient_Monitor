import sqlite3
import os

# dbfile = os.path.join('device_module/', 'table.db')
if os.path.exists('table.db'):
    os.remove('table.db')

conn = sqlite3.connect('table.db')
cur = conn.cursor()

cur.execute('CREATE TABLE Users(User_id INTEGER PRIMARY KEY, Name TEXT, Date_of_Birth TEXT, Roles TEXT, Gender TEXT)')
cur.execute('CREATE TABLE Devices(Device_id INTEGER PRIMARY KEY, MAC TEXT, Date_of_Purchase TEXT, User_id INTEGER, Fir_ver TEXT)')
cur.execute('CREATE TABLE Measurements(User_id INTEGER PRIMARY KEY, Weight REAL, Height REAL, Temperature REAL, Systolic_Pressure REAL, Diastolic_Pressure REAL, Pulse REAL, Oximeter REAL, Glucometer REAL)')
cur.execute('CREATE TABLE Assignments(Device_id INTEGER PRIMARY KEY, User_id INTEGER, Assigner_id INTEGER, Date_Assigned TEXT)')
cur.execute('CREATE TABLE Storage(Premission INTEGER PRIMARY KEY AUTOINCREMENT, User_id INTEGER, Device_id INTEGER, Roles TEXT)')

cur.execute('INSERT INTO Users VALUES(1, "AA", "07/28/99", "Patient", "Female")')
cur.execute('INSERT INTO Users VALUES(2, "BB", "06/18/99", "Doctor", "Male")')

cur.execute('INSERT INTO Devices VALUES(3, "00:00:5e:00:53:af", "03/01/22", 1, "1.3.4")')
cur.execute('INSERT INTO Devices VALUES(5, "00:00:44:00:53:ab", "02/01/22", 2, "1.8.9")')

cur.execute('INSERT INTO Measurements VALUES(1, 50.2, 164, 36.4, 110, 75, 70, 97, 7.4)')
cur.execute('INSERT INTO Measurements VALUES(2, 63, 173, 35.7, 113, 77, 88, 96, 8.2)')

cur.execute('INSERT INTO Assignments VALUES(3, 1, 5, "03/02/22")')
cur.execute('INSERT INTO Assignments VALUES(5, 2, 7, "02/04/22")')

cur.execute('INSERT INTO Storage VALUES(01, 1, 3, "Patient")')
cur.execute('INSERT INTO Storage VALUES(02, 2, 5, "Doctor")')

conn.commit()
conn.close