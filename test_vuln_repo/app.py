import os
import pickle
from flask import Flask, request
import sqlite3

app = Flask(__name__)
SECRET_KEY = "my-super-secret-key-123"
DEBUG = True
OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP1234"

@app.route('/search')
def search():
    q = request.args.get('q')
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name = '{q}'")
    return str(cursor.fetchall())

@app.route('/run')
def run_code():
    code = request.args.get('code')
    return str(eval(code))

@app.route('/load')
def load_data():
    data = request.args.get('data')
    return str(pickle.loads(data.encode()))
