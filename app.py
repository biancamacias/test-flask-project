from flask import Flask, make_response, session, render_template, url_for, redirect
import hashlib
import json
import os


# gets client_id and client_secret keys from client_secrets json file
def get_all():
    filename = "client_secrets.json"  # TODO: change filename/path to wherever secrets json file is located
    with open(filename) as file:
        data_dict = json.load(file)
    return data_dict['web']['client_id'], data_dict['web']['client_secret'], data_dict['web']['auth_uri'], \
           data_dict['web']['redirect_uris']


app = Flask(__name__)
app_name = "insert app name here"  # TODO: add your app name
client_id, client_secret, auth_uri, redirect_uri = get_all()
os.environ['FLASK_APP'] = "app"
