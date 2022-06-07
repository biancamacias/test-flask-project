from flask import Flask, abort, redirect, request, url_for, render_template, session
from oauthlib.oauth2 import WebApplicationClient
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip_vendor import cachecontrol
import google.auth.transport.requests
import hashlib
import json
import os
import pathlib
import requests


# gets client_id and client_secret keys from client_secrets json file
def get_all():
    filename = "client_secrets.json"  # TODO: change filename/path to wherever secrets json file is located
    with open(filename) as file:
        data_dict = json.load(file)
    return data_dict['web']['client_id'], data_dict['web']['client_secret'], data_dict['web']['auth_uri'], \
           data_dict['web']['redirect_uris']


app = Flask(__name__)
discovery_url = ""
app_name = "insert app name here"  # TODO: add your app name
client_id, client_secret, auth_uri, redirect_uri = get_all()
os.environ['FLASK_APP'] = "app"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
client = WebApplicationClient(client_id)
state = hashlib.sha256(os.urandom(1024)).hexdigest()
flow = Flow.from_client_secrets_file(client_secrets_file="client_secrets.json",
                                     scopes=["https://www.googleapis.com/auth/userinfo.profile",
                                             "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri=redirect_uri)


def login_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    session['state'] = state
    return redirect(auth_uri)


@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    req_session = requests.session()
    cached_session = cachecontrol.CacheControl(req_session)
    token_req = google.auth.transport.requests.Request(session=cached_session)

    info = id_token.verify_oauth2_token(id_token=credentials.id_token, request=token_req, audience=client_id)

    session["google_id"] = info.get("sub")
    session["name"] = info.get("name")
    return redirect("/in")


@app.route("/in")
@login_required
def logged_in():
    return render_template("home.html", name=session["name"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
