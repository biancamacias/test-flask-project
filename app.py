import flask
from flask import Flask, abort, make_response, redirect, request, render_template, session, url_for
from oauthlib.oauth2 import WebApplicationClient
from google_auth_oauthlib.flow import Flow
# from googleapiclient.discovery import build
import json
import os


# gets CLIENT_ID, CLIENT_SECRET, and applicable uris from client_secrets json file downloaded from api console
def get_all():
    filename = "client_secrets.json"  # TODO: change filename/path to wherever secrets json file is located
    with open(filename) as file:
        data_dict = json.load(file)
    return data_dict['web']['client_id'], data_dict['web']['client_secret'], data_dict['web']['redirect_uris'][0]


# set up env vars
os.environ['FLASK_APP'] = "app"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# set up flask
app = Flask(__name__)

# set up OAuth2.0 client
CLIENT_ID, CLIENT_SECRET, REDIRECT_URI = get_all()
CLIENT = WebApplicationClient(CLIENT_ID)

# obtain user info and use scopes to identify app and specify scopes for requesting authorization
# scopes can be changed to any applicable scopes that the app wants access to
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile"]
flow = Flow.from_client_secrets_file(
    "client_secrets.json",
    scopes=SCOPES)


def login_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    flow.redirect_uri = REDIRECT_URI
    auth_url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopeds="true")
    session['state'] = state
    return redirect(auth_url)


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    flow.redirect_uri = url_for("oauth2callback", _external=True)

    auth_response = request.url
    flow.fetch_token(authorization_response=auth_response)

    # verify state received matches session token
    if session['state'] != request.args['state']:
        res = make_response(json.dumps('Invalid state'), 401)
        res.headers['Content-Type'] = "application/json"
        return res

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'CLIENT_ID': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    return redirect(url_for('test'))


@app.route('/test', methods=['GET', 'POST'])
@login_required
def test_login():
    if "credentials" not in session:
        return redirect('login')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    # profile =

    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'CLIENT_ID': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    creds = session['credentials']

    # serv = build("oauth2", "", credentials=creds)
    # user = serv.userinfo().get().execute()

    return render_template("home.html")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect("/")
