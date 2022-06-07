import flask
from flask import Flask, abort, redirect, request, render_template, session, url_for
from oauthlib.oauth2 import WebApplicationClient
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import cachecontrol
import google.auth.transport.requests
import json
import os
import requests


# gets client_id, client_secret, and applicable uris from client_secrets json file downloaded from gcp
def get_all():
    filename = "client_secrets.json"  # TODO: change filename/path to wherever secrets json file is located
    with open(filename) as file:
        data_dict = json.load(file)
    return data_dict['web']['client_id'], data_dict['web']['client_secret'], data_dict['web']['auth_uri'], \
           data_dict['web']['redirect_uris'][0]


# set up env vars
os.environ['FLASK_APP'] = "app"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# set up flask
app = Flask(__name__)

# set up OAuth2.0 client
discovery_url = ""
client_id, client_secret, auth_uri, redirect_uri = get_all()
client = WebApplicationClient(client_id)

# obtain user info and use scopes to identify app and specify scopes for requesting authorization
scps = []
flow = Flow.from_client_secrets_file(
    'client_secrets.json',
    scopes=scps)


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
    flow.redirect_uri = redirect_uri
    auth_url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopeds="true")
    print(auth_url)
    return redirect(auth_url)


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    curr_state = session['state']
    flow.redirect_uri = url_for("oauth2callback", _external=True)

    auth_response = request.url
    flow.fetch_token(authorization_response=auth_response)

    if session['state'] != request.args['state']:
        abort(500)

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    # flow.fetch_token(authorization_response=request.url)
    # if not session["state"] == request.args["state"]:
    #     abort(500)
    #
    # credentials = flow.credentials
    # req_session = requests.session()
    # cached_session = cachecontrol.CacheControl(req_session)
    # token_req = google.auth.transport.requests.Request(session=cached_session)
    #
    # info = id_token.verify_oauth2_token(id_token=credentials.id_token, request=token_req, audience=client_id)
    #
    # session["google_id"] = info.get("sub")
    # session["name"] = info.get("name")
    # return redirect("/in")


@app.route("/in", methods=['GET', 'POST'])
@login_required
def logged_in():
    return render_template("home.html", name=session["name"])


@app.route("/logout", methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect("/")
