import google.oauth2.credentials
import json
import os
import requests
from flask import Flask, make_response, redirect, request, render_template, session, url_for
from google.auth import jwt
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from oauthlib.oauth2 import WebApplicationClient


# gets CLIENT_ID, CLIENT_SECRET, and applicable uris from client_secrets json file downloaded from api console
def get_all():
    filename = "client_secrets.json"  # TODO: change filename/path to wherever secrets json file is located
    with open(filename) as file:
        data_dict = json.load(file)
    return data_dict['web']['client_id'], data_dict['web']['client_secret'], data_dict['web']['redirect_uris'][0]


# set up env vars
os.environ['FLASK_APP'] = "app"
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# set up OAuth2.0 client
CLIENT_ID, CLIENT_SECRET, REDIRECT_URI = get_all()
CLIENT = WebApplicationClient(CLIENT_ID)
GOOGLE_CCM_PUBLIC_CERT_URL = "https://www.googleapis.com/robot/v1/metadata/x509/cloud-commerce-partner@system.gserviceaccount.com"

# set up flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# specify scopes for when requesting authorization
# scopes can be changed to any applicable scopes that the app wants access to
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile"]
API_SERVICE = "people"
API_VERSION = "v1"


@app.route('/', methods=['GET', 'POST'])
def initiate_sso():
    """Verifies JWT based on requirements at
            https://cloud.google.com/marketplace/docs/partners/integrated-saas/frontend-integration#verify-jwt

    Returns:
        Redirect to SSO at /login or appropriate 401 response with error message
    """
    token = open("jwt_token", "r").readline()  # hardcoded token as do not have response yet from HTTP
    header, payload, signed_section, signature = jwt._unverified_decode(token)
    kid = header['kid']

    try:
        public_jwt_cert = json.loads(requests.get(GOOGLE_CCM_PUBLIC_CERT_URL).text)[kid]
    except ValueError:
        print("Specified kid does not match a public Google certificate. Generate a new JWT or try again.")
    aud = payload['aud']  # Put your API domain here
    try:
        # Verify JWT signature, exp claim, aud claim
        verified_payload = jwt.decode(token, certs=public_jwt_cert, verify=True, audience=aud)
    except ValueError as e:
        res = make_response(json.dumps('Could not verify token: '+str(e)), 401)
        res.headers['Content-Type'] = "application/json"
        return res

    # Verify iss claim and sub
    iss = payload['iss']
    sub = payload['sub']
    if iss == GOOGLE_CCM_PUBLIC_CERT_URL and sub is not None:
        user_identity = payload['google']['user_identity']
        return redirect((url_for('login', user_identity=user_identity)))
    else:
        res = make_response(json.dumps('Check iss and sub claim:\n'+payload), 401)
        res.headers['Content=Type'] = "application/json"
        return res


@app.route('/login', methods=['GET', 'POST'])
def login():
    flow = Flow.from_client_secrets_file(
        "client_secrets.json",
        scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    user_identity = request.args['user_identity']
    auth_url, state = flow.authorization_url(
        access_type="offline",
        login_hint=user_identity,
        prompt="consent",
        include_granted_scopeds="true")
    session['state'] = state
    return redirect(auth_url)


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    flow = Flow.from_client_secrets_file(
        "client_secrets.json",
        scopes=SCOPES)
    flow.redirect_uri = url_for("callback", _external=True)

    auth_response = request.url
    flow.fetch_token(authorization_response=auth_response)

    print("auth_response= ", auth_response)

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
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    return redirect(url_for('test_login'))


def get_name(profile):
    return profile['names'][0]['givenName']


# NOTE: People API must be enabled to view user information
@app.route('/test', methods=['GET', 'POST'])
def test_login():
    if "credentials" not in session:
        return redirect('login')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])

    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    service = build(API_SERVICE, API_VERSION, credentials=creds)
    profile = service.people().get(
        resourceName="people/me",
        personFields="names") \
        .execute()
    return render_template("home.html", name=get_name(profile))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
