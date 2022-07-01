import json
import requests
from google.auth import jwt

GOOGLE_CCM_PUBLIC_CERT_URL = "https://www.googleapis.com/robot/v1/metadata/x509/cloud-commerce-partner@system.gserviceaccount.com"


def verify_jwt(token):
    """Verifies JWT based on requirements at
        https://cloud.google.com/marketplace/docs/partners/integrated-saas/frontend-integration#verify-jwt

    Args:
      token: JWT token in string format

    Returns:
      Payload of decoded and verified JWT in JSON format
    """
    header, payload, signed_section, signature = jwt._unverified_decode(token)

    kid = header['kid']
    try:
        public_jwt_cert = json.loads(requests.get(GOOGLE_CCM_PUBLIC_CERT_URL).text)[kid]
    except ValueError:
        print("Specified kid does not match a public Google certificate. Generate a new JWT or try again.")
    aud = payload['aud']  # TODO: your api domain here
    return jwt.decode(token, certs=public_jwt_cert, verify=True, audience=aud)


def main():
    with open("jwt_token") as file:
        token = file.readline()
    verified_payload = verify_jwt(token)
    print(verified_payload)


main()
