import json
import requests
import os
from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
from functools import wraps
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode, quote_plus
from flask import Blueprint, request
from flask import Blueprint, request
from google.cloud import datastore


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

bp = Blueprint('boats', __name__, url_prefix='/boats')
BOATS = "boats"
client = datastore.Client()

CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")
ALGORITHMS = ["RS256"]
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

#change to bp? THIS USED TO BE APP.ERROHANDLER IF IT DOESNT WORK
@bp.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# Get and Post for boat entity
@bp.route('/', methods=['POST', 'GET', 'DELETE'])
def boats_post():
    if request.accept_mimetypes['application/json'] != True:
        return jsonify(error='Accept header is not json'), 406
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        query = client.query(kind=BOATS, filters=[('owner', '=', payload["sub"])]).fetch()
        for entity in query:
            client.delete(entity.key)
        return ('', 204)
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(BOATS))
        new_boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"], "owner": payload["sub"], "slip": None, "self": request.url_root + "boats/" + str(new_boat.key.id)})
        client.put(new_boat)
        return (new_boat, 201)
    elif request.method == 'GET':
            payload = verify_jwt(request)
            query = client.query(kind=BOATS, filters=[('owner', '=', payload["sub"])])
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + '/' + str(e.key.id)
            total_boats = list(query.fetch())
            output = {"boats": results}
            output["total"] = len(total_boats)
            if next_url:
                output["next"] = next_url
            return (output, 200)
        
    else:
        return jsonify(error='Method not recogonized')
    


@bp.route("/<boat_id>", methods=['DELETE', 'GET', 'PATCH', 'PUT'])
def delete_boat(boat_id):
    if request.accept_mimetypes['application/json'] != True:
        return jsonify(error='Accept header is not json'), 406
    
    if request.method == 'PUT':
        payload = verify_jwt(request)
        content = request.get_json()
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        
        if boat is None:
            return ({"Error": "There is no boat with this id"}, 404)
        if payload['sub'] != boat["owner"]:
            return ({"Error": "action not permitted"}, 403)    
        else:
            for key in content:
                boat.update({key: content[key]})
            client.put(boat)
            return ('', 204)
    if request.method == 'PATCH':
        payload = verify_jwt(request)
        content = request.get_json()
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        
        if boat is None:
            return ({"Error": "There is no boat with this id"}, 404)
        if payload['sub'] != boat["owner"]:
            return ({"Error": "action not permitted"}, 403)    
        else:
            boat.update({"name": content["name"], "type": content["type"],
          "length": content["length"]})
            client.put(boat)
            return ('', 204)
    if request.method == 'GET':
        payload = verify_jwt(request)
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        
        if boat is None :
            return ({"Error": "There is no boat with this id"}, 404)
        if payload['sub'] != boat["owner"]:
            return ({"Error": "action unauthorized"}, 403)    
        else:
            boat["id"] = boat.key.id
            boat["self"] = request.base_url + '/' + str(boat.key.id)
            return (boat, 200)
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        
        if boat is None:
            return ({"Error": "no boat with this id"}, 404)
        if payload['sub'] != boat["owner"]:
            return ({"Error": "not permitted"}, 403)    
        else:
            client.delete(boat_key)
            return ('', 204)