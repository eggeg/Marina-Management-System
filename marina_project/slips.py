from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
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

bp = Blueprint('slip', __name__, url_prefix='/slips')
CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")
ALGORITHMS = ["RS256"]
client = datastore.Client()
slips = "slips"
boats = "boats"

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


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


@bp.route('/', methods=['POST','GET', 'DELETE'])
def slips_get_post():
    if request.accept_mimetypes['application/json'] != True:
        return jsonify(error='Accept header is not json'), 406
    
    if request.method == 'DELETE':
        return jsonify(error='Method not recognized'), 405
    
    if request.method == 'POST':
        content = request.get_json()
        new_slip = datastore.entity.Entity(key=client.key(slips))
        new_slip.update({
            "size": content["size"],
            "price": content["price"],
            "condition": content["condition"],
            "current_boat": None,
            "self": request.url + "/" + str(new_slip.key.id)
            })
        client.put(new_slip)
        new_slip["id"] = new_slip.key.id
        return new_slip, 201
    
    elif request.method == 'GET':
        query = client.query(kind=slips)
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
        total_slips = list(query.fetch())
        output = {"slips": results}
        output["total"] = len(total_slips)
        if next_url:
            output["next"] = next_url
        return (output, 200)
    else:
        return jsonify(error='Method not recognized')
    
@bp.route('/<slip_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def get_slip(slip_id):
    slip_key = client.key(slips, int(slip_id))
    slip = client.get(key=slip_key)
    
    if slip is None:
        return {"Error": "No slip with this slip_id exists"}, 404
    
    if request.accept_mimetypes['application/json'] != True:
        return jsonify(error='Accept header is not json'), 406
    
    if request.method == 'GET':
        slip_key = client.key(slips, int(slip_id))
        slip = client.get(key=slip_key)
        slip["id"] = slip.key.id
        return slip
    elif request.method == 'DELETE':
        key = client.key(slips, int(slip_id))
        client.delete(key)
        return ('',204)
    elif request.method == 'PUT':
        content = request.get_json()
        slip_key = client.key(slips, int(slip_id))
        slip = client.get(key=slip_key)
        
        if slip is None:
            return {"Error": "No slip with this slip_id exists"}, 404   
        else:
            for key in content:
                slip.update({key: content[key]})
            client.put(slip)
        return ('',204)
    
    elif request.method == 'PATCH':
        content = request.get_json()
        slip_key = client.key(slips, int(slip_id))
        slip = client.get(key=slip_key)
        
        if slip is None:
            return {"Error": "No slip with this slip_id exists"}, 404   
        else:
            for key in content:
                slip.update({key: content[key]})
            client.put(slip)
        return ('',204)
    else:
        return {"Error": "No slip with this slip_id exists"}, 404
    
@bp.route('/<slip_id>/<boat_id>', methods=['PUT'])
def boat_arrives(slip_id, boat_id):
    if request.accept_mimetypes['application/json'] != True:
        return jsonify(error='Accept header is not json'), 406
    
    if request.method == 'PUT':
        payload = verify_jwt(request)
        slip_key = client.key(slips, int(slip_id))
        slip = client.get(key=slip_key)
        
        boat_key = client.key(boats, int(boat_id))
        boat = client.get(key=boat_key)
        
        if slip is None or boat is None:
            return {"Error":"The specified boat and/or slip does not exist"}, 404
        if payload['sub'] != boat["owner"]:
            return ({"Error": "action not permitted"}, 403)
        
        if "current_boat" in slip and slip["current_boat"] is not None:
            return json.dumps({"Error": "The slip is not empty"}), 403
        else:
            slip.update({"current_boat": int(boat_id)})
            client.put(slip)
            return ('', 204)
        
@bp.route('/<slip_id>/<boat_id>', methods=['DELETE'])
def boat_departs(slip_id, boat_id):     
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        slip_key = client.key(slips, int(slip_id))
        slip = client.get(key=slip_key)
        
        boat_key = client.key(boats, int(boat_id))
        boat = client.get(key=boat_key)
        
        #print(slip["current_boat"], boat_id)
        
        if slip is None or boat is None:
            return {"Error": "No boat with this boat_id is at the slip with this slip_id"}, 404
        if payload['sub'] != boat["owner"]:
            return ({"Error": "action not permitted"}, 403)
        
        if "current_boat" in slip:
            print(type(slip["current_boat"]), type(boat.key.id))
            print(slip["current_boat"], boat.key.id)

            if slip["current_boat"] != boat.key.id:
                return {"Error": "No boat with this boat_id is at the slip with this slip_id"}, 404
            else:
                slip.update({"current_boat": None})
                client.put(slip)
                return ('', 204)  
        else:
            return {"Error": "No boat with this boat_id is at the slip with this slip_id"}, 404 
