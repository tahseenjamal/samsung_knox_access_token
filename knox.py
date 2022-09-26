import requests, json, jwt, uuid, time

# fetch client id from client id file
def client_id_from_json_file(filename):
    return json.load(open(filename))['clientid']

# fetch json data from certificate json file
def certificate_file_to_json(filename):
    return json.load(open(filename))

# fetch public key from the certificate json
def public_key_from_certificate_json(certificate_json):
    return certificate_json['Public']

# from certificate json, fetch private key string and convert it into pem
def private_pem_from_certificate_json(certificate_json):

    key = certificate_json['Private']
    pem = ''
    final_pem = '-----BEGIN PRIVATE KEY-----\n{}-----END PRIVATE KEY-----'
    pem += ''.join([f"{key[i*64:(i+1)*64]}\n" for i in range(len(key)//64+1)])
    return final_pem.format(pem)


# Return signed client id jwt token
def signed_clientid_jwt(client_id, public_key, expiration_minutes):

    payload={"clientIdentifier" : client_id,
            "publicKey" : public_key,
            "aud": "KnoxWSM",
            "iat" : int(time.time()),
            "exp": int(time.time()) + expiration_minutes * 60,
            "jti" : str(uuid.uuid1()) + str(uuid.uuid1())}

    return jwt.encode(payload=payload, key=private_pem, algorithm="RS512")


# Return access token by calling knox API
def access_token_request(client_id, public_key, minutes):

    client_identifier_jwt = signed_clientid_jwt(client_id, public_key, minutes)

    json_data = {'clientIdentifierJwt' : client_identifier_jwt, 'base64EncodedStringPublicKey' : public_key}

    res = requests.post('https://eu-kcs-api.samsungknox.com/ams/v0/users/accesstoken', json=json_data)

    if res.status_code == 200:

        return res.json()['accessToken']

    else:

        print("Access Token Error:", res.status_code)

        return None

# Use access token, public key and private pem to return signed access jwt 
def signed_access_token(access_token, public_key, private_pem):

    payload = {
        'accessToken' : access_token,
        'publicKey' : public_key,
    }

    return jwt.encode( payload=payload, key=private_pem, algorithm="RS512")


# Return device information by calling Knox API
def device_info(access_token, public_key, page_number, page_size, imei):

    signedAccessToken = signed_access_token(access_token, public_key, private_pem)

    headers = {"x-knox-apitoken" : signedAccessToken, "Content-Type" : "application/json"} 

    json_data = {"pageNum": page_number, "pageSize": page_size, "search": imei}

    res = requests.post('https://eu-kcs-api.samsungknox.com/kcs/v1.1/kg/devices/list', json=json_data, headers=headers)
    
    if res.status_code == 200:

        return res.json()

    else:

        print("Device information error", res.status_code)

        return None



client_id_filename = 'clientid.json' # File json content -> {"clientid" : "YOU CLIENT ID"}
certificate_filename = 'certificate.json' # File generated from Knox portal
access_token_expiration_minutes = 30

client_id = client_id_from_json_file(client_id_filename)
certificate_json = certificate_file_to_json(certificate_filename)

private_pem = private_pem_from_certificate_json(certificate_json)
public_key = public_key_from_certificate_json(certificate_json)


access_token = access_token_request(client_id, public_key, access_token_expiration_minutes)

page_number = 0
page_size = 100
imei = 353430750057657

device_info = device_info(access_token, public_key, page_number, page_size, imei)

print(device_info)





