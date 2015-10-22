import hmac
import hashlib
import base64
import urllib
import json
import requests
from collections import OrderedDict
import logging
import copy

#############################################
# is_valid_registration_notification
#############################################
def is_valid_registration_notification(payload, clientSecret=None):
    """
    This method implements the Jive logic to validate if an add-on registration request originates from an authentic Jive instance.
     
    Arguments:
    1) payload (REQUIRED) - The JSON structure (not a string) Jive sends to the register_url and unregister_url defined in your add-on's meta.json
    { 
        "clientId" : "xxxxx",
        "tenantId" : "xxxxx",
        "jiveSignatureURL" : "xxxxx",
        "clientSecret" : "xxxxx",
        "jiveSignature" : "xxxxx",
        "jiveUrl" : "xxxxx",
        "timestamp" : "2015-10-16T18:11:11.113+0000"
    }
    
    2) clientSecret (OPTIONAL) - In the event of an UNREGISTER event, Jive will NOT send the clientSecret again.  To validate, you will need to provide the clientSecret with this argument. 

    Examples of calls to this method include:
        jive_sdk.is_valid_registration_notification(your_json) - Used for Register Events
        jive_sdk.is_valid_registration_notification(your_json, clientSecret="your_secret") - Used for UNregister Events
        
    For more details, check out the Jive Developer Community
        https://community.jivesoftware.com/docs/DOC-99941
        https://community.jivesoftware.com/docs/DOC-156557
        
    """
    # NEED THESE FOR LATER
    jiveSignatureURL = payload['jiveSignatureURL']
    jiveSignature = payload['jiveSignature']
    
    # MAKING A COPY
    data_json = copy.deepcopy(payload)
    
    # REMOVE JIVE SIGNATURE FROM PAYLOAD
    data_json.pop('jiveSignature')
        
    # IS THERE AN EXISTING clientSecret OUTSIDE OF THE PAYLOAD
    if not clientSecret:        
        # THEN WE ARE A REGISTER EVENT
        if not data_json['clientSecret']:
            logging.warn("Registration Event with no Secret, Invalid Payload")
            return False
        else:
            data_json['clientSecret'] = hashlib.sha256(data_json['clientSecret']).hexdigest()
    else:
        if 'clientSecret' in payload:
            logging.warn("Client Secret already in payload, ignoring argument.  Make sure you are not passing in clientId on register events")
        else:
            data_json['clientSecret'] = clientSecret
        
    # COMPILING THE BODY TO SEND TO THE MARKET TO VALIDATE
    data = ''
    for k,v in sorted(OrderedDict(data_json).items()):
        data += k + ":" + v +"\n"
    
    logging.debug("Signature Validation URL: [%s]", jiveSignatureURL)
    logging.debug("Signature Data:\n%s", data)

    res = requests.post(jiveSignatureURL, data=data, headers={ "X-Jive-MAC" : jiveSignature })
    
    if res.status_code == 204:
        logging.info("Validation Successful [%d]",res.status_code)
        return True
    
    logging.warn("Validation Failed [%d]", res.status_code)
    return False

#############################################
# is_valid_authorization
#############################################
def is_valid_authorization(authorization, clientId, clientSecret):
    """
    This method implements the Jive logic to validate a signed-fetch request from the OpenSocial container in Jive request.
     
    Arguments:

    1) authorization (REQUIRED) - the value of the "Authorization" header on the request
    2) clientId (REQUIRED) - the shared clientId for the add-on
    3) clientSecret (REQUIRED) - the clientSecret for the add-on

    Examples of calls to this method include:
        jive_sdk.is_valid_authorization(your_authorization_header,your_clientId,your_clientSecret)
        
    For more details, check out the Jive Developer Community
        https://community.jivesoftware.com/docs/DOC-99941
        https://community.jivesoftware.com/docs/DOC-156557
        https://community.jivesoftware.com/docs/DOC-163586
        
    """
    if not authorization:
        logging.warn("Invalid Authorization (null/empty)")
        return False
    
    fields = authorization.split(' ')
   
    if fields[0] != "JiveEXTN":
        logging.warn("Invalid Authorization Type [%s]",fields[0])
        return False

    if not fields[1]:
        logging.warn("Invalid Parameters [None]")
        return False   
    
    flag = fields[0]
    message = ''
    signature = ''
    for kv in fields[1].split('&'):
        key, value = kv.split("=")
        
        if (key == "client_id" and value != clientId):
            logging.warn("ClientId [%s] did not match expected ClientId [%s]",key,clientId)             
            return False
        elif key == "signature":
            signature = urllib.unquote(value).decode()
        else:
            message += "&" + key + "=" + value
    
    message = message[1:]
    
    # REMOVING SUFFIX FOR PROPER BASE64 DECODE
    if clientSecret.endswith(".s"):
        clientSecret = clientSecret[:-2]

    # PROCESSING EXPECTING SIGNATURE        
    secret = base64.b64decode(clientSecret)
    dig = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
    expectedSignature = base64.b64encode(dig).decode();
    expectedSignature = urllib.unquote(expectedSignature).decode()
    
    # DO THE FINAL SIGNATURE COMPARISON
    if signature != expectedSignature:
        logging.warn("Signatures did NOT match! [expected: %s]  [actual: %s]",expectedSignature, signature)    
        return False
    
    return True