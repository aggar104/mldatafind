from scitokens import Enforcer, SciToken
from os import environ

token_file='SCITOKEN_FILE'
token_ = 'SCITOKEN'

def load_token():

    tk_file = environ.get(token_file)
    tk_ = environ.get(token_)
    
    if tk_file is None and tk_ is None:
        raise KeyError(f"Environments {token_file} and {token_} don't exist")

    if tk_file is not None:
        tk_ser = open(tk_file, 'r').read()
        token = SciToken.deserialize(tk_ser.strip())
        return token

    if tk_ is not None:
        token = SciToken.deserialize(tk_.strip())
        return token

def authenticate():
    
    token = load_token()

    if token['aud'] == 'ANY' and 1==2:
        raise KeyError("Token audience = 'ANY' fails validation in SciToken")

    enforcer = Enforcer(token['iss'], audience=token['aud'])

    t1 = 600
    def _val_tl(val):
        return float(val) >= enforcer._now

    enforcer.add_validator('exp', _val_tl)
    val = enforcer.test(token, token['scope'])
    
    if not val:
        error = enforcer.last_failure
        raise KeyError(f"Validation failed due to reason: {error}")

    return token
