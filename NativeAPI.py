# -*- coding: utf-8 -*-
"""
Created on Sun May 10 19:12:29 2020

@author: Trocotronic
"""

class VWError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)

class UrlError(VWError):
    def __init__(self, status_code, message, request):
        self.status_code = status_code
        self.request = request
        super().__init__(message)
    pass

import requests, pickle, hashlib, base64, os, random, time, json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote_plus

def get_random_string(length=12,
                      allowed_chars='abcdefghijklmnopqrstuvwxyz'
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'):
    return ''.join(random.choice(allowed_chars) for i in range(length))

def base64URLEncode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')

def get_url_params(url):
    args = url.split('?')
    blocks = args[-1].split('#')
    pars = blocks[-1].split('&')
    params = {}
    for p in pars:
        para = p.split('=')
        params[para[0]] = unquote_plus(para[1])
    return params

class CarNetAdapter(requests.adapters.HTTPAdapter):

    class CarNetResponse():
        elapsed = 0
        history = None
        raw = ''
        is_redirect = False
        content = ''
        status_code = 200
        url = None
        request = None
        params = {}
        
        def __init__(self, request):
            self.request = request
            self.url = request.url
            self.params = get_url_params(self.url)
                
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        return self.CarNetResponse(request)

class WeConnect():
    __session = None
    __dashboard = None
    __edit_profile_url = None
    SESSION_FILE = 'weconnectAPI.session'
    ACCESS_FILE = 'weconnectAPI.access'
    BASE_URL = 'https://msg.volkswagen.de/fs-car'
    TOKEN_URL = 'https://tokenrefreshservice.apps.emea.vwapps.io'
    PROFILE_URL = 'https://customer-profile.apps.emea.vwapps.io/v1/customers/{}'
    __tokens = None
    __credentials = {}
    
    def __get_url(self, url,get=None,post=None,json=None,cookies=None,headers=None):
        if (post == None and json == None):
            r = self.__session.get(url, params=get, headers=headers, cookies=cookies)
        else:
            r = self.__session.post(url, data=post, json=json, params=get, headers=headers, cookies=cookies)
        if r.status_code != requests.codes.ok:
            raise UrlError(r.status_code, "Error: status code {}".format(r.status_code), r)
        return r
    
    def __command(self, command, post=None, dashboard=None):
        if (not dashboard):
            dashboard = self.__dashboard
        try:
            if (not self.__check_tokens()):
                self.__force_login()
        except UrlError as e:
            raise VWError('Aborting command {}: login failed ({})'.format(command,e.message))
        r = self.__get_url(dashboard+command, json=post, headers={'authorization': 'Bearer '+self.__tokens['access_token'], 'authority': 'customer-profile.apps.emea.vwapps.io'})
        if ('application/json' in r.headers['Content-Type']):
            jr = r.json()
            return jr
        return r
    
    def __init__(self, user, password):
        self.__session = requests.Session()
        self.__credentials['user'] = user
        self.__credentials['password'] = password
        try:
            with open(WeConnect.SESSION_FILE, 'rb') as f:
                self.__session.cookies.update(pickle.load(f))
        except FileNotFoundError:
            pass
        try:
            with open(WeConnect.ACCESS_FILE, 'rb') as f:
                d = json.load(f)
                self.__identities = d['identities']
                self.__identity_kit = d['identity_kit']
                self.__tokens = d['tokens']
        except FileNotFoundError:
            pass
        self.__session.mount("carnet://", CarNetAdapter())
        
    def __check_tokens(self):
        if (self.__tokens):
            if (self.__tokens['timestamp']+self.__tokens['expires_in'] > time.time()):
                return True
            r = self.__get_url(self.TOKEN_URL+'/refreshTokens', post={'refresh_token': self.__tokens['refresh_token']})
            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            self.__save_access()
            return True
        return False
        
    def __save_access(self):
        t = {}
        t['identities'] = self.__identities
        t['identity_kit'] = self.__identity_kit
        t['tokens'] = self.__tokens
        with open(WeConnect.ACCESS_FILE, 'w') as f:
            json.dump(t, f)
        
    
    def login(self):     
        if (not self.__check_tokens()):
            return self.__force_login()
        return True
    
    def __force_login():
        try:
            code_verifier = base64URLEncode(os.urandom(32))
            if len(code_verifier) < 43:
                raise ValueError("Verifier too short. n_bytes must be > 30.")
            elif len(code_verifier) > 128:
                raise ValueError("Verifier too long. n_bytes must be < 97.")
            challenge = base64URLEncode(hashlib.sha256(code_verifier).digest())
            login_para = {
                'prompt': 'login',
                'state': get_random_string(43),
                'response_type': 'code id_token token',
                'code_challenge_method': 's256',
                'scope': 'openid profile mbb cars birthdate nickname address phone',
                'code_challenge': challenge.decode(),
                'redirect_uri': 'carnet://identity-kit/login',
                'client_id': '9496332b-ea03-4091-a224-8c746b885068@apps_vw-dilab_com',
                'nonce': get_random_string(43),
                }
            r = self.__get_url('https://identity.vwgroup.io/oidc/v1/authorize', get=login_para)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'emailPasswordForm'})
            form_url = form['action']
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['email'] = self.__credentials['user']
            
            upr = urlparse(r.url)
            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'credentialsForm'})
            if (not form):
                form = soup.find('form', {'id': 'emailPasswordForm'})
                if (form):
                    span = form.find('span', { 'class': 'message'})
                    e = 'Cannot login. Unknown error.'
                    if (span):
                        e = span.text
                    else:
                        div = form.find('div', {'class': 'sub-title'})
                        if (div):
                            e = div.text
                    raise UrlError(r.status_code, e, r)
                raise UrlError(r.status_code, 'This account does not exist', r)
            form_url = form['action']
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['password'] = self.__credentials['password']
            
            upr = urlparse(r.url)
            r =  self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            self.__identities = get_url_params(r.history[-1].url)
            self.__identities['profile_url'] = WeConnect.PROFILE_URL.format(self.__identities['user_id'])
            self.__identity_kit = r.params
            data = {
                'auth_code': self.__identity_kit['code'],
                'code_verifier': code_verifier.decode(),
                'id_token': self.__identity_kit['id_token'],
                }
            r = self.__get_url('https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode', post=data)
            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            with open(WeConnect.SESSION_FILE, 'wb') as f:
                pickle.dump(self.__session.cookies, f)
            self.__save_access()
            return True
        except UrlError:
            pass
        return False
 
    def get_personal_data(self):
        r = self.__command('/personalData', dashboard=self.__identities['profile_url'])
        return r
        