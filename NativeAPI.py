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

def random_id():
    allowed_chars = '0123456789abcdef'
    
    return (''.join(random.choice(allowed_chars) for i in range(8))+'-'+
        ''.join(random.choice(allowed_chars) for i in range(4))+'-'+
        ''.join(random.choice(allowed_chars) for i in range(4))+'-'+
        ''.join(random.choice(allowed_chars) for i in range(4))+'-'+
        ''.join(random.choice(allowed_chars) for i in range(12)))


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
    OAUTH_URL = 'https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token'
    USER_URL = 'https://userinformationservice.apps.emea.vwapps.io/iaa/uic/v1'
    MAL_URL = 'https://mal-1a.prd.ece.vwg-connect.com/api'
    __tokens = None
    __credentials = {}
    __x_client_id = None
    __oauth = {}
    __accept_mbb = 'application/json, application/vnd.volkswagenag.com-error-v1+json, */*'
    
    def __get_url(self, url,get=None,post=None,json=None,cookies=None,headers=None):
        if (post == None and json == None):
            r = self.__session.get(url, params=get, headers=headers, cookies=cookies)
        else:
            r = self.__session.post(url, data=post, json=json, params=get, headers=headers, cookies=cookies)
        if r.status_code >= 400:
            print(r.url)
            raise UrlError(r.status_code, "Error: status code {}".format(r.status_code), r)
        return r
    
    def __command(self, command, post=None, dashboard=None, accept='application/json', content_type=None, scope=None):
        if (not dashboard):
            dashboard = self.__dashboard
        if (not scope):
            scope = self.__tokens
        try:
            if (not self.__check_tokens()):
                self.__force_login()
        except UrlError as e:
            raise VWError('Aborting command {}: login failed ({})'.format(command,e.message))
        headers = {
            'Authorization': 'Bearer '+scope['access_token'],
            'Accept': accept,
            'X-App-Version': '5.3.2',
            'X-App-Name': 'We Connect',
            }
        if (content_type):
            headers['Content-Type'] = content_type
        r = self.__get_url(dashboard+command, json=post, headers=headers)
        if ('json' in r.headers['Content-Type']):
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
                self.__x_client_id = d['x-client-id']
                self.__oauth = d['oauth']
        except FileNotFoundError:
            pass
        self.__session.mount("carnet://", CarNetAdapter())
    
    def __refresh_oauth_scope(self, scope):
        data = {
            'grant_type': 'refresh_token',
            'scope': scope,
            'token': self.__oauth['sc2:fal']['refresh_token']
            }
        r = self.__get_url(self.OAUTH_URL, post=data, headers={'X-Client-Id':self.__x_client_id})
        jr = r.json()
        self.__oauth[scope] = jr
        self.__oauth[scope]['timestamp'] = time.time()
        self.__save_access()
    
    def __check_kit_tokens(self):
        if (self.__tokens):
            if (self.__tokens['timestamp']+self.__tokens['expires_in'] > time.time()):
                return True
            r = self.__get_url(self.TOKEN_URL+'/refreshTokens', post={'refresh_token': self.__tokens['refresh_token']})
            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            self.__save_access()
            return True
        return False
    
    def __check_oauth_scope(self, scope):
        if (scope in self.__oauth and self.__oauth[scope]):
            if (self.__oauth[scope]['timestamp']+self.__oauth[scope]['expires_in'] > time.time()):
                return True
            if ('sc2:fal' in self.__oauth and 'refresh_token' in self.__oauth['sc2:fal']):
                self.__refresh_oauth_scope(scope)
                return True
        return False
    
    def __check_oauth_tokens(self):
        return self.__check_oauth_scope('sc2:fal') and self.__check_oauth_scope('t2_v:cubic')
    
    def __check_tokens(self):
        return self.__check_kit_tokens() and self.__check_oauth_tokens()
        
    def __save_access(self):
        t = {}
        t['identities'] = self.__identities
        t['identity_kit'] = self.__identity_kit
        t['tokens'] = self.__tokens
        t['x-client-id'] = self.__x_client_id
        t['oauth'] = self.__oauth
        with open(WeConnect.ACCESS_FILE, 'w') as f:
            json.dump(t, f)
        
    
    def login(self):     
        if (not self.__check_tokens()):
            return self.__force_login()
        return True
    
    def __force_login(self):
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
            if (not self.__x_client_id):
                data = {
                    "appId": "de.volkswagen.car-net.eu.e-remote",
                    "appName": "We Connect",
                    "appVersion": "5.3.2",
                    "client_brand": "VW",
                    "client_name": "iPhone",
                    "platform": "iOS"
                }
                r = self.__get_url('https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/register/v1', json=data)
                self.__x_client_id = r.json()['client_id']
            
            data = {
                'grant_type': 'id_token',
                'scope': 'sc2:fal',
                'token': self.__tokens['id_token']
                }
            r = self.__get_url(self.OAUTH_URL, post=data, headers={'X-Client-Id':self.__x_client_id})
            jr = r.json()
            self.__oauth['sc2:fal'] = jr
            self.__oauth['sc2:fal']['timestamp'] = time.time()
            
            self.__refresh_oauth_scope('t2_v:cubic')
            with open(WeConnect.SESSION_FILE, 'wb') as f:
                pickle.dump(self.__session.cookies, f)
            r = self.get_personal_data()
            self.__identities['business_id'] = r['businessIdentifierValue']
            self.__save_access()
 
    def get_personal_data(self):
        r = self.__command('/personalData', dashboard=self.__identities['profile_url'])
        return r
        
    def get_real_car_data(self):
        r = self.__command('/realCarData', dashboard=self.__identities['profile_url'])
        return r
        
    def get_mbb_status(self):
        r = self.__command('/mbbStatusData', dashboard=self.__identities['profile_url'])
        return r
        
    def get_identity_data(self):
        r = self.__command('/identityData', dashboard=self.__identities['profile_url'])
        return r
    
    def get_vehicles(self):
        r = self.__command('/usermanagement/users/v1/VW/DE/vehicles', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'])
        return r
    
    def get_vehicle_data(self, vin):
        __accept = 'application/vnd.vwg.mbb.vehicleDataDetail_v2_1_0+json, application/vnd.vwg.mbb.genericError_v1_0_2+json'
        r = self.__command('/vehicleMgmt/vehicledata/v2/VW/DE/vehicles/'+vin, dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=__accept)
        return r
    
    def get_users(self, vin):
        r = self.__command('/vin/'+vin+'/users', dashboard=self.USER_URL, post={'idP_IT': self.__identity_kit['id_token']})
        return r
    
    def get_fences(self, vin):
        r = self.__command('/bs/geofencing/v1/VW/DE/vehicles/'+vin+'/geofencingAlerts', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_alerts(self, vin):
        r = self.__command('/bs/speedalert/v1/VW/DE/vehicles/'+vin+'/speedAlerts', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_trip_data(self, vin, type='longTerm'):
        #type: longTerm, cyclic, shortTerm
        r = self.__command('/bs/tripstatistics/v1/VW/DE/vehicles/'+vin+'/tripdata/'+type+'?type=list', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_vsr(self, vin):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/status', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_departure_timer(self, vin):
        r = self.__command('/bs/departuretimer/v1/VW/DE/vehicles/'+vin+'/timer', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_climater(self, vin):
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_position(self, vin):
        r = self.__command('/bs/cf/v1/VW/DE/vehicles/'+vin+'/position', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_destinations(self, vin):
        r = self.__command('/destinationfeedservice/mydestinations/v1/VW/DE/vehicles/'+vin+'/destinations', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_charger(self, vin):
        r = self.__command('/bs/batterycharge/v1/VW/DE/vehicles/'+vin+'/charger', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_heating_status(self, vin):
        r = self.__command('/bs/rs/v1/VW/DE/vehicles/'+vin+'/status', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_history(self, vin):
        r = self.__command('/bs/dwap/v1/VW/DE/vehicles/'+vin+'/history', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def request_status_update(self, vin):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/requests', dashboard=self.BASE_URL, post={}, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def __flash_and_honk(self, vin, mode, lat, long):
        data = {
            'honkAndFlashRequest': {
                'serviceOperationCode': mode,
                'serviceDuration': 15,
                'userPosition': {
                    'latitude': lat,
                    'longitude': long,
                    }
                }
            }
        r = self.__command('/bs/rhf/v1/VW/DE/vehicles/'+vin+'/honkAndFlash', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def flash(self, vin, lat, long):
        return self.__flash_and_honk(vin, 'FLASH_ONLY', lat, long)
        
    def honk(self, vin, lat, long):
        return self.__flash_and_honk(vin, 'HONK_AND_FLASH', lat, long)
    
    def get_honk_and_flash_status(self, vin, rid):
        r = self.__command('/bs/rhf/v1/VW/DE/vehicles/'+vin+'/honkAndFlash/'+str(rid)+'/status', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def battery_charge(self, vin, action='off'):
        data = {
            'action': {
                'type': 'start' if action.lower() == 'on' else 'stop'
                }
                
            }
        r = self.__command('/bs/batterycharge/v1/VW/DE/vehicles/'+vin+'/charger/actions', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def climatisation(self, vin, action='off'):
        data = {
            'action': {
                'type': 'startClimatisation' if action.lower() == 'on' else 'stopClimatisation'
                }
                
            }
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def climatisation_temperature(self, vin, temperature=21.5):
        dk = temperature*10+2731
        data = {
            'action': {
                'type': 'setSettings',
                'settings': {
                    'targetTemperature': dk,
                    'climatisationWithoutHVpower': False,
                    'heaterSource': 'electric',
                    }
                }
                
            }
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def window_melt(self, vin, action='off'):
        data = {
            'action': {
                'type': 'startWindowHeating' if action.lower() == 'on' else 'stopWindowHeating'
                }
                
            }
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def request_secure_token(self, vin, service):
        r = self.__command('/rolesrights/authorization/v2/vehicles/'+vin+'/services/'+service+'/security-pin-auth-requested', dashboard=self.MAL_URL, scope=self.__oauth['sc2:fal'])
        return r
        
    def heating(self, vin, action='off'):
        data = {
            'performAction': {
                'quickstart': {
                    'active': True if action.lower() == 'on' else False
                    }
                }
                
            }
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.BASE_URL, post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    
        
        