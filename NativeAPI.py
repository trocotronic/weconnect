# -*- coding: utf-8 -*-
"""
Created on Sun May 10 19:12:29 2020

@author: Trocotronic
"""
import _version
import logging
import credentials
from vsr import VSR

logging.basicConfig(format='[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%d/%m/%Y %H:%M:%S')
logging.getLogger().setLevel(logging.WARN)

class VWError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)
        logging.critical('Raising error msg: %s', message)

class UrlError(VWError):
    def __init__(self, status_code, message, request):
        self.status_code = status_code
        self.request = request
        super().__init__(message)
    pass

import requests, pickle, hashlib, base64, os, random, time, json, xmltodict
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
        headers = None
        
        def __init__(self, request):
            self.request = request
            self.url = request.url
            self.headers = request.headers
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
    USER_URL = 'https://userinformationservice.apps.emea.vwapps.io/iaa'
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
        logging.info('Sending %s request to %s', r.request.method, r.url)
        logging.debug('Parameters: %s', r.request.url)
        logging.debug('Headers: %s', r.request.headers)
        logging.info('Response with code: %d', r.status_code)
        logging.debug('Headers: %s', r.headers)
        logging.debug('History: %s', r.history)
        if r.status_code >= 400:
            try:
                e = r.json()
                msg = 'Error {}'.format(r.status_code)
                logging.debug('Response error in JSON format')
                if ('error' in e):
                    msg += ':'
                    if ('errorCode' in e['error']):
                        msg += ' [{}]'.format(e['error']['errorCode'])
                    if ('description' in e['error']):
                        msg += ' '+e['error']['description']
            except ValueError:
                logging.debug('Response error is not JSON format')
                msg = "Error: status code {}".format(r.status_code)
            raise UrlError(r.status_code, msg, r)
        #else:
        #    print(r.content.decode())
        return r
    
    def __command(self, command, post=None, data=None, dashboard=None, accept='application/json', content_type=None, scope=None, secure_token=None):
        if (not dashboard):
            dashboard = self.__dashboard
        if (not scope):
            scope = self.__tokens
        logging.info('Preparing command: %s', command)
        if (post):
            logging.debug('JSON data: %s', post)
        if (data):
            logging.debug('POST data: %s', data)
        logging.debug('Dashboard: %s', dashboard)
        if (accept):
            logging.debug('Accept: %s', accept)
        if (content_type):
            logging.debug('Content-tpye: %s', content_type)
        if (scope):
            logging.debug('Scope: %s', scope['__name__'])
        if (secure_token):
            logging.debug('Secure token: %s', secure_token)
        try:
            if (not self.__check_tokens()):
                self.__force_login()
        except UrlError as e:
            raise VWError('Aborting command {}: login failed ({})'.format(command,e.message))
        headers = {
            'Authorization': 'Bearer '+scope['access_token'],
            'Accept': accept,
            'X-App-Version': '5.8.0',
            'X-App-Name': 'We Connect',
            'Accept-Language': 'en-US',
            }
        if (content_type):
            headers['Content-Type'] = content_type
        if (secure_token):
            headers['X-MBBSecToken'] = secure_token
        r = self.__get_url(dashboard+command, json=post, post=data, headers=headers)
        if ('json' in r.headers['Content-Type']):
            jr = r.json()
            return jr
        return r
    
    def __init__(self, spin=None):
        self.__session = requests.Session()
        self.__credentials['user'] = credentials.username
        self.__credentials['password'] = credentials.password
        self.__credentials['spin'] = None
        if (spin):
            if (isinstance(spin, int)):
                spin = str(spin).zfill(4)
            if (isinstance(spin, str)):
                if (len(spin) != 4):
                    raise VWError('Wrong S-PIN format: must be 4-digits')
                try:
                    d = int(spin)
                except ValueError:
                    raise VWError('Wrong S-PIN format: must be 4-digits')
                self.__credentials['spin'] = spin
            else:
                raise VWError('Wrong S-PIN format: must be 4-digits')
        
        try:
            with open(WeConnect.SESSION_FILE, 'rb') as f:
                self.__session.cookies.update(pickle.load(f))
        except FileNotFoundError:
            logging.warning('Session file not found')
        try:
            with open(WeConnect.ACCESS_FILE, 'rb') as f:
                d = json.load(f)
                self.__identities = d['identities']
                self.__identity_kit = d['identity_kit']
                self.__tokens = d['tokens']
                self.__x_client_id = d['x-client-id']
                self.__oauth = d['oauth']
        except FileNotFoundError:
            logging.warning('Access file not found')
        self.__session.mount("carnet://", CarNetAdapter())
    
    def __refresh_oauth_scope(self, scope):
        data = {
            'grant_type': 'refresh_token',
            'scope': scope,
            'token': self.__oauth['sc2:fal']['refresh_token']
            }
        logging.debug('Refreshing OAUth scope %s', scope)
        r = self.__get_url(self.OAUTH_URL, post=data, headers={'X-Client-Id':self.__x_client_id})
        logging.debug('Refreshed OAuth scope %s', scope)
        jr = r.json()
        self.__oauth[scope] = jr
        self.__oauth[scope]['timestamp'] = time.time()
        self.__oauth[scope]['__name__'] = 'OAuth '+scope
        self.__save_access()
    
    def __check_kit_tokens(self):
        if (self.__tokens):
            if (self.__tokens['timestamp']+self.__tokens['expires_in'] > time.time()):
                logging.debug('Tokens still valid')
                return True
            logging.debug('Token expired. Refreshing tokens')
            r = self.__get_url(self.TOKEN_URL+'/refreshTokens', post={'refresh_token': self.__tokens['refresh_token']})
            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            self.__tokens['__name__'] = 'Token'
            self.__save_access()
            return True
        logging.debug('Token checking failed')
        return False
    
    def __check_oauth_scope(self, scope):
        if (scope in self.__oauth and self.__oauth[scope]):
            if (self.__oauth[scope]['timestamp']+self.__oauth[scope]['expires_in'] > time.time()):
                logging.debug('OAuth %s still valid', scope)
                return True
            logging.debug('OAUth %s expired. Refreshing', scope)
            if (scope in self.__oauth and 'refresh_token' in self.__oauth[scope]):
                self.__refresh_oauth_scope(scope)
                return True
            logging.error('OAUTH {} not present. Cannot refresh'.format(scope))
        logging.debug('OAuth [%s] checking failed', scope)
        return False
    
    def __check_oauth_tokens(self):
        return self.__check_oauth_scope('sc2:fal') and self.__check_oauth_scope('t2_v:cubic')
    
    def __check_tokens(self):
        logging.debug('Checking tokens')
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
        logging.info('Saving access to file')
        
    def login(self):
        logging.info('Logging')
        if (not self.__check_tokens()):
            return self.__force_login()
        return True
    
    def __force_login(self):
            logging.warning('Forcing login')
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
            logging.info('Attempting to login')
            logging.debug('Login parameters: %s', login_para)
            r = self.__get_url('https://identity.vwgroup.io/oidc/v1/authorize', get=login_para)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'emailPasswordForm'})
            if (not form):
                raise VWError('Login form not found. Cannot continue')
            if (not form.has_attr('action')):
                raise VWError('action not found in login email form. Cannot continue')
            form_url = form['action']
            logging.info('Found email login url: %s', form_url)
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
                    raise VWError(e)
                raise VWError('This account does not exist')
            if (not form.has_attr('action')):
                raise VWError('action not found in login password form. Cannot continue')
            form_url = form['action']
            logging.info('Found password login url: %s', form_url)
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['password'] = self.__credentials['password']
            
            upr = urlparse(r.url)
            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            if ('carnet://' not in r.url):
                logging.info('No carnet scheme found in response.')
                soup = BeautifulSoup(r.text, 'html.parser')
                metakits = soup.find_all("meta", {'name':'identitykit'})
                print(metakits)
                for metakit in metakits: 
                    if (metakit['content'] == 'termsAndConditions'): #updated terms and conditions?
                        logging.debug('Meta identitykit is termsandconditions')
                        form = soup.find('form', {'id': 'emailPasswordForm'})
                        if (form):
                            if (not form.has_attr('action')):
                                raise VWError('action not found in terms and conditions form. Cannot continue')
                            form_url = form['action']
                            logging.info('Found terms and conditions url: %s', form_url)
                            hiddn = form.find_all('input', {'type': 'hidden'})
                            post = {}
                            for h in hiddn:
                                post[h['name']] = h['value']
                            upr = urlparse(r.url)
                            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
                            logging.info('Successfully accepted updated terms and conditions')
                        break
                    elif (metakit['content'] == 'loginAuthenticate'):
                        logging.warn('Meta identitykit is loginAuthenticate')
                        if ('error' in r.url):
                            raise VWError(r.url.split('error=')[1])
                    
            self.__identities = get_url_params(r.history[-1].url)
            logging.info('Received Identities')
            logging.debug('Identities = %s', self.__identities)
            self.__identities['profile_url'] = WeConnect.PROFILE_URL.format(self.__identities['user_id'])
            self.__identity_kit = r.params
            logging.info('Received CarNet Identity Kit')
            logging.debug('Identity Kit = %s', r.params)
            data = {
                'auth_code': self.__identity_kit['code'],
                'code_verifier': code_verifier.decode(),
                'id_token': self.__identity_kit['id_token'],
                }
            logging.info('Requesting Tokens')
            r = self.__get_url('https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode', post=data)
            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            self.__tokens ['__name__'] = 'Token'
            logging.info('Received Tokens')
            if (not self.__x_client_id):
                logging.warning('X-client-id not found. Requesting a new one')
                data = {
                    "appId": "de.volkswagen.car-net.eu.e-remote",
                    "appName": "We Connect",
                    "appVersion": "5.8.0",
                    "client_brand": "VW",
                    "client_name": "iPhone",
                    "platform": "iOS"
                }
                r = self.__get_url('https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/register/v1', json=data)
                self.__x_client_id = r.json()['client_id']
                logging.info('Received X-client-id')
                logging.debug('X-client-id = %s', self.__x_client_id)
            logging.info('Requesting OAuth [fal]')
            data = {
                'grant_type': 'id_token',
                'scope': 'sc2:fal',
                'token': self.__tokens['id_token']
                }
            r = self.__get_url(self.OAUTH_URL, post=data, headers={'X-Client-Id':self.__x_client_id})
            logging.info('Received OAuth [fal]')
            jr = r.json()
            
            self.__oauth['sc2:fal'] = jr
            self.__oauth['sc2:fal']['timestamp'] = time.time()
            self.__oauth['sc2:fal']['__name__'] = 'OAuth sc2:fal'
            logging.debug('OAuth [fal] timestamp = %s', time.time())
            logging.info('Requesting OAuth [cubic]')
            self.__refresh_oauth_scope('t2_v:cubic')
            logging.debug('Received OAuth [cubic]')
            with open(WeConnect.SESSION_FILE, 'wb') as f:
                pickle.dump(self.__session.cookies, f)
            logging.debug('Saving session')
            logging.info('Requesting personal data')
            r = self.get_personal_data()
            self.__identities['business_id'] = r['businessIdentifierValue']
            logging.info('Received business identity')
            logging.debug('Bussiness identity = %s', r['businessIdentifierValue'])
            self.__save_access()
            
    def __get_homeregion(self, vin):
        r = self.__command('/cs/vds/v1/vehicles/'+vin+'/homeRegion', dashboard=self.MAL_URL, scope=self.__oauth['sc2:fal'])
        self.__identities['mal3'] = r['homeRegion']['baseUri']['content']
        if ('mal-1a' in self.__identities['mal3']):
            self.__identities['fal3'] = self.BASE_URL
        else:
            upr = urlparse(self.__identities['mal3'])
            self.__identities['fal3'] = upr.scheme+'://'+upr.netloc.replace('mal','fal')+'/fs-car'
        logging.debug('fal3 URL = %s', self.__identities['fal3'])
        logging.info('Received fal/mal Uri')
        
    def __get_fal_url(self, vin):
        if ('fal3' not in self.__identities):
            self.__get_homeregion(vin)
        return self.__identities['fal3']
    
    def __get_mal_url(self, vin):
        if ('mal3' not in self.__identities):
            self.__get_homeregion(vin)
        return self.__identities['mal3']
    
    def set_logging_level(self, level):
        logging.getLogger().setLevel(level)
        
    def version(self):
        return _version.__version__
 
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
        r = self.__command('/vehicleMgmt/vehicledata/v2/VW/DE/vehicles/'+vin, dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=__accept)
        return r
    
    def get_users(self, vin):
        r = self.__command('/uic/v1/vin/'+vin+'/users', dashboard=self.USER_URL, post={'idP_IT': self.__tokens['id_token']})
        return r
    
    def get_fences(self, vin):
        r = self.__command('/bs/geofencing/v1/VW/DE/vehicles/'+vin+'/geofencingAlerts', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_fences_configuration(self):
        r = self.__command('/bs/geofencing/v1/VW/DE/geofencingConfiguration', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_speed_alerts(self, vin):
        r = self.__command('/bs/speedalert/v1/VW/DE/vehicles/'+vin+'/speedAlerts', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_speed_alerts_configuration(self):
        r = self.__command('/bs/speedalert/v1/VW/DE/speedAlertConfiguration', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_trip_data(self, vin, type='longTerm'):
        # type: 'longTerm', 'cyclic', 'shortTerm'
        r = self.__command('/bs/tripstatistics/v1/VW/DE/vehicles/'+vin+'/tripdata/'+type+'?type=list', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_vsr(self, vin):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/status', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_departure_timer(self, vin):
        r = self.__command('/bs/departuretimer/v1/VW/DE/vehicles/'+vin+'/timer', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_climater(self, vin):
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_position(self, vin):
        r = self.__command('/bs/cf/v1/VW/DE/vehicles/'+vin+'/position', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_destinations(self, vin):
        r = self.__command('/destinationfeedservice/mydestinations/v1/VW/DE/vehicles/'+vin+'/destinations', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_charger(self, vin):
        r = self.__command('/bs/batterycharge/v1/VW/DE/vehicles/'+vin+'/charger', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_heating_status(self, vin):
        r = self.__command('/bs/rs/v1/VW/DE/vehicles/'+vin+'/status', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_history(self, vin):
        r = self.__command('/bs/dwap/v1/VW/DE/vehicles/'+vin+'/history', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_roles_rights(self, vin):
        r = self.__command('/rolesrights/operationlist/v3/vehicles/'+vin+'/users/'+self.__identities['business_id'], dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_fetched_role(self, vin):
        r = self.__command('/rolesrights/permissions/v1/VW/DE/vehicles/'+vin+'/fetched-role', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_vehicle_health_report(self, vin):
        # DEPRECATED: this method is not reliable. It queries to far away GW sometimes it returns e504. The information returned is equivlent to get_vsr()
        # https://blog.vensis.pl/2019/11/vw-hacking/
        __accept = 'application/vnd.vwg.mbb.sharedTelemetricReport_v1_0_0+xml, application/vnd.vwg.mbb.genericError_v1_1_1+xml, */*'
        r = self.__command('/vehiclehealthreport/myreports/v1/VW/DE/vehicles/'+vin+'/users/'+self.__identities['business_id']+'/vehicleHealthReports/history', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=__accept)
        namespaces = {
            'http://www.vw.com/mbb/service_TelemetricSharedService_MBB': None,
            'http://xmldefs.volkswagenag.com/DD/MaintenanceEvent/V1': None,
            }
        jr = json.dumps(xmltodict.parse(r.content,process_namespaces=True,namespaces=namespaces))
        return jr
    
    def get_car_port_data(self, vin):
        # It seems disabled. It returns e403 Forbidden
        r = self.__command('/promoter/portfolio/v1/VW/DE/vehicle/'+vin+'/carportdata', dashboard=self.__get_fal_url(vin), accept=self.__accept_mbb, scope=self.__oauth['sc2:fal'])
        return r
    
    def request_status_update(self, vin):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/requests', dashboard=self.__get_fal_url(vin), post={}, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def request_status(self, vin, reqId):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/requests/'+reqId+'/jobstatus', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_vsr_request(self, vin, reqId):
        r = self.__command('/bs/vsr/v1/VW/DE/vehicles/'+vin+'/requests/'+reqId+'/status', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
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
        r = self.__command('/bs/rhf/v1/VW/DE/vehicles/'+vin+'/honkAndFlash', dashboard=self.__get_fal_url(vin), post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def flash(self, vin, lat, long):
        return self.__flash_and_honk(vin, 'FLASH_ONLY', lat, long)
        
    def honk(self, vin, lat, long):
        return self.__flash_and_honk(vin, 'HONK_AND_FLASH', lat, long)
    
    def get_honk_and_flash_status(self, vin, rid):
        r = self.__command('/bs/rhf/v1/VW/DE/vehicles/'+vin+'/honkAndFlash/'+str(rid)+'/status', dashboard=self.__get_fal_url(vin), scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def get_honk_and_flash_configuration(self):
        r = self.__command('/bs/rhf/v1/VW/DE/configuration', dashboard=self.BASE_URL, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def battery_charge(self, vin, action='off'):
        data = {
            'action': {
                'type': 'start' if action.lower() == 'on' else 'stop'
                }
                
            }
        r = self.__command('/bs/batterycharge/v1/VW/DE/vehicles/'+vin+'/charger/actions', dashboard=self.__get_fal_url(vin), post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb)
        return r
    
    def climatisation(self, vin, action='off'):
        data = {
            'action': {
                'type': 'startClimatisation' if action.lower() == 'on' else 'stopClimatisation'
                }
                
            }
        secure_token = self.__request_secure_token(vin, 'rclima_v1/operations/P_START_CLIMA_AU')
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.__get_fal_url(vin), post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb, secure_token=secure_token)
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
        secure_token = self.__request_secure_token(vin, 'rclima_v1/operations/P_START_CLIMA_AU')
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.__get_fal_url(vin), post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb, secure_token=secure_token)
        return r
    
    def window_melt(self, vin, action='off'):
        data = {
            'action': {
                'type': 'startWindowHeating' if action.lower() == 'on' else 'stopWindowHeating'
                }
                
            }
        secure_token = self.__request_secure_token(vin, 'rclima_v1/operations/P_START_CLIMA_AU')
        r = self.__command('/bs/climatisation/v1/VW/DE/vehicles/'+vin+'/climater/actions', dashboard=self.__get_fal_url(vin), post=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb, secure_token=secure_token)
        return r
    
    def __generate_secure_pin(self, challenge):
        logging.info('Generating secure pin')
        if (not self.__credentials['spin']):
            raise VWError('Cannot process this command: S-PIN not provided.')
        spin =  hashlib.sha512(bytearray.fromhex(self.__credentials['spin']+challenge)).hexdigest().upper()
        logging.info('Generated secure pin')
        logging.debug('spin = %s', spin)
        return spin
    
    def __request_secure_token(self, vin, service):
        logging.info('Requesting secure token')
        r = self.__command('/rolesrights/authorization/v2/vehicles/'+vin+'/services/'+service+'/security-pin-auth-requested', dashboard=self.MAL_URL, scope=self.__oauth['sc2:fal'])
        logging.info('Received secure token')
        challenge = r['securityPinAuthInfo']['securityPinTransmission']['challenge']
        logging.debug('Challenge = %s', challenge)
        secure_pin = self.__generate_secure_pin(challenge)
        data = {
            'securityPinAuthentication': {
                'securityPin': {
                    'challenge': challenge,
                    'securityPinHash': secure_pin.upper(),
                    },
                'securityToken': r['securityPinAuthInfo']['securityToken']
            }
        }
        logging.info('Completing security pin auth')
        r = self.__command('/rolesrights/authorization/v2/security-pin-auth-completed', post=data, dashboard=self.MAL_URL, scope=self.__oauth['sc2:fal'])
        logging.info('Completed security pin auth')
        if ('securityToken' in r):
            logging.info('Received security token')
            return r['securityToken']
        logging.error('No security token found')
        return None    
        
    def heating(self, vin, action='off'):
        if (action == 'on'):
            data = '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstart>\n      <active>true</active>\n   </quickstart>\n</performAction>'
        else:
            data = '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstop>\n      <active>false</active>\n   </quickstop>\n</performAction>'
        
        secure_token = self.__request_secure_token(vin, 'rheating_v1/operations/P_QSACT')
        r = self.__command('/bs/rs/v1/VW/DE/vehicles/'+vin+'/actions', dashboard=self.BASE_URL, data=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb, content_type='application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml', secure_token=secure_token)
        return r
    
    def lock(self, vin, action='lock'):
        if (action == 'unlock'):
            data = '<?xml version="1.0" encoding= "UTF-8" ?>\n<rluAction xmlns="http://audi.de/connect/rlu">\n   <action>unlock</action>\n</rluAction>'
        else:
            data='<?xml version="1.0" encoding= "UTF-8" ?>\n<rluAction xmlns="http://audi.de/connect/rlu">\n   <action>lock</action>\n</rluAction>'
        secure_token = self.__request_secure_token(vin, 'rlu_v1/operations/' + action.upper())
        r = self.__command('/bs/rlu/v1/VW/DE/vehicles/'+vin+'/actions', dashboard=self.BASE_URL, data=data, scope=self.__oauth['sc2:fal'], accept=self.__accept_mbb, content_type='application/vnd.vwg.mbb.RemoteLockUnlock_v1_0_0+xml', secure_token=secure_token)
        return r
    
    def parse_vsr(self, j):
        parser = VSR()
        return parser.parse(j)
    
        