# -*- coding: utf-8 -*-
"""
Created on Sun May 10 19:12:29 2020

@author: Trocotronic
"""
import _version
import logging
import credentials
from vsr import VSR
import yaml

logging.basicConfig(format='[%(asctime)s] [%(name)s::%(levelname)s] %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

logger = logging.getLogger('API')
logger.setLevel(logging.getLogger().level)

class VWError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)
        logger.critical('Raising error msg: %s', message)

class UrlError(VWError):
    def __init__(self, status_code, message, request):
        self.status_code = status_code
        self.request = request
        super().__init__(message)
    pass

import requests, pickle, hashlib, base64, os, random, time, json, xmltodict, re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote_plus, parse_qs

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
    SESSION_FILE = 'weconnectAPI.session'
    ACCESS_FILE = 'weconnectAPI.access'
    PROFILE_URL = 'https://customer-profile.vwgroup.io/v1/customers/{}'
    CARIAD_URL = 'https://emea.bff.cariad.digital'
    CARIAD_CLOUD = 'https://myvw-deep-link-router-prod.apps.mega.cariad.cloud/es-ES/userlist?vin={vin}'
    AUTH_PROXY = 'https://www.volkswagen.es/app/authproxy/vw-es/proxy'
    __dashboard = CARIAD_URL
    __tokens = None
    __credentials = {}
    __x_client_id = None
    __oauth = {}
    __openid_conf = None
    __vehicles = None

    def __get_url(self, url,get=None,post=None,json=None,cookies=None,headers={}):
        if ('user-agent' not in headers):
            headers.update({
                'user-agent': 'Volkswagen/2.20.0 iOS/17.1.1'
            })
        if (post == None and json == None):
            r = self.__session.get(url, params=get, headers=headers, cookies=cookies)
        else:
            r = self.__session.post(url, data=post, json=json, params=get, headers=headers, cookies=cookies)
        logger.info('Sending %s request to %s', r.request.method, r.url)
        logger.debug('Parameters: %s', r.request.url)
        logger.debug('Headers: %s', r.request.headers)
        logger.info('Response with code: %d', r.status_code)
        logger.debug('Headers: %s', r.headers)
        logger.debug('History: %s', r.history)
        if r.status_code >= 400:
            try:
                e = r.json()
                msg = 'Error {}'.format(r.status_code)
                logger.debug('Response error in JSON format')
                print(e)
                if ('error' in e):
                    msg += f': {e["error"]} ({e["error_description"]})'
            except ValueError:
                logger.debug('Response error is not JSON format')
                msg = "Error: status code {}".format(r.status_code)
                print(r.content.decode())
            raise UrlError(r.status_code, msg, r)
        #else:
        #    print(r.content.decode())
        return r

    def __command(self, command, post=None, data=None, dashboard=None, accept='*/*', content_type=None, scope=None, secure_token=None, get=None):
        if (not dashboard):
            dashboard = self.__dashboard
        if (not scope):
            scope = self.__tokens
        #command = command.format(brand=self.__brand, country=self.__country)
        logger.info('Preparing command: %s', command)
        if (post):
            logger.debug('JSON data: %s', post)
        if (data):
            logger.debug('POST data: %s', data)
        logger.debug('Dashboard: %s', dashboard)
        if (accept):
            logger.debug('Accept: %s', accept)
        if (content_type):
            logger.debug('Content-tpye: %s', content_type)
        if (scope):
            logger.debug('Scope: %s', scope['__name__'])
        if (secure_token):
            logger.debug('Secure token: %s', secure_token)
        try:
            if (not self.__check_tokens()):
                self.__force_login()
        except UrlError as e:
            raise VWError('Aborting command {}: login failed ({})'.format(command,e.message))
        headers = {
            'Accept': accept,
            'Accept-Language': 'en-US',
        }
        if (dashboard == self.AUTH_PROXY):
            csrf_token = self.__session.cookies.get_dict().get('csrf_token', None)
            if (csrf_token):
                headers.update({
                    'User-Id': '__userId__',
                    'x-csrf-token': csrf_token,
                })
        else:
            headers.update({
                'Authorization': 'Bearer '+scope['access_token'],
            })
        if (content_type):
            headers['Content-Type'] = content_type
        if (secure_token):
            headers['X-MBBSecToken'] = secure_token
        r = self.__get_url(dashboard+command, get=get, json=post, post=data, headers=headers)
        if ('json' in r.headers.get('Content-Type', [])):
            jr = r.json()
            return jr
        return r

    def __init__(self):
        self.__session = requests.Session()
        self.__credentials['user'] = credentials.username
        self.__credentials['password'] = credentials.password
        self.__credentials['spin'] = None
        if (hasattr(credentials,'spin') and credentials.spin is not None):
            if (isinstance(credentials.spin, int)):
                credentials.spin = str(credentials.spin).zfill(4)
            if (isinstance(credentials.spin, str)):
                if (len(credentials.spin) != 4):
                    raise VWError('Wrong S-PIN format: must be 4-digits')
                try:
                    d = int(credentials.spin)
                except ValueError:
                    raise VWError('Wrong S-PIN format: must be 4-digits')
                self.__credentials['spin'] = credentials.spin
            else:
                raise VWError('Wrong S-PIN format: must be 4-digits')

        try:
            with open(WeConnect.SESSION_FILE, 'rb') as f:
                self.__session.cookies.update(pickle.load(f))
        except FileNotFoundError:
            logger.warning('Session file not found')
        try:
            with open(WeConnect.ACCESS_FILE, 'rb') as f:
                d = json.load(f)
                self.__identities = d['identities']
                self.__identity_kit = d['identity_kit']
                self.__tokens = d['tokens']
                self.__x_client_id = d['x-client-id']
                self.__oauth = d['oauth']
        except FileNotFoundError:
            logger.warning('Access file not found')
        self.__session.mount("weconnect://", CarNetAdapter())

    def __check_kit_tokens(self):
        if (self.__tokens):
            if (self.__tokens['timestamp']+self.__tokens['expires_in'] > time.time()):
                logger.debug('Tokens still valid')
                return True
            logger.debug('Token expired. Refreshing tokens')
            get = {
                'client_id': 'a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
                'grant_type': 'refresh_token',
                'code': self.__identity_kit['code'],
                'redirect_uri': 'weconnect://authenticated',
                'refresh_token': self.__tokens['refresh_token']
            }

            if (not self.__openid_conf):
                self.__openid_conf = self.__get_url(self.CARIAD_URL + '/login/v1/idk/openid-configuration').json()
            try:
                r = self.__get_url(self.__openid_conf['token_endpoint'], get=get)
            except:
                return self.__force_login()

            self.__tokens = r.json()
            self.__tokens['timestamp'] = time.time()
            self.__tokens['__name__'] = 'Token'
            self.__save_access()
            return True
        logger.debug('Token checking failed')
        return False

    def __check_tokens(self):
        logger.debug('Checking tokens')
        return self.__check_kit_tokens()

    def __get_idk(self, soup):
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'window._IDK' in script.string:
                try:
                    idk_txt = '{'+re.search(r'\{(.*)\}',script.string,re.M|re.S).group(1)+'}'
                    idk_txt = re.sub(r'([\{\s,])(\w+)(:)', r'\1"\2"\3', idk_txt.replace('\'','"'))
                    idk = yaml.load(idk_txt, Loader=yaml.FullLoader)
                    return idk
                except json.decoder.JSONDecodeError:
                    raise VWError('Cannot find IDK credentials')
        return None

    def __save_access(self):
        t = {}
        t['identities'] = self.__identities
        t['identity_kit'] = self.__identity_kit
        t['tokens'] = self.__tokens
        t['x-client-id'] = self.__x_client_id
        t['oauth'] = self.__oauth
        with open(WeConnect.ACCESS_FILE, 'w') as f:
            json.dump(t, f)
        logger.info('Saving access to file')

    def login(self):
        logger.info('logger')
        if (not self.__check_tokens()):
            return self.__force_login()
        if (not self.__vehicles):
            self.__vehicles = self.__command('/vehicle/v2/vehicles')
        return True

    def __parse_market_consent(self, r):
        soup = BeautifulSoup(r.text, 'html.parser')
        upr = urlparse(r.url)
        qs = parse_qs(upr.query)
        idk = self.__get_idk(soup)
        ix = 0
        while ('templateModel' in idk and 'csrf_token' in idk and 'hmac' in idk['templateModel'] and 'marketChannels' in idk['templateModel']):
            logger.debug('Found marketChannels')
            post = {
                'documentKey': idk['templateModel']['documentKey'],
                '_csrf': idk['csrf_token'],
                'hmac': idk['templateModel']['hmac'],
                'countryOfJurisdiction': idk['templateModel']['countryOfJurisdiction'],
                'language': idk['templateModel']['language'],
                'callback': idk['templateModel']['callback'],
                'relayState': idk['templateModel']['relayStateToken'],
            }
            for idx, mkt in enumerate(idk['templateModel']['marketChannels']):
                post[f'channel{mkt["channelId"]}'] = False

            r = self.__get_url(f'{upr.scheme}://{upr.netloc}{"/".join(upr.path.split("/")[:-1])}/{str(ix)}/skip', post=post)
            if ('weconnect://' in r.url):
                break
            idk = self.__get_idk(soup)
            ix += 1

    def __force_login(self):
        logger.warning('Forcing login')
        code_verifier = base64URLEncode(os.urandom(32))
        if len(code_verifier) < 43:
            raise ValueError("Verifier too short. n_bytes must be > 30.")
        elif len(code_verifier) > 128:
            raise ValueError("Verifier too long. n_bytes must be < 97.")
        if (not self.__openid_conf):
            self.__openid_conf = self.__get_url(self.CARIAD_URL + '/login/v1/idk/openid-configuration').json()
        login_para = {
            'response_type': 'code',
            'scope': 'openid profile badge cars dealers vin',
            'redirect_uri': 'weconnect://authenticated',
            'client_id': 'a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
            }
        logger.info('Attempting to login')
        logger.debug('Login parameters: %s', login_para)
        r = self.__get_url(self.__openid_conf['authorization_endpoint'], get=login_para)
        if ('weconnect://' not in r.url):
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'emailPasswordForm'})
            if (not form):
                raise VWError('Login form not found. Cannot continue')
            if (not form.has_attr('action')):
                raise VWError('action not found in login email form. Cannot continue')
            form_url = form['action']
            logger.info('Found email login url: %s', form_url)
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['email'] = self.__credentials['user']

            upr = urlparse(r.url)
            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            soup = BeautifulSoup(r.text, 'html.parser')
            idk = self.__get_idk(soup)

            post['hmac'] = idk['templateModel']['hmac']
            post['password'] = self.__credentials['password']

            upr = urlparse(r.url)
            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url.replace(idk['templateModel']['identifierUrl'],idk['templateModel']['postAction']), post=post)
            if ('weconnect://' not in r.url):
                logger.info('No carnet scheme found in response.')
                soup = BeautifulSoup(r.text, 'html.parser')
                metakits = soup.find_all("meta", {'name':'identitykit'})
                for metakit in metakits:
                    if (metakit['content'] == 'termsAndConditions'): #updated terms and conditions?
                        logger.debug('Meta identitykit is termsandconditions')
                        form = soup.find('form', {'id': 'emailPasswordForm'})
                        if (form):
                            if (not form.has_attr('action')):
                                raise VWError('action not found in terms and conditions form. Cannot continue')
                            form_url = form['action']
                            logger.info('Found terms and conditions url: %s', form_url)
                            hiddn = form.find_all('input', {'type': 'hidden'})
                            post = {}
                            for h in hiddn:
                                post[h['name']] = h['value']
                            upr = urlparse(r.url)
                            r = self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
                            logger.info('Successfully accepted updated terms and conditions')
                        else:
                            logger.debug('Get IDK for legal documents')
                            idk = self.__get_idk(soup)
                            if ('templateModel' in idk and 'legalDocuments' in idk['templateModel'] and 'csrf_token' in idk and 'hmac' in idk['templateModel']):
                                logger.debug('Found legal documents')
                                post = {'countryOfResidence': idk['userSession']['countryOfResidence'], '_csrf': idk['csrf_token'], 'hmac': idk['templateModel']['hmac']}
                                for idx, legal in enumerate(idk['templateModel']['legalDocuments']):
                                    for name, val in legal.items():
                                        post[f'legalDocuments[{idx}].{name}'] = val
                                qs = parse_qs(upr.query)
                                for name, val in qs.items():
                                    post[name] = val[0]
                                upr = urlparse(r.url)
                                r = self.__get_url(upr.scheme+'://'+upr.netloc+upr.path, post=post)
                                logger.debug('Got marketing consent')
                                self.__parse_market_consent(r)

                        break
                    elif (metakit['content'] == 'loginAuthenticate'):
                        logger.warn('Meta identitykit is loginAuthenticate')
                        if ('error' in r.url):
                            raise VWError(r.url.split('error=')[1])
                    elif (metakit['content'] == 'marketConsent'):
                        logger.debug('Meta identitykit is marketConsent')
                        self.__parse_market_consent(r)
        self.__identities = get_url_params(r.history[-1].url)
        logger.info('Received Identities')
        logger.debug('Identities = %s', self.__identities)
        self.__identities['profile_url'] = WeConnect.PROFILE_URL.format(self.__identities['user_id'])
        self.__identity_kit = r.params
        logger.info('Received CarNet Identity Kit')
        logger.debug('Identity Kit = %s', r.params)
        logger.info('Requesting Tokens')
        post = {
            'client_id': 'a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com',
            'grant_type': 'authorization_code',
            'code': self.__identity_kit['code'],
            'redirect_uri': 'weconnect://authenticated'
        }
        r = self.__get_url(self.__openid_conf['token_endpoint'], post=post)
        self.__tokens = r.json()
        self.__tokens['timestamp'] = time.time()
        self.__tokens ['__name__'] = 'Token'
        logger.info('Received Tokens')
        cars = self.get_vehicles()
        for car in cars:
            vin = car['vin']
            r = self.__get_url(self.CARIAD_CLOUD.format(vin=vin))
            headers = {
                'x-csrf-token': self.__session.cookies.get_dict()['csrf_token']
            }
            r = self.__get_url('https://www.volkswagen.es/app/authproxy/vw-es/user', headers=headers)
            self.__tokens['csrf'] = self.__session.cookies.get_dict()['csrf_token']
        logger.debug('Saving session')
        self.__save_access()
        with open(WeConnect.SESSION_FILE, 'wb') as f:
            pickle.dump(self.__session.cookies, f)

    def get_jobs(self, vin):
        r = self.get_full_capabilities(vin)
        ret = []
        for v in r:
            ret.append(v['id'])
        return ret

    def get_selective_status(self, vin, jobs=['userCapabilities']):
        get = {
            'jobs': {",".join(jobs)}
        }
        r = self.__command(f'/vehicle/v1/vehicles/{vin}/selectivestatus', get=get)
        return r

    def set_logging_level(self, level):
        logger.setLevel(level)

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
        r = self.__command('/vehicle/v2/vehicles')
        return r.get('data', [])

    def get_vehicle_data(self, vin):
        r1 = self.__command('/vehicleData/es-ES/'+vin, dashboard=self.AUTH_PROXY, get={'resourceHost': 'myvw-gvf-proxy-prod'})
        r2 = self.__command('/vehicleDetails/es-ES/'+vin, dashboard=self.AUTH_PROXY, get={'resourceHost': 'myvw-gvf-proxy-prod'})
        r1.update(r2)
        return r1

    def get_vehicle_status(self, vin):
        jobs = self.get_jobs(vin)
        r = self.get_selective_status(vin, jobs=jobs)
        return r

    def get_trip_data(self, vin, type='shortterm', last=True):
        # type: 'longterm', 'cyclic', 'shortterm'
        cmd = f'/vehicle/v1/trips/{vin}/{type}'
        if (last):
            cmd += '/last'
        r = self.__command(cmd)
        return r

    def get_full_capabilities(self, vin):
        r = self.__command(f'/vehicles/{vin}/usercapabilities', get={'gdc': 'myvw-mbb-prod', 'resourceHost': 'myvw-vcf-prod'}, dashboard=self.AUTH_PROXY)
        return r['data']

    def get_position(self, vin):
        r = self.__command(f'/vehicle/v1/vehicles/{vin}/parkingposition')
        return r['data']

    def force_wakeup(self, vin):
        self.__command(f'/vehicle/v1/vehicles/{vin}/vehiclewakeuptrigger', post='')
        return True

    def get_warnings(self, vin):
        r = self.__command(f'/vehicles/{vin}/warninglights/last', get={'gdc': 'myvw-mbb-prod', 'resourceHost': 'myvw-vcf-prod'}, dashboard=self.AUTH_PROXY)
        return r.get('data', None)

    def get_oil(self, vin):
        r = self.__command('/bs/vsr/v1/vehicles/{vin}',dashboard='https://mal-3a.prd.eu.dp.vwg-connect.com/api')
        return r
