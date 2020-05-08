# -*- coding: utf-8 -*-
"""
Created on Thu May  7 10:39:56 2020

@author: Trocotronic

"""

COUNTRY_CODE = 'es_ES'


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

import requests, pickle
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class WeConnect():
    __session = None
    __dashboard = None
    __edit_profile_url = None
    SESSION_FILE = 'weconnect.session'
    BASE_URL = 'https://www.portal.volkswagen-we.com'
    
    def __get_url(self, url,get=None,post=None,json=None,cookies=None,headers=None):
        if (post == None and json == None):
            r = self.__session.get(url, params=get, headers=headers, cookies=cookies)
        else:
            r = self.__session.post(url, data=post, json=json, params=get, headers=headers, cookies=cookies)
        if r.status_code != requests.codes.ok:
            raise UrlError(r.status_code, "Unknown status code", r)
        return r
    
    def __command(self, command, post={}, dashboard=None):
        if (not dashboard):
            dashboard = self.__dashboard
        r = self.__get_url(dashboard+command, json=post, headers={'X-CSRF-Token': self.__csrf})
        if ('application/json' in r.headers['Content-Type']):
            jr = r.json()
            if (jr['errorCode'] != '0'):
                print((r.request.body))
                raise VWError('JSON Response with error = {}'.format(jr['errorCode']))
            return jr
        return r
    
    def __init__(self, country_code=None):
        self.__session = requests.Session()
        self._CountryCode = country_code
        try:
            with open(WeConnect.SESSION_FILE, 'rb') as f:
                self.__session.cookies.update(pickle.load(f))
        except FileNotFoundError:
            pass
    
    def login(self, user, password):      
        r = self.__get_url(WeConnect.BASE_URL)
        soup = BeautifulSoup(r.text, 'html.parser')
        if (not soup.find('cn-menu-garage')): #session is not valid
            if (not soup.find('cn-welcome-view')):
                c = soup.find('ul',{ 'ng-controller' :'cnSignedOutCtrl'})
                ng_init = c['ng-init']
                js = ng_init[ng_init.find("{")+1:ng_init.find("}")]
                parms = list(map(str.strip, js.split(',')))
                country_url = None
                for p in parms:
                    sp = p.split(':',1)
                    if (sp[0] == 'getCountriesURL'):
                        country_url = sp[1].strip()[1:-1]
                        break
                if (not country_url):
                    raise UrlError(r.status_code, "Country URL not found", r)
                
                r =  self.__get_url(country_url)
                rj = r.json()
                if (rj['errorCode'] != '0'):
                    raise UrlError(r.status_code, "get-country error", r)
                
                if (not COUNTRY_CODE):
                    print('Please, select language:\n')
                
                countries = {}
                for lang in rj['countries']:
                    for (loc,disp) in lang['languages'].items():
                        if (loc == 'length'):
                            continue
                        country_code = '{}_{}'.format(loc, lang['countryKey'].upper())
                        countries[country_code] = '{} ({})'.format(lang['displayName'], disp)
                
                if (not self._CountryCode in countries):
                    print('Please, select language:\n')
                    for (k,v) in countries.items():
                        print('{} = {}'.format(v,k))
                    print('\nIntroduce the language code:', end=' ')
                    self._CountryCode = input()
                    while (not self._CountryCode in countries):
                        print('Wrong value. Please, select a valid language code:', end=' ')
                        self._CountryCode = input()
                
                cncl = soup.find('cn-country-language-selection')
                cn_namespace = cncl['cn-namespace']
                cn_url = cncl['cn-action-url']
                lcod = self._CountryCode.split('_')
                r =  self.__get_url(cn_url, post={cn_namespace+'country': lcod[1].lower(), cn_namespace+'language': lcod[0]})
                
                soup = BeautifulSoup(r.text, 'html.parser')
            cn_welcome = soup.find('cn-welcome-view')
            cn_w_url = cn_welcome['cn-login-url']
            
            r =  self.__get_url(cn_w_url)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'emailPasswordForm'})
            form_url = form['action']
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['email'] = USER
            
            upr = urlparse(r.url)
            
            r =  self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form', {'id': 'credentialsForm'})
            if (not form):
                form = soup.find('form', {'id': 'emailPasswordForm'})
                if (form):
                    print(form)
                    div = form.find('div', {'class': 'sub-title'}).find('div').text
                    raise UrlError(r.status_code, div, r)
                raise UrlError(r.status_code, 'This account does not exist', r)
            form_url = form['action']
            hiddn = form.find_all('input', {'type': 'hidden'})
            post = {}
            for h in hiddn:
                post[h['name']] = h['value']
            post['password'] = PASSWORD
            
            upr = urlparse(r.url)
            r =  self.__get_url(upr.scheme+'://'+upr.netloc+form_url, post=post)
            
            soup = BeautifulSoup(r.text, 'html.parser')
            ng_ctrl = soup.find('div', {'ng-controller': 'cnCompleteLoginCtrl'})
            if (not ng_ctrl):
                form = soup.find('form', {'id': 'credentialsForm'})
                if (form):
                    span = form.find('span', {'class': 'message'})
                    if (span):
                        raise UrlError(r.status_code,span.find_all(text=True, recursive=False)[0],r)
                raise UrlError(r.status_code, 'Cannot login', r)
            ng_init = ng_ctrl['ng-init']
            js = ng_init[ng_init.find("{")+1:ng_init.find("}")]
            parms = list(map(str.strip, js.split(',')))
            loginStatusUrl = None
            loginCode = None
            loginNS = None
            for p in parms:
                sp = p.split(':',1)
                if (sp[0] == 'loginStatusUrl'):
                    loginStatusUrl = sp[1].strip()[1:-1]
                elif (sp[0] == 'code'):
                    loginCode = sp[1].strip()[1:-1]
                elif (sp[0] == 'namespace'):
                    loginNS = sp[1].strip()[1:-1]
            if (not loginStatusUrl):
                raise UrlError(r.status_code, "LoginStatus URL not found", r)
            if (not loginCode):
                raise UrlError(r.status_code, "loginCode not found", r)
            if (not loginNS):
                raise UrlError(r.status_code, "loginNS not found", r)
            r =  self.__get_url(loginStatusUrl, post={loginNS+'code': loginCode})
            self.__dashboard = r.url
            r = self.__get_url(self.__dashboard)
            soup = BeautifulSoup(r.text, 'html.parser')
        else: #already logged
            self.__dashboard = r.url
        meta = soup.find('meta', {'name': '_csrf'})
        if (not meta):
            raise UrlError(r.status_code, 'CSRF token not found.', r)
        self.__csrf = meta['content']
        with open(WeConnect.SESSION_FILE, 'wb') as f:
            pickle.dump(self.__session.cookies, f)
        stpos = r.text.find('editProfileUrl:')+15
        stend = r.text.find(',',stpos)
        self.__edit_profile_url = WeConnect.BASE_URL+r.text[stpos:stend].strip()[1:-1]
        
    def __check_dashboard(self):
        if (not self.__dashboard):
            raise VWError('Dashboard not found. Please, login first.')
        if (not self.__csrf):
            raise VWError('CSRF not found. Please, login first.')
        if (not self.__edit_profile_url):
            raise VWError('EditProfile URL not found. Please, login first.')
            
    def logout(self):
        self.__check_dashboard()
        jr = self.__command('/-/logout/revoke')
        self.__get_url(jr['endPointURL']['logoutURL'])
        
    def get_fully_loaded_cars(self):
        self.__check_dashboard()
        jr = self.__command('/-/mainnavigation/get-fully-loaded-cars')
        return jr['fullyLoadedVehiclesResponse']
        
    def get_location(self):
        self.__check_dashboard()
        jr = self.__command('/-/cf/get-location')
        return jr['position']
    
    def get_fences(self):
        self.__check_dashboard()
        jr = self.__command('/-/geofence/get-fences')
        return jr['geoFenceResponse']
    
    def get_alerts(self):
        self.__check_dashboard()
        jr = self.__command('/-/rsa/get-alerts')
        return jr['remoteSpeedAlertsResponse'] 
    
    def get_psp_tile_status(self):
        self.__check_dashboard()
        jr = self.__command('/-/psp/get-psp-tile-status')
        return jr['pspTile'] 
    
    def get_shutdown(self):
        self.__check_dashboard()
        jr = self.__command('/-/mainnavigation/get-shutdown')
        return jr['getShutdownResponse'] 
    
    def load_car_details(self, vin):
        self.__check_dashboard()
        jr = self.__command('/-/mainnavigation/load-car-details/'+vin)
        return jr['completeVehicleJson'] 
    
    def get_expired_placeids(self):
        self.__check_dashboard()
        jr = self.__command('/-/expiredplaceids/get-expired-placeids')
        return jr['expiredPlaceidsResponse'] 
    
    def get_psp_status(self):
        self.__check_dashboard()
        jr = self.__command('/-/mainnavigation/get-psp-status')
        return jr['pspStatusResponse'] 
    
    def get_vehicle_details(self, vin=None):
        self.__check_dashboard()
        if (vin):
            jr = self.__command('/-/profile/get-vehicle-details', dashboard=self.__edit_profile_url, post={'vin': vin})
            return jr['vehicle']
        else:
            jr = self.__command('/-/vehicle-info/get-vehicle-details')
            return jr['vehicleDetails'] 
    
    def get_latest_report(self):
        self.__check_dashboard()
        jr = self.__command('/-/vhr/get-latest-report')
        return jr['vehicleHealthReportList'] 
    
    def get_latest_trip_statistics(self):
        self.__check_dashboard()
        jr = self.__command('/-/rts/get-latest-trip-statistics')
        return jr['rtsViewModel'] 
    
    def get_vsr(self):
        self.__check_dashboard()
        jr = self.__command('/-/vsr/get-vsr')
        return jr['vehicleStatusData'] 
    
    def get_preferred_dealer(self, brand='v'):
        self.__check_dashboard()
        jr = self.__command('/-/mainnavigation/get-preferred-dealer', post={'vehicleBrand': brand})
        return jr['preferredDealerResponse'] 
    
    def get_last_refuel_trip_statistics(self):
        self.__check_dashboard()
        jr = self.__command('/-/rts/get-last-refuel-trip-statistics')
        return jr['rtsViewModel'] 
    
    def get_trip_statistics(self):
        self.__check_dashboard()
        jr = self.__command('/-/rts/get-trip-statistics')
        return jr['rtsViewModel'] 
    
    def search_vechiles(self):
        self.__check_dashboard()
        jr = self.__command('/-/profile/search-vehicles', dashboard=self.__edit_profile_url)
        return jr['vehicleList'] 
    
    def get_trusted_device_status(self, vin):
        self.__check_dashboard()
        jr = self.__command('/-/profile/digitalkey/get-trusted-device-status/'+vin, dashboard=self.__edit_profile_url)
        return jr['vehicleList'] 
        
