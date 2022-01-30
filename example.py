# -*- coding: utf-8 -*-
"""
Created on Fri May  8 14:06:16 2020

@author: Trocotronic
"""

from NativeAPI import WeConnect
import logging
import requests

logging.getLogger().setLevel(logging.WARN)
vwc = WeConnect()
vwc.login()
cars = vwc.get_real_car_data()
profile = vwc.get_personal_data()
print('Hi {} {} {} ({})!'.format(profile.get('salutation','UNKNOWN'), profile.get('firstName','UNKNOWN'), profile.get('lastName','UNKNOWN'), profile.get('nickname','UNKNOWN')))
mbb = vwc.get_mbb_status()
print('Profile completed?', mbb.get('profileCompleted','UNKNOWN'))
print('S-PIN defined?', mbb.get('spinDefined','UNKNOWN'))
print('CarNet enrollment country:',mbb.get('carnetEnrollmentCountry','UNKNOWN'))
if (cars and len(cars)):
    print('Enumerating cars...')
    for car in cars.get('realCars',[]):
        vin = car.get('vehicleIdentificationNumber','UNKNOWN')
        print('\tNickname:', car.get('nickname','UNKNOWN'))
        print('\tDealer:', car.get('allocatedDealerBrandCode','UNKNOWN'))
        print('\tCarNet enrollment date:', car.get('carnetAllocationTimestamp','UNKNOWN'))
        print('\tCarNet indicator:', car.get('carNetIndicator','UNKNOWN'))
        print('\tDeactivated:', car.get('deactivated','UNKNOWN'))
        if (car.get('deactivated',False) == True):
            print('\tDeactivation reason:',car.get('deactivationReason','UNKNOWN'))

        print('---\nFetching information of {} (vin {})...\n---\n'.format(car.get('nickname','UNKNOWN'), vin))
        details = vwc.get_vehicle_data(vin)
        cardata = details.get('vehicleDataDetail',[]).get('carportData',[])
        print('\tModel:' ,cardata.get('modelName','UNKNOWN'))
        print('\tYear:', cardata.get('modelYear','UNKNOWN'))
        print('\tModel code:', cardata.get('modelCode','UNKNOWN'))
        print('\tEngine:', cardata.get('engine','UNKNOWN'))
        print('\tMMI:', cardata.get('mmi','UNKNOWN'))
        print('\tTransmission:', cardata.get('transmission','UNKNOWN'))
        users = vwc.get_users(vin)
        print('\tFound {} user(s) with access: {}'.format(len(users.get('users',[])), ', '.join([user.get('nickname','UNKNOWN') for user in users.get('users',[])])))
        #r = vwc.request_status_update(vin)
        vsr = vwc.get_vsr(vin)
        pvsr = vwc.parse_vsr(vsr)
        print('\tStatus:')
        status = pvsr.get('status',[])
        print('\t\tDistance covered:', status.get('distance_covered','UNKNOWN'))
        print('\t\tParking light:', status.get('parking_light','UNKNOWN'))
        print('\t\tParking brake:', status.get('parking_brake','UNKNOWN'))
        print('\t\tTemperature outside:', (int(status.get('temperature_outside','0 0').split(' ')[0])-2731)/10)
        print('\t\tBEM:', status.get('bem','UNKNOWN'))
        print('\t\tSpeed:', status.get('speed','UNKNOWN'))
        print('\t\tTotal range:', status.get('total_range','UNKNOWN'))
        print('\t\tPrimary range:', status.get('primary_range','UNKNOWN'))
        print('\t\tSecondary range:', status.get('secondary_range','UNKNOWN'))
        print('\t\tFuel level:', status.get('fuel_level','UNKNOWN'))
        print('\t\tCNG level:', status.get('cng_level','UNKNOWN'))
        
        print('\tIntervals:')
        intv = pvsr.get('intervals',[])
        print('\t\tDistance to oil change:', intv.get('distance_to_oil_change','UNKNOWN'))
        print('\t\tDays to oil change:', intv.get('time_to_oil_change','UNKNOWN'))
        print('\t\tDistance to inspection:', intv.get('distance_to_inspection','UNKNOWN'))
        print('\t\tDays to inspection:', intv.get('time_to_inspection','UNKNOWN'))
        print('\t\tAdBlue range:', intv.get('ad_blue_range','UNKNOWN'))
        
        print('\tOil level:')
        oil = pvsr.get('oil_level',[])
        print('\t\tLiters:', oil.get('liters','UNKNOWN'))
        print('\t\tPercentage:', oil.get('dipstick_percentage','UNKNOWN'))
        
        print('\tDoors:')
        doors = pvsr.get('doors',[])
        avdoors = {'left_front':'Left front', 'right_front':'Right front', 'left_rear':'Left rear', 'right_rear':'Right rear', 'trunk':'Trunk', 'hood':'Hood'}
        for d in avdoors.items():
            print('\t\t{}: {}, {}'.format(d[1], doors.get('open_'+d[0],''), doors.get('lock_'+d[0],'')))
        
        print('\tWindows:')
        win = pvsr.get('windows',[])
        avwin = {'left_front':'Left front', 'right_front':'Right front', 'left_rear':'Left rear', 'right_rear':'Right rear'}
        for d in avwin.items():
            print('\t\t{}: {}, {}'.format(d[1], win.get('state_'+d[0],'UNKNOWN'), win.get('position_'+d[0],'UNKNOWN')))
        print('\t\tState roof:', win.get('state_roof','UNKNOWN'))
        print('\t\tState roof rear:', win.get('state_roof_rear','UNKNOWN'))
        print('\t\tState service flap:', win.get('state_service_flap','UNKNOWN'))
        print('\t\tState spoiler:', win.get('state_spoiler','UNKNOWN'))
        print('\t\tState convertible top:', win.get('state_convertible_top','UNKNOWN'))
        
        print('\tTyre pressure:')
        tyre = pvsr.get('tyre_pressure',[])
        avtyre = {'left_front':'Left front', 'right_front':'Right front', 'left_rear':'Left rear', 'right_rear':'Right rear','spare':'Spare'}
        for d in avtyre.items():
            print('\t\t{}: {} (desired {}, diff {})'.format(d[1], tyre.get('current_'+d[0],''), tyre.get('desired_'+d[0],''), tyre.get('difference_'+d[0],'')))
        pos = vwc.get_position(vin)
        latlong = pos.get('storedPositionResponse',[]).get('position',[]).get('carCoordinate','')
        data = requests.get('https://nominatim.openstreetmap.org/search.php?q='+str(latlong['latitude']/1e6)+','+str(latlong['longitude']/1e6)+'&polygon_geojson=1&format=jsonv2')
        j = data.json()
        if (len(j) > 0):
            print('\tLocation: '+j[0]['display_name'])
            