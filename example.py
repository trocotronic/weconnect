# -*- coding: utf-8 -*-
"""
Created on Fri May  8 14:06:16 2020

@author: Trocotronic
"""

COUNTRY_LANG = 'es_ES'
USER = 'your_user'
PASSWORD = 'your_password'

from WeConnect import WeConnect

vwc = WeConnect(COUNTRY_LANG)
vwc.login(USER,PASSWORD)
vehicles = vwc.search_vehicles()
if (vehicles and len(vehicles) > 0):
    print('Found {} vehicles'.format(len(vehicles)))
    vin = vehicles[0]['vin']
    tech = vwc.load_car_details(vin)
    details = vwc.get_vehicle_details(vin)
    print('---\nFetching information of {} (vin {})...'.format(vehicles[0]['vehicleName'], vin))
    print('Model: {}'.format(tech['model']))
    print('Year: {}'.format(tech['modelYear']))
    print('Model code: {}'.format(tech['modelCode']))
    print('Engine:')
    print('\tCombustion: {}'.format(tech['engineTypeCombustian']))
    print('\tElectric: {}'.format(tech['engineTypeElectric']))
    print('\tHybrid: {}'.format(tech['engineTypeHybridOCU1'] or tech['engineTypeHybridOCU2']))
    print('\tGNC: {}'.format(tech['engineTypeCNG']))
    print('Mobile key activated: {}'.format(tech['mobileKeyActivated']))
    print('eSIM compatible: {}'.format(tech['esimCompatible']))
    print('Power layer: {}'.format(tech['vwConnectPowerLayerAvailable']))
    print('Member since: {}'.format(details['enrollmentDate']))
    print('Contracts:')
    for c in tech['packageServices']:
        print('\t{}, expires in {}'.format(c['packageServiceName'], c['expirationDate']))
    lr = vwc.get_latest_report()[0]
    print('Latest report')
    print('\tDate: {} {}'.format(lr['creationDate'], lr['creationTime']))
    print('\tMileage: {} km'.format(lr['mileageValue']))
    print('\tNext service: {} (overdue {})'.format(details['serviceDates']['service'], lr['headerData']['serviceOverdue']))
    print('\tNext oil: {} (overdue {})'.format(details['serviceDates']['oil'], lr['headerData']['oilOverdue']))
    stat = vwc.get_latest_trip_statistics()
    print('Latest trip statistics:')
    for i in range(len(stat['tripStatistics'])-1,0,-1):
        s = stat['tripStatistics'][i]
        if (s):
            t = s['tripStatistics'][-1]
            print('\tDate: {} km'.format(t['timestamp']))
            print('\tAverage speed: {} km/h'.format(t['averageSpeed']))
            print('\tDuration: {} min'.format(t['tripDuration']))
            print('\tDistance: {} km'.format(t['tripLength']))
            if (t['averageFuelConsumption']):
                print('\tAverage Fuel Consumption {} l'.format(t['averageFuelConsumption']))
            if (t['averageElectricConsumption']):
                print('\tAverage Electric Consumption {} kWh'.format(t['averageElectricConsumption']))
            if (t['averageCngConsumption']):
                print('\tAverage GNC Consumption {} kWh'.format(t['averageCngConsumption']))
            break
    
    