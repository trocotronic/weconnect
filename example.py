# -*- coding: utf-8 -*-
"""
Created on Fri May  8 14:06:16 2020

@author: Trocotronic
"""

import logging
logging.getLogger().setLevel(logging.WARN)

from NativeAPI import WeConnect
import requests

vwc = WeConnect()
vwc.login()
cars = vwc.get_real_car_data()
profile = vwc.get_personal_data()
print('Hi {} {} {} ({})!'.format(profile.get('salutation','UNKNOWN:').split(':')[1], profile.get('firstName','UNKNOWN'), profile.get('lastName','UNKNOWN'), profile.get('nickname','UNKNOWN')))
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
        wrn = vwc.get_warnings(vin).get('warningLights', [])
        if (len(wrn) > 0):
            print(f"\t\tWarnings: {','.join(wrn)}")

        print('---\nFetching information of {} (vin {})...\n---\n'.format(car.get('nickname','UNKNOWN'), vin))
        cardata = vwc.get_vehicle_data(vin)
        print('\tModel:' ,cardata.get('modelName','UNKNOWN'))
        print('\tYear:', cardata.get('modelYear','UNKNOWN'))
        print('\tEngine:', cardata.get('engine','UNKNOWN'))
        print('\tColor:', cardata.get('exteriorColorText','UNKNOWN'))
        status = vwc.get_vehicle_status(vin)
        print('\tStatus:')
        meas = status.get('measurements', {})
        print(f"\t\tDistance covered: {meas.get('odometerStatus',{}).get('value', {}).get('odometer', 'UNKNOWN')} km")
        print(f"\t\tFuel level: {meas.get('fuelLevelStatus',{}).get('value', {}).get('currentFuelLevel_pct', 'UNKNOWN')} %")
        print(f"\t\tFuel range: {meas.get('rangeStatus',{}).get('value', {}).get('totalRange_km', 'UNKNOWN')} km")

        print('\tLights:')
        lght = status.get('vehicleLights',{}).get('lightsStatus', {}).get('value', {})
        for l in lght.get('lights', []):
            print(f"\t\tLight {l['name']}: {l['status']}")

        print('\tIntervals:')
        intv = status.get('vehicleHealthInspection',{}).get('maintenanceStatus', {}).get('value', {})
        print(f"\t\tDistance to oil change: {intv.get('oilServiceDue_km','UNKNOWN')} km")
        print('\t\tDays to oil change:', intv.get('oilServiceDue_days','UNKNOWN'))
        print(f"\t\tDistance to inspection: {intv.get('inspectionDue_km','UNKNOWN')} km")
        print('\t\tDays to inspection:', intv.get('inspectionDue_days','UNKNOWN'))

        print('\tDoors:')
        doors = status.get('access',{}).get('accessStatus', {}).get('value', {})
        print('\t\tOverall status:', doors['overallStatus'])
        for door in doors.get('doors', []):
            print(f"\t\tDoor {door['name']}: {','.join(door['status'])}")
        print('\t\tDoor lock status:', doors['doorLockStatus'])

        print('\tWindows:')
        for wdw in doors.get('windows', []):
            print(f"\t\tDoor {wdw['name']}: {','.join(wdw['status'])}")

        pos = vwc.get_position(vin)
        data = requests.get('https://nominatim.openstreetmap.org/search.php?q='+str(pos['lat'])+','+str(pos['lon'])+'&polygon_geojson=1&format=jsonv2')
        j = data.json()
        if (len(j) > 0):
            print('\tLocation: '+j[0]['display_name'])

        trip = vwc.get_trip_data(vin, type='shortterm').get('data',{})
        print('\tLast trip:')
        print(f"\t\tEnd time: {trip.get('tripEndTimestamp','')}")
        print(f"\t\tVehicle type: {trip.get('vehicleType','UNKNOWN')}")
        print(f"\t\tMileage: {trip.get('mileage_km', 'UNKNOWN')} km ({trip.get('startMileage_km','')} - {trip.get('overallMileage_km','')})")
        print(f"\t\tTrip time: {trip.get('travelTime','UNKNOWN')} minutes")
        print(f"\t\tAverage fuel consumption: {trip.get('averageFuelConsumption','UNKNOWN')} l")
        print(f"\t\tAverage speed: {trip.get('averageSpeed_kmph','UNKNOWN')} km/h")

        trip = vwc.get_trip_data(vin, type='longterm').get('data', {})
        print('\tLast long trip:')
        print(f"\t\tEnd time: {trip.get('tripEndTimestamp','')}")
        print(f"\t\tVehicle type: {trip.get('vehicleType','UNKNOWN')}")
        print(f"\t\tMileage: {trip.get('mileage_km', 'UNKNOWN')} km ({trip.get('startMileage_km','')} - {trip.get('overallMileage_km','')})")
        print(f"\t\tTrip time: {trip.get('travelTime','UNKNOWN')} minutes")
        print(f"\t\tAverage fuel consumption: {trip.get('averageFuelConsumption','UNKNOWN')} l")
        print(f"\t\tAverage speed: {trip.get('averageSpeed_kmph','UNKNOWN')} km/h")

        trip = vwc.get_trip_data(vin, type='cyclic').get('data', {})
        print('\tLast cyclic trip:')
        print(f"\t\tEnd time: {trip.get('tripEndTimestamp','')}")
        print(f"\t\tVehicle type: {trip.get('vehicleType','UNKNOWN')}")
        print(f"\t\tMileage: {trip.get('mileage_km', 'UNKNOWN')} km ({trip.get('startMileage_km','')} - {trip.get('overallMileage_km','')})")
        print(f"\t\tTrip time: {trip.get('travelTime','UNKNOWN')} minutes")
        print(f"\t\tAverage fuel consumption: {trip.get('averageFuelConsumption','UNKNOWN')} l")
        print(f"\t\tAverage speed: {trip.get('averageSpeed_kmph','UNKNOWN')} km/h")
