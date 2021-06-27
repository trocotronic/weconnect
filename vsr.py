#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jun 28 00:08:42 2021

@author: trocotronic
"""

import logging

class VSR:
    __vsr_fields = [
        ('0x0101010001', '0x0101010001', 'status', 'utc_time'),
        ('0x0101010002', '0x0101010002', 'status', 'distance_covered'),
        ('0x0203FFFFFF', '0x0203010001', 'intervals', 'distance_to_oil_change'),
        ('0x0203FFFFFF', '0x0203010002', 'intervals', 'time_to_oil_change'),
        ('0x0203FFFFFF', '0x0203010003', 'intervals', 'distance_to_inspection'),
        ('0x0203FFFFFF', '0x0203010004', 'intervals', 'time_to_inspection'),
        ('0x0203FFFFFF', '0x0203010005', 'intervals', 'warning_oil_change'),
        ('0x0203FFFFFF', '0x0203010006', 'intervals', 'alarm_inspection'),
        ('0x0203FFFFFF', '0x0203010007', 'intervals', 'monthly_mileage'),
        ('0x0204FFFFFF', '0x0204040001', 'oil_level', 'liters'),
        ('0x0204FFFFFF', '0x0204040002', 'oil_level', 'minimum_warning'),
        ('0x0204FFFFFF', '0x0204040003', 'oil_level', 'dipstick_percentage'),
        ('0x0204FFFFFF', '0x0204040004', 'oil_level', 'display'),
        ('0x0204FFFFFF', '0x02040C0001', 'intervals', 'ad_blue_range'),
        ('0x0301FFFFFF', '0x0301010001', 'status', 'parking_light', {'1':'on','2':'off'}),
        ('0x0301FFFFFF', '0x0301020001', 'status', 'temperature_outside'),
        ('0x0301FFFFFF', '0x0301030001', 'status', 'parking_brake', {'0':'inactive', '1':'active'}),
        ('0x0301FFFFFF', '0x0301030002', 'status', 'state_of_charge'),
        ('0x0301FFFFFF', '0x0301030003', 'status', 'bem'),
        ('0x0301FFFFFF', '0x0301030004', 'status', 'speed'),
        ('0x0301FFFFFF', '0x0301030005', 'status', 'total_range'),
        ('0x0301FFFFFF', '0x0301030006', 'status', 'primary_range'),
        ('0x0301FFFFFF', '0x0301030007', 'status', 'primary_drive'),
        ('0x0301FFFFFF', '0x0301030008', 'status', 'secondary_range'),
        ('0x0301FFFFFF', '0x0301030009', 'status', 'secondary_drive'),
        ('0x0301FFFFFF', '0x030103000A', 'status', 'fuel_level'),
        ('0x0301FFFFFF', '0x030103000B', 'status', 'fuel_method', {'0':'measured', '1':'calculated'}),
        ('0x0301FFFFFF', '0x030103000D', 'status', 'cng_level'),
        ('0x0301FFFFFF', '0x0301040001', 'doors', 'lock_left_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040002', 'doors', 'open_left_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040003', 'doors', 'safety_left_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040004', 'doors', 'lock_left_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040005', 'doors', 'open_left_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040006', 'doors', 'safety_left_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040007', 'doors', 'lock_right_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040008', 'doors', 'open_right_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040009', 'doors', 'safety_right_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000A', 'doors', 'lock_right_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000B', 'doors', 'open_right_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000C', 'doors', 'safety_right_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000D', 'doors', 'lock_trunk', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000E', 'doors', 'open_trunk', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030104000F', 'doors', 'safety_trunk', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040010', 'doors', 'lock_hood', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040011', 'doors', 'open_hood', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301040012', 'doors', 'safety_hood', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050001', 'windows', 'state_left_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050002', 'windows', 'position_left_front'),
        ('0x0301FFFFFF', '0x0301050003', 'windows', 'state_left_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050004', 'windows', 'position_left_rear'),
        ('0x0301FFFFFF', '0x0301050005', 'windows', 'state_right_front', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050006', 'windows', 'position_right_front'),
        ('0x0301FFFFFF', '0x0301050007', 'windows', 'state_right_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050008', 'windows', 'position_right_rear'),
        ('0x0301FFFFFF', '0x0301050009', 'windows', 'state_convertible_top', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030105000A', 'windows', 'position_convertible_top'),
        ('0x0301FFFFFF', '0x030105000B', 'windows', 'state_roof', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030105000C', 'windows', 'position_roof'),
        ('0x0301FFFFFF', '0x030105000D', 'windows', 'state_roof_rear', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x030105000E', 'windows', 'position_roof_rear'),
        ('0x0301FFFFFF', '0x030105000F', 'windows', 'state_service_flap', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050010', 'windows', 'position_service_flap'),
        ('0x0301FFFFFF', '0x0301050011', 'windows', 'state_spoiler', {'0':'n/a', '1':'open', '2':'locked', '3':'closed'}),
        ('0x0301FFFFFF', '0x0301050012', 'windows', 'position_spoiler'),
        
        ('0x0301FFFFFF', '0x0301060001', 'tyre_pressure', 'current_left_front'),
        ('0x0301FFFFFF', '0x0301060002', 'tyre_pressure', 'desired_left_front'),
        ('0x0301FFFFFF', '0x0301060003', 'tyre_pressure', 'current_left_rear'),
        ('0x0301FFFFFF', '0x0301060004', 'tyre_pressure', 'desired_left_rear'),
        ('0x0301FFFFFF', '0x0301060005', 'tyre_pressure', 'current_right_front'),
        ('0x0301FFFFFF', '0x0301060006', 'tyre_pressure', 'desired_right_front'),
        ('0x0301FFFFFF', '0x0301060007', 'tyre_pressure', 'current_right_rear'),
        ('0x0301FFFFFF', '0x0301060008', 'tyre_pressure', 'desired_right_rear'),
        ('0x0301FFFFFF', '0x0301060009', 'tyre_pressure', 'current_spare'),
        ('0x0301FFFFFF', '0x030106000A', 'tyre_pressure', 'desired_spare'),
        ('0x0301FFFFFF', '0x030106000B', 'tyre_pressure', 'difference_left_front'),
        ('0x0301FFFFFF', '0x030106000C', 'tyre_pressure', 'difference_left_rear'),
        ('0x0301FFFFFF', '0x030106000D', 'tyre_pressure', 'difference_right_front'),
        ('0x0301FFFFFF', '0x030106000E', 'tyre_pressure', 'difference_right_rear'),
        ('0x0301FFFFFF', '0x030106000F', 'tyre_pressure', 'difference_spare'),
        ('0x0301FFFFFF', '0x0301060001', 'tyre_pressure', 'current_left_front'),
        ('0x0301FFFFFF', '0x0301060002', 'tyre_pressure', 'desired_left_front'),
        ('0x0301FFFFFF', '0x0301060003', 'tyre_pressure', 'current_left_rear'),
        ('0x0301FFFFFF', '0x0301060004', 'tyre_pressure', 'desired_left_rear'),
        ('0x0301FFFFFF', '0x0301060005', 'tyre_pressure', 'current_right_front'),
        ('0x0301FFFFFF', '0x0301060006', 'tyre_pressure', 'desired_right_front'),
        ('0x0301FFFFFF', '0x0301060007', 'tyre_pressure', 'current_right_rear'),
        ('0x0301FFFFFF', '0x0301060008', 'tyre_pressure', 'desired_right_rear'),
        ('0x0301FFFFFF', '0x0301060009', 'tyre_pressure', 'current_spare'),
        ('0x0301FFFFFF', '0x030106000A', 'tyre_pressure', 'desired_spare'),
        ('0x0301FFFFFF', '0x030106000B', 'tyre_pressure', 'difference_left_front'),
        ('0x0301FFFFFF', '0x030106000C', 'tyre_pressure', 'difference_left_rear'),
        ('0x0301FFFFFF', '0x030106000D', 'tyre_pressure', 'difference_right_front'),
        ('0x0301FFFFFF', '0x030106000E', 'tyre_pressure', 'difference_right_rear'),
        
        ]
    
    def __init__(self):
        pass
    
    def parse(self, j):
        r = {}
        rr = {}
        if ('StoredVehicleDataResponse' in j):
            j = j['StoredVehicleDataResponse']
            r['VehicleDataResponse'] = {}
            rr['vin'] = j['vin']
            if ('vehicleData' in j and 'data' in j['vehicleData']):
                for d in j['vehicleData']['data']:
                    if ('id' in d and 'field' in d):
                        for f in d['field']:
                            found = False
                            for e in self.__vsr_fields:
                                if (e[1] == f['id']):
                                    if (e[2] not in rr):
                                        rr[e[2]] = {}
                                    rr[e[2]][e[3]] = 'null'
                                    if ('value' in f):
                                        if (len(e) == 5 and f['value'] in e[4]):
                                            rr[e[2]][e[3]] = e[4][f['value']]
                                        else:
                                            rr[e[2]][e[3]] = f['value'] if f['value'] else 'null'
                                    if ('unit' in f):
                                        rr[e[2]][e[3]] += ' '+f['unit']
                                    #if ('textId' in f):
                                    #    rr[e[2]][e[3]] += ' ({})'.format(f['textId'])
                                    found = True
                                    break
                            if (not found):
                                logging.warning('[parse_vsr] item %s, field %s not found', d['id'],f['id'])
                                logging.warning('[parse_vsr] %s', f)
        return rr
        
        