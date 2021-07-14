# Volkswagen We Connect
API for Python to interact with Volkswagen's service We Connect (formerly CarNet).

## Information
This modules contains some of the methods to interact with Volkswagen's service We Connect. This API is made for Python and retrieves the information in JSON format. It can be imported into your application and interact with VW's servers directly.
Edit `credentials.py` to specify your username (e-mail), password and S-PIN.

## Features
- Direct login with the same USER and PASSWORD you use.
- Session is stored to prevent massive logins.
- Auto-accept new Terms & Conditions.
- Available methods:
  - `get_personal_data()`
  - `get_real_car_data()`
  - `get_mbb_status()`
  - `get_identity_data()`
  - `get_vehicles()`
  - `get_vehicle_data(vin)`
  - `get_users(vin)`
  - `get_fences(vin)`
  - `get_fences_configuration()`
  - `get_speed_alerts(vin)`
  - `get_speed_alerts_configuration()`
  - `get_trip_data(vin, type='longTerm')`: `type` can be `'longTerm'`, `'shortTerm'` or `'cyclic'`.
  - `get_vsr(vin)`
  - `get_departure_timer(vin)`
  - `get_climater(vin)`
  - `get_position(vin)`
  - `get_destinations(vin)`
  - `get_charger(vin)`
  - `get_heating_status(vin)`
  - `get_history(vin)`
  - `get_roles_rights(vin)`
  - `get_fetched_role(vin)`
  - `get_vehicle_health_report(vin)`
  - `get_car_port_data(vin)`
  - `request_status_update(vin)`
  - `request_status(vin)`
  - `get_vsr_request(vin, reqId)`
  - `flash(vin, lat, long)`
  - `honk(vin, lat, long)`
  - `get_honk_and_flash_status(vin, rid)`
  - `get_honk_and_flash_configuration()`
  - `battery_charge(vin, action='off')`: `action` can be `'off'` or `'on'`.
  - `climatisation(vin, action='off')`: `action` can be `'off'` or `'on'`.
  - `climatisation_temperature(vin, temperature=21.5)`: `temperature` is a `float` in Celsius degrees.
  - `window_melt(vin, action='off')`: `action` can be `'off'` or `'on'`.
  - `heating(vin, action='off')`: `action` can be `'off'` or `'on'`.
  - `heating(vin, action='lock')`: `action` can be `'lock'` or `'unlock'`.
  - `parse_vsr(vsr)`
  - `set_logging_level(level)`: `level` can be `logging.DEBUG`, `logging.INFO`, `logging.WARN`, `logging.ERROR` or `logging.CRITICAL`.
  - `version()`

NOTE: `vin` is the Vehicle Identification Number, a string with capital letters and digits.

## Usage
See `example.py`.

## License
Under ODC Open Database License v1.0.
