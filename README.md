# Home Assistant component for the JSON IoT Server (https://github.com/luisfog/jits)

## Example configuration:
**IMPORTANT:** Don't use spaces and special chars as names
~~~
jits_history:
  url: 'https://your_jits_server.com/publisher.php'
  scan_interval: 60
  clients:
    - connection_key: '1234abc1234abc1234abc1234abc'
      aes_key: '789456asd789456asd789456asd'
      aes_iv: '555asdAdxasD=='
      whitelist:
        sensor.temp: 'Temperature'
        sensor.hum: 'Humidity'
    - connection_key: '321qew321qew321qew'
      aes_key: 'f42bd42d40bd7bd9'
      aes_iv: 'ASDCad13fg2Advg=='
      whitelist:
        sensor.light: 'LivingroomLux'
~~~
