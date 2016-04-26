# pybullet

Pybullet is a Python extension plugin for [weechat](https://weechat.org/) that pushes smart notifications to the [PushBullet](https://www.pushbullet.com/) service.

Notifications are grouped per channel, have increasing delays if ignored, preview the first few lines, go away when you have been active in the channel, and detect when notifications have been dismissed remotely.

### Requirements

- requests
- urllib3

currently, [for better security](https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl) in old Python versions like Ubuntu:

- pyopenssl
- ndg-httpsclient
- pyasn1

### Features

- Low footprint in the client, on the network, and on your phone
- Notification grouping and smart dismissal
- Full Unicode compatibility, emoji included
- Customizable delays
- Python 2.7 and 3.5 compatible

Feel free to submit feature requests and issues; this is a dogfood plugin in progress.
