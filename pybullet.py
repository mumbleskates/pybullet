# -*- coding: utf-8 -*-
from __future__ import unicode_literals

try:
    # noinspection PyUnresolvedReferences,PyShadowingBuiltins
    str = unicode
except NameError:
    # noinspection PyShadowingBuiltins,PyUnboundLocalVariable
    str = str

try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from itertools import chain

import requests
from requests.exceptions import RequestException
import weechat


LICENSE = "MIT"

NAME = "pybullet"
VERSION = 0.1
AUTHOR = "Kent Ross"
__doc__ = (
    "{0} {1}: Push smart notifications to pushbullet. Authored by {2}"
    .format(NAME, VERSION, AUTHOR)
)

BULLET_URL = "https://api.pushbullet.com/v2/"

session = requests.session()
session.headers['User-Agent'] = "{0}/{1}".format(NAME, VERSION)


# Registration #

weechat.register(
    NAME,
    AUTHOR,
    str(VERSION),
    LICENSE,
    __doc__,  # description
    "",  # shutdown_function
    ""  # charset, default utf-8
)


# Configuration #

# options (default, type, description)
config = {
    'api_secret': (
        "",
        weechat.config_string,
        "PushBullet access token"
    ),

    'notification_title': (
        "weechat",
        weechat.config_string,
        "Title for notifications sent"
    ),

    'only_when_away': (
        False,
        weechat.config_boolean,
        "Only send notifications when away (default: off)"
    ),

    'highlights': (
        True,
        weechat.config_boolean,
        "Send notifications for highlights (default: on)"
    ),

    'privmsg': (
        True,
        weechat.config_boolean,
        "Send notifications for private messages (default: on)"
    ),

    'displayed_messages': (
        3,
        weechat.config_integer,
        "Number of messages for which to display the full text (default: 3)"
    ),

    'count_limit': (
        10,
        weechat.config_integer,
        "More than this many messages will be reported as 'many' instead of a "
        "specific number of messages (default: 10)"
    ),

    'short_buffer_name': (
        False,
        weechat.config_boolean,
        "Use the short name of the buffer rather than the long one "
        "(default: off)"
    ),

    'debug': (
        False,
        weechat.config_boolean,
        "Print debug info while the app is running"
    ),
}

# functions to convert configs read from the application
config_types = {}


def config_as_str(value):
    """Convert config defaults to strings for weechat"""
    if isinstance(value, bool):
        return "on" if value else "off"
    else:
        return str(value)


def init_config():
    """Perform initial configuration of the application settings"""
    for option, (default_value, config_type, description) in config.items():
        # set config type
        config_types[option] = config_type
        # set descriptions for options
        weechat.config_set_desc_plugin(option, description)
        # setdefault the script's options from weechat
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, config_as_str(default_value))
            config[option] = default_value
        else:
            config[option] = config_type(weechat.config_get_plugin(option))

init_config()


def config_cb(data, option, value):
    """Called when a config option is changed."""
    if data != "config":
        debug("Got wrong data in config_cb: {0}".format(data))
        return weechat.WEECHAT_RC_ERROR
    if option in config:
        config[option] = config_types[option](value)
        debug('Option "{0}" set to "{1}" as {2}'.format(option, value, repr(config[option])))
    return weechat.WEECHAT_RC_OK


def debug(text):
    if config['debug']:
        weechat.prnt("", "{0}: {1}".format(NAME, text))


# Notification functions #

class Notification(object):
    """Class to track notifications for a particular buffer"""

    by_buffer = {}

    def __init__(self):
        self.buffer_show = ""
        self.messages = []
        self.count = 0
        self.iden = None

    def add_message(self, show_buffer_name, message):
        """Add a message to this notification and update the push"""
        self.buffer_show = show_buffer_name

        if not config['api_secret']:
            debug("no access token set, aborting")
            return

        changed = False

        self.check_dismissal()

        # remember message if it will be displayed
        to_display = config['displayed_messages']
        if to_display != 0 and to_display < len(self.messages):
            self.messages.append(message)
            changed = True

        # update count of messages
        if type(self.count) is int:
            self.count += 1
            changed = True
            if self.count > config['count_limit']:
                self.count = "Many"

        if changed:
            # Notification's content has changed, update the push
            self.repost()

    def json(self):
        """Create the notification's push data for its current state"""
        return {
            'type': "note",
            'title': config['notification_title'],
            'body': "\n".join(chain(
                ["{1}[{0}]".format(
                    self.buffer_show,
                    "{0} messages from ".format(self.count) if self.count > 1 else ""
                )],
                self.messages,
                ["..."] if self.count > len(self.messages) else ()
            ))
        }

    def check_dismissal(self):
        """Check if this notification's push was dismissed and reset it if so."""
        if not self.iden:
            return
        try:
            res = session.get(BULLET_URL + "pushes/{0}".format(self.iden))
        except RequestException as ex:
            debug("Bad error while getting push info: {0}".format(ex))
            return

        if res.status_code == 200:
            try:
                if res.json()['dismissed']:
                    # reset self
                    debug("Push for {0} was dismissed".format(self.buffer_show))
                    self.messages.clear()
                    self.count = 0
                    self.iden = None
            except (JSONDecodeError, KeyError) as ex:
                debug("Error while reading push info: {0}".format(ex))
        else:
            debug("Error while getting push info: status {0}".format(res.status_code))

    def repost(self):
        """Delete this notification's current push, then post a new one."""
        debug("Reposting for {0} from iden {1}".format(self.buffer_show, self.iden))
        if self.iden:
            res = session.delete(BULLET_URL + "pushes/{0}".format(self.iden))
            if res.status_code not in (200, 404):
                debug(
                    "Failed to delete pushes/{0} with status code {1}"
                    .format(self.iden, res.status_code)
                )
            else:
                self.iden = None

        # Now post the new push
        try:
            res = session.post(
                BULLET_URL + "pushes",
                headers={'Access-Token': config['api_secret']},
                json=self.json()
            )
        except RequestException as ex:
            debug("Bad error while posting push: {0}".format(ex))
            return
        if res.status_code == 200:
            try:
                self.iden = res.json()['iden']
                debug("Got new iden {0}".format(self.iden))
            except (JSONDecodeError, KeyError) as ex:
                debug("Error reading push creation response: {0}".format(ex))
        else:
            debug("Error posting push: status {0}".format(res.status_code))


def dispatch_notification(buffer_name, show_buffer_name, message_text):
    note = Notification.by_buffer.get(buffer_name)
    if not note:
        note = Notification()
        Notification.by_buffer[buffer_name] = note
    note.add_message(show_buffer_name, message_text)


# Core callbacks #

# inspector doesn't like unused parameters
# noinspection PyUnusedLocal
def print_cb(data, buffer_ptr, date, tag_count, is_displayed, is_highlight, prefix, message):
    """
    Called from weechat when something is printed.

    This is only hooked to relevant prints (private and highlight) so it is generally
    not necessary to check for the former.
    """
    if data != "print":
        debug("Got wrong data in print_cb: {0}".format(data))
        return weechat.WEECHAT_RC_ERROR

    buffer_name = weechat.buffer_get_string(buffer_ptr, 'full_name')

    # away rules: cancel
    if config['only_when_away'] and not weechat.buffer_get_string(buffer_ptr, 'localvar_away'):
        debug("Message for {0} ignored due to away status".format(buffer_name))

    # highlight or private message
    elif (
        (is_highlight and config['highlights']) or
        (config['privmsg'])
    ):
        if config['short_buffer_name']:
            show_buffer_name = weechat.buffer_get_string(buffer_ptr, 'short_name')
        else:
            show_buffer_name = buffer_name

        debug("Dispatching notification for {0}".format(buffer_name))

        # send the notification
        dispatch_notification(
            buffer_name, show_buffer_name,
            "<{0}> {1}".format(prefix, message)
        )

    else:
        debug("Not dispatching notification for {0}".format(buffer_name))

    return weechat.WEECHAT_RC_OK


# Register callbacks #

weechat.hook_print(
    "",                                         # buffer (blank: any buffer)
    "notify_private,notify_highlight",          # print tags to catch
    "",                                         # message must contain this string
    1,                                          # 1 if strip colors from message
    'print_cb',                                 # name of callback function
    "print"                                     # data given to callback function
)
weechat.hook_config(
    "plugins.var.python.{0}.*".format(NAME),    # filter for configs to watch
    'config_cb',                                # name of callback function
    "config"                                    # data given to callback function
)

weechat.prnt("", "{0}: loaded and running. Debug is {1}".format(NAME, config_as_str(config['debug'])))
