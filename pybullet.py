# -*- coding: utf-8 -*-
from __future__ import unicode_literals

try:
    # noinspection PyUnresolvedReferences,PyShadowingBuiltins
    str = unicode
except NameError:
    # noinspection PyShadowingBuiltins,PyUnboundLocalVariable
    str = str

import json
try:
    from json import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from datetime import datetime, timedelta
from itertools import chain

import urllib3.contrib.pyopenssl
import requests
from requests.exceptions import RequestException
import weechat


LICENSE = "MIT"

NAME = "pybullet"
VERSION = 0.2
AUTHOR = "Kent Ross"
__doc__ = (
    "{0} {1}: Push smart notifications to pushbullet. Authored by {2}"
    .format(NAME, VERSION, AUTHOR)
)

BULLET_URL = "https://api.pushbullet.com/v2/"
CONFIG_NAMESPACE = "plugins.var.python.{0}.".format(NAME)

TIMER_GRACE = timedelta(seconds=1)
# minimum effective value for max_poll_delay: never force polling faster than this
MIN_POLL_DELAY = 20

# https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()
session = requests.session()
session.headers['User-Agent'] = "{0}/{1}".format(NAME, VERSION)


# Configuration #

def option_string(value):
    return value


def option_boolean(value):
    return value.lower() in ("on", "yes", "y", "true", "t", "1")


def option_integer(value):
    try:
        return int(value)
    except ValueError:
        return 0


def debug(text):
    if config['debug']:
        weechat.prnt("", "{0}: {1}".format(NAME, text))


def config_as_str(value):
    """Convert config defaults to strings for weechat"""
    if isinstance(value, bool):
        return "on" if value else "off"
    else:
        return str(value)


# options (default, type, description)
config = {
    'api_secret': (
        "",
        option_string,
        "PushBullet access token"
    ),

    'notification_title': (
        "weechat",
        option_string,
        "Title for notifications sent"
    ),

    'only_when_away': (
        False,
        option_boolean,
        "Only send notifications when away"
    ),

    'highlights': (
        True,
        option_boolean,
        "Send notifications for highlights"
    ),

    'privmsg': (
        True,
        option_boolean,
        "Send notifications for private messages"
    ),

    'displayed_messages': (
        3,
        option_integer,
        "Number of messages for which to display the full text. Set to zero "
        "to always show all messages (not a good idea) or negative to never "
        "show message text"
    ),

    'ignore_after_talk': (
        10,
        option_integer,
        "For this many seconds after you have talked in a buffer, additional "
        "highlights and PMs will be ignored, assuming you saw them"
    ),

    'delay_after_talk': (
        90,
        option_integer,
        "For this many seconds after you last talked in a buffer, notifications "
        "will be delayed. If you talk again before this timer, no notification "
        "will appear"
    ),

    'min_spacing': (
        13,
        option_integer,
        "Notifications for a single buffer will never appear closer together "
        "than this many seconds"
    ),

    'long_spacing': (
        200,
        option_integer,
        "After many unseen messages in a channel, wait at least this long "
        "before notifying again - see many_messages"
    ),

    'increase_spacing': (
        70,
        option_integer,
        "Each time a notification is received on a very busy channel the next "
        "notification will be delayed this many more seconds."
    ),

    'max_poll_delay': (
        90,
        option_integer,
        "Be able to notify again at most this many seconds after a notification "
        "has been dismissed. Not a big deal, leave it high. Minimum {0}"
        .format(MIN_POLL_DELAY)
    ),

    'many_messages': (
        8,
        option_integer,
        "After this many messages in a channel, use the long spacing between "
        "notifications - seen long_spacing"
    ),

    'short_buffer_name': (
        False,
        option_boolean,
        "Use the short name of the buffer rather than the long one"
    ),

    'delete_dismissed': (
        False,
        option_boolean,
        "Delete dismissed notifications"
    ),

    'debug': (
        True,
        option_boolean,
        "Print debug info while the app is running"
    ),
}
# functions to convert configs read from the application
config_types = {}


def init_config():
    """Perform initial configuration of the application settings"""
    for option, (default_value, config_type, description) in config.items():
        # set config type
        config_types[option] = config_type
        # set descriptions for options
        weechat.config_set_desc_plugin(
            option,
            '{0} (default: "{1}")'.format(description, config_as_str(default_value))
        )
        # setdefault the script's options from weechat
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, config_as_str(default_value))
            config[option] = default_value
            debug('Option "{0}" was not set, is now {1}'.format(option, repr(default_value)))
        else:
            config[option] = config_type(weechat.config_get_plugin(option))
            debug('Option "{0}" set to {1}'.format(option, repr(config[option])))


def config_cb(data, option, value):
    """Called when a config option is changed."""
    debug("Config callback: {0} {1} {2}".format(data, option, value))
    if data != "config":
        debug("Got wrong data in config_cb: {0}".format(data))
        return weechat.WEECHAT_RC_ERROR
    if not option.startswith(CONFIG_NAMESPACE):
        debug("Got an option from the wrong namespace: {0}".format(option))
        return weechat.WEECHAT_RC_ERROR
    option = option[len(CONFIG_NAMESPACE):]
    if option in config:
        config[option] = config_types[option](value)
        debug('Option "{0}" set to "{1}" as {2}'.format(option, value, repr(config[option])))
    else:
        debug('Option "{0}" does not seem to be in config'.format(option))
    return weechat.WEECHAT_RC_OK


# Notification functions #

class Notification(object):
    """Class to track notifications for a particular buffer"""

    by_buffer = {}

    def __init__(self, buffer):
        self.buffer = buffer                    # full name of buffer
        self.buffer_show = ""                   # display name of buffer
        self.messages = []                      # list of messages displayed
        self.count = 0                          # number of messages
        self.iden = None                        # iden of current push
        self.waiting_until = None               # whether we are delaying before sending
        self.wait_hook = None                   # hook_timer hook id for our current wait
        self.bonus_delay = 0                    # total extra delay accrued between notifications
        self.changed = False                    # whether the notification has changed since last posted
        self.self_last_talked = datetime.min    # last time we talked in the buffer

    @staticmethod
    def get_for_buffer(buffer_name):
        note = Notification.by_buffer.get(buffer_name)
        if not note:
            note = Notification(buffer_name)
            Notification.by_buffer[buffer_name] = note
        return note

    def notification_text(self):
        return "\n".join(chain(
            ["{1}[{0}]".format(
                self.buffer_show,
                "{0} messages from ".format(self.count) if self.count > 1 else ""
            )],
            self.messages,
            ["..."] if self.count > len(self.messages) else ()
        ))

    def pushbullet_json(self):
        """Create the notification's push data for its current state"""
        return {
            'type': "note",
            'title': config['notification_title'],
            'body': self.notification_text()
        }

    def add_message(self, show_buffer_name, message):
        """Add a message to this notification and update the push"""
        self.buffer_show = show_buffer_name

        if not config['api_secret']:
            debug("No access token set, aborting")
            return

        self.check_dismissal()

        if (datetime.utcnow() - self.self_last_talked).total_seconds() < config['ignore_after_talk']:
            debug("Self talked in channel too recently, ignoring")
            return

        self.changed = True

        # remember message if it will be displayed
        to_display = config['displayed_messages']
        if to_display == 0 or len(self.messages) < to_display:
            self.messages.append(message)

        # update count of messages
        self.count += 1

        if self.waiting_until:
            pass  # already waiting
        else:
            self.send_notification()

    def self_talked(self):
        """We talked in the buffer; clear notification, reset status, and set last talked time"""
        self.check_dismissal()
        self.delete()  # continue even with error
        self.reset()
        self.self_last_talked = datetime.utcnow()
        # if we are already waiting, bump up the timer until our delay_after_talk
        self.delay(config['delay_after_talk'])

    def delay(self, seconds):
        """Ensure that there is a running timer hook for the time <seconds> from now"""
        after_delay = datetime.utcnow() + timedelta(seconds=seconds)
        if self.waiting_until:
            self.waiting_until = max(self.waiting_until, after_delay)
        else:
            self.waiting_until = after_delay
            self.go_wait()

    def go_wait(self):
        """Set callback hook to wait until our destination time"""
        seconds = (self.waiting_until - datetime.utcnow()).total_seconds()
        # do not wait more than max_poll_delay seconds, and max_poll_delay cannot be
        # less than MIN_POLL_DELAY
        if config['max_poll_delay'] > MIN_POLL_DELAY:
            seconds = min(seconds, config['max_poll_delay'])
        debug("Waiting {0} seconds for {1}".format(seconds, self.buffer))
        if seconds > 0:
            self.wait_hook = weechat.hook_timer(
                int(seconds * 1000),    # interval to wait in milliseconds
                0,                      # seconds alignment
                1,                      # max calls
                'done_waiting_cb',      # callback name
                self.buffer             # callback data
            )
        else:  # waiting_until already passed, don't wait at all actually
            self.waiting_until = None
            self.send_notification()

    def done_waiting(self):
        """Timer has returned at approximately the given time. Only sent from callbacks"""
        self.wait_hook = None  # done with this
        if self.waiting_until and datetime.utcnow() > self.waiting_until + TIMER_GRACE:
            # we haven't waited long enough, perhaps the timer was increased
            # or we are capped at max_poll_delay
            self.check_dismissal()
            if self.waiting_until:
                # still waiting
                self.go_wait()
            else:
                # notification was dismissed and we were reset
                self.send_notification()
        else:
            debug("Finished waiting for {0}".format(self.buffer))
            self.waiting_until = None
            self.send_notification()

    def send_notification(self):
        """Send an updated notification immediately, if one exists"""
        if self.changed:
            self.check_dismissal()
            self.repost()
            self.changed = False
            # we just sent a message, introduce a delay before more are sent
            if self.count < config['many_messages']:
                self.delay(config['min_spacing'])
            else:
                self.delay(config['long_spacing'] + self.bonus_delay)
                if config['increase_spacing'] > 0:
                    self.bonus_delay += config['increase_spacing']

    def reset(self):
        """Reset the state of this notification as it's been seen or dismissed"""
        # cancel any current wait
        if self.wait_hook is not None:
            debug("Unhooking wait for {0}".format(self.buffer))
            weechat.unhook(self.wait_hook)
            self.wait_hook = None
        self.waiting_until = None
        del self.messages[:]
        self.count = 0
        self.bonus_delay = 0
        self.iden = None
        self.changed = False

    def check_dismissal(self):
        """Check if this notification's push was dismissed and reset if so"""
        if not self.iden:
            return
        try:
            res = session.get(
                BULLET_URL + "pushes/{0}".format(self.iden),
                headers={'Access-Token': config['api_secret']}
            )
        except RequestException as ex:
            debug("Bad error while getting pushes/{0}: {1}".format(self.iden, ex))
            return

        # reset and possibly delete if it's marked as dismissed
        if res.status_code == 200:
            try:
                if res.json()['dismissed']:
                    # reset self
                    debug("Push for {0} was dismissed".format(self.buffer_show))
                    if config['delete_dismissed']:
                        self.delete()  # continue even with error
                    self.reset()
            except (JSONDecodeError, KeyError) as ex:
                debug("Error while reading push info: {0}".format(ex))
        else:
            debug("Error while getting push info: status {0}".format(res.status_code))

    def delete(self):
        """Delete this notification's current push, returning False if a bad error occurred"""
        if self.iden:
            try:
                res = session.delete(
                    BULLET_URL + "pushes/{0}".format(self.iden),
                    headers={'Access-Token': config['api_secret']}
                )
            except RequestException as ex:
                debug("Bad error while deleting pushes/{0}: {1}".format(self.iden, ex))
                return False
            if res.status_code not in (200, 404):
                debug(
                    "Failed to delete pushes/{0} with status code {1}"
                    .format(self.iden, res.status_code)
                )
            else:
                self.iden = None
        return True

    def repost(self):
        """Delete the old push and post a new one"""
        debug("Reposting for {0} from iden {1}".format(self.buffer_show, self.iden))
        if not self.delete():
            return  # don't continue if we got a request error
        # Now post the new push
        try:
            res = session.post(
                BULLET_URL + "pushes",
                headers={
                    'Access-Token': config['api_secret'],
                    'Content-Type': "application/json",
                },
                data=json.dumps(self.pushbullet_json())
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
    """Send a notification for a buffer"""
    Notification.get_for_buffer(buffer_name).add_message(show_buffer_name, message_text)


def dispatch_self_talked(buffer_name):
    """Self talked in the buffer, mark and clear status"""
    Notification.get_for_buffer(buffer_name).self_talked()


# Core callbacks #

# inspector doesn't like unused parameters
# noinspection PyUnusedLocal
def print_cb(data, buffer_ptr, timestamp, tags, is_displayed, is_highlight, prefix, message):
    """
    Called from weechat when something is printed.

    This is only hooked to relevant prints (private and highlight) so it is generally
    not necessary to check for the former.
    """
    if data != "print":
        debug("Got wrong data in print_cb: {0}".format(data))
        return weechat.WEECHAT_RC_ERROR

    prefix = prefix.decode('utf_8')
    message = message.decode('utf-8')
    tags = set(tags.decode('utf-8').split(','))

    # debug(
    #     "print_cb: timestamp={0} tags={1} is_displayed={2} is_highlight={3} prefix={4} message={5}"
    #     .format(timestamp, tags, is_displayed, is_highlight, prefix, message)
    # )

    buffer_name = weechat.buffer_get_string(buffer_ptr, 'full_name')

    # away rules: cancel
    if config['only_when_away'] and not weechat.buffer_get_string(buffer_ptr, 'localvar_away'):
        debug("Message for {0} ignored due to away status".format(buffer_name))

    # sent by me: clear and delay more messages
    # messages sent by you will have the tag "nick_?" with your localvar nick.
    # Prefix is unreliable as it may include mode indicator symbols.
    if "nick_{0}".format(weechat.buffer_get_string(buffer_ptr, 'localvar_nick').decode('utf-8')) in tags:
        debug("Dispatching self talked for {0}".format(buffer_name))
        dispatch_self_talked(buffer_name)

    # highlight or private message
    elif (
        (  # highlight
            config['highlights'] and
            int(is_highlight)
        ) or (  # private message
            config['privmsg'] and
            weechat.buffer_get_string(buffer_ptr, 'localvar_type') == "private"
        )
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

    # else:
    #     debug("Not dispatching notification for {0} from {1}".format(buffer_name, prefix))

    return weechat.WEECHAT_RC_OK


# inspector doesn't like unused parameters
# noinspection PyUnusedLocal
def done_waiting_cb(data, remaining_calls):
    """Callback for hook_timer; data will be set to a tuple of buffer and expected arrival time"""
    Notification.get_for_buffer(data).done_waiting()
    return weechat.WEECHAT_RC_OK


if __name__ == '__main__':
    weechat.register(
        NAME,
        AUTHOR,
        str(VERSION),
        LICENSE,
        __doc__,                            # description
        "",                                 # shutdown_function
        ""                                  # charset, default utf-8
    )
    init_config()
    weechat.hook_print(
        "",                                 # buffer (blank: any buffer)
        "irc_privmsg",                      # print tags to catch
        "",                                 # message must contain this string
        1,                                  # 1 if strip colors from message
        'print_cb',                         # name of callback function
        "print"                             # data given to callback function
    )
    weechat.hook_config(
        "{0}*".format(CONFIG_NAMESPACE),    # filter for configs to watch
        'config_cb',                        # name of callback function
        "config"                            # data given to callback function
    )

    weechat.prnt("", "{0}: loaded and running. Debug is {1}".format(NAME, config_as_str(config['debug'])))
