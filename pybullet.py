# -*- coding: utf-8 -*-
from collections import namedtuple
from datetime import datetime, timedelta
from itertools import chain, count
import json
from json import JSONDecodeError
import sys
from types import coroutine

import weechat


# Constants #

__license__ = "MIT"

NAME = "pybullet"
__version__ = '0.4'
__author__ = "Kent Ross"
__email__ = "k@mad.cash"
__maintainer__ = __author__
__doc__ = (
    "{0} {1}: Push smart notifications to pushbullet. Authored by {2}"
    .format(NAME, __version__, __author__)
)

BULLET_URL = "https://api.pushbullet.com/v2/"
CONFIG_NAMESPACE = "plugins.var.python.{0}.".format(NAME)

TIMER_GRACE = timedelta(seconds=1)
# minimum effective value for max_poll_delay: never force polling faster than
# this
MIN_POLL_DELAY = 20
HTTP_TIMEOUT = 30 * 1000  # milliseconds


# Configuration #

def debug(text):
    if config['debug']:
        weechat.prnt("", "{0}: {1}".format(NAME, text))


def option_string(value):
    return value


def option_boolean(value):
    return value.lower() in ("on", "yes", "y", "true", "t", "1")


def option_integer(value):
    try:
        return int(value)
    except ValueError:
        return 0


def config_as_str(value):
    """Convert config defaults to strings for weechat."""
    if isinstance(value, bool):
        return "on" if value else "off"
    else:
        return str(value)


def secret_renderer(value):
    return "[redacted]" if value else repr("")


def boolean_renderer(value):
    return "on" if value else "off"


def default_renderer(value):
    return repr(value)


# options (default, type, renderer, description)
config = {
    'api_secret': (
        "",
        option_string,
        secret_renderer,
        "PushBullet access token"
    ),

    'target_device': (
        "",
        option_string,
        default_renderer,
        "PushBullet device iden of a specific device to push notifications "
        "to. Leave blank to send to all devices"
    ),

    'notification_title': (
        "weechat",
        option_string,
        default_renderer,
        "Title for notifications sent"
    ),

    'only_when_away': (
        False,
        option_boolean,
        boolean_renderer,
        "Only send notifications when away"
    ),

    'highlights': (
        True,
        option_boolean,
        boolean_renderer,
        "Send notifications for highlights"
    ),

    'highlight_spam_threshold': (
        10,
        option_integer,
        default_renderer,
        "If a message highlights this many people in channel, assume it is "
        "spam and do not send a notification. Values less than 2 disable "
        "this heuristic"
    ),

    'privmsg': (
        True,
        option_boolean,
        boolean_renderer,
        "Send notifications for private messages"
    ),

    'displayed_messages': (
        3,
        option_integer,
        default_renderer,
        "Number of messages for which to display the full text. Set to zero "
        "to always show all messages (not necessarily a good idea) or negative "
        "to never show message text"
    ),

    'ignore_after_talk': (
        10,
        option_integer,
        default_renderer,
        "For this many seconds after you have talked in a buffer, additional "
        "highlights and PMs will be ignored, assuming you saw them"
    ),

    'delay_after_talk': (
        90,
        option_integer,
        default_renderer,
        "For this many seconds after you last talked in a buffer, "
        "notifications will be delayed. If you talk again before this timer, "
        "no notification will appear"
    ),

    'min_spacing': (
        13,
        option_integer,
        default_renderer,
        "Notifications for a single buffer will never appear closer together "
        "than this many seconds"
    ),

    'long_spacing': (
        200,
        option_integer,
        default_renderer,
        "After many unseen messages in a channel, wait at least this long "
        "before notifying again - see many_messages"
    ),

    'increase_spacing': (
        70,
        option_integer,
        default_renderer,
        "Each time a notification is received on a very busy channel the next "
        "notification will be delayed this many more seconds."
    ),

    'max_poll_delay': (
        90,
        option_integer,
        default_renderer,
        "Be able to notify again at most this many seconds after a "
        "notification has been dismissed. Not a big deal, leave it high. "
        "Minimum {0}"
        .format(MIN_POLL_DELAY)
    ),

    'many_messages': (
        8,
        option_integer,
        default_renderer,
        "After this many messages in a channel, use the long spacing between "
        "notifications - seen long_spacing"
    ),

    'short_buffer_name': (
        False,
        option_boolean,
        boolean_renderer,
        "Use the short name of the buffer rather than the long one"
    ),

    'delete_dismissed': (
        False,
        option_boolean,
        boolean_renderer,
        "Delete dismissed notifications"
    ),

    'debug': (
        False,
        option_boolean,
        boolean_renderer,
        "Print debug info while the app is running"
    ),
}
# Functions to convert configs read from the application from saved strings to
# usable internal values
config_types = {}
# Functions to render config values to printable values for the console
config_renderers = {}


def init_config():
    """Perform initial configuration of the application settings."""
    for option, (default, config_type, renderer, description) in config.items():
        # set config type
        config_types[option] = config_type
        config_renderers[option] = renderer
        # set descriptions for options
        weechat.config_set_desc_plugin(
            option,
            '{0} (default: "{1}")'.format(
                description,
                config_as_str(default)
            )
        )
        # setdefault the script's options from weechat
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, config_as_str(default))
            config[option] = default
            debug(
                'Option "{0}" was not set, is now {1}'
                .format(option, repr(default))
            )
        else:
            config[option] = config_type(weechat.config_get_plugin(option))
            debug(
                'Option "{0}" set to {1}'
                .format(option, config_renderers[option](config[option]))
            )


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
        debug(
            'Option "{0}" set to "{1}" as {2}'
            .format(option, value, repr(config[option]))
        )
    else:
        debug('Option "{0}" does not seem to be in config'.format(option))
    return weechat.WEECHAT_RC_OK


# Async #

# http request data, a dict of {stash_id: coroutine}
async_stash = {}
http_stash_id_provider = ("request" + str(n) for n in count())


def run_async(coro):
    """Like loop.call_soon."""
    send_async(coro, None)


def send_async(coro, value):
    """Sends a value back to the coroutine."""
    try:
        async_stash[coro.send(value)] = coro
        debug(
            "async stash now has {0} in-flight request(s)"
            .format(len(async_stash))
        )
    except StopIteration:
        pass


def throw_async(coro, error):
    """Throws an error in the coroutine."""
    try:
        async_stash[coro.throw(error)] = coro
        debug(
            "async stash now has {0} in-flight request(s)"
            .format(len(async_stash))
        )
    except StopIteration:
        pass


class RequestException(Exception):
    pass


# HTTP response.
#   http_version: str
#   status_code: int
#   headers: dict[str, list[str]]
#   body: bytes
#   stderr: bytes or str
HttpResponse = namedtuple(
    'HttpResponse',
    'http_version status_code headers body stderr'
)


@coroutine
def http_request(method, url, headers=None, data=None):
    """Async function that returns a response for an HTTP request."""
    # We make async work by registering the hook with weechat, then yielding the
    # stash id of the request to the top level. Our callback to the hook will
    # take the coroutine out of the stash by the stash id and send it the
    # response (or an exception).
    #
    # This has to be a @coroutine-decorated generator function instead of an
    # async def because we need to directly yield raw values to the top level of
    # the iterator chain.
    options = {
        'customrequest': method,
        'header': "1",
    }
    if headers is not None:
        options['httpheader'] = "\n".join(
            "{0}: {1}".format(k, v)
            for k, v in headers.items()
        )
    if data is not None:
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        elif isinstance(data, (list, dict)):
            data_bytes = json.dumps(data).encode('utf-8')
        else:
            raise ValueError(
                "Bad type {0} passed to http_request data param"
                .format(type(data))
            )
        options['copypostfields'] = data_bytes

    stash_id = next(http_stash_id_provider)
    debug("sending {0}: {1} {2}".format(stash_id, method, repr(url)))
    weechat.hook_process_hashtable(
        "url:{0}".format(url),
        options,
        HTTP_TIMEOUT,
        'http_cb_receiver',
        stash_id,
    )
    stdout, stderr = yield stash_id
    try:
        # We receive http responses with the response header intact so we
        # can parse out the status etc.
        if isinstance(stdout, str):
            # weechat returns str unless the content is not valid utf-8.
            stdout = stdout.encode('utf-8')
        header_bytes, _, body = stdout.partition(b"\r\n\r\n")
        header = header_bytes.decode('ascii')
        [status_line, *header_lines] = header.split("\r\n")
        http_version, _, status_str = status_line.partition(" ")
        status_code_str, _, status_code_name = status_str.partition(" ")
        status_code = int(status_code_str)
        header_dict = {}
        for line in header_lines:
            field, _, value = line.partition(":")
            header_dict.setdefault(field.lower(), []).append(value.strip())
        return HttpResponse(
            http_version=http_version,
            status_code=status_code,
            headers=header_dict,
            body=body,
            stderr=stderr,
        )
    except (UnicodeDecodeError, ValueError) as ex:
        raise RequestException("bad HTTP header received: {0}".format(ex))


def http_cb_receiver(data, command, return_code, stdout, stderr):
    # data is the stash_id for this request
    coro = async_stash.pop(data)
    debug("got http response for {0}".format(data))
    if return_code == weechat.WEECHAT_HOOK_PROCESS_ERROR:
        throw_async(
            coro,
            RequestException("Error with command {0}".format(repr(command)))
        )
        return weechat.WEECHAT_RC_OK
    send_async(coro, (stdout, stderr))
    return weechat.WEECHAT_RC_OK


# Notification functions #

class Notifier:
    """Class to manage notifications for a particular buffer."""

    by_buffer = {}

    def __init__(self, buffer_name):
        self.buffer = buffer_name   # full name of buffer
        self.buffer_show = ""       # display name of buffer
        self.messages = []          # list of messages displayed
        self.message_count = 0      # number of messages
        self.unsent = []            # list of unsent messages (w/ no notif sent)
        self.unsent_count = 0       # number of unsent messages
        self.current_notif = None   # current push notification
        self.waiting_until = None   # whether we are delaying before sending
        self.wait_hook = None       # hook_timer hook id for our current wait
        self.bonus_delay = 0  # total extra delay accrued between notifications
        self.self_last_talked = datetime.min  # last time we talked in the buff

    @staticmethod
    def get_for_buffer(buffer_name):
        note = Notifier.by_buffer.get(buffer_name)
        if not note:
            note = Notifier(buffer_name)
            Notifier.by_buffer[buffer_name] = note
        return note

    def notification_text(self):
        return "\n".join(chain(
            ["{1}[{0}]".format(
                self.buffer_show,
                (
                    "{0} messages from ".format(self.message_count)
                    if self.message_count > 1 else
                    ""
                )
            )],
            self.messages,
            ["..."] if self.message_count > len(self.messages) else ()
        ))

    def pushbullet_json(self):
        """Create the notification's push data for its current state."""
        result = {
            'type': "note",
            'title': config['notification_title'],
            'body': self.notification_text()
        }
        if config['target_device']:
            result['device_iden'] = config['target_device']
        return result

    async def add_message(self, show_buffer_name, message):
        """Add a message to this notification and update the push."""
        self.buffer_show = show_buffer_name

        if not config['api_secret']:
            debug("No access token set, aborting")
            return

        if (
            (datetime.utcnow() - self.self_last_talked).total_seconds()
            < config['ignore_after_talk']
        ):
            debug("Self talked in channel too recently, ignoring")
            return

        # remember message if it might be displayed
        to_display = config['displayed_messages']
        if to_display == 0 or len(self.unsent) < to_display:
            self.unsent.append(message)

        # update count of messages
        self.unsent_count += 1

        if self.waiting_until:
            if self.current_notif:
                await self.current_notif.check_dismissal()
        else:
            await self.send_notification()

    async def self_talked(self):
        """
        We talked in the buffer; clear notification, reset status, and set last
        talked time.
        """
        if self.current_notif:
            run_async(self.current_notif.delete())
        self.current_notif = None
        # fully reset the state of the notifier now that we are all up to date
        # on this channel
        self.reset_seen()
        if self.wait_hook is not None:
            debug("Unhooking wait for {0}".format(self.buffer))
            weechat.unhook(self.wait_hook)
            self.wait_hook = None
        self.waiting_until = None
        self.bonus_delay = 0
        del self.unsent[:]
        self.unsent_count = 0
        self.self_last_talked = datetime.utcnow()
        # if we are already waiting, bump the timer until our delay_after_talk
        await self.delay(config['delay_after_talk'])

    async def delay(self, seconds):
        """
        Ensure that there is a running timer hook for the time <seconds> from
        now.
        """
        after_delay = datetime.utcnow() + timedelta(seconds=seconds)
        if self.waiting_until:
            self.waiting_until = max(self.waiting_until, after_delay)
        else:
            self.waiting_until = after_delay
            await self.go_wait()

    async def go_wait(self):
        """Set callback hook to wait until our destination time"""
        seconds = (self.waiting_until - datetime.utcnow()).total_seconds()
        # do not wait more than max_poll_delay seconds, and max_poll_delay
        # cannot be less than MIN_POLL_DELAY
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
            await self.send_notification()

    async def done_waiting(self):
        """
        Timer has returned at approximately the given time. Only sent from
        callbacks.
        """
        self.wait_hook = None  # done with this
        if (
            self.waiting_until
            and datetime.utcnow() > self.waiting_until + TIMER_GRACE
        ):
            # we haven't waited long enough, perhaps the timer was increased
            # or we are capped at max_poll_delay
            if self.current_notif:
                await self.current_notif.check_dismissal()
            await self.go_wait()
        else:
            debug("Finished waiting for {0}".format(self.buffer))
            self.waiting_until = None
            await self.send_notification()

    async def send_notification(self):
        """Send an updated notification immediately, if one exists"""
        if self.unsent_count:
            # post the new state
            await self.repost()
            # we just sent a message, introduce a delay before more are sent
            if self.message_count < config['many_messages']:
                await self.delay(config['min_spacing'])
            else:
                await self.delay(config['long_spacing'] + self.bonus_delay)
                if config['increase_spacing'] > 0:
                    self.bonus_delay += config['increase_spacing']

    def reset_seen(self):
        """
        Reset the state of this notifier as we have at least seen posted
        notifications.
        """
        # cancel any current wait
        del self.messages[:]
        self.message_count = 0

    async def repost(self):
        """Delete the old push and post a new one"""
        debug("Reposting for {0} from iden {1}".format(
            self.buffer_show,
            self.current_notif and self.current_notif.iden
        ))
        if self.current_notif:
            await self.current_notif.check_dismissal()

        if self.current_notif:
            run_async(self.current_notif.delete())
            self.current_notif = None

        # add unsent messages into displaying messages
        to_show = config['displayed_messages']
        if to_show > 0:
            new_messages_to_show = to_show - len(self.messages)
            self.messages.extend(self.unsent[:new_messages_to_show])
        elif to_show == 0:
            self.messages.extend(self.unsent)  # zero: display all
        self.message_count += self.unsent_count
        del self.unsent[:]
        self.unsent_count = 0

        # POST a new notification
        try:
            http_response = await http_request(
                method='POST',
                url=BULLET_URL + "pushes",
                headers={
                    'Access-Token': config['api_secret'],
                    'Content-Type': "application/json",
                },
                data=self.pushbullet_json(),
            )
        except RequestException as ex:
            debug("Bad error while posting push: {0}".format(ex))
            return

        if http_response.status_code != 200:
            debug(
                "Error posting push: status {0}"
                .format(http_response.status_code)
            )
            return

        try:
            iden = json.loads(
                http_response.body.decode('utf-8')
            )['iden']
            debug("Got new iden {0}".format(iden))
            self.current_notif = Notification(notifier=self, iden=iden)
        except (JSONDecodeError, UnicodeDecodeError, KeyError) as ex:
            debug("Error reading push creation response: {0}".format(ex))


class Notification:
    """
    Class to manage the state of a pushed notification. Mostly responsible for
    deleting individual notifications and checking their status. Once created,
    the iden of this notification never changes.
    """

    def __init__(self, notifier, iden):
        self.notifier = notifier
        self.iden = iden

    async def check_dismissal(self, always_delete=False):
        """Check if this notification's push was dismissed and reset if so."""
        try:
            http_response = await http_request(
                method='GET',
                url=BULLET_URL + "pushes/{0}".format(self.iden),
                headers={'Access-Token': config['api_secret']},
            )
        except RequestException as ex:
            debug(
                "Bad error while getting pushes/{0}: {1}"
                .format(self.iden, ex)
            )
            return

        if http_response.status_code == 200:
            try:
                if json.loads(http_response.body.decode('utf-8'))['dismissed']:
                    # dismissed notifications are deleted only if configured,
                    # but we forget about them even if they are not deleted,
                    # and we mark their messages as seen when they are found to
                    # be dismissed.
                    debug(
                        "Push {0} for {1} was dismissed"
                        .format(self.iden, self.notifier.buffer_show)
                    )
                    if always_delete or config['delete_dismissed']:
                        run_async(self.delete())
                    self.notifier.reset_seen()
                    if self.notifier.current_notif is self:
                        self.notifier.current_notif = None
            except (JSONDecodeError, UnicodeDecodeError, KeyError) as ex:
                debug("Error while reading push info: {0}".format(ex))
        else:
            debug(
                "Error while getting push info: status {0}"
                .format(http_response.status_code)
            )

    async def delete(self):
        """Delete this notification's push."""
        try:
            http_response = await http_request(
                method='DELETE',
                url=BULLET_URL + "pushes/{0}".format(self.iden),
                headers={'Access-Token': config['api_secret']},
            )
            if http_response.status_code not in (200, 404):
                debug(
                    "Failed to delete pushes/{0} with status code {1}"
                    .format(self.iden, http_response.status_code)
                )
        except RequestException as ex:
            debug(
                "Bad error while deleting pushes/{0}: {1}"
                .format(self.iden, ex)
            )


async def dispatch_notification(buffer_ptr, buffer_name, prefix, message):
    """Send a notification for a buffer"""
    if config['short_buffer_name']:
        show_buffer_name = weechat.buffer_get_string(buffer_ptr, 'short_name')
    else:
        show_buffer_name = buffer_name

    debug("Dispatching notification for {0}".format(buffer_name))
    # send the notification
    await Notifier.get_for_buffer(buffer_name).add_message(
        show_buffer_name,
        "<{0}> {1}".format(prefix, message)
    )


async def dispatch_self_talked(buffer_name):
    """Self talked in the buffer, mark and clear status"""
    await Notifier.get_for_buffer(buffer_name).self_talked()


# Heuristics #

def detect_highlight_spam(buffer_ptr, message):
    """
    Return True if the message highlights more than the configured threshold
    of users in the nicklist of the channel.
    """
    threshold = config['highlight_spam_threshold']
    if threshold < 2:
        return False
    checked = set()

    # extract words to check from message
    words = message.split()
    if not weechat.buffer_get_integer(buffer_ptr, 'nicklist_case_sensitive'):
        words = map(str.lower, words)

    for word in words:
        if word in checked:
            continue
        checked.add(word)
        # check if this highlights a user in the channel
        if weechat.nicklist_search_nick(buffer_ptr, "", word):
            threshold -= 1
            if threshold == 0:
                return True
    return False


# Core callbacks #

# inspector doesn't like unused parameters
# noinspection PyUnusedLocal
def print_cb(
    data,
    buffer_ptr,
    timestamp,
    tags,
    is_displayed,
    is_highlight,
    prefix,
    message
):
    """Called from weechat when something is printed."""
    if data != "print":
        debug("Got wrong data in print_cb: {0}".format(data))
        return weechat.WEECHAT_RC_ERROR

    buffer_name = weechat.buffer_get_string(buffer_ptr, 'full_name')

    # away rules: cancel
    if (
        config['only_when_away']
        and not weechat.buffer_get_string(buffer_ptr, 'localvar_away')
    ):
        debug("Message for {0} ignored due to away status".format(buffer_name))

    # sent by me: clear and delay more messages
    # messages sent by you will have the tag "nick_?" with your localvar nick.
    # Prefix is unreliable as it may include mode indicator symbols.
    tags = tags.split(",")
    my_nick = weechat.buffer_get_string(buffer_ptr, 'localvar_nick')
    if "nick_{0}".format(my_nick) in tags:
        debug("Dispatching self talked for {0}".format(buffer_name))
        run_async(dispatch_self_talked(buffer_name))

    # highlight
    elif config['highlights'] and int(is_highlight):
        if detect_highlight_spam(buffer_ptr, message):
            debug(
                "Message for {0} ignored due to detection of highlight spam"
                .format(buffer_name)
            )
        else:
            run_async(
                dispatch_notification(buffer_ptr, buffer_name, prefix, message)
            )
    elif (
        config['privmsg']
        and weechat.buffer_get_string(buffer_ptr, 'localvar_type') == "private"
    ):
        run_async(
            dispatch_notification(buffer_ptr, buffer_name, prefix, message)
        )

    return weechat.WEECHAT_RC_OK


# inspector doesn't like unused parameters
# noinspection PyUnusedLocal
def done_waiting_cb(data, remaining_calls):
    """Callback for hook_timer; data will be set to the name of the buffer"""
    run_async(Notifier.get_for_buffer(data).done_waiting())
    return weechat.WEECHAT_RC_OK


if __name__ == '__main__':
    weechat.register(
        NAME,
        __author__,
        __version__,
        __license__,
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

    weechat.prnt(
        "", "{0}: loaded and running. Debug is {1}"
        .format(NAME, config_as_str(config['debug']), repr(sys.version))
    )
    debug("Python version is {0}".format(repr(sys.version)))
