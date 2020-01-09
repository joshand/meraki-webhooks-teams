#!/usr/bin/env python3
from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for, render_template, jsonify
from webexteamssdk import WebexTeamsAPI
import os
import json
import meraki
import meraki_addons
import requests
import dateutil.parser
import sys
import hashlib
import codecs
import base64
import sqlite3
from datetime import datetime

"""
requests_oauthlib requires secure transport.
Insecure transport is enabled here for this test environment.
Do not use insecure transport in production
"""
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# os.environ['DEBUG'] = '1'

app = Flask(__name__)
app.secret_key = os.urandom(24)
dodebug = True

app_port = os.getenv("PORT")
if not app_port:
    app_port = 5000
else:
    app_port = int(app_port)

# Load additional environment variables
CLIENT_ID = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
CLIENT_SECRET = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
BOT_USER = os.getenv("WEBEX_BOT_USERNAME")
BOT_TOKEN = os.getenv("WEBEX_BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL")

# If any of the bot environment variables are missing, terminate the application
if not CLIENT_ID or not CLIENT_SECRET or not BOT_USER or not BOT_TOKEN or not BASE_URL:
    print("app.py - Missing Environment Variable.")
    if not CLIENT_ID:
        print("CLIENT_ID")
    if not CLIENT_SECRET:
        print("CLIENT_SECRET")
    if not BOT_USER:
        print("BOT_USER")
    if not BOT_TOKEN:
        print("BOT_TOKEN")
    if not BASE_URL:
        print("BASE_URL")
    sys.exit()

AUTHORIZATION_BASE_URL = 'https://api.ciscospark.com/v1/authorize'
TOKEN_URL = 'https://api.ciscospark.com/v1/access_token'
SCOPE = 'spark:rooms_read spark:rooms_write spark:memberships_read spark:memberships_write spark:people_read'
if BASE_URL[-1:] != "/":
    BASE_URL += "/"
REDIRECT_URI = BASE_URL + 'callback'


def dolog(data):
    if dodebug:
        now = datetime.now()
        date_time = now.strftime("%Y/%m/%d-%H:%M:%S")
        try:
            ipaddr = request.remote_addr
        except:
            ipaddr = "0.0.0.0"
        print(date_time, ipaddr, data)


"""
###############################################################################
SQLite3 functions for Webhook Filtering
###############################################################################
"""


def check_create_table():
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='filters'")
    if c.fetchone()[0] != 1:
        dolog("Setting up database...")
        c.execute("CREATE TABLE filters (roomid text, filtername text)")
        conn.commit()
    conn.close()


check_create_table()


def does_filter_exist(roomid, filtername):
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("SELECT * FROM filters WHERE roomid=? AND filtername=?", (roomid, filtername))
    rec = c.fetchone()
    conn.close()

    if not rec:
        return False
    else:
        dolog("Filter exists; message dropped.")
        return True


def del_filter(roomid, filtername):
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("DELETE FROM filters WHERE roomid=? AND filtername=?", (roomid, filtername))
    conn.commit()
    conn.close()

    return True


def get_filter_list(roomid):
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("SELECT * FROM filters WHERE roomid=?", (roomid,))
    rec = c.fetchall()
    conn.close()

    if not rec:
        return False
    else:
        return rec


def check_insert_filter(roomid, filtername):
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("SELECT * FROM filters WHERE roomid=? AND filtername=?", (roomid, filtername))
    if not c.fetchone():
        dolog("Adding room filter for:" + filtername)
        c.execute("INSERT INTO filters VALUES (?, ?)", (roomid, filtername))
        conn.commit()
    conn.close()


def clear_filters_for_room(roomid):
    conn = sqlite3.connect('filter.db')
    c = conn.cursor()
    c.execute("DELETE FROM filters WHERE roomid=?", (roomid,))
    conn.commit()
    conn.close()


"""
###############################################################################
These URL Routes & Functions are all to support the provisioning UI
###############################################################################
"""


@app.route("/")
def landing():
    dolog("/:landing")
    """ Step 1: Landing Page.

    / is the landing page for the application. Render the HTML Template for
    the landing page.
    """
    return render_template('landing.html')


@app.route("/connect")
def login():
    dolog("/connect:login::" + REDIRECT_URI)
    """ Step 2: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Webex Teams)
    using a URL with a few key OAuth parameters.
    """
    teams = OAuth2Session(CLIENT_ID, scope=SCOPE, redirect_uri=REDIRECT_URI)
    authorization_url, state = teams.authorization_url(AUTHORIZATION_BASE_URL)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    dolog("/connect:login::" + str(session))
    return redirect(authorization_url)


# Step 3: User authorization, this happens on the provider.
@app.route("/callback", methods=["GET"])
def callback():
    dolog("/callback:callback")
    """ Step 4: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    auto_token = False
    if auto_token:
        # At one point, this worked. And then it didn't. request.url was returning 'http' instead of 'https'...
        # Forcing that fixed caused a 'Missing access token parameter.' error. Decided not to troubleshoot
        # further because a simple requests.post works without any issues at all...
        auth_code = OAuth2Session(CLIENT_ID, state=session.get('oauth_state', ""), redirect_uri=REDIRECT_URI)
        token = auth_code.fetch_token(TOKEN_URL, client_secret=CLIENT_SECRET, authorization_response=request.url)
        # request.build_absolute_uri()
    else:
        access_url = TOKEN_URL + '?grant_type=authorization_code' + '&code=' + request.args.get('code', '') + '&client_id=' + CLIENT_ID + '&redirect_uri=' + REDIRECT_URI + '&client_secret=' + CLIENT_SECRET + '&state=' + session.get('oauth_state', "")
        headers = {"content-type": "application/x-www-form-urlencoded"}
        tokendata = requests.post(access_url, headers=headers)
        token = tokendata.json()

    """
    At this point you can fetch protected resources but lets save
    the token and show how this is done from a persisted token
    """

    session['oauth_token'] = token
    return redirect(url_for('.rooms'))


@app.route("/rooms", methods=["GET"])
def rooms():
    dolog("/rooms:rooms")
    """ Step 5: Retrieving list of Teams Rooms using Token

    We now have an authorization token. Next step is to get a list of all
    rooms and present those to the user
    """
    teams_token = session['oauth_token']
    api = WebexTeamsAPI(access_token=teams_token['access_token'])
    roomlist = api.rooms.list(sortBy='lastactivity')
    newrooms = []
    for r in roomlist:
        if r.type == "group":
            newrooms.append(r)
    return render_template('rooms.html', rooms=newrooms, teams_token=teams_token)


@app.route("/addintegration", methods=["POST"])
def add_integration():
    dolog("/addintegration:add_integration")
    """ Step 6: Create room if necessary, and add the bot to the room

    User has opted to create a new room or has selected an existing
    one. If it's a new room, use the Integration token to create it.

    Next, add the webhook receiver bot to the room so that it can
    post the contents of the received webhooks.
    """
    iroom = request.form.get("roomid", None)
    itoken = request.form.get("token", None)
    if itoken:
        itoken = json.loads(itoken.replace("'", '"'))
        user_api = WebexTeamsAPI(access_token=itoken['access_token'])
        bot_api = WebexTeamsAPI(access_token=BOT_TOKEN)
        if iroom == "new":
            newroom = bot_api.rooms.create("Meraki Webhooks")
            iroom = newroom.id
            person = user_api.people.me()
            newmemb = bot_api.memberships.create(iroom, personId=person.id)
        else:
            memblist = bot_api.memberships.list()
            for m in memblist:
                dolog(m.roomId + "::" + iroom + "::" + m.personEmail + "::" + BOT_USER)
                if m.roomId == iroom and m.personEmail == BOT_USER:
                    dolog("membership exists")
                    msg = bot_api.messages.create(iroom, text="Meraki Webhooks will be delivered to this room.")
                    wh = create_update_webhook(bot_api, iroom, BASE_URL + "teamswebhook/" + iroom)
                    return redirect(BASE_URL + "webhook/" + iroom)

            user_api.memberships.create(iroom, personEmail=BOT_USER)

        msg = bot_api.messages.create(iroom, text="Meraki Webhooks will be delivered to this room.")
        wh = create_update_webhook(bot_api, iroom, BASE_URL + "teamswebhook/" + iroom)
        return redirect(BASE_URL + "webhook/" + iroom)
    else:
        return "Error creating webhook."


def shorthash(roomid):
    md5bytes = hashlib.md5(roomid.encode("utf")).hexdigest()
    d1 = codecs.decode(md5bytes, "hex")
    d2 = base64.b64encode(d1).decode("UTF-8")
    d3 = d2.replace("+", "").replace("/", "").replace("=", "")
    d4 = d3[:12]
    return d4


def create_update_webhook(api, roomid, targeturl):
    searchname = "Meraki Webhook Messages " + shorthash(roomid)
    webhooks = api.webhooks.list()

    # Look for an Existing Webhook with this name, if found update it
    wh = None
    # webhooks is a generator
    for h in webhooks:
        if h.name == searchname:
            sys.stderr.write("Found existing webhook.  Updating it.\n")
            wh = h

    # No existing webhook found, create new one
    # we reached the end of the generator w/o finding matching webhook
    if wh is None:
        sys.stderr.write("Creating new webhook.\n")
        wh = api.webhooks.create(
            name=searchname,
            targetUrl=targeturl,
            resource="attachmentActions",
            event="created",
        )

    # if we have an existing webhook, delete and recreate
    #   (can't update resource/event)
    else:
        # try block because if there are NO webhooks it throws error
        try:
            wh = api.webhooks.delete(webhookId=wh.id)
            wh = api.webhooks.create(
                name=searchname, targetUrl=targeturl,
                resource="attachmentActions", event="created"
            )
        except Exception as e:
            msg = "Encountered an error updating webhook: {}"
            sys.stderr.write(msg.format(e))
            return False

    return wh


@app.route("/webhook/<id>", methods=["GET"])
def webhook_get(id):
    dolog("/webhook:webhook_get")
    """ Step 7: Get info for the Meraki integration

    Now that we know the room, we will get information from the user
    so that we can enable Webhooks in Meraki Dashboard.
    """
    myurl = BASE_URL + "webhook/" + id
    return render_template('meraki.html', rid=id, whurl=myurl)


@app.route("/configuremeraki", methods=["POST"])
def configure_meraki():
    dolog("/configuremeraki:configure_meraki")
    """ Step 8: Perform the Meraki integration

    User has now provided all Meraki information. Provision webhooks
    in Dashboard
    """
    formdata = request.form
    merakitoken = formdata.get("token", None)
    button = formdata.get("button", None)
    orgid = formdata.get("orgid", None)
    orgname = formdata.get("orgname", None)
    teamsroom = formdata.get("teamsroom", None)
    netlist = []
    for f in formdata:
        if f == "token" or f == "button" or f == "orgid" or f == "orgname" or f == "teamsroom" or f == "whurl":
            pass
        else:
            netlist.append({"id": f, "name": formdata.get(f)})

    dolog(netlist + "::" + orgname + "::" + orgid + "::" + merakitoken + "::" + button + "::" + teamsroom)
    return render_template('webhook.html', nets=netlist, nets_string=json.dumps(netlist), orgname=orgname, orgid=orgid, merakitoken=merakitoken, button=button, teamsroom=teamsroom)


@app.route("/done", methods=["GET", "POST"])
def done():
    dolog("/done:done")
    """ Step 9: Finally done

    Webhooks have been set up. Give the user an option to start over.
    """
    m = request.form.get("button", None)
    # m = request.args.get("button")
    if m == "activate":
        modestring = "connected to"
    else:
        modestring = "disconnected from"
    return render_template('done.html', mode=modestring)


@app.route("/orgs", methods=["GET"])
def meraki_getorgs():
    """
    Called from meraki.html to get a list of Meraki Orgs. This is
    piped through Python because Dashboard does not support
    OPTIONS / CORS to do it in JS

    :return: List of Meraki Organizations in JSON format
    """
    apikey = request.headers.get('X-Cisco-Meraki-API-Key')
    c = meraki.myorgaccess(apikey, suppressprint=True)
    dolog(c)
    if c:
        try:
            j = jsonify(c)
            return j
        except:
            dolog(c)
    else:
        dolog("API Key does not have org permission or bad API Key.")
        return jsonify([])


@app.route("/nets/<orgid>", methods=["GET"])
def meraki_getnets(orgid):
    """
    Called from meraki.html to get a list of Meraki Networks. This is
    piped through Python because Dashboard does not support
    OPTIONS / CORS to do it in JS

    :return: List of Meraki Networks in JSON format
    """
    apikey = request.headers.get('X-Cisco-Meraki-API-Key')
    c = meraki.getnetworklist(apikey, orgid, suppressprint=True)
    try:
        j = jsonify(c)
        return j
    except:
        dolog(c)


@app.route("/setwebhook/<netid>", methods=["GET"])
def meraki_setwebhook(netid):
    """
    Called from webhook.html to configure webhooks in Meraki Dashboard.
    This is piped through Python because Dashboard does not support
    OPTIONS / CORS to do it in JS

    :return: Dictionary with webhook ID "whid" and activate/deactive "mode"
    """
    apikey = request.headers.get('X-Cisco-Meraki-API-Key')
    teamsroom = request.headers.get('Webex-Teams-Room-Id')
    webhook_desc = "Teams|" + base64.b64encode(hashlib.md5(teamsroom.encode("ascii")).digest()).decode("ascii")[0:8]
    mode = request.headers.get('Action-Type')
    dolog(mode)

    svrs = meraki_addons.get_api_http_servers(apikey, netid)
    myurl = BASE_URL + "webhook/" + teamsroom
    whid = None
    for s in svrs:
        if s["url"] == myurl:
            dolog("already exists")
            whid = s["id"]
            break
        elif s["name"] == webhook_desc:
            dolog("name exists; updating URL")
            whid = s["id"]
            wh = meraki_addons.update_api_http_servers(apikey, netid, whid, webhook_desc, myurl)

    if mode == "activate":
        if not whid:
            dolog("creating webhook")
            wh = meraki_addons.add_api_http_servers(apikey, netid, webhook_desc, myurl)
            whid = wh["id"]

        if whid:
            dolog(whid)
            meraki_addons.update_alert_settings(apikey, netid, whid)
    else:
        if whid:
            dolog("deleting webhook")
            meraki_addons.del_api_http_servers(apikey, netid, whid)
        else:
            dolog("no webhook to delete")

    c = {"whid": whid, "mode": mode}
    j = jsonify(c)
    return j


"""
###############################################################################
These URL Routes & Functions are all to support the Teams Webhook Receivers
###############################################################################
"""


@app.route("/teamswebhook/<id>", methods=["POST"])
def teamswebhook_post(id):
    """ Step 1: Teams Webhook Receiver.

    This is the URL that Webex Teams will POST webhooks to. Used for
    card actions; specifically to filter events.
    """
    formdata = request.get_json()
    m = get_attachment_actions(formdata["data"]["id"])
    card_action = m["inputs"]
    if card_action.find("ignore_") >= 0:
        ignore_action = card_action.replace("ignore_", "")
        dolog(ignore_action)
        check_insert_filter(id, ignore_action)
    return ""


@app.route("/resetfilter/<id>", methods=["GET"])
def resetfilter(id):
    """ Used to clear filters for a given room

    This is a URL that would have to be called manually. It will clear
    and and all filters for Meraki Webhook events
    """
    clear_filters_for_room(id)
    return "Reset Filters for room '" + str(id) + "'."


def get_attachment_actions(attachmentid):
    headers = {
        'content-type': 'application/json; charset=utf-8',
        'authorization': 'Bearer ' + BOT_TOKEN
    }

    url = 'https://api.ciscospark.com/v1/attachment/actions/' + attachmentid
    response = requests.get(url, headers=headers)
    return response.json()


"""
###############################################################################
These URL Routes & Functions are all to support the Meraki Webhook Receivers
###############################################################################
"""


@app.route("/<id>/filters", methods=["GET"])
def filters_get(id):
    """ Step 0: Manage any filters

    If the user has ignored any alerts, display them and allow them to be
    removed
    """
    myurl = BASE_URL + "webhook/" + id
    f = get_filter_list(id)
    return render_template('filter.html', rid=id, whurl=myurl, filters=f)


@app.route("/<id>/filters/<name>", methods=["DELETE"])
def filters_del(id, name):
    """ Step 0: Delete filter

    User requested to delete a filter
    """
    dolog(id + "::" + name)
    del_filter(id, name)

    myurl = BASE_URL + "webhook/" + id
    f = get_filter_list(id)
    return render_template('filter.html', rid=id, whurl=myurl, filters=f)


@app.route("/webhook/<whid>", methods=["POST"])
def webhook_post(whid):
    """ Step 1: Meraki Webhook Receiver.

    This is the URL that Meraki Dashboard will POST webhooks to. We will
    generate the card, then send it to the designated Teams room.
    """
    formdata = request.get_json()
    if not does_filter_exist(whid, formdata["alertType"]):
        alertdata = generate_card(formdata, whid)
        create_message_with_attachment(whid, str(alertdata["html"]), alertdata["attachments"])
    return ""


def generate_card(data, roomid):
    """ Step 2: Generate Card

    Used to generate card and alternate text for Webhook alert

    data: raw json from webhook
    roomid: Webex Teams Room ID to post card to
    :return: Dictionary with card attachment "attachments" and alt text "html"
    """
    dolog(data)
    if "imageUrl" in data.get("alertData", {}):
        fn1 = 'device_alert_image.json'
        fn2 = 'device_alert_image.html'
    elif "deviceName" in data:
        fn1 = 'device_alert.json'
        fn2 = 'device_alert.html'
    else:
        fn1 = 'network_alert.json'
        fn2 = 'network_alert.html'

    with open(fn1) as json_file:
        outtxt = json_file.read()
        outtxt = outtxt.replace("{{alert-desc-uppercase}}", get_action_desc(data["alertType"]).upper())
        outtxt = outtxt.replace("{{alert-desc-plural}}",  "'" + get_action_desc(data["alertType"]) + "' notifications.")
        outtxt = outtxt.replace("{{alert-desc}}",  get_action_desc(data["alertType"]))

        outtxt = outtxt.replace("{{alert-type}}", data["alertType"])
        outtxt = outtxt.replace("{{alert-data}}", get_alert_data(data["alertType"], data["alertData"]))
        outtxt = outtxt.replace("{{timestamp}}", convert_timestamp_to_time(data["occurredAt"]))
        outtxt = outtxt.replace("{{organization-name}}", data["organizationName"])
        outtxt = outtxt.replace("{{organization-url}}", data["organizationUrl"])
        outtxt = outtxt.replace("{{network-name}}", data["networkName"])
        outtxt = outtxt.replace("{{network-url}}", data["networkUrl"])
        if "imageUrl" in data.get("alertData", {}):
            outtxt = outtxt.replace("{{image-url}}", data["alertData"]["imageUrl"])
        if "deviceName" in data:
            if data["deviceName"] == "":
                outtxt = outtxt.replace("{{device-name}}", data["deviceMac"])
            else:
                outtxt = outtxt.replace("{{device-name}}", data["deviceName"])
            outtxt = outtxt.replace("{{device-url}}", data["deviceUrl"])
        outtxt = outtxt.replace("{{ignore-submit-action}}", "ignore_" + data["alertType"].replace(" ", "-"))
        outtxt = outtxt.replace("{{ignore-submit-data}}", "ignore_" + data["alertType"])
        outtxt = outtxt.replace("{{filter-url}}", BASE_URL + roomid + "/" + "filters")
        outtxt = {"contentType": "application/vnd.microsoft.card.adaptive", "content": json.loads(outtxt)}

    with open(fn2) as html_file:
        outhtml = html_file.read()
        outhtml = outhtml.replace("{{alert-desc-uppercase}}", get_action_desc(data["alertType"]).upper())
        outhtml = outhtml.replace("{{alert-desc-plural}}",  "'" + get_action_desc(data["alertType"]) + "' notifications.")
        outhtml = outhtml.replace("{{alert-desc}}",  get_action_desc(data["alertType"]))

        outhtml = outhtml.replace("{{alert-type}}", data["alertType"])
        outhtml = outhtml.replace("{{alert-data}}", get_alert_data(data["alertType"], data["alertData"]))
        outhtml = outhtml.replace("{{timestamp}}", convert_timestamp_to_time(data["occurredAt"]))
        outhtml = outhtml.replace("{{organization-name}}", data["organizationName"])
        outhtml = outhtml.replace("{{organization-url}}", data["organizationUrl"])
        outhtml = outhtml.replace("{{network-name}}", data["networkName"])
        outhtml = outhtml.replace("{{network-url}}", data["networkUrl"])
        if "imageUrl" in data.get("alertData", {}):
            outhtml = outhtml.replace("{{image-url}}", data["alertData"]["imageUrl"])
        if "deviceName" in data:
            if data["deviceName"] == "":
                outhtml = outhtml.replace("{{device-name}}", data["deviceMac"])
            else:
                outhtml = outhtml.replace("{{device-name}}", data["deviceName"])
            outhtml = outhtml.replace("{{device-url}}", data["deviceUrl"])
        outhtml = outhtml.replace("{{ignore-submit-action}}", "ignore_" + data["alertType"].replace(" ", "-"))
        outhtml = outhtml.replace("{{ignore-submit-data}}", "ignore_" + data["alertType"])
        outhtml = outhtml.replace("{{ignore-url}}", BASE_URL + roomid + "/" + "ignore_" + data["alertType"])
        outhtml = outhtml.replace("{{filter-url}}", BASE_URL + roomid + "/" + "filters")
        outhtml = outhtml.replace("\n", "")

    return {"attachments": outtxt, "html": outhtml}


def get_action_desc(action_type):
    """ Called by generate_card

    Used to filter / modify any alert categories

    action_type: raw alert category
    :return: More friendly name of the alert category
    """
    return action_type


def get_alert_data(action_type, action_data):
    """ Called by generate_card

    Used to convert alert data from raw JSON into friendly text

    action_type: raw alert category
    action_data: raw alert data
    :return: More friendly output for the alert data
    """

    # TODO: Need to define specific alert attributes. For now, return nothing.
    return ""

    # if action_data == {}:
    #     return ""
    # else:
    #     if action_type.lower() == "network usage alert":
    #         return "\\nTotal: " + str(action_data["kbTotal"]) + "kb\\nThreshold: " + str(action_data["usageThreshold"]) + "kb\\nTime Period: " + str(action_data["period"] / 60)
    #     elif action_type.lower() == "clients are violating their security policy" or action_type.lower() == "clients are compliant with their security policy":
    #         return "\\nSecurity Policy: " + str(action_data["pccSecurityPolicyId"]) + "\\nAlert Policy: " + str(action_data["pccSecurityAlertConfigId"])
    #     else:
    #         return str(action_data).replace('"', "'")


def convert_timestamp_to_time(timestamp):
    """ Called by generate_card

    Used to convert the Unix format timestamps into something more readable

    timestamp: Unix epoch timestamp
    :return: Formatted Timestamp
    """
    ts = dateutil.parser.parse(timestamp)

    return str(ts.strftime('%m/%d/%y %H:%M:%S')) + " GMT"


def create_message_with_attachment(rid, msgtxt, attachment):
    """ Step 3: Send Teams Message w/Attachment

    Used to Send Message via Webex Teams API

    Not leveraging webexteamssdk, because it does not currently have coverage
    for sending message with card attachment

    rid: Webex Teams Room ID to post card to
    msgtxt: Webex Teams html alternate text
    attachment: Webex Teams attachment (card) data
    :return: JSON from POST Response
    """
    headers = {
        'content-type': 'application/json; charset=utf-8',
        'authorization': 'Bearer ' + BOT_TOKEN
    }

    url = 'https://api.ciscospark.com/v1/messages'
    data = {"roomId": rid, "attachments": [attachment], "html": msgtxt}
    response = requests.post(url, json=data, headers=headers)
    return response.json()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=app_port)
