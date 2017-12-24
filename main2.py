#!/usr/bin/env python
import tornado.wsgi
from tornado.wsgi import WSGIContainer
from tornado.wsgi import WSGIAdapter
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
import pyrestful.rest
from pyrestful import mediatypes
from pyrestful.rest import get, post, put, delete
import json
import logging
import datetime
from google.appengine.api import users
from google.appengine.ext import ndb as db
from components.helpers import generate_hash_key
from components.helpers import calculate_time_delta
from components.helpers import check_key_validity
from components.helpers import Keystore
from components.helpers import Urlstore
from components.helpers import get_ancestor
from components.helpers import get_word_list

#from apiclient.discovery import build
#from oauth2client.client import GoogleCredentials


class MainHandler(pyrestful.rest.RestHandler):

    ONLYONE = 1
    FIRSTELEMENT = 0
    MAXKEYVALTIME = 900
    VALID = 1
    PREFIX = "/api/v1.0"

#    credentials = GoogleCredentials.get_application_default()
#    service = build('compute', 'v1', credentials=credentials)

#    PROJECT = 'gigichallange'
#    ZONE = 'Zona B'
#    request = service.instances().list(project=PROJECT, zone=ZONE)
#    response = request.execute()

    @get(_path="/", _produces=mediatypes.TEXT_HTML)
    def getHome(self):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr
        user = users.get_current_user()
        if user:
            nickname = user.nickname()
        else:
            nickname = "stranger"
        # enctype='application/x-www-form-urlencoded'
        return "<html><body>Hello "+nickname+"</br><form action='https://gigichallange.appspot.com/sendurl' enctype='application/x-www-form-urlencoded' method='post'>Appkey : <input type='text' name='key'></br>Input the url : <input type='text' name='url'><input type='submit' value='Submit'></form></body></html>"

    @post(_path="/idp", _consumes=mediatypes.APPLICATION_JSON, _produces=mediatypes.APPLICATION_JSON)
    def postId(self, data):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr
        #ancestor_key = db.Key("mkey", data["key"])

        ancestor_key = get_ancestor("mkey", data["key"])
        a = Keystore.query_keys(ancestor_key).fetch(self.ONLYONE)

        ck = check_key_validity(a, data["key"], remote_ip, self.MAXKEYVALTIME)
        if ck is True:
            return {"value" : data["value"], "ip" : a[self.FIRSTELEMENT].ip}
        else:
            return ck

    @post(_path="/checkkeytime", _consumes=mediatypes.APPLICATION_JSON, _produces=mediatypes.APPLICATION_JSON)
    def postCheckTime(self, data):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr

        ancestor_key = get_ancestor("mkey", data["key"])
        #ancestor_key = db.Key("mkey", data["key"])
        a = Keystore.query_keys(ancestor_key).fetch(self.ONLYONE)

        ck = check_key_validity(a, data["key"], remote_ip, self.MAXKEYVALTIME )
        if ck is True:
            return {"inserted": a[self.FIRSTELEMENT].inserted.strftime('%m/%d/%Y'),
                    "updated": a[self.FIRSTELEMENT].updated.strftime('%m/%d/%Y')}
        else:
            return ck

    @get(_path="/id/{key}{value}", _types=[str,int], _produces=mediatypes.APPLICATION_JSON)
    def getId(self, key, value):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr

        ancestor_key = get_ancestor("mkey", key)
        a = Keystore.query_keys(ancestor_key).fetch(self.ONLYONE)
        ck = check_key_validity(a, key, remote_ip, self.MAXKEYVALTIME)
        if ck is True:
            return {"value" : value, "ip" : remote_ip, "key" : key}
        else:
            return ck

    @get(_path="/ids/{value}", _types=[str], _produces=mediatypes.APPLICATION_JSON)
    def getIds(self, value):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr
        return {"value" : value, "ip" : remote_ip}


    @post(_path="/sendurl", _types=[str, str], _produces=mediatypes.APPLICATION_JSON)
    def sendUrl(self, url, key):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr

        ancestor_key = get_ancestor("mkey", key)
        a = Keystore.query_keys(ancestor_key).fetch(self.ONLYONE)

        ck = check_key_validity(a, key, remote_ip, self.MAXKEYVALTIME)
        if ck is True:
            return {"key": key , "nounslist" : get_word_list(url)}
            #return {"url": url, "key": key}
        else:
            return ck


    @post(_path="/login", _consumes=mediatypes.APPLICATION_JSON, _produces=mediatypes.APPLICATION_JSON)
    def getLogin(self, login):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr

        user = None
        user = users.get_current_user()

        if user:
            nickname = user.nickname()
        else:
            nickname = "no logged user"

        gkey = generate_hash_key()
        ciccio = Keystore(parent=db.Key("mkey",gkey), \
                 loggeduser = nickname, \
                 ukey = gkey, \
                 ip = remote_ip, \
                 valid = True, \
                 user  = login["username"], \
                 password = login["password"])

        ciccio.put()
        return { "key" : gkey  , "ip" : remote_ip, "user" : nickname, "user1" : login["username"], "pwd" : login["password"] }

    @get(_path="/getallkeys", _produces=mediatypes.APPLICATION_JSON)
    def getAllKeys(self):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip or self.request.remote_addr

        listAllKeys = {}
        keys = Keystore.all().order('-inserted')
        k = None

        for k in keys:
            listAllKeys.update({'key' : k.ukey, 'ip' : k.ip, 'inserted' : k.inserted})

        if k:
            return {"key": k.ukey}
        else:
            return {"keylength" : len(keys)}

    def get_login_url(self):
        return users.create_login_url(self.request.uri)

app = pyrestful.rest.RestService([MainHandler])

if __name__ == '__main__':

    http_server = HTTPServer(WSGIAdapter(app))
    http_server.listen(5000)
    IOLoop.instance().start()

else:

    application = tornado.wsgi.WSGIAdapter(app)


