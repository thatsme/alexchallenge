import os
import base64
import hashlib
import random
import datetime
from google.appengine.ext import ndb as db
from bs4 import BeautifulSoup
from bs4.element import Comment
import urllib
from collections import Counter
import MySQLdb
import hashlib
from Crypto.Hash import SHA256
from base64 import b64encode
from base64 import b64decode

wordnot = ["a", "is","if","to","we","it","end","not","aboard", "about", "above", "absent", "across", "after", "against", \
           "along", "alongside", "amid", "amidst", "among", "amongst", "apud", "around", "round", \
           "as", "astride", "at", "@", "on", "atop", "ontop", "bar", "before", "behind","below", \
           "allow", "beneath", "beside", "besides", "between", "beyond", "but", "by", "circa", "come", \
           "dehors", "despite", "spite" , "down", "during", "except", "for", "from", "in", "inside", \
           "into", "less", "like", "minus", "near", "notwithstanding", "us", "your", "&", "on", "this", \
           "of", "off", "on", "onto", "opposite", "out", "outside", "over", "pace", "past", "per", "post", \
           "pre", "pro", "qua",  "re",  "sans", "short", "since", "than", "through", "thru", "throughout", \
           "thruout", "to", "toward", "towards", "under", "underneath", "unlike", "until", "up", "upon", \
           "upside", "versus", "via", "with", "within", "without", "worth", "with", "the", "and", "there"]


# These environment variables are configured in app.yaml.
CLOUDSQL_CONNECTION_NAME = os.environ.get('CLOUDSQL_CONNECTION_NAME')
CLOUDSQL_USER = os.environ.get('CLOUDSQL_USER')
CLOUDSQL_PASSWORD = os.environ.get('CLOUDSQL_PASSWORD')
MAX_LIST_RECORD = 100

class Database:

    def __init__(self,dbname):
        self.message = None
        self.db = None

        # When deployed to App Engine, the `SERVER_SOFTWARE` environment variable
        # will be set to 'Google App Engine/version'.
        if os.getenv('SERVER_SOFTWARE', '').startswith('Google App Engine/'):
            # Connect using the unix socket located at
            # /cloudsql/cloudsql-connection-name.
            cloudsql_unix_socket = os.path.join(
                '/cloudsql', CLOUDSQL_CONNECTION_NAME)

            try:
                self.db = MySQLdb.connect(
                    unix_socket=cloudsql_unix_socket,
                    user=CLOUDSQL_USER,
                    passwd=CLOUDSQL_PASSWORD,
                    db=dbname)
            except MySQLdb.Error, e:
                self.message = "[CONNECT ERROR] %d: %s" % (e.args[0], e.args[1])

        # If the unix socket is unavailable, then try to connect using TCP. This
        # will work if you're running a local MySQL server or using the Cloud SQL
        # proxy, for example:
        #
        #   $ cloud_sql_proxy -instances=your-connection-name=tcp:3306
        #
        else:
            try:
                self.db = MySQLdb.connect(
                    host='127.0.0.1', user=CLOUDSQL_USER, passwd=CLOUDSQL_PASSWORD, db=dbname)
            except MySQLdb.Error, e:
                self.message = "[CONNECT ERROR] %d: %s" % (e.args[0], e.args[1])

        self.cursor = self.db.cursor()

    def create(self):
        create_words = """
                     CREATE TABLE wordlist ( 
                     sword varchar(80),
                     eword varchar(2048),
                     frequency int)
                     """

        self.insert(create_words)
        create_websites = """
                     CREATE TABLE websites (
                     url varchar(200))
                      """
        self.insert(create_websites)

    def insert(self, query):
        self.message = None
        try:
            self.cursor.execute(query)
            self.db.commit()
        except MySQLdb.Error, e:
            self.message = "[INSERT ERROR] %d: %s" % (e.args[0], e.args[1])
            self.db.rollback()

    def query(self, query):
        self.message = None
        try:
            cursor = self.db.cursor( MySQLdb.cursors.DictCursor )
            cursor.execute(query)
        except MySQLdb.Error, e:
            self.message = "[QUERY ERROR] %d: %s" % (e.args[0], e.args[1])

        return cursor.fetchall()

    def squery(self, query):
        self.message = None
        try:
            #cursor = self.db.cursor( MySQLdb.cursors.DictCursor )
            self.cursor.execute(query)
        except MySQLdb.Error, e:
            self.message = "[SQUERY ERROR] %d: %s" % (e.args[0], e.args[1])

        return self.cursor.fetchone()

    def getMessage(self):
        return self.message

    def getConnection(self):
        return self.db

    def getCursor(self):
        return self.cursor

    def __del__(self):
        self.db.close()


class Keystore(db.Model):
    """A single key entry."""
    #author      = db.UserProperty()
    loggeduser  = db.StringProperty(required=False)
    ip          = db.StringProperty(required=True)
    ukey        = db.StringProperty(required=True)
    user        = db.StringProperty(required=True)
    password    = db.StringProperty(required=True)
    valid       = db.BooleanProperty(required=True)
    inserted    = db.DateTimeProperty(auto_now_add=True)
    updated     = db.DateTimeProperty(auto_now=True)

    @classmethod
    def query_keys(cls, ancestor_key):
        return cls.query(ancestor=ancestor_key)

def get_ancestor(label, key):
    """

    :param label:
    :param key:
    :return:
    """
    return db.Key(label, key)

def generate_hash_key():
    """
    @return: A hashkey for use to authenticate agains the API.
    """
    return base64.b64encode(hashlib.sha256(str(random.getrandbits(256))).digest(),
                            random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])).rstrip('==')


def calculate_time_delta(inserted, max_time):
    """
    :param inserted: time of first api key generation and db insertion
    :param max_time: max time of api key validity in seconds
    :return: True if delta time < max_time
    """
    time1 = datetime.datetime.now()
    return round((time1 - inserted).total_seconds()) <= max_time

def check_key_validity(a, key, ip, max):
    """
    Check the validity of the api key
    :param a : Keystore Model
    :param key : api key from client
    :param ip : ip address of client
    :param max : max time of api key validity in seconds

    :return : True if valid, json message if False
    """
    if a:
        issameip = a[0].ip == ip
        valtime = calculate_time_delta(a[0].inserted, max)
        if issameip:
            if valtime:
                return True
            else:
                return {"key still valid": valtime, "max time" : max}
        else:
            return {"Is same ip address": str(issameip)}
    else:
        return {"Error Appkey not present ": key}


def check_websitepresence(url, data):
    """

    :param url: website scanned
    :param data : db pointer
    :return:
    """

    cwquery = "SELECT COUNT(*) from websites WHERE url='{0}'".format(url)
    r = data.squery(cwquery)
    if r is None:
        return 0
    else:
        return r

    return r

def get_frequency(hashed, data):
    """

    :param hash:
    :param data : db pointer
    :return:
    """
    clquery = "SELECT frequency from wordlist WHERE sword='{0}'".format(hashed)
    r = data.squery(clquery)
    return r

def check_wordpresence(hashed, data):
    """

    :param hash:
    :param data : db pointer
    :return:
    """
    clquery = "SELECT COUNT(*) from wordlist WHERE sword='{0}'".format(hashed)
    r = data.squery(clquery)
    if r is None:
        return 0
    else:
        return r

def update_wordfrequency(hashed, revvalue, addvalue, data):
    """

    :param word:
    :param value:
    :return:
    """
    sum = revvalue + addvalue
    uwquery = "INSERT UPDATE wordlist SET `frequency`={0} where sword='{1}".format(sum, hashed)
    data.insert(uwquery)

    return

def insert_wordlist(mlist, server, data):
    """

    :param list: worl list
    :return:
    """

    if data.getConnection() is None:
        return data.getMessage()
    #else:
    #    return data.getCursor()

    mylist = []
    i = 0
    for a in mlist[:MAX_LIST_RECORD]:
        word = MySQLdb.escape_string(a[0].encode('utf-8')).strip()

        hashed =  SHA256.new(word).hexdigest()
        client_key = server.publickey()
        encrypted = client_key.encrypt(word, 32)
        ecc = b64encode(encrypted[0])
        freq = a[1]
        r = check_wordpresence(word, data)
        if int(r[0]) == 0:
            i += 1
            lquery = "INSERT INTO wordlist (`sword`, `eword`, `frequency`) VALUES ('{0}', '{1}', {2})".format(word, ecc, freq)
            mylist.append(lquery)
            data.insert(lquery)
        else:
            k = get_frequency(word, data)
            return r
            update_wordfrequency(word, k, freq, data)

    mylist.append(data.getMessage())
    mylist.append("record : "+str(i))
    return mylist

def insert_websites(website, data):
    """

    :param list: website scanned
    :param data : db pointer
    :return:
    """
    wb = website.strip()

    if data.getConnection() is None:
        return data.getMessage()
    #else:
    #    return data.getCursor()
    r = check_websitepresence(wb, data)
    if int(r[0]) == 0:
        wquery = "INSERT INTO websites (`url`) VALUES ('{0}')".format(wb)
        data.insert(wquery)

        return wquery
    else:
        return ""

def tag_visible(element):
    """
    Define exclusion elements of page from where not get the
    words
    :param element:
    :return:
    """
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True

def text_from_html(body):
    """
    Create a parser

    :param body:
    :return:
    """
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)

def get_word_list(url):
    """
    Get a list of words from url, drop exclusion list
    reverse and count instance of single word
    :param url:
    :return:
    """
    html = urllib.urlopen(url).read()
    lines = text_from_html(html).lower()
    wordlist = [w for w in lines.split()]
    result = [x for x in wordlist if x not in wordnot]
    counts = list(reversed(sorted(Counter(result).items(),key=lambda x:x[1])))[10:]
    return counts

