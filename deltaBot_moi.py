import praw, logging, time, sqlite3
from logging.handlers import TimedRotatingFileHandler
from modules import *
from settings import *

DATA = config.read_config_json()
MESSAGES = messages.read_msg_json()

DELTA_ARR = [u'\u2206',u'\u0394',u'!delta',u'&#8710;',u'&amp;#8710;']  #need to change to config
TOKEN = u'\u0394'
USERNAME = DATA["username"]
PASSWORD = DATA["password"]                                            
SUBREDDIT = DATA["subreddit"]
USER_AGENT = DATA["user_agent"]
QUOTES = [u'"',u'\'']
PROPER_LENGTH = int(DATA["min_length"])

r = praw.Reddit(user_agent=USER_AGENT)
logging.debug("logging in as %s" % USERNAME)
r.login(USERNAME,PASSWORD)
sub = r.get_subreddit(SUBREDDIT)
comments = sub.get_comments()

### HISTORY ###

historyDB = sqlite3.connect('deltaHistory.db')
sqlCursor = historyDB.cursor()
sqlCursor.execute("CREATE TABLE IF NOT EXISTS History(Comment_id TEXT, Date INTEGER);")
historyDB.commit()

def set_History(id):
    sqlCursor.execute("INSERT INTO History(Comment_id,Date) VALUES ('%s',strftime('%%s','now'));" % id)     #stores comment_id and unix date
    historyDB.commit() 

def get_History(id):
    sqlCursor.execute("SELECT * FROM History WHERE Comment_id='%s';" % id)
    return sqlCursor.fetchall()

### /HISTORY ###

### LOGGING ###

consoleFormatter = logging.Formatter("%(asctime)s: %(message)s",datefmt="%I:%M:%S %p")
fileFormatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s",datefmt="%I:%M:%S %p")
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.DEBUG)
fileHandler = TimedRotatingFileHandler("logs/mars.log",when="midnight",backupCount=14)
fileHandler.setFormatter(fileFormatter)
rootLogger.addHandler(fileHandler)
consoleHandler = logging.StreamHandler()
if DATA["loglevel"] == "debug":
	consoleHandler.setLevel(logging.DEBUG)
elif DATA["loglevel"] == "info":
	consoleHandler.setLevel(logging.INFO)
else:
	consoleHandler.setLevel(logging.WARNING)
consoleHandler.setFormatter(consoleFormatter)
rootLogger.addHandler(consoleHandler)

### /LOGGING ###

### CHECKS ###

def delta_search(comment):
    logging.debug("searching for deltas in comment %s" % comment.id)
    body = comment.body
    for delta in DELTA_ARR:
        loc = body.find(delta)
        if loc == -1:
            None
        elif (loc == 0) or (loc == len(body)-len(delta)): 
            logging.debug("DELTA FOUND")
            return True
        elif body[loc-1] not in QUOTES and body[loc+len(delta)] not in QUOTES:
            logging.debug("DELTA FOUND")
            return True
    return False

def correct_author(comment):
    """checks if OP is author at non-root position & not replying to self"""
    logging.debug("Checking for correct comment author and position of %s" % comment.id)
    if not comment.is_root:
        if comment.author == comment.submission.author and comment.author != r.get_info(thing_id=comment.parent_id).author:     #certainly /feels/ like a hack
            return True
    return False

def is_unique_delta(comment):
    logging.debug("looking for previous deltas in History")
    if len(get_History(comment.parent_id)) is not 0:
        logging.debug("DELTA NOT UNIQUE")
        return False
    logging.info("DELTA UNIQUE")
    return True

def is_proper_length(comment):
    logging.debug("checking if long enough")
    if len(comment.body) < PROPER_LENGTH:
        if get_History(comment.id) == 0:
            comment.reply(text=MESSAGES["error_length"])        #TODO: check mail
        return False
    return True

### /CHECKS ###


def add_to_history(deltaComment):
    """add to history AND reply to say so"""
    logging.info("Adding %s to history" % deltaComment.parent_id)
    set_History(deltaComment.parent_id)
    deltaComment.reply(MESSAGES["confirmation"].format(r.get_info(thing_id=deltaComment.parent_id).author.name))         #GODDAMN maybe should just pass it in

def increment_flair(user,comment):
    logging.info("Incrementing flair for %s" % user.name)
    flair = sub.get_flair(user)
    flairText = flair[u'flair_text']
    if flairText is None:
        flairText = u'1' + TOKEN                            #NEED FIRST TIME MESSAGE
        sub.set_flair(item=user,flair_text=flairText)
    elif not flairText[0].isdigit():
        logging.info("IRREGULAR FLAIR")
    else:
        flairText = str(int(flairText[0])+1).encode('utf-8') + TOKEN
        logging.debug("FLAIRTEXT:\t%s" % flairText)
        sub.set_flair(item=user,flair_text=flairText)
          
checks = [delta_search,             #checking functions! Order is //IMPORTANT//
          correct_author,        
          is_unique_delta,
          is_proper_length]


def main(comments):
    for comment in comments:
        if all(func(comment) for func in checks):                  #True if all checking functions are True. Short circuits, too
            add_to_history(comment)
            parentAuthor = r.get_info(thing_id=comment.parent_id).author        #good thing praw caches everything...
            increment_flair(parentAuthor,comment)           



while True:
    try:
        comments = sub.get_comments(limit=None)
        main(comments)
        logging.debug("Waiting 10s")
        time.sleep(10)
    except Exception as e:
        logging.error("Error Code %s" % e)