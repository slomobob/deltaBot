import praw, logging, time, sqlite3, json
from logging.handlers import TimedRotatingFileHandler
from modules import *

def read_json(path):
	with open(path,"r") as json_msg:
		msg = json.load(json_msg)
	return msg

DATA = read_json("settings/config.json")
MESSAGES = read_json("settings/messages.json")

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

historyDB = sqlite3.connect('commentHistory.db')
sqlCursor = historyDB.cursor()
sqlCursor.execute("CREATE TABLE IF NOT EXISTS History(HasDelta INT, Comment_id TEXT, Date INT);")
sqlCursor.execute("CREATE VIEW IF NOT EXISTS deltaHistory AS SELECT * FROM History WHERE HasDelta=1;")
historyDB.commit()

def set_History(id, hasDelta=False):
    sqlCursor.execute("INSERT INTO History(Delta,Comment_id,Date) VALUES ({1},'{0}',strftime('%s','now'));".format(id,int(hasDelta)))     #stores comment_id and unix date and hasDelta
    historyDB.commit() 

def get_History(id):
    sqlCursor.execute("SELECT * FROM History WHERE Comment_id='%s';" % id)
    return sqlCursor.fetchone()

def get_deltaHistory(id):
    sqlCursor.execute("SELECT * FROM deltaHistory WHERE Comment_id='%s';" % id)
    return sqlCursor.fetchone()

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
def not_in_history(comment):
    """checks in history for a comment and adds it if not found"""
    universalID = u't1_' + comment.id           #Why can't comment.parent_id and comment.id jsut return values formatted the same? 
    if get_History(universalID):
        set_History(universalID, False)
        return False
    return True

def is_not_deleted(comment):
    if comment.banned_by or comment.author == None:
        return False
    return True

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
        elif loc == None:
            logging.error("NONTYPES ARE BITCHES")
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
    if len(get_deltaHistory(comment.parent_id)) is not 0:
        logging.debug("DELTA NOT UNIQUE")
        return False
    logging.info("DELTA UNIQUE")
    return True

def is_proper_length(comment):
    logging.debug("checking if long enough")
    if len(comment.body) < PROPER_LENGTH:
        comment.reply(text=MESSAGES["error_length"])        #TODO: check mail
        return False
    return True

### /CHECKS ###


def add_to_deltaHistory(deltaComment):
    """sets id Delta to True (+add to history if not found) AND reply to say so"""
    logging.info("Adding %s to deltaHistory" % deltaComment.parent_id)
    not_in_history(deltaComment.id)
    sqlCursor.execute("UPDATE History SET Delta=1 WHERE Comment_id='%s'" % deltaComment.parent_id)
    historyDB.commit()
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
          
checks = [not_in_history,
          is_not_deleted,
          delta_search,             #checking functions! Order is //IMPORTANT//.  For efficiency, and some assumptions are made with comment replies
          correct_author,        
          is_unique_delta,
          is_proper_length]


def main(comments):
    for comment in comments:
        if all(func(comment) for func in checks):                  #True if all checking functions are True. Short circuits, too
            parentComment = r.get_info(thing_id=comment.parent_id)       #good thing praw caches everything...
            add_to_deltaHistory(parentComment)
            increment_flair(parentComment.author)           



while True:
    try:
        comments = sub.get_comments(limit=None)
        main(comments)
        logging.debug("Waiting 10s")
        time.sleep(10)
    except Exception as e:
        logging.error("Error Code %s" % e)
        logging.error("Waiting for you to notice")
        time.sleep(30)