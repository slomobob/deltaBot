# encoding: utf-8

# Comments #
############

# Import #
##########

import praw
import logging
import time
import datetime
import calendar
from urllib2 import HTTPError
import re

# Functions #
#############

def start(data,r,token_comment,awarder,awardee,flair_count):
 logging.debug("Starting Module: Wiki")
 submission_title = token_comment.submission.title
 submission_url = token_comment.submission.permalink
 today = datetime.date.today()
 try:
  user_wiki_page = r.get_wiki_page(data["running_subreddit"],"user/" + awardee)
  logging.debug("Found existing user wiki page")
  user_found = True
 except Exception as e:
  if e.response.status_code == 404:
   logging.debug("Did not find existing user wiki page")
   user_found = False
 if user_found:
  update_wiki_page(data,r,token_comment,awarder,awardee,flair_count,user_wiki_page)
 else:
  new_wiki_page(data,r,token_comment,awarder,awardee,flair_count)
 try:
  tracker_page = r.get_wiki_page(data["running_subreddit"],data["running_username"] + "/tracker")
  logging.debug("Found existing tracker wiki page")
  tracker_found = True
 except Exception as e:
  if e.response.status_code == 404:
   logging.debug("Did not find existing tracker wiki page")
   tracker_found = False
 if tracker_found:
  update_tracker_page(data,r,awardee,token_comment,tracker_page)
 else:
  new_tracker_page(data,r,awardee,token_comment)
 try:
  queue_page = r.get_wiki_page(data["running_subreddit"],data["running_username"] + "/queue")
  logging.debug("Found existing token queue wiki page")
  queue_found = True
 except Exception as e:
  if e.response.status_code == 404:
   logging.debug("Did not find existing token queue wiki page")
   queue_found = False
 if queue_found:
  update_queue_page(data,r,awardee,token_comment,queue_page)
 else:
  new_queue_page(data,r,awardee,token_comment)

def new_wiki_page(data,r,token_comment,awarder,awardee,flair_count):
 submission_title = token_comment.submission.title
 submission_url = token_comment.submission.permalink
 today = datetime.date.today()
 add_header = "| Date | Submission | Delta Comment | Awarded By |\n| --- | :-: | --- | --- |\n"
 add_content = "|%s/%s/%s|[%s](%s)|[Link](%s)|/u/%s|" % (today.month,today.day,today.year,submission_title,
 submission_url,token_comment.permalink + "?context=2",awarder)
 if int(flair_count) < 2:
  initial_text = "/u/%s has received %s delta for the following comment:\n\n" % (awardee,flair_count)
 else:
  initial_text = "/u/%s has received %s deltas for the following comments:\n\n" % (awardee,flair_count)
 full_update = initial_text + add_header + add_content
 r.edit_wiki_page(data["running_subreddit"],"user/" + awardee,full_update,"Created user's delta history page.")

def update_wiki_page(data,r,token_comment,awarder,awardee,flair_count,user_wiki_page):
 submission_title = token_comment.submission.title
 submission_url = token_comment.submission.permalink
 today = datetime.date.today()
 old_content = user_wiki_page.content_md
 add_header = "| Date | Submission | Delta Comment | Awarded By |\n| --- | :-: | --- | --- |\n"
 add_content = "|%s/%s/%s|[%s](%s)|[Link](%s)|/u/%s|" % (today.month,today.day,today.year,submission_title,
        submission_url,token_comment.permalink + "?context=2",awarder)
 if int(flair_count) < 2:
  initial_text = "/u/%s has received %s delta for the following comment:\n\n" % (awardee,flair_count)
 else:
  initial_text = "/u/%s has received %s deltas for the following comments:\n\n" % (awardee,flair_count)
 lines = old_content.split("\n")
 note = ""
 table = []
 for line in lines:
  if re.match("(\|)",line):
   if not re.match("(\| Date |\| --- \|)",line):
    table.append(line)
  elif re.match("Any delta history",line):
   note = line + "\n\n"
 table.append(add_content)
 table.sort(reverse=True)
 new_content = '\n'.join(table)
 full_update = initial_text + note + add_header + new_content
 r.edit_wiki_page(data["running_subreddit"],"user/" + awardee,full_update,"Updated user's delta history page.")

def remove_wiki_line(data,r,wiki_line,awardee,flair_count):
 user_wiki_page = r.get_wiki_page(data["running_subreddit"],"user/" + awardee)
 old_content = user_wiki_page.content_md
 add_header = "| Date | Submission | Delta Comment | Awarded By |\n| --- | :-: | --- | --- |\n"
 if int(flair_count) < 2:
  initial_text = "/u/%s has received %s delta for the following comment:\n\n" % (awardee,flair_count)
 else:
  initial_text = "/u/%s has received %s deltas for the following comments:\n\n" % (awardee,flair_count)
 lines = old_content.split("\n")
 note = ""
 table = []
 for line in lines:
  if re.match("(\|)",line):
   if not re.match("(\| Date |\| --- \|)",line):
    if wiki_line not in line:
     table.append(line)
  elif re.match("Any delta history",line):
   note = line + "\n\n"
 table.sort(reverse=True)
 new_content = '\n'.join(table)
 full_update = initial_text + note + add_header + new_content
 r.edit_wiki_page(data["running_subreddit"],"user/" + awardee,full_update,"Updated user's delta history page.")

def new_tracker_page(data,r,awardee,token_comment):
 today = datetime.date.today()
 initial_text = "Below is a list of all of the users that have earned deltas.\n\n"
 add_header = "| User | Delta List | Delta Earned|\n| --- | --- | --- |\n"
 add_content = "|/u/%s|[Link](/r/%s/wiki/user/%s)|[%s/%s/%s](%s)|" % (awardee,data["running_subreddit"],
        awardee,today.month,today.day,today.year,token_comment.permalink + "?context=2")
 full_update = initial_text + add_header + add_content
 r.edit_wiki_page(data["running_subreddit"],data["running_username"] + "/tracker",full_update,"Updated tracker")

def update_tracker_page(data,r,awardee,token_comment,tracker_page):
 today = datetime.date.today()
 initial_text = "Below is a list of all of the users that have earned deltas.\n\n"
 add_header = "| User | Delta List | Last Delta Earned |\n| --- | --- | --- |\n"
 add_content = "|/u/%s|[Link](/r/%s/wiki/user/%s)|[%s/%s/%s](%s)|" % (awardee,data["running_subreddit"],
        awardee,today.month,today.day,today.year,token_comment.permalink + "?context=2")
 old_content = tracker_page.content_md
 awardee_already_exists = False
 lines = old_content.split("\n")
 table = []
 for line in lines:
  if re.match("(\|)",line):
   if not re.match("(\| User |\| --- \|)",line):
    if awardee not in line:
     table.append(line)
    else:
     table.append(add_content)
     awardee_already_exists = True
 if not awardee_already_exists:
  table.append(add_content)
 table.sort()
 new_content = '\n'.join(table)
 full_update = initial_text + add_header + new_content
 r.edit_wiki_page(data["running_subreddit"],data["running_username"] + "/tracker",full_update,"Updated tracker")

def new_queue_page(data,r,awardee,token_comment):
 initial_text = "## Delta Queue\n\nUse this page to moderate deltas that DeltaBot has awarded. After clicking approve/reject you will need to click send to send the message to DeltaBot.\n\n**Approve:** This will remove the line from this queue. No other action is taken.\n\n**Reject:** Will remove the delta and all related information and then reply to the user with the reason it was removed based on your selection.\n\n"
 add_header="|Awardee|Comment|Approve|Reject (Low Effort)|Reject (Remind)|Reject (Abuse)|\n|---|---|---|---|---|---|\n"
 token_comment_body = token_comment.body.replace("\n"," ")
 add_content = "|/u/%s|[%s](%s)|[Approve](/message/compose/?to=%s&subject=%s&message=%s)|[Reject for Low Effort](/message/compose/?to=%s&subject=reject low effort&message=%s)|[Reject and Remind](/message/compose/?to=%s&subject=reject remind&message=%s)|[Reject for Abuse](/message/compose/?to=%s&subject=reject abuse&message=%s)|" % \
  (awardee,token_comment_body,token_comment.permalink + "?context=2",data["running_username"],"approve",token_comment.permalink,
  data["running_username"],token_comment.permalink,data["running_username"],token_comment.permalink,data["running_username"],token_comment.permalink)
 full_update = initial_text + add_header + add_content
 r.edit_wiki_page(data["running_subreddit"],data["running_username"] + "/queue",full_update,"Updated queue")

def update_queue_page(data,r,awardee,token_comment,queue_page):
 initial_text = "## Delta Queue\n\nUse this page to moderate deltas that DeltaBot has awarded. After clicking approve/reject you will need to click send to send the message to DeltaBot.\n\n**Approve:** This will remove the line from this queue. No other action is taken.\n\n**Reject:** Will remove the delta and all related information and then reply to the user with the reason it was removed based on your selection.\n\n"
 add_header="|Awardee|Comment|Approve|Reject (Low Effort)|Reject (Remind)|Reject (Abuse)|\n|---|---|---|---|---|---|\n"
 token_comment_body = token_comment.body.replace("\n"," ")
 token_comment_body = token_comment_body.replace("amp;amp;","amp;")
 add_content = "|/u/%s|[%s](%s)|[Approve](/message/compose/?to=%s&subject=%s&message=%s)|[Reject for Low Effort](/message/compose/?to=%s&subject=reject low effort&message=%s)|[Reject and Remind](/message/compose/?to=%s&subject=reject remind&message=%s)|[Reject for Abuse](/message/compose/?to=%s&subject=reject abuse&message=%s)|" % \
  (awardee,token_comment_body,token_comment.permalink + "?context=2",data["running_username"],"approve",token_comment.permalink,
  data["running_username"],token_comment.permalink,data["running_username"],token_comment.permalink,data["running_username"],token_comment.permalink)
 old_content = queue_page.content_md
 lines = old_content.split("\n")
 table = []
 for line in lines:
  if re.match("(\|)",line):
   if not re.match("(\|Awardee|\|---\|)",line):
    table.append(line)
 table.append(add_content)
 new_content = '\n'.join(table)
 full_update = initial_text + add_header + new_content
 r.edit_wiki_page(data["running_subreddit"],data["running_username"] + "/queue",full_update,"Updated queue")

def remove_queue_line(data,r,queue_line):
 initial_text = "## Delta Queue\n\nUse this page to moderate deltas that DeltaBot has awarded. After clicking approve/reject you will need to click send to send the message to DeltaBot.\n\n**Approve:** This will remove the line from this queue. No other action is taken.\n\n**Reject:** Will remove the delta and all related information and then reply to the user with the reason it was removed based on your selection.\n\n"
 add_header="|Awardee|Comment|Approve|Reject (Low Effort)|Reject (Remind)|Reject (Abuse)|\n|---|---|---|---|---|---|\n"
 queue_page = r.get_wiki_page(data["running_subreddit"],data["running_username"] + "/queue")
 old_content = queue_page.content_md
 lines = old_content.split("\n")
 table = []
 for line in lines:
  if re.match("(\|)",line):
   if not re.match("(\|Awardee|\|---\|)",line):
    if queue_line not in line:
     line = line.replace("amp;amp;","amp;")
     table.append(line)
 new_content = '\n'.join(table)
 full_update = initial_text + add_header + new_content
 r.edit_wiki_page(data["running_subreddit"],data["running_username"] + "/queue",full_update,"Updated queue")

# EOF
