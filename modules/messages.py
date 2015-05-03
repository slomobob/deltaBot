# Messages #
############

# Import

import praw
import json
import logging
import time

# VARIABLES LEGEND
#
# Use this section to build your messages. You want the information AFTER the equal sign (=) to put in your messages.
#
# subreddit = data["running_subreddit"]
# username = data["running_username"]
# token = msg["token"]
# 

# Functions

# Reads in the json for the messages
def read_msg_json():
	with open("settings/messages.json","r") as json_msg:
		msg = json.load(json_msg)
	return msg

# COMMANDS MODULE FUNCTIONS
def remind(comment):
	comment.reply(msg["remind"]).distinguish()

def stop(data,msg,r,mail):
	r.send_message("/r/" + data["running_subreddit"],msg["stop_subject"] % data["running_subreddit"],msg["stop_body"] % (data["running_username"],mail.author.name,mail.body))

# COMMENTS MODULE FUNCTIONS
def confirm(data,msg,awardee_comment,awardee):
	confirmation = msg["confirmation"] % (msg["token"],awardee_comment.author.name,awardee_comment.author.name,msg["token"],data["running_subreddit"],awardee,msg["token"],data["running_subreddit"],data["running_username"])
	return confirmation

def error_bad_recipient(data,msg,token_comment):
	error_bad_recipient = msg["error_bad_recipient"] % (msg["token"],msg["token"],msg["token"],data["running_username"],token_comment.permalink)
	return error_bad_recipient

def error_submission_history(msg,awardee):
	error_submission_history = msg["error_submission_history"] % (awardee,msg["token"])
	return error_submission_history

def error_length(data,msg,awardee):
	error_length = msg["error_length"] % (awardee,msg["token"])
	return error_length

# TOKEN MODULE FUNCTIONS
def congrats_first_subject(msg):
	congrats_first_subject = msg["congrats_first_subject"] % msg["token"]
	return congrats_first_subject

def congrats_first_body(data,msg,awardee):
	congrats_first_body = msg["congrats_first_body"] % (msg["token"],msg["token"],msg["token"],data["running_subreddit"],data["running_username"],data["running_username"],data["running_subreddit"],awardee,msg["token"],data["running_subreddit"],data["running_subreddit"])
	return congrats_first_body
	
# EOF
