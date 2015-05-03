# CONFIG #
##########

# Import

import json

# Variables



# Functions

# Reads contents of JSON file
def read_config_json():
	with open("settings/config.json","r") as json_data:
		data = json.load(json_data)
	return data

# Writes to JSON file
def write_config_json(data):
	with open("settings/config.json","w") as outfile:
		json.dump(data,outfile,sort_keys=True,indent=2)

# Check which environment to run in
def check_environment(data):
	if data["environment"] == "prod":
		data["running_subreddit"] = data["prod_subreddit"]
		data["running_username"] = data["prod_username"]
		data["running_password"] = data["prod_password"]
	elif data["environment"] == "test":
		data["running_subreddit"] = data["test_subreddit"]
		data["running_username"] = data["test_username"]
		data["running_password"] = data["test_password"]
	write_config_json(data)
	return data
