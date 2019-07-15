'''
This script manages the unread GMail mails via API.
It allows you to decide what you want to do with particular sender.
After you select the same action three times, it allows you to add it to database and therefore you no longer need to approve that action.
TODO: add other kind of algorithms to segment the letters (like certain keywords: purchases, promotions)
TODO: allow to choose labels
'''

import logging
import sys
import dateutil.parser as parser
import shelve
import webbrowser
from collections import OrderedDict
from email import message_from_string as mfs
from base64 import urlsafe_b64decode as decode
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from pprint import pprint, pformat
from bs4 import BeautifulSoup as soup

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger()
handler = logging.FileHandler('organize.log', 'w', encoding="UTF-8")
handler.setFormatter(logging.Formatter(u'%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(handler)

SCOPES = 'https://mail.google.com/'

def delete(msg_id):
	service.users().messages().delete(userId='me', id=msg_id).execute()
	logger.info("{} has been deleted".format(msg_id))

def read(msg_id):
	service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
	logger.info("{} has been read".format(msg_id))

def picking_option(user_input):
	if user_input == "y" or user_input == "yes":
		return True
	elif user_input == "x" or user_input == "exit":
		sys.exit("Exiting, beep boop")
	else:
		return False

def main():
	# Call the Gmail API to fetch LABELS
	labels = service.users().labels().list(userId='me').execute().get('labels', [])
	# get unread messages, to get more than 100 there's while true cycle
	while True:
		messages = service.users().messages().list(userId='me', labelIds = ['INBOX', 'UNREAD']).execute().get('messages', [])
		for msg in messages:
			# reopening database on each cycle to ensure syncing
			database = shelve.open("db", writeback=True)
			email = OrderedDict() # Ordered dict, so the important information is printed at the bottom

			message = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()

			# some messages don't have proper body
			# TODO: Add regex to parse messages and forward them to Slack instead (all the important ones at once)
			try:
				payload = message['payload']['parts'][0]['body']['data']
				payload_decoded = decode(bytes(payload.replace("-", "+").replace("_", "/"), "UTF-8"))
				email['Body'] = soup(payload_decoded, 'lxml').body()
			except Exception as e:
				logger.error(e)
				pass

			email['Snippet'] = message['snippet']
			for each in message['payload']['headers']:
				if each["name"] == "Date":
					email['Date'] = str(parser.parse(each['value']).date())
				elif each["name"] == "From":
					email['From'] = each["value"]
				elif each['name'] == "Subject":
					email['Subject'] = each["value"]
				else:
					continue
			
			pprint(email)
			pprint(message['payload']['headers'])
			# this block checks if the sender is already in any of the lists in database
			# if yes, proceeds with the action

			if email["From"] in database["to_pass"]:
				webbrowser.open_new("https://mail.google.com/mail/u/0/#inbox/{}".format(msg["id"]))
				continue
			elif email["From"] in database["to_delete"]:
				delete(msg["id"])
			elif email["From"] in database["to_read"]:
				read(msg["id"])
			# if not counts the times the action has been selected in current session
			else:
				prompt = input("What would you like to do with this email? [(r)ead, (d)elete, (o)pen, e(x)it] ")
				if prompt == "x" or prompt == "exit":
					sys.exit("Exiting, beep boop")
				elif prompt == "d" or prompt == "delete":
					delete(msg["id"])
					action = "delete"
				elif prompt == "r" or prompt == "read":
					read(msg["id"])
					action = "read"
				else:
					webbrowser.open_new("https://mail.google.com/mail/u/0/#inbox/{}".format(msg["id"]))
					action = "pass"

				if email["From"] not in current_session:
					current_session.update({email["From"] : {"count" : 1, "action" : action}})
				else:
					current_session[email["From"]]["count"] += 1

				if action != current_session[email["From"]]["action"]:
					change_action = input("Would you like to change the action from {} to {} {}".format(current_session[email["From"]]["action"], action, options))
					if picking_option(change_action):
						current_session[email["From"]]["action"] = action
			# if the count breaches threshold - offers to add to the database permanently
				if current_session[email["From"]]["count"] >= session_threshold:
					add_to_database = input("Would you like to PERMANENTLY add {} to {} list? {}".format(email["From"], current_session[email["From"]]["action"].upper(), options))
					if picking_option(add_to_database):
						if current_session[email["From"]]["action"] == "pass":
							database["to_pass"].append(email["From"])
						elif current_session[email["From"]]["action"] == "delete":
							database["to_delete"].append(email["From"])
						elif current_session[email["From"]]["action"] == "read":
							database["to_read"].append(email["From"])
						else:
							logger.error("No action found, something went wrong.")
			
			database.sync()
			database.close()

if __name__ == "__main__":
	options = "\n[(y)es, (n)o, e(x)it] "
	database = shelve.open("db", writeback=True)
	if "to_read" not in database:
		database["to_read"] = []
	if "to_delete" not in database:
		database["to_delete"] = []
	if "to_pass" not in database:
		database["to_pass"] = []
	for collection in database:
		print(collection)
		pprint(database[collection])
	database_modify = input("Would you like to review and modify the lists in database? {}".format(options))
	if picking_option(database_modify):
		print("These mailers are currently in the list: \n{}".format(pformat(database)))
		list_to_modify = input("Which list would you like to modify? [{}]".format([key for key in database_modify]))
	database.close()
	#current session should become a part of database
	current_session = {}
	session_threshold = 3
	threshold_change = input("Would you like to change session threshold? Current value: {} {}".format(session_threshold, options))
	storage = file.Storage('token.json')
	creds = storage.get()
	if not creds or creds.invalid:
		flow = client.flow_from_clientsecrets('creds.json', SCOPES)
		creds = tools.run_flow(flow, storage)
	service = build('gmail', 'v1', http=creds.authorize(Http()))
	main()