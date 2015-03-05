#!/usr/bin/env python3
from flask import Flask, request, abort
from sh import cd, git
import json, configparser
import traceback
import requests
import socket
import posixpath
from sys import stderr
from hashlib import sha1
import hmac
import systemd.journal as journal
import logging

app = Flask(__name__)

config = configparser.SafeConfigParser()
config.read('/etc/yagd.ini')

channels = config['yagd']['channels']
repos = config['yagd']['repos']
basedir = config['yagd']['repodir']

log = logging.getLogger('yagd')
log.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER='yagd'))
log.setLevel(logging.INFO)

COLORS = {'reset': '\x0f', 'yellow': '\x0307', 'green': '\x0303', 'bold': '\x02', 'red': '\x0305', 'cyan': '\x0310'}

def update_mirror(repo):
	cd(basedir + repo + '.git')
	git.remote.update()

def shorten(url):
	res = requests.post('http://git.io', data={'url': url.encode('utf-8')})
	if res.status_code == 201:
		url = res.headers.get('Location', url)
	else:
		log.info("git.io returned status: {}".format(res.reason))
	return url

def verify_signature(client_secret, raw_response, signature):
	digest = hmac.new(client_secret.encode('utf-8'),
	                  msg = raw_response.encode('utf-8'),
	                  digestmod = sha1,
	                  ).hexdigest()
	log.debug('Signature received: {:s}'.format(signature))
	log.debug('Digest calculated:  {:s}'.format(digest))
	return digest == signature

def format_commit(everything, commit):
	short_url = shorten(commit["url"])
	message = commit["message"].split("\n")[0][:80]
	return ("{green}{author}{reset} {repo}:{yellow}{branch}{reset} "
	        "{bold}[{sha}]{reset}: {msg} {red}<{url}>{reset}"
	        ).format(
	                 project = everything["repository"]["owner"]["name"],
	                 repo    = everything["repository"]["name"],
	                 branch  = everything["ref"].split("/")[-1],
	                 author  = commit["author"]["username"],
	                 sha     = commit["id"][:7],
	                 msg     = message,
	                 url     = short_url,
	                 **COLORS)

def format_tag(everything):
	return ("{green}{pusher}{reset} {repo}: "
	        "{bold}[{sha}]{reset} tagged as {yellow}{tag}{reset}"
	        ).format(
	                 project = everything["repository"]["owner"]["name"],
	                 repo    = everything["repository"]["name"],
	                 pusher  = everything["pusher"]["username"],
	                 tag     = everything["ref"].split("/")[-1],
	                 sha     = everything["head_commit"]["id"][:7],
	                 **COLORS)

def format_issue(everything):
	short_url = shorten(everything['issue']['html_url'])
	variables = {
		'user': everything['issue']['user']['login'],
		'repo': everything['repository']['name'],
		'action': everything['action'],
		'number': everything['issue']['number'],
		'title': everything['issue']['title'],
		'url': short_url
	}
	variables.update(COLORS)
	message = '{green}{user}{reset} {repo} {cyan}issue #{number}{reset}'

	if everything['action'] == 'labeled':
		variables.update({'label': everything['label']['name']})
		message += ' {bold}label ‘{label}’ added{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'unlabeled':
		variables.update({'label': everything['label']['name']})
		message += ' {bold}label ‘{label}’ removed{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'assigned':
		variables.update({'assignee': everything['assignee']['login']})
		message += ' {bold}assigned to {assignee}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'unassigned':
		variables.update({'assignee': everything['assignee']['login']})
		message += ' {bold}unassigned from {assignee}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	else:
		message += ' {bold}{action}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	return message

def format_pull_request(everything):
	short_url = shorten(everything['pull_request']['html_url'])
	variables = {
		'user': everything['pull_request']['user']['login'],
		'repo': everything['repository']['name'],
		'action': everything['action'],
		'number': everything['number'],
		'title': everything['pull_request']['title'],
		'url': short_url
	}
	variables.update(COLORS)
	message = '{green}{user}{reset} {repo} {cyan}PR #{number}{reset}'

	if everything['action'] == 'labeled':
		variables.update({'label': everything['label']['name']})
		message += ' {bold}label ‘{label}’ added{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'unlabeled':
		variables.update({'label': everything['label']['name']})
		message += ' {bold}label ‘{label}’ removed{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'assigned':
		variables.update({'assignee': everything['assignee']['login']})
		message += ' {bold}assigned to {assignee}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'unassigned':
		variables.update({'assignee': everything['assignee']['login']})
		message += ' {bold}unassigned from {assignee}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'closed':
		if everything['pull_request']['merged'] == True:
			message += ' {bold}merged{reset}: {title} {red}<{url}>{reset}'
		else:
			message += ' {bold}{action}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	elif everything['action'] == 'synchronize':
		message += ' {bold}synchronized{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	else:
		message += ' {bold}{action}{reset}: {title} {red}<{url}>{reset}'
		message = message.format(**variables)

	return message


def send_to_irker(message, channels):
	log.info("{chans}: {msg}".format(chans=",".join(channels), msg=message))
	envelope = { "to": channels, "privmsg": message }
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto(json.dumps(envelope).encode("utf-8"), ("localhost", 6659))

def process_blob(blob):
	if (blob["created"] or blob["deleted"]) == True:
		if blob["created"] == True:
			action = 'created'
		else:
			action = 'deleted'

		message = ('{green}{pusher}{reset} {cyan}{action} branch{reset} '
		           '{repo}:{yellow}{branch}{reset}'
		          ).format(
		                   pusher = blob['pusher']['name'],
		                   action = action,
		                   repo   = blob['repository']['name'],
		                   branch = blob['ref'].split('/')[-1],
		                   **COLORS)
		send_to_irker(message, channels)

	elif blob["forced"] == True:
		message = ('{green}{pusher}{reset} {red}force pushed{reset} '
		           'to {repo}:{yellow}{branch}{reset}'
		          ).format(
		                   pusher = blob['pusher']['name'],
		                   repo   = blob['repository']['name'],
		                   branch = blob['ref'].split('/')[-1],
		                   **COLORS)
		send_to_irker(message, channels)

	for commit in blob["commits"]:
		try:
			if blob["ref"].split("/")[-1] != 'coverity_scan':
				message = format_commit(blob, commit)
				send_to_irker(message, channels)
		except:
			traceback.print_exc()
	if blob["ref"].startswith("refs/tags"):
		try:
			message = format_tag(blob)
			fake_commit = {"author":blob["pusher"]} #TODO: factor this properly
			send_to_irker(message, channels)
		except:
			traceback.print_exc()

def handle_push(data):
	repo    = data['repository']['name']
	process_blob(data)

	if repo in repos:
		update_mirror(repo)

def handle_issue(data):
	message = format_issue(data)
	send_to_irker(message, channels)

def handle_pull_request(data):
	message = format_pull_request(data)
	send_to_irker(message, channels)

@app.route('/',methods=['POST'])
def index():
	secret = config['yagd']['github_secret']
	data = json.loads(request.data.decode('utf-8'))
	event = request.headers.get('X-GitHub-Event')
	signature = request.headers.get('X-Hub-Signature').replace('sha1=', '')

	if not verify_signature(secret, request.data.decode('utf-8'), signature):
		abort(401)

	if event == 'ping':
		log.info("Ping. Zen: {}".format(data['zen']))

	elif event == 'push':
		handle_push(data)

	elif event == 'issues':
		handle_issue(data)

	elif event == 'pull_request':
		handle_pull_request(data)

	else:
		log.info("New notification: {}".format(data))

	return "OK"

if __name__ == '__main__':
	app.run(port=5002, debug=True)
	app.logger.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER='yagd'))

