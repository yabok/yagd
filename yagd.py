#!/usr/bin/env python3
from flask import Flask, request
from sh import cd, git
import json, configparser

app = Flask(__name__)

config = configparser.ConfigParser()
config.read('config.ini')

repos = config['yagd']['repos']
basedir = config['yagd']['repodir']

def update_mirror(repo):
	cd(basedir + repo + '.git')
	git.remote.update()


@app.route('/',methods=['POST'])
def index():
	data = json.loads(request.data.decode('utf-8'))

	if request.headers.get('X-GitHub-Event') == 'ping':
		print("Ping. Zen: {}".format(data['zen']))

	elif request.headers.get('X-GitHub-Event') == 'push':
		user    = data['pusher']['name']
		repo    = data['repository']['name']
		repo_fn = data['repository']['full_name']
		ref     = data['ref']
		before  = data['before']
		after   = data['after']
		compare = data['compare']
		forced  = data['forced']
		print('Push to {}: user {} updated ref {} from {} to {}. {}'.format(repo_fn, user, ref, before, after, compare))

		if repo in repos:
			update_mirror(repo)

	else:
		print("New notification: {}".format(data))

	return "OK"

if __name__ == '__main__':
	app.run(port=5002, debug=True)
