import json
import os
import hashlib
import hmac
import re
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import subprocess



def runSecretCodeScanning(text):
    regexDict = {
        "SLACK_WEBHOOKS":"""https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}""",
        "TWILIO_API_TOKENS": """SK[0-9a-fA-F]{32}""",
        "STRIPE_API_TOKENS" : """[s|r]k_(live|test)_[0-9a-zA-Z]{24}""",
        "SLACK_API_TOKENS" : """xox[baprs]([0-9a-zA-Z-]{10,72})""",
        "PRIVATE_KEYS" : """(?s)(-----BEGIN .+?-----)\\S{0,}""",
        "MAILGUN_API_TOKENS" : """key-[0-9a-zA-Z]{32}""",
        "MAILCHIMP_API_TOKENS" : """[0-9a-f]{32}-us[0-9]{1,2}""",
        "HEROKU_API_TOKENS" : """[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}""",
        "GOOGLE_API_TOKENS" : """AIza[0-9A-Za-z\\-_]{35}|[0-9]+-[0-9A-Za-z_]{32}""",
        "GITHUB_TOKENS" : """(ghu|ghs|gho|ghp|ghr)_[0-9a-zA-Z]{36}""",
        "GITLAB_TOKENS": """glpat-[0-9a-zA-Z\-\_]{20}""",
        "FACEBOOK_SECRET_TOKENS" : """[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[0-9a-f]{32}""",
        "FACEBOOK_ACCESS_TOKENS" : """EAACEdEose0cBA[0-9A-Za-z]+""",
        "AWS_ACCESS_KEY" : """(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}""",
        "AWS_API_TOKENS" : """(?<![A-Za-z0-9\\/+=])[A-Za-z0-9\\/+=]{40}(?![A-Za-z0-9\\/+=])"""
    }
    
    for regex in regexDict.keys():
        x = re.search(re.compile(regexDict[regex]), text)
        if x is not None:
            print("Leak detected: {0}".format(regex))
            return x.group()
        else:
            print("No leak found")


def replaceSecretWithURL(body, msg, messageID, reply_broadcast, thread_ts=None):
    client = WebClient(token=os.getenv('SLACK_USER_TOKEN'))
    channelID = body['event']['channel']
    privateBinURL = ''

    # generating privatebin url
    try:
        server = os.getenv('server')
        out = subprocess.run(['python', '/opt/python/lib/python3.8/site-packages/pbincli_bin', 'send', '-t', msg, '-s', server, '-E', '5min'], capture_output=True, text=True)
        privateBinURL = out.stdout.split('Link:')[-1].strip()
    except Exception as e:
        print("Unable to generate privatebin link: {0}".format(e))
    
    try:
        result = client.chat_delete(channel=channelID,ts=messageID)
        print("Successfully deleted the message from the channel")
    except SlackApiError as e:
        print(f"Error deleting message: {e}")
        return {
                'statusCode': 200
            }
    #Posting link to the slack channel
    try:
        if len(privateBinURL) > 0:
            if thread_ts is not None:
                result = client.chat_postMessage(channel=channelID, thread_ts=thread_ts, reply_broadcast=reply_broadcast, text="Above message is containing hardcoded secret, so we removed it, please fetch it using below given link:\n"+str(privateBinURL))
            else:
                result = client.chat_postMessage(channel=channelID, reply_broadcast=reply_broadcast, text="Above message is containing hardcoded secret, so we removed it, please fetch it using below given link:\n"+str(privateBinURL))
    except SlackApiError as e:
        print(f"Error posting message: {e}")
        
def verify(body, timestamp, slack_signature, slack_signing_secret):
    slack_signing_secret = bytes(slack_signing_secret, 'utf-8')
    sig_basestring = f"v0:{timestamp}:{body}".encode('utf-8')
    signature = 'v0=' + hmac.new(slack_signing_secret, sig_basestring, hashlib.sha256).hexdigest()
    if hmac.compare_digest(signature, slack_signature):
        return True
    else:
        print('Hash does not match: {0}'.format(signature))
        return False
    

def lambda_handler(event, context):
    slack_signing_secret = os.getenv('SLACK_SIGNING_SECRET')
    print(event)
    body = json.loads(event['body'])
    if body['type'] == 'url_verification':
        if verify(event['body'], event['headers']['x-slack-request-timestamp'], event['headers']['x-slack-signature'], slack_signing_secret): # Here I am using event['body'] because it is of type string.
            return {
                'Content-type': 'application/json',
                'statusCode': 200,
                'body': body['challenge']
            }
    elif body['type'] == 'event_callback':
        if body.get('event').get('subtype') is not None and body.get('event').get('subtype') == 'message_deleted': # ignoring the message delete events.
            # print(event)
            print('Message deletion event')
            return {
                'statusCode': 200
            }
        if event.get('headers').get('x-slack-retry-reason') is not None and event.get('headers').get('x-slack-retry-reason') == 'http_timeout':
            # print(event)
            print('Slack is retrying to send the event because of timeout, ignore it.')
            return {
                'statusCode': 200
            }
            
        if body.get('event').get('subtype') is not None and body.get('event').get('subtype') == 'message_changed':
            if body.get('event').get('message') is not None and body.get('event').get('message').get('subtype') is not None and body.get('event').get('message').get('subtype') == 'thread_broadcast':
                reply_broadcast = True
            else:
                reply_broadcast = False
            text = '''{0}'''.format(body['event']['message']['text'])
            messageID = body['event']['message']['ts']
            thread_ts = body.get('event').get('message').get('thread_ts')
        else:
            text = '''{0}'''.format(body['event']['text'])
            messageID = body['event']['ts']
            thread_ts = body.get('event').get('thread_ts')
            reply_broadcast = False 
        
        out = runSecretCodeScanning(text)
        if out is not None and len(out) > 0:
            replaceSecretWithURL(body, text, messageID, reply_broadcast, thread_ts)
        return {
            'statusCode': 200
        }
    else:
        return {
            'statusCode': 400,
            'body': 'Bad Request'
        }

