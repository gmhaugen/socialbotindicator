from twython import *
from analyzetwitteruser import analyzeuser

'''
Author: Geir Haugen
This program was developed as part of a Master's thesis at NTNU. This program is an additional program to launch the actual program that performs analyses (file: retrieve_twitter_info.py).
Analysis of a user is instantiated by calling the function analyzeuser. This function requires a Twython object and a string with a Twitter username (screen name) as parameters.
'''

app_token = 'YOUR-APP-TOKEN'
app_secret = 'YOUR-APP-SECRET'
auth_token = 'YOUR-AUTH-TOKEN'
auth_secret = 'YOUR-AUTH-SECRET'

twitter = Twython(
	app_key=app_token,
	app_secret=app_secret,
	oauth_token=auth_token,
	oauth_token_secret=auth_secret)

#######################################
analyzeuser(twitter, 'username')
#######################################
