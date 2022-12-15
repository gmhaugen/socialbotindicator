from datetime import datetime, timedelta
import datetime
from datetime import datetime
import numpy as np
import datetime
from dateutil.parser import parse
from collections import defaultdict, OrderedDict
from operator import itemgetter
from matplotlib import pyplot, dates, style
import matplotlib.patches as mpatches
import json, time, sys, operator, csv
import re
import requests
import signal
import sys
from scipy.interpolate import spline
from numpy import linspace, array

'''
Author: Geir Haugen
This program was developed as part of a Master's thesis at NTNU.
The program is used to analyze a Twitter account and its tweets to find out if it belongs to a social bot.
Every function used to perform the analyses are listed in the first function of this program (analyzeuser).
'''

totalscore = []
indicator = {}
max = None

def analyzeuser(twitter, username):
	getuserinfo(twitter, username)
	getalltweets(twitter, username)

	analyzename(username)
	analyzeaccountage(username)
	analyzetweetsources(username)
	analyzetweeturls(username)
	analyzetweettimedif(username)
	analyzeprofilepicture(username)
	analyzeduplicates(username)
	analyzetweethoursaverage(twitter, ['erna_solberg', 'Siv_Jensen_FrP', 'jonasgahrstore', 'HadiaTajik', 'KAHareide', 'audunlysbakken', 'bmoxnes', 'Trinesg'], username)
	calculatescore(username)

#This function calculates the average of number of tweets per hour in a day of a list
#of given Twitter users and another user to compare to the average.
#The average is shown in a graph as red, and the one user as blue.
#The function takes a twython object, a list of usernames (for average calculation) and a username as a string.
def analyzetweethoursaverage(twitter, usernames, screenname):
	clocktimes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]
	uxn = []
	uyn = []
	hourtimes = {}
	userhourtimes = {}
	numofusers = len(usernames)
	threshold = 100
	indicator['averagedif'] = 0

	#Iterate through all users in the list and; retrieve info on the user profile and
	#tweets from that user.
	for username in usernames:
		getuserinfo(twitter, username)
		getalltweets(twitter, username)
		tweets = displaytweetjsonfile(username)

		#Iterate through all the tweets of the current user.
		for tweet in tweets:

			#Create a datetime object from the tweet creation timestamp.
			dateindatetime = datetime.datetime.strptime(tweet['created_at'], '%a %b %d %H:%M:%S +0000 %Y')
			#Extract the hour attribute from the timestamp.
			hourtime = dateindatetime.hour

			#Check if the hour is already in the dictionary hourtimes. If it is, its value is
			#incremented by 1. If not, the hour is added with a value of 1.
			if hourtime in hourtimes:
				hourtimes[hourtime] += 1
			else:
				hourtimes[hourtime] = 1

	#Iterate through every hour of the clock (0-23), and see if the hours are in
	#the hourtimes dictionary. If it is not, the hour is added to the dictionary with
	#a value of 0.
	for hour in clocktimes:
		if hour not in hourtimes:
			hourtimes[hour] = 0

	#Iterate through the dictionary of total tweets at hours of a day and calculate
	#the average tweets of that hour by dividing by the number of users.
	for hour in hourtimes:
		hourtimes[hour] = hourtimes[hour] / numofusers

	#Saving the average tweets in hours of a day to a .csv file.
	with open('averagehours.csv', 'w') as tf:
		writer = csv.writer(tf, delimiter=',')
		tweethour = 0
		#for key in hourtimes:
		#	if tweethour in hourtimes:
		#		writer.writerow( str((key)) + str((hourtimes[key])))
		#	else:
		#		writer.writerow( str((tweethour)) + str((0)))
		for hour in clocktimes:
			if hour in hourtimes:
				data = [hour, hourtimes[hour]]
				writer.writerow(data)
			else:
				data = [hour, 0]
				writer.writerow(data)

	#Getting user account info and tweets from the user being compared to the average.
	#getuserinfo(twitter, screenname)
	#newgetalltweets(twitter, screenname)
	tweets = displaytweetjsonfile(screenname)

	#Iterate through every tweet of the user to compare to the average. 
	for tweet in tweets:

		#Creating a datetime object from the tweet creation timestamp.
		dateindatetime = datetime.datetime.strptime(tweet['created_at'], '%a %b %d %H:%M:%S +0000 %Y')

		#Extract the hour attribute from the timestamp.
		hourtime = dateindatetime.hour

		#Check if the hour is already in the dictionary userhourtimesif it is, its value is
		#incremented by 1. If it is not, the hour is added to the dictionary with a value
		#of 0.
		if hourtime in userhourtimes:
			userhourtimes[hourtime] += 1
		else:
			userhourtimes[hourtime] = 1

	#Saving the hours of the tweets for the single user as a .csv file.
	with open(screenname + '_tweethours.csv', 'w') as tf:
		writer = csv.writer(tf, delimiter=',')
		for hour in clocktimes:
			if hour in userhourtimes:
				data = [hour, userhourtimes[hour]]
				writer.writerow(data)
			else:
				data = [hour, 0]
				writer.writerow(data)

	#Showing the average and tweets of the one user in a graph.
	ux,uy = np.loadtxt(screenname + '_tweethours.csv', unpack=True, delimiter=',')

	for i in range(0, len(uy)):
		if uy[i] > hourtimes[ux[i]] + threshold or uy[i] < hourtimes[ux[i]] - threshold:
			indicator['averagedif'] = 1
			print('Average difference!')

	for value in ux:
		uxn.append(value)
	for value in uy:
		uyn.append(value)

	#Changing the arrays x and y to numpy arrays.
	x = np.array(clocktimes)
	y = np.array(hourtimes.values())

	#Calculate new x values to have a smooth graph.
	xnew = linspace(x.min(),x.max(),300)
	ysmooth = spline(x, y, xnew)

	#Setting the values for the graph and displaying it.
	pyplot.plot(xnew, ysmooth, 'r', label='Average')
	pyplot.plot(uxn, uyn, 'b', label=screenname)
	pyplot.legend(loc='upper left')
	pyplot.title('Tweets at hours of a day')
	pyplot.ylabel('Number of tweets')
	pyplot.xlabel('Time of day (hour)')
	pyplot.grid()
	pyplot.show()

#This function fetches account information from a username (screen name).
#The information is saved to a file as json data in the format "username"_userinfo.
#Takes a twython object and a username (screen name) as parameters.
def getuserinfo(twitter, username):
	user = twitter.show_user(screen_name=username)
	savetojson(username, user, '_userinfo')

#This function analyze a set of tweets to look for tweets with exactly the same content.
#Takes a username (screen name) as a string as parameter.
def analyzeduplicates(username):
	tweets = displaytweetjsonfile(username)
	indicator['duplicatetweets'] = 0
	duplicates = 0
	threshold = 0
	tweetscheck = tweets

	#For every tweet, iterate through all of the tweets.
	for tweet in tweets:
		for tweetc in tweetscheck:
			#Checking if tweets contains the same text, but does not have the same id. If the case, increment int duplicates.
			if tweet['text'] == tweetc['text'] and tweet['id_str'] != tweetc['id_str']:
				duplicates += 1
	if duplicates > threshold:
		print('Duplicate tweets exist! ({})'.format(duplicates))
		indicator['duplicatetweets'] = 1

#This function analyze a user's screen name for spaces.
#Takes a username (screen name) as a string as parameter.
def analyzename(username):
	user = displayuserinfojsonfile(username)
	if ' ' not in user['name']:
		print('The name of this user might be auto-generated!')
		indicator['nospacesinname'] = 1
	else:
		indicator['nospacesinname'] = 0

#This function analyze whether a user has default profile image.
#Takes a username (screen name) as a string as parameter
def analyzeprofilepicture(username):
	user = displayuserinfojsonfile(username)
	if user['default_profile_image'] == True:
		print('This account uses default profile image!')
		indicator['defaultprofileimage'] = 1
	else:
		indicator['defaultprofileimage'] = 0

#This function analyze 1: Wether there have not been any activity in the first 30 days of an account. 2: Wether the account have been inactive for 30 days.
#Takes a username (screen name) as a string as parameter.
def analyzeaccountage(username):
	indicator['noactivity'] = 0
	indicator['thirtydays'] = 0
	user = displayuserinfojsonfile(username)
	datedif = datetime.datetime.now() - to_sdatetime(str(user['created_at']))
	days = datedif.days

	#Creating hours, minutes and seconds based on the account age (days).
	hours = datedif.seconds / 3600
	minutes = datedif.seconds / 60%60
	seconds = datedif.seconds % 60
	print('The account "' + username + '" is ' + str(days) + ' days ' + str(hours) + ' hours ' + str(minutes) + ' minutes ' + str(seconds) + ' seconds' + ' old.')
	dayssincelast = datetime.datetime.now() - to_sdatetime(user['status']['created_at'])
	dayssincelast = dayssincelast.days

	if user['statuses_count'] > 0:
		if dayssincelast > 30:
			indicator['thirtydays'] = 1

	if days > 30 and user['statuses_count'] == 0:
		indicator['noactivity'] = 1

#This function analyze the sources/devices used in a set of tweets of a particular user.
#Analyses include: 1: Wether the account is application-controlled. 2: The number of sources found in the tweets of the account. 3: Wether an unknown source/device is used to post tweets.
#Takes username as a string as parameter.
def analyzetweetsources(username):
	indicator['applicationcontrolled'] = 0
	indicator['numofsources'] = 0
	indicator['unknownsource'] = 0

	#The list of known/accepted sources.
	sourceslist = ['Twitter for iPhone', 'Twitter for Android', 'Twitter Web Client', 'Twitter for Mac', 'Twitter for Windows Phone', 'Tweetdeck', 'Instagram', 'Twitter for iPad']

	threshold = 3
	tweets = displaytweetjsonfile(username)
	numoftweets = len(tweets)
	sources = {}
	newsources = {}

	#Iterate through all the tweets of the user.
	for tweet in tweets:
		source = tweet['source'].partition('>')[-1].rpartition('<')[0]
		source = source.encode('utf8')#convert the value from unicode to utf8.

		#Filling the dictionary sources. If the source is already in the dictionary,
		#increment with 1, if not, add it to the dictionary and set value to 1.
		if source in sources:
			sources[source] += float(1)
		else:
			sources[source] = float(1)

	#Sort the dictionary.
	newsources = OrderedDict(sorted(sources.items(), key=itemgetter(1), reverse=True))

	#Iterate through the dictionary newsources and calculate and print the percentages
	#of all sources used.
	for source in newsources:
		percentage = float((newsources[source] / numoftweets) * 100)
		print(source + ': ' + repr(percentage) + '%')

		#If a user's screen name is equal to one of the sources used, add indicator.
		if source == username or source.lower() == username or source.upper() == username:
			print('This account is application-controlled!^')
			indicator['applicationcontrolled'] = 1

	print('sources num = ' + str(len(newsources)))

	if len(newsources) < threshold:
		indicator['numofsources'] = 1

	for source in newsources:
		if source not in sourceslist:
			print(source + ' is not in the list of sources!')
			indicator['unknownsource'] = 1


#This function analyze the use of URLs in a set of tweets. This function will only
#analyze URLs with a http:// or https:// format.
#First, the number of URLs in the tweets are inspected and printed. If no URLs are
#found, the inspection will abort. If URLs are present, the percentage of URLs used
#in the tweets are printed. The operator is then prompted if he/she would like to
#further inspect the URLs found.
#Takes username as a string as parameter.
def analyzetweeturls(username):
	tweets = displaytweetjsonfile(username)
	numoftweets = float(len(tweets))
	urltweets = float(0)

	#Iterate through all the tweets and count the URLs.
	for tweet in tweets:
		if 'http://' in tweet['text'] or 'https://' in tweet['text']:
			urltweets += float(1)

	#If no URLs are found, abort inspection.
	if urltweets == 0.0:
		print('No URLs found, aborting inspection.')
		return

	#Calculating and printing the percentage of tweets that contain URLs.
	urlpercentage = float((urltweets / numoftweets) * 100)
	print(repr(urlpercentage) + '% of the tweets have urls. (' + str(int(urltweets)) + ' of ' + str(int(numoftweets)) + ')')

	#A URL percentage of 60% is the current threshold for bot activity. If the URL
	#percentage is above 60%, this will be added as an indicator.
	if urlpercentage > 60.0:
		indicator['urlpercentage'] = 1
	else:
		indicator['urlpercentage'] = 0

	#If there are more than 0 urls, prompt the user for further inspection of the URLs.
	if urltweets > 0.0:
		userinput = raw_input('Further inspect URLs? (y/n)>')
		if userinput == 'y':
			analyze_tweeturls(username)
		else:
			return

#This function analyze the maximum and minimum time difference between tweets.
#The minimum time difference is not included as an indicator because the approach still contains bugs. Only maximum time difference is included in the solution.
#Takes a username (screen name) as a string as parameter.
def analyzetweettimedif(username):
	tweets = displaytweetjsonfile(username)
	counter = 0
	datelist = []
	difference = []
	minmax = []
	newdatelist = []
	occurrencesmin = 0

	#Sorting the tweets by date.
	tweets.sort(key=lambda item:item['created_at'], reverse=True)

	#Iterate through all the tweets and convert timestamp to datetime object and add to datelist.
	for tweet in tweets:
		datelist.append(datetime.datetime.strptime(str(tweet['created_at']), '%a %b %d %H:%M:%S +0000 %Y'))

	#Sorting the datetime objects in datelist.
	datelist.sort(reverse=True)

	#Iterate through all the datetime objects in datelist and calculate timedelta (difference between dates) and add these to newdatelist.
	while (counter < len(datelist) - 1):
		if counter < len(datelist) - 1:
			tweettimea = datelist[counter]
			tweettimeb = datelist[counter + 1]
			delta = tweettimea - tweettimeb
			newdatelist.append(delta)
			counter += 1
	counter = 0

	#Sorting the timedelta objects in newdatelist.
	newdatelist.sort(key=lambda item:item, reverse=True)

	#Setting the minimum and maximum time differences to have a starting point.
	min = newdatelist[0]
	max = newdatelist[len(newdatelist) - 1]

	#Iterate through all the timedelta objects in newdatelist and change minimum and maximum time difference if current timedelta is smaller/bigger than current minimum or maximum time difference.
	for calctime in newdatelist:
		if calctime == min:
			occurrencesmin += 1
		if calctime > max:
			max = calctime
		if calctime < min:
			min = calctime

	#Calculating the maximum threshold (28 days).
	maxthreshold = datetime.datetime.strptime('Wed Apr 26 10:00:00 +0000 2017', '%a %b %d %H:%M:%S +0000 %Y') - datetime.datetime.strptime('Wed Mar 24 10:00:00 +0000 2017', '%a %b %d %H:%M:%S +0000 %Y')

	if max >= maxthreshold:
		indicator['maxdif'] = 1
	else:
		indicator['maxdif'] = 0

	print('Maximum time difference between tweets = ' + str(max))
	print('Minimum time difference between tweets = ' + str(min) + ' (' + str(occurrencesmin) + ' times)')

#This function plots at which times of a day a user posts tweets (in which hours).
#This information is stored as a .csv file with format username_tweethours.csv.
#The information is also displayed as a graph.
#Takes a username (screen name) as a string as parameter.
def analyzetweethours(username):
	tweets = displaytweetjsonfile(username)
	hourtimes = {}
	clocktimes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]

	#Iterate through all the tweets of the user, extracts the hour from the tweet
	#timestamp and adds it to the dictionary hourtimes.
	for tweet in tweets:
		dateindatetime = datetime.datetime.strptime(tweet['created_at'], '%a %b %d %H:%M:%S +0000 %Y')
		hourtime = dateindatetime.hour
		if hourtime in hourtimes:
			hourtimes[hourtime] += 1
		else:
			hourtimes[hourtime] = 1

	#Writes the information to a .csv file.
	with open(username + '_tweethours.csv', 'w') as tf:
		writer = csv.writer(tf, delimiter=',')
		tweethour = 0
		for hour in clocktimes:
			if hour in hourtimes:
				data = [hour, hourtimes[hour]]
				writer.writerow(data)
			else:
				data = [hour, 0]
				writer.writerow(data)

	#Setting the values of the graph and displaying it.
	x,y = np.loadtxt(username + '_tweethours.csv', unpack=True, delimiter=',')
	pyplot.xticks(clocktimes)
	pyplot.plot(x,y)
	pyplot.title('Tweets at hours of a day')
	pyplot.ylabel('Number of tweets')
	pyplot.xlabel('Hour of a day')
	pyplot.show()

#Help method to manage timeout exceptions.
def timeout_handler(signum, frame):
	raise TimeoutException

#Help class to manage timeout exceptions.
class TimeoutException(Exception):
	pass

#This function calculates a score based on the indicator dictionary and prints it.
#The score is solely based on the average of all the scores in the dictionary "indicators".
#Takes a username (screen name) as a string as parameter.
def calculatescore(username):
	user = displayuserinfojsonfile(username)
	score = 0.0
	for ind in indicator:
		score += float(indicator[ind])
	score = score / len(indicator)
	print('Bot indicator score: ' + str(score))
	print(indicator)
	if user['verified'] == True:
		print('The account \"' + username + '\" is verified, and should not be considered a bot.')

#This function extracts URLs from tweets. Shortened urls are deflated
#and further analyzed with the function checkurl(). Only URLs that are
#shortened in the twitter format (t.co) will be deflated.
#Takes username (screen name) as a string as parameters.
def analyze_tweeturls(username):
	urllist = []
	tweets = displaytweetjsonfile(username)
	user = displayuserinfojsonfile(username)
	requestsnum = 0
	urlsnum = 0
	averageseconds = 5.0#approximate time needed to deflate a URL.
	signal.signal(signal.SIGALRM, timeout_handler)
	calculatedtime = 0

	#Counting number of tweets with URLs in them. Will abort (return) if no URLs are found.
	for tweet in tweets:
		if 'https://' in tweet['text'] or 'http://' in tweet['text']:
			urlsnum += 1
	if urlsnum == 0:
		print('No URLs found. Aborting...')
		return

	#Calculate the approximate time it takes to defalte all the urls.
	totalcalctime = (averageseconds * float(urlsnum))

	#Calculate the percentage of tweets that have URLs in them.
	urlpercentage = float((urlsnum / float(len(tweets))) * float(100))

	#Print the percentage of tweets with URLs.
	print(str(urlsnum) + ' of ' + str(len(tweets)) + ' (' + str(urlpercentage) + '%) tweets have URLs in them.')

	#Print the approximate time needed to complete the process.
	print('This process can take up to {} minutes and {} seconds to complete!'.format(*divmod(totalcalctime, 60)))

	#Prompt the user if he/she would like to continue
	userinput = raw_input('Continue? (y/n)>')

	if userinput == 'y':
		indicator['maliciousurl'] = 0
		#Iterate through all the tweets for the user.
		for tweet in tweets:
			tweetcontent = tweet['text']
			exurl = re.findall(r'(https?://\S+)', tweetcontent)
			for url in exurl:
				print(url)
				if 't.co' in url:#if the url have been shortened by Twitter.
					if 't.co/' not in url:#checking if the shortened URL is complete (i.e. "t.co..." which is invalid and "t.co/<restoftheurl>" which is valid). This check is needed because not all urls extracted from tweets are complete.
						print('"' + url + '" is not a valid URL!')
					else:
						print('tick')
						signal.alarm(5)#give 5 seconds to get the original (unshortened) URL. Will skip current one if 5 seconds pass.
						try:
							newurl = requests.get(url)#getting the original (unshortened) URL.
							urllist.append(newurl.url)
							print('^to ' + newurl.url)
						except (TimeoutException, requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
							print('^Failed to check this URL!')
							print(e)
							continue
						else:
							signal.alarm(0)
				else:#if the url is not shortened by Twitter.
					urllist.append(url)
				print('----------------------------------------')
	else:
		return
	print('Checking URLs...')
	for url in urllist:
		signal.alarm(5)#give 5 seconds to analyze url. Will skip current one if 5 seconds pass.
		try:
			print(url)
			checkurl(url)
		except TimeoutException:#prints message if there is a timeout.
			print('^Could not analyze this URL! (timed out)')
			if indicator['maliciousurl'] != 1:
				indicator['maliciousurl'] = 0
			continue
		else:
			signal.alarm(0)

# This function evaluates a given URL with the url-checking service provided
# by virustotal. Will skip the current URL checking if analysis is not available.
# Takes one URL as parameter.
def checkurl(url):
	headers = {
	  "Accept-Encoding": "gzip, deflate",
	  "User-Agent" : "gzip,  My Python requests library example client or username"}
	params = {'apikey': '38abf966c0f06b8abd4afd1d16bd0981988cd36d60dce4fc50c1cbdf06ac05a5', 'resource': url}
	response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params)
	print(response)

	#If the response have no json-content, current URL checking is skipped (return).
	try:
		json_response = response.json()
	except Exception as e:#if an error is thrown, skip this inspection
		print(e)
		print('(error: no content in response!)')
		return

	json_response = response.json()
	print(json_response)
	responsecode = json_response['response_code']
	print(json_response['response_code'])

	if json_response['response_code'] == 0:
		print('Bad response!')

	#Checking if the response contains the key "scans", continue if it is present.
	if json_response['response_code'] != -1 and 'scans' in json_response:
		counter = 0
		for scan1 in json_response['scans']:
			for scan2 in json_response['scans'][scan1]:
				for scan3 in json_response['scans'][scan1]:
					if json_response['scans'][scan1][scan3] == True and json_response['scans'][scan1]['result'] != "u'clean site" and json_response['scans'][scan1]['result'] != "u'unrated site":
						counter = counter
					if json_response['scans'][scan1]['result'] == "malicious site" or json_response['scans'][scan1]['result'] == "malware site":
						counter += 1

		#Divide the counter by 4. A bug causes the original number of malicious URLs to be 4 times higher than it should.
		counter = counter / 4
		print(str(counter) + ' sites report this url as malicious.')
		if counter > 0:
			indicator['maliciousurl'] = 1
	else:
		print('Request could not be handled! (No analyses available for this URL)')

#This function reads a file with tweets as json data and returns it.
#Takes a username (screen name) as a string as parameter.
def displaytweetjsonfile(username):
	json_data = {}
	with open(username + '_tweets') as file:
		json_data = file.read()
	tweets = json.loads(json_data)
	print(str(len(tweets)) + ' tweets loaded from file "' + username + '_tweets"')
	return tweets

#This function reads a file with user info as json data and returns it.
#Takes a username (screen name) as a string as parameter.
def displayuserinfojsonfile(username):
	json_data = {}
	with open(username + '_userinfo') as file:
		json_data = file.read()
	userdata = json.loads(json_data)
	print('User data loaded from file "' + username + '_userinfo"')
	return userdata

#This function retrieves all the tweets available for a particular user. Because of
#limits, only approximately the last 3200 tweets will be collected. The retrieved
#tweets are saved to a file with format "username"_tweets where username is the screen
#name of a particular user.
#Takes a Twython object and username (screen name) as a string as parameters.
def getalltweets(twitter, username):
	tweets = []
	print('Getting tweets from user \"' + username + '\"...')

	#getting the last 200 tweets
	new_tweets = twitter.get_user_timeline(screen_name = username, count = 200)
	tweets.extend(new_tweets)

	#finding id of the oldest tweet
	oldest = tweets[-1]['id'] - 1

	#tweets will be fetched as long as new_tweets is not empty
	while len(new_tweets) > 0:
		new_tweets = twitter.get_user_timeline(screen_name = username, count = 200, max_id = oldest)
		tweets.extend(new_tweets)
		oldest = tweets[-1]['id'] - 1
	savetojson(username, tweets, '_tweets')

#This function calculate and return the daily average of tweets. This is
#based on the number of tweets a user have and for how many days the account
#have been registered (tweetcount divided by days since the account was created).
#Takes number of tweets a user have as int and the creation date of the account as a String.
def calcavgtweets(statuses_count, created_at):
	return statuses_count / daysregistered(created_at)

#This function calculate the number of days since an account were registered.
#Does not take leap years in precaution.
#Returns the number of days since the account was created (float).
#Takes the creation date of an account as a string as parameter.
def daysregistered(created_at):
	return ((to_sdatetime(datetime.datetime.now().strftime('%a %b %d %H:%M:%S +0000 %Y')) - datetime.datetime.strptime(created_at, '%a %b %d %H:%M:%S +0000 %Y')).total_seconds() / (24*60*60))

#This function saves parameter data (json) to file.
#Filename used is in following format: username_type.json where type is a filename format.
def savetojson(username, data, type):
	print('\nSaving json data to filename \"' + username + type + '\"...')
	with open(username + type + '', 'a') as tf:
		json.dump(data, tf)
	print(str(len(data)) + ' entries written')

#This function returns the id of a twitter account by username.
#Takes a Twython object and a username (screen name) as a string as parameters.
def fromnametoid(twitter, username):
	twitter = twitter
	output = twitter.lookup_user(screen_name=username)
	userid_list=[]
	userid = output[0]['id_str']
	return userid

#This function returns a detetime-object based on a string.
#Takes a timestamp as a string as parameter.
def to_sdatetime(datestring):
	return datetime.datetime.strptime(datestring, '%a %b %d %H:%M:%S +0000 %Y')
