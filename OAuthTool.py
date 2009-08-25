"""
* OAuthTool v1.0
*
* Copyright (c) 2009, Jeffrey Tchang
*
* All rights reserved.
*
*
* THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

import optparse
import ConfigParser
import logging
import sys

import urllib
import urllib2
import httplib
import socket

import calendar
import time
from datetime import datetime

import hashlib
import oauth

import ConnectHTTPHandler



# Create an instance of the options parser. This object will hold
# all the command line options
optionsParser = optparse.OptionParser()



# This setups the proper logging levels when given a configuration object
def setupLogging(oAuthToolConfiguration):

  # Declare the main logger as a global
  global oAuthToolLogger
    
  # Determine the log level 
  if(oAuthToolConfiguration['Global']['LogLevel'] == 'DEBUG'):
    loglevel = logging.DEBUG
    
  elif(oAuthToolConfiguration['Global']['LogLevel'] == 'INFO'):
    loglevel = logging.INFO
    
  elif(oAuthToolConfiguration['Global']['LogLevel'] == 'WARNING'):
    loglevel = logging.WARNING

  elif(oAuthToolConfiguration['Global']['LogLevel'] == 'ERROR'):
    loglevel = logging.ERROR

  elif(oAuthToolConfiguration['Global']['LogLevel'] == 'CRITICAL'):
    loglevel = logging.CRITICAL

  else:
    loglevel = logging.ERROR

  # Create the logger with the appropriate log level
  oAuthToolLogger = logging.Logger("oAuthToolLogger",loglevel)

  # Define the logging format to be used
  oAuthToolLoggingFormat = logging.Formatter("[%(asctime)s][%(funcName)s] - %(message)s",'%m/%d/%y %I:%M%p')


  # Option to suppress console messages
  if( oAuthToolConfiguration['Global'].as_bool('ConsoleOutput') == True ):
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(oAuthToolLoggingFormat)
    oAuthToolLogger.addHandler(consoleHandler)

  # Option to log to a file
  if( 'LogFile' in oAuthToolConfiguration['Global'] ):
    fileHandler = logging.FileHandler(oAuthToolConfiguration['Global']['LogFile'],"w",encoding=None, delay=0)
    fileHandler.setFormatter(oAuthToolLoggingFormat)
    oAuthToolLogger.addHandler(fileHandler)

  # Define a do-nothing handler so that existing logging messages don't error out
  class NullHandler(logging.Handler):
    def emit(self, record):
      pass
  oAuthToolLogger.addHandler(NullHandler())




# Add the available command line options
# Think about using optparse callbacks to validate each of the arguments
def loadCommandLineOptions():



  optionsParser.add_option("-c", "--config", action="store", dest="configfile",
                           help="Path to configuration file (example in DefaultConfig.ini)")

  optionsParser.add_option("-m", "--method", action="store", type="string", dest="oauth_method", default="header",
                           help="Request method to use. Either 'header', 'POST', or 'GET'. By default 'header' is used.")


  optionsParser.add_option("-a", "--action", action="store", type="string", dest="oauth_action",
                           help="OAuth action to perform: getRequestToken, getAccessToken, authorizeToken")


  # OAuth options for getting a request token
  optionsParser.add_option("", "--consumerkey", action="store", type="string", dest="oauth_consumer_key", default="OAuthTool",
                           help="The consumer key (can be anything and is much like a firstname)")

  optionsParser.add_option("", "--consumersecret", action="store", type="string", dest="oauth_consumer_secret",
                           help="Shared secret between the consumer and the service provider")

  optionsParser.add_option("", "--signaturemethod", action="store", type="string", dest="oauth_signature_method",
                           help="The signature method to sign the request: HMAC-SHA1, RSA-SHA1, or PLAINTEXT")

  optionsParser.add_option("", "--callback", action="store", type="string", dest="oauth_callback",
                           help="The parameter oauth_callback (can be defined as 'oob' for out of band)")


  optionsParser.add_option("", "--tokenkey", action="store", type="string", dest="oauth_tokenkey",
                           help="The token key")

  optionsParser.add_option("", "--tokensecret", action="store", type="string", dest="oauth_tokensecret",
                           help="The token secret")



  optionsParser.add_option("", "--force_signature", action="store", type="string", dest="oauth_signature",
                           help="Force the oauth_signature parameter")

  optionsParser.add_option("", "--force_timestamp", action="store", type="string", dest="oauth_timestamp",
                           help="Force the oauth_timestamp parameter")

  optionsParser.add_option("", "--force_nonce", action="store", type="string", dest="oauth_nonce",
                           help="Force the oauth_nonce parameter")

  optionsParser.add_option("", "--force_version", action="store", type="string", dest="oauth_version",
                           help="Force the oauth_version parameter")


# This function attempts to read the configuration file. If no configuration
# was passed into the program then this function is responsible for setting
# defaults before returning the ConfigParser object
def readConfigurationFile(options):
  
  # Use the configobj 3rd party module
  from configobj import ConfigObj

  # Create a dictionary with default values
  defaultOAuthToolConfiguration =  { 'Global':
                                         { 'LogLevel'  : 'DEBUG',
                                           'ConsoleOutput': 'True'}
                                   }
                                                                
                              
  # Load the defaults into a configuration object
  oAuthToolConfiguration = ConfigObj(defaultOAuthToolConfiguration)
  
  # If the configuration file parameter was given attempt to read the configuration file
  if( options.configfile != None ):
    oAuthToolConfiguration.merge(ConfigObj(options.configfile))
  else:
    print "Warning: No configuration file specified! Run this tool with the -h command."
  
  # Return the entire ConfigParser object
  return oAuthToolConfiguration



# I haven't decided how to implement proxies in this tool. By default urllib2 will
# get the proxy from the http_proxy and https_proxy environment variables. But what
# if you want to override them? The tool should allow you to override the proxy
def configureProxy():

  oAuthToolLogger.debug("Overriding default urllib opener with one that supports HTTPS proxying")
  opener = urllib2.build_opener(ConnectHTTPHandler.ConnectHTTPHandler)
  urllib2.install_opener(opener)

  #proxy_handler = urllib2.ProxyHandler({'http': 'http://username:password@internet.example.com:443',
  #                                      'https': 'http://username:password@internet.example.com:443'})

  #opener = urllib2.build_opener(proxy_handler)
  #urllib2.install_opener(opener)
 


# Prints out a request token given an OAuthRequest object
def getRequestToken(oAuthRequest):
  

  # Determine which HTTP method to use (by default OAuth recommends header based)
  if oAuthRequest.oauth_method == "header":


    # OAuth uses the standard HTTP Authorization: header
    oAuthToolLogger.debug("Forming Authorization header method to submit request")
    oAuthFormattedAuthorizationHeader = oAuthRequest.to_header()
    oAuthToolLogger.debug("Authorization: " + oAuthFormattedAuthorizationHeader['Authorization'])
    

    oAuthToolLogger.debug("Preparing HTTP request")
    request = urllib2.Request(url=oAuthRequest.http_url, headers=oAuthFormattedAuthorizationHeader)


    try:
      oAuthToolLogger.debug("Opening connection to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)


    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

      
  # POST based OAuth
  elif oAuthRequest.oauth_method == "POST":
    oAuthToolLogger.debug("POST formatted data: " + str(oAuthRequest.to_postdata()))

    oAuthToolLogger.debug("Preparing HTTP request")
    request = urllib2.Request(url=oAuthRequest.http_url, data=oAuthRequest.to_postdata())

    try:
      oAuthToolLogger.debug("POSTing to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)

    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

 
  # GET querystring based OAuth
  elif oAuthRequest.oauth_method == "GET":
    oAuthToolLogger.debug("Preparing HTTP GET request")
    oAuthGETUrl = oAuthRequest.to_url()

    oAuthToolLogger.debug("oAuthGETUrl: " + oAuthGETUrl)
    
    request = urllib2.Request(url=oAuthGETUrl)

    try:
      oAuthToolLogger.debug("GET request to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)

    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

    
  # Invalid method
  else:
    oAuthToolLogger.error("Invalid method argument. It should be either header, POST, or GET.")



def getAccessToken(oAuthRequest):
  # Determine which HTTP method to use (by default OAuth recommends header based)
  if oAuthRequest.oauth_method == "header":


    # OAuth uses the standard HTTP Authorization: header
    oAuthToolLogger.debug("Forming Authorization header method to submit request")
    oAuthFormattedAuthorizationHeader = oAuthRequest.to_header()
    oAuthToolLogger.debug("Authorization: " + oAuthFormattedAuthorizationHeader['Authorization'])
    

    oAuthToolLogger.debug("Preparing HTTP request")
    request = urllib2.Request(url=oAuthRequest.http_url, headers=oAuthFormattedAuthorizationHeader)


    try:
      oAuthToolLogger.debug("Opening connection to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)


    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

      
  # POST based OAuth
  elif oAuthRequest.oauth_method == "POST":
    oAuthToolLogger.debug("POST formatted data: " + str(oAuthRequest.to_postdata()))

    oAuthToolLogger.debug("Preparing HTTP request")
    request = urllib2.Request(url=oAuthRequest.http_url, data=oAuthRequest.to_postdata())

    try:
      oAuthToolLogger.debug("POSTing to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)

    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

 
  # GET querystring based OAuth
  elif oAuthRequest.oauth_method == "GET":
    oAuthToolLogger.debug("Preparing HTTP GET request")
    oAuthGETUrl = oAuthRequest.to_url()

    oAuthToolLogger.debug("oAuthGETUrl: " + oAuthGETUrl)
    
    request = urllib2.Request(url=oAuthGETUrl)

    try:
      oAuthToolLogger.debug("GET request to " + str(request.get_full_url()))

      # Open a connection to the server and save the response
      responseObject = urllib2.urlopen(request)

      fullResponse = "\n\n" + str(responseObject.info()) + "\n" + responseObject.read()
      oAuthToolLogger.debug("Server response: " + fullResponse)

    except urllib2.HTTPError, httpError:
      oAuthToolLogger.error(str(httpError))
      oAuthToolLogger.error(httpError.read())
      oAuthToolLogger.error(httpError.info())

    
  # Invalid method
  else:
    oAuthToolLogger.error("Invalid method argument. It should be either header, POST, or GET.")

  
  
  
  
  


def authorizeToken(commandLineOptions, commandArguments):
  pass






# Creates an OAuthRequest object based on command line options and returns the object
def createOAuthRequest(commandLineOptions, commandArguments):

  # Create an empty request object
  oAuthRequest = oauth.OAuthRequest()
    
  # Store the oauth_method to be used
  oAuthRequest.oauth_method = commandLineOptions.oauth_method

  # Set the HTTP method to use (this instance variable is used as part of the base signature string)
  if ( commandLineOptions.oauth_method == "header" or commandLineOptions.oauth_method == "GET" ):
    oAuthRequest.http_method = "GET"
  else:
    oAuthRequest.http_method = "POST"


  # Set the URL end point
  if( len(commandArguments) == 1):
    oAuthRequest.http_url = commandArguments[0]
  else:
    oAuthToolLogger.error("Error: Final command line argument must be a URL endpoint")
    sys.exit(1)


  # Create an OAuth consumer object and store it in the oAuthRequest object 
  oAuthRequest.consumer = oauth.OAuthConsumer(key = commandLineOptions.oauth_consumer_key, secret = commandLineOptions.oauth_consumer_secret)


  # Create an OAuthToken object
  if( commandLineOptions.oauth_tokenkey != None and commandLineOptions.oauth_tokensecret != None):
    oAuthRequest.token = oauth.OAuthToken(key = commandLineOptions.oauth_tokenkey, secret = commandLineOptions.oauth_tokensecret)
  else:
    oAuthRequest.token = None

  
  # Clear out the oAuthRequest's parameters dictionary and populate it manually
  oAuthRequest.parameters = {}    
  oAuthRequest.parameters['oauth_consumer_key'] = oAuthRequest.consumer.key
  oAuthRequest.parameters['oauth_version'] = '1.0'


  # Use a specific timestamp if given
  if ( commandLineOptions.oauth_timestamp != None ):
    oAuthRequest.parameters['oauth_timestamp'] = commandLineOptions.oauth_timestamp
  else:
    oAuthRequest.parameters['oauth_timestamp'] = calendar.timegm(time.gmtime(time.time()))

  # Use a specific nonce if given  
  if ( commandLineOptions.oauth_nonce != None ):
    oAuthRequest.parameters['oauth_nonce'] = commandLineOptions.oauth_nonce
  else:
    oAuthRequest.parameters['oauth_nonce'] = hashlib.sha224(str(oAuthRequest.parameters['oauth_timestamp'])).hexdigest()  


  if ( commandLineOptions.oauth_callback != None ):
    oAuthRequest.parameters['oauth_callback'] = commandLineOptions.oauth_callback
  
  
  # The token parameter is only used in certain instances
  if ( oAuthRequest.token != None ):
    oAuthRequest.parameters['oauth_token'] = oAuthRequest.token.key


  # Determine which signature method to use
  if ( commandLineOptions.oauth_signature_method == "HMAC-SHA1"):
    signatureMethod = oauth.OAuthSignatureMethod_HMAC_SHA1()
  elif ( commandLineOptions.oauth_signature_method == "RSA-SHA1"):
    pass
  elif ( commandLineOptions.oauth_signature_method == "PLAINTEXT"):
    signatureMethod = oauth.OAuthSignatureMethod_PLAINTEXT()
  else:
    oAuthToolLogger.error("Unknown signature method. Please specify one of HMAC-SHA1, RSA-SHA1, or PLAINTEXT")
    sys.exit("Unknown signature method. Please specify one of HMAC-SHA1, RSA-SHA1, or PLAINTEXT")

  # Calculate the signature (this will store it in oauth_signature)
  oAuthRequest.sign_request(signatureMethod, oAuthRequest.consumer, oAuthRequest.token)
  oAuthToolLogger.debug("Calculated signature: " + str(oAuthRequest.parameters['oauth_signature']))

  return oAuthRequest
  
  

# Starting point of the command line tool
def main():
  
  # Load the available command line options
  loadCommandLineOptions()
  
  # Parse the command line options
  (commandLineOptions, commandArguments) = optionsParser.parse_args()
    
  # Read the configuration file
  oAuthToolConfiguration = readConfigurationFile(commandLineOptions)
        
  # Setup the logging that will be used for the rest of the program
  setupLogging(oAuthToolConfiguration)

  oAuthToolLogger.debug("Command line options: " + str(commandLineOptions))
  oAuthToolLogger.debug("Command line arguments: " + str(commandArguments))
  oAuthToolLogger.debug("oAuthToolConfiguration: " + str(oAuthToolConfiguration))

  # Configure proxy settings (uncomment if using a proxy)
  # configureProxy()



  # Execute function based on what OAuth action was specified
  if (commandLineOptions.oauth_action == 'getRequestToken'):
  
    oAuthRequest = createOAuthRequest(commandLineOptions, commandArguments)      
    oAuthToolLogger.debug("Calling getRequestToken()")
    getRequestToken(oAuthRequest)

  elif (commandLineOptions.oauth_action == 'getAccessToken'):
  
    if( commandLineOptions.oauth_consumer_secret == None ):
      oAuthToolLogger.error("No consumer secret found. Specify one using --consumersecret")
      sys.exit(1)
    
    oAuthRequest = createOAuthRequest(commandLineOptions, commandArguments)  
    oAuthToolLogger.debug("Calling getAccessToken()")
    getAccessToken(oAuthRequest)

  elif (commandLineOptions.oauth_action == 'authorizeToken'):
    oAuthToolLogger.debug("Calling authorizeToken()")
    authorizeToken(commandLineOptions, commandArguments)


  else:
    oAuthToolLogger.error("Invalid OAuth action specified. Please specify a valid action using --action")
    oAuthToolLogger.error("Valid actions are getRequestToken, getAccessToken, authorizeToken")
    

 
if __name__ == '__main__':
    main()















