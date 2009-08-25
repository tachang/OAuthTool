import urllib2
import urllib
import httplib
import socket
import ssl
import sys
import base64


class ConnectBasedProxyHTTPConnection(httplib.HTTPConnection):
  
  # Variable to store the protocol being requested
  protocol = None

  # Initialization
  def __init__(self, host, port=None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, ):
    print host
    httplib.HTTPConnection.__init__(self, host, port)

  def request(self, method, url, body=None, headers={}):

    # Dissect the url to determine the protocol. Store it in the instance variable.
    self.protocol, stuffAfterProtocol = urllib.splittype(url)

    # Check to make sure we got some kind of protocol
    if self.protocol is None:
      raise ValueError, "Unknown protocol type in " + url

    # Parse out the host from the URL resource. host should be something like www.example.com or www.example.com:8888
    # and resourceString should be something like /example.html
    host, resourceString = urllib.splithost(stuffAfterProtocol)
    
    # Parse out the port from the host
    host, port = urllib.splitport(host)

    # It is possible that port is not defined. In that case we go by the protocol
    if port is None:
      # List of common protocol to port mappings
      protocolToPortMapping = {'http' : 80, 'https' : 443}

      # Check if the protocol is in the list
      if self.protocol in protocolToPortMapping:
        protocolToPortMapping[self.protocol]
        self._real_port = protocolToPortMapping[self.protocol]
      else:
        raise ValueError, "Unknown port for protocol " + str(self.protocol)
    else:
      self._real_port = port
    
    self._real_host = host

    httplib.HTTPConnection.request(self, method, url, body, headers)




  def connect(self):
    # Call the connect() method of httplib.HTTPConnection
    httplib.HTTPConnection.connect(self)

    # At this point I am connected to the proxy server so I can send the CONNECT request
    connectCommand = "CONNECT " + str(self._real_host) + ":" + str(self._real_port) + " HTTP/1.0\r\n\r\n"
    self.send(connectCommand)

    # Expect a HTTP/1.0 200 Connection established
    response = self.response_class(self.sock, strict=self.strict, method=self._method)
    (version, code, message) = response._read_status()

    # Probably here we can handle auth requests...

    # 407 Proxy Authentication Required
    if (code == 407):
      # Obtain the list of proxies using a call to urllib.getproxies()
      proxyDictionary = urllib.getproxies()
      
      # Base the proxy string on what protocol was requested
      desiredProxy = proxyDictionary[self.protocol]

      # Parse out the proxy string for the username and password  
      proxy_type, user, password, hostport = urllib2._parse_proxy(desiredProxy)

      proxyAuthorizationString = 'Proxy-Authorization: Basic %s\r\n\r\n' % base64.b64encode('%s:%s' % (user, password))

      connectCommand = "CONNECT " + str(self._real_host) + ":" + str(self._real_port) + " HTTP/1.0\r\n"
      httplib.HTTPConnection.connect(self)
      self.send(connectCommand)
      self.send(proxyAuthorizationString)

    # Proxy returned something other than 407 or 200
    elif (code != 200):   
      self.close()
      raise socket.error, "Proxy connection failed: %d %s" % (code, message.strip())

    # Eat up header block from proxy....
    while True:
      # Note to investigate using "fp" directly and performing a readline().
      line = response.fp.readline()
      if line == '\r\n': break

    # Determine if we are trying to do an SSL connection. If we are
    # we need to make sure we do the SSL handshake
    if (self.protocol == 'https'):
      newSSLSocket = ssl.wrap_socket(self.sock, keyfile=None, certfile=None)
      self.sock = newSSLSocket



# ConnectHTTPHandler class that does multiple inheritance                                
# This will override both urllib2.HTTPHandler and urllib2.HTTPSHandler
class ConnectHTTPHandler(urllib2.HTTPHandler, urllib2.HTTPSHandler):

 # This method returns a urllib.addinfourl object. The "addinfourl" object contains headers, an http return code
 # the url, and a socket reference
 def do_open(self, http_class, req):

   # The response object returned is of type urllib.addinfourl
   responseObject = urllib2.HTTPHandler.do_open(self, ConnectBasedProxyHTTPConnection, req)
   return responseObject





if __name__ == '__main__':

  opener = urllib2.build_opener(ConnectHTTPHandler)
  urllib2.install_opener(opener)
  req = urllib2.Request(url='https://login.yahoo.com/config/mail?.intl=us')
  #req = urllib2.Request(url='http://www.bing.com/')
  f = urllib2.urlopen(req)
  print f.read()


