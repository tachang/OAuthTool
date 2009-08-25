import urllib2
import urllib
import httplib
import socket
import ssl
import sys

class ProxyHTTPConnection(httplib.HTTPConnection):

  _ports = {'http' : 80, 'https' : 443}

  # The request() method is called first. This allows us to determine what kind of protocol
  # we are dealing with before the connection actually happens
  def request(self, method, url, body=None, headers={}):
    proto, rest = urllib.splittype(url)
    if proto is None:
      raise ValueError, "unknown URL type: %s" % url
    #get host
    host, rest = urllib.splithost(rest)
    #try to get port
    host, port = urllib.splitport(host)
    #if port is not defined try to get from proto
    if port is None:
      try:
        port = self._ports[proto]
      except KeyError:
        raise ValueError, "unknown protocol for: %s" % url
    self._real_host = host
    self._real_port = port
    httplib.HTTPConnection.request(self, method, url, body, headers)
        
  # The connect() method is called after the request() method
  def connect(self):
    httplib.HTTPConnection.connect(self)
    #send proxy CONNECT request
    self.send("CONNECT %s:%d HTTP/1.0\r\n\r\n" % (self._real_host, self._real_port))
    #expect a HTTP/1.0 200 Connection established
    response = self.response_class(self.sock, strict=self.strict, method=self._method)
    (version, code, message) = response._read_status()
    #probably here we can handle auth requests...
    if code != 200:
        #proxy returned and error, abort connection, and raise exception
        self.close()
        raise socket.error, "Proxy connection failed: %d %s" % (code, message.strip())
    #eat up header block from proxy....
    while True:
      # Note to investigate using "fp" directly and performing a readline().
      line = response.fp.readline()
      if line == '\r\n': break


class ProxyHTTPSConnection(ProxyHTTPConnection):
    
    default_port = 443

    def __init__(self, host, port = None, key_file = None, cert_file = None, strict = None, timeout=None):
        ProxyHTTPConnection.__init__(self, host, port)
        self.key_file = key_file
        self.cert_file = cert_file
    
    def connect(self):
        ProxyHTTPConnection.connect(self)
        #make the sock ssl-aware
        newsocket = ssl.wrap_socket(self.sock, self.key_file, self.cert_file)
        self.sock = newsocket
        
                                       
class ConnectHTTPHandler(urllib2.HTTPHandler):
 def do_open(self, http_class, req):
   return urllib2.HTTPHandler.do_open(self, ProxyHTTPSConnection, req)


class ConnectHTTPSHandler(urllib2.HTTPSHandler):

    def do_open(self, http_class, req):
        return urllib2.HTTPSHandler.do_open(self, ProxyHTTPSConnection, req)



if __name__ == '__main__':
  # This program is more of a study into how urllib2 works

  # After importing urllib2 printing it out simply yields the module's location
  print "Module location: " + str(urllib2)
  
  # Initially urllib2 has no opener. We verify this by printing it out
  print "urllib2._opener: " + str(urllib2._opener)

  # The reason urllib2 has no opener is because we have not initiated a urlopen.
  # The source of urllib2.py has this in the urlopen function:
  # 
  # if _opener is None:
  #   _opener = build_opener()
  #
  # Lets go ahead and do this manually so we can poke a bit
  urllib2._opener = urllib2.build_opener()
  
  # We now have an instance of the OpenerDirector object. Printing it out doesn't
  # really yield anything too interesting
  print urllib2._opener

  # Digging a bit deeper lets see all the default handlers that were installed
  print "List of urllib2 default handlers: "
  for handler in urllib2._opener.handlers:
    print handler
  
  # List of urllib2 default handlers:
  #
  # <urllib2.ProxyHandler instance at 0xb7db16ac>
  # <urllib2.UnknownHandler instance at 0xb7db884c>
  # <urllib2.HTTPHandler instance at 0xb7db894c>
  # <urllib2.HTTPDefaultErrorHandler instance at 0xb7db852c>
  # <urllib2.HTTPRedirectHandler instance at 0x86a1d4c>
  # <urllib2.FTPHandler instance at 0x86a818c>
  # <urllib2.FileHandler instance at 0x86a820c>
  # <urllib2.HTTPSHandler instance at 0x86ade2c>
  # <urllib2.HTTPErrorProcessor instance at 0x86a1ccc>


  # What we need to do is replace the 


  # Handlers raise an exception if no one else should try to handle
  # the request, or return None if they can't but another handler
  # could.  Otherwise, they return the response.


  # OpenerDirector instance
  #urllib2._opener = urllib2.build_opener()

  # opener = urllib2.build_opener(ConnectHTTPHandler, ConnectHTTPSHandler)

  # urllib2.install_opener(opener)
  # req = urllib2.Request(url='https://login.yahoo.com/config/mail?.intl=us')
  # req.set_proxy('localhost:8888', 'https')
  # f = urllib2.urlopen(req)
  # print f.read()


