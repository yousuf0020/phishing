#!/usr/bin/env python2
"""PhishThis

A Python script that connects to Gmail in IMAP's IDLE mode and forwards test phishing emails back to InfoSec.

Requirements:
    Python 2.5 or greater
    OpenSSL 0.9.8j or greater
    
Usage: python phishthis.py [options]

Options:
    -h, --help                Show this help
    -u ..., --username=...    Gmail username
    -p ..., --password=...    Gmail password
    -l ..., --location=...    Location of openssl
    -f ..., --forward=...     Address to forward phish tests to
    
Example:
    python phishthis.py
    python phishthis.py -u <YOUR_GMAIL_USERNAME> -p <YOUR_GMAIL_PASSWORD>
"""

import base64
import cgi
import email
import getopt
import getpass
import hashlib
import os
import signal
import smtplib
import subprocess
import sys
import threading
import time
import urllib2

# Gmail user name
username = ""
# Gmail password
password = ""
# FwdTo Address
forwardAddr = ""
# openssl location
openssl = "/usr/bin/openssl"
# IMAP connection command
cmd = [openssl, "s_client", "-connect", "imap.gmail.com:993", "-crlf"]
# Connection restart interval
# 15 minutes in seconds
timeOutInterval = 900
# Previous email's ID
previousId = ""

# API key from https://keyvalue.immanuel.co/
# used as a datastore for the exponential forwarding
kvApiKey = "drrgmto0"
datastoreKey = ""
kvUrlBase = "https://keyvalue.immanuel.co/api/KeyVal"

class GmailIdleNotifier:
    def __init__(self):
        self.p = None
        self.timer = None
        self.checkClient()
        self.checkConnection()
        
        if(len(username) == 0):
            self.getGmailUserName()
            
        if(len(password) == 0):
            self.getGmailPassword()
            
        self.checkGmailCredentials()
    
    def checkClient(self):
        """Determines if the OpenSSL path is valid."""
        global openssl
        
        if(not os.path.isfile(openssl)):
            print "The OpenSSL path is not valid."
            sys.exit(1)
    
    def checkConnection(self):
        """Determines if the system has an Internet connection available."""
        try:
            urllib2.urlopen("http://www.google.com")
        except:
            print "An Internet connection is not available."
            sys.exit(1)
        
    def getGmailUserName(self):
        """Get the user's Gmail username."""
        global username
        username = raw_input("Gmail User Name: ")
        
    def getGmailPassword(self):
        """Get the user's Gmail password."""
        global password
        password = getpass.getpass("Gmail Password: ")
        
    def checkGmailCredentials(self):
        """Prompt the user and verify their Gmail credentials."""
        global username, password
        
        loop = True
        while(loop):
            global cmd
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            line = p.stdout.readline()
            while(line != None):
                # Input the credentials
                if("* OK Gimap ready" in line):
                    p.stdin.write(". login %s %s\n" % (username, password))
                # Credentials are valid
                elif("authenticated (Success)" in line):
                    print "Successful authentication..."
                    loop = False
                    break
                elif("Invalid credentials" in line):
                    print "The Gmail username or password entered is invalid."
                    print "Please re-enter the Gmail username and password."
                    self.getGmailUserName()
                    self.getGmailPassword()
                    break
                
                line = p.stdout.readline()
            
            # Kill the subprocess
            os.kill(p.pid, signal.SIGTERM)

    def fetchCurrentFwdCount(self):
        global kvUrlBase, kvApiKey, datastoreKey
        get = "GetValue"
        post = "UpdateValue"
        default = "0"

        return int(urllib2.urlopen('/'.join([kvUrlBase, get, kvApiKey, datastoreKey])).read().replace('"', '') \
        or urllib2.urlopen('/'.join([kvUrlBase, post, kvApiKey, datastoreKey, default]), data="").read().replace('true', default))

    def incrementFwdCount(self):
        global kvUrlBase, kvApiKey, datastoreKey
        put = "ActOnValue"
        increment = "Increment"

        urllib2.urlopen('/'.join([kvUrlBase, put, kvApiKey, datastoreKey, increment]), data="")
    
    def start(self):
        """Log into the Google IMAP server and enable IDLE mode."""
        global cmd

        # Start the timer to keep alive the OpenSSL subprocess
        self.timer = threading.Timer(timeOutInterval, self.keepAlive)
        self.timer.start()
        
        # Start the openssl process
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
        idleMode = False
        global username, password, previousId
        line = self.p.stdout.readline()
        while(line != ""):
            # Input the credentials
            if("* OK Gimap ready" in line):
                self.p.stdin.write(". login %s %s\n" % (username, password))
            # Select the INBOX
            elif("authenticated (Success)" in line):
                self.p.stdin.write(". examine INBOX\n")
            # Invalid command line credentials
            elif("Invalid credentials" in line):
                print "Invalid Gmail credentials..."
                sys.exit(1)
            # Start IDLE mode
            elif("INBOX selected. (Success)" in line):
                self.p.stdin.write(". idle\n")
                idleMode = True
            # If IDLE mode is True and the email ID was not
            # previously sent, send a Prowl message
            elif(idleMode and "EXISTS" in line):
                emailId = line.split(" ")[1]
                
                if(emailId not in previousId):
                    previousId = emailId
                    self.fetchEmail(emailId)
                    
            
            line = self.p.stdout.readline()
                    
    def keepAlive(self):
        """Keep the connection from timing out by toggling
        IDLE mode on/off."""
        self.p.stdin.write("DONE\n")
        self.p.stdin.write(". idle\n")
        
        self.timer = threading.Timer(timeOutInterval, self.keepAlive)
        self.timer.start()
        
    def stop(self):
        """Kill the timer thread."""
        self.timer.cancel()
        os.kill(self.p.pid, signal.SIGTERM)
          
    def fetchEmail(self, emailId):
        """Grab the email's information and forward if a phishing message."""
        global cmd
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        imAPhish = False
        rawMsg = fakeAddr = ''
        global username, password, forwardAddr
        line = p.stdout.readline()
        while(line != None):
            # Input credentials
            if("* OK Gimap ready" in line):
                p.stdin.write(". login %s %s\n" % (username, password))
            # Select the INBOX
            elif("authenticated (Success)" in line):
                p.stdin.write(". examine INBOX\n")
            # Make sure the e-mail has a phish header.
            elif("INBOX selected. (Success)" in line):
                p.stdin.write(". fetch %s (body[header.fields (x-phishtest from)])\n" % emailId)
                line = p.stdout.readline()
                while(". OK Success" not in line):
                    if("X-PHISHTEST" in line):
                        imAPhish = True
                    if("From:" in line):
                        fakeAddr = line.split("From:",1)[1].rstrip()
                    line = p.stdout.readline()
                if(imAPhish):
                    print "A new phishing email has been detected from: " + fakeAddr + " @ " + time.strftime("%m-%d-%Y %H:%M:%S %Z")
                else:
                    print "A non-phish event @ " + time.strftime("%m-%d-%Y %H:%M:%S %Z")
                    break
            # Extract the email information
            elif(imAPhish):         
                print "Fetching the phish..."
                p.stdin.write(". fetch %s (body[])\n" % emailId)
                emailInfo = p.stdout.readline()
                captureBody = False
                while(". OK Success" not in emailInfo):
                    if(captureBody):
                        rawMsg += emailInfo
                    
                    if("BODY[]" in emailInfo):
                        captureBody = True
                    
                    emailInfo = p.stdout.readline()

                # Move the phish to the trash
                p.stdin.write(". move %s [Gmail]/Trash\n" % emailId)
                while "EXPUNGE" not in p.stdout.readline():
                  continue

                break
            if(". OK Success" not in line):
                line = p.stdout.readline()
        
        # Kill the subprocess
        os.kill(p.pid, signal.SIGTERM)
           
        if(imAPhish):
            fwdMsg = self.buildFwdMessage(rawMsg.rstrip().rstrip(')'))
            self.fwdToSuspicious(fwdMsg, forwardAddr)    

    def removeEmailAddress(self, email):
        """Removes the email address from the FROM field."""
        pos = email.find(" <")
        
        return email[:pos].replace('\"', '')

    def buildFwdMessage(self, body):
        """Insert Forward Header at the top of each payload in the body"""
        header = subject = ''
        msg = email.message_from_string(body)
        subject = msg['Subject']
        payload = msg.get_payload()

        if type(payload) is not list:
            fwdPayload = self.attachFwdHeaderToBody(msg)
            msg.set_payload(fwdPayload)
        else:
          for i,part in enumerate(payload):
              fwdPayload = self.attachFwdHeaderToBody(part)
              msg.get_payload()[i].set_payload(fwdPayload)
        
        for k,v in msg.items():
            if k not in ('Content-Type', 'Content-Transfer-Encoding'):
                del msg[k]
        msg['Subject'] = "Fwd: " + subject
        return msg

    def attachFwdHeaderToBody(self, msg):
        header = self.buildFwdMsgHeader(msg, msg.get_content_subtype())
        return base64.b64encode(header + msg.get_payload(decode=True)) if msg['Content-Transfer-Encoding'] == 'base64' else header + msg.get_payload()

    def buildFwdMsgHeader(self, msg, contentType):
        """Build standard forwarded msg headers and add Fwd: to subject"""
        s = '<br>' if contentType == 'html' else '\n'
        toAddr = fromAddr = date = subject = ''
        fwdHeader = "---------- Forwarded message ----------"
        toAddr = "To: " + msg['To']
        fromAddr = "From: " + msg['From']
        date = "Date: " + msg['Date']
        subject = "Subject: " + msg['Subject']
        def e(s):
            return cgi.escape(s) if contentType == 'html' else s
        return s + e(fwdHeader) + s + e(fromAddr) + s + e(date) + s + e(subject) + s + e(toAddr) + s + s

    def fwdToSuspicious(self, msg, address):
        """Forward phishing email to provided address"""
        global username, password
        count = 2**self.fetchCurrentFwdCount()
        print "Forwarding to: " + address + ", " + str(count) + " times"

        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo()
        server.starttls()
        server.login(username, password)
        for _ in range(count):
          server.sendmail(username, address, msg.as_string())
          # Don't try to send the email TOO fast
          time.sleep(1)
        server.quit()
        self.incrementFwdCount()

def usage():
    """Prints the usage."""
    print __doc__
    
def main(argv):
    """Parses the arguments and starts the program."""
    
    global username, password, openssl, forwardAddr, datastoreKey
    
    try:
        opts, args = getopt.getopt(argv, "hl:u:p:f:", ["help","location=","username=","password=","forward="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-l", "--location"):
            openssl = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-f", "--forward"):
            forwardAddr = arg
            
    print "Starting Phishing Detector..."
    phisher = GmailIdleNotifier()
    # Create user unique key to store/retrieve count values
    datastoreKey = hashlib.sha256(username + password).hexdigest()
    try:
        phisher.start()
    except KeyboardInterrupt:
        print "\nStopping PhishThis..."
        phisher.stop()
        sys.exit(0)   
    
if __name__ == "__main__":
    main(sys.argv[1:])
