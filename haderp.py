from twisted.internet import reactor
from twisted.internet import protocol
import pickle
import base64
import traceback
import logging

logger = logging.getLogger('fickle')
logging.basicConfig(filename="/tmp/haderp.log",filemode="a+")
logger.setLevel(logging.INFO)

class Haderper(protocol.Protocol):
    def dataReceived(self, data):
        logger.info("[*] Rcvd (%s:%s): %s" % (self.transport.getPeer().host, self.transport.getPeer().port, data))
        print "[*] Rcvd (%s:%s): %s" % (self.transport.getPeer().host, self.transport.getPeer().port, data)
        result = checkCommand(data.strip())
        if result == "exit":
            self.closed()
        else:
            self.transport.write(result + "\n> ")
            logger.info("[*] Sent (%s:%s): %s" % (self.transport.getPeer().host, self.transport.getPeer().port, result))
            print "[*] Sent (%s:%s): %s" % (self.transport.getPeer().host, self.transport.getPeer().port, result)

    def connectionMade(self):
        logger.info("[*] Connection from: %s:%s" % (self.transport.getPeer().host, self.transport.getPeer().port))
        print "[*] Connection from: %s:%s" % (self.transport.getPeer().host, self.transport.getPeer().port)
        self.transport.write("""
-----------------------------
| Welcome to Haderper!      |
| Please enter your command |
-----------------------------
> """)

    def closed(self):
        self.transport.write("Exiting...\n")
        self.transport.loseConnection()

def checkCommand(command):
    if command == 'help':
        result = """
Haderper v0.1-alpha

Command help:

help        - this screen
exec        - execute a command    
derp        - derp a string
underp      - underp a string
logout/exit - disconnect
"""
        return result
    elif command.split(" ")[0] == "exec":
        result = "Insufficient permissions"
        return result
    elif command.split(" ")[0] == "derp":
        try:
            derped = derper(command.split(" ")[1])
            return derped
        except:
            result = "Error: plaintext string not supplied"
            return result
    elif command.split(" ")[0] == "underp":
        try:
            underped = underper(command.split(" ")[1])
            return underped
        except IndexError:
            result = "Error: derped string not supplied"
            return result
        except:
            tb = traceback.format_exc()
            return tb
    elif command.split(" ")[0] == "logout" or command.split(" ")[0] == "exit":
            result = "exit"
            return result
    else:
        result = "Unknown command."
        return result

def derper(string):
    derped = pickle.dumps(string)
    print base64.b64encode(derped)
    return base64.b64encode(derped)

def underper(stream):
    underped = pickle.loads(base64.b64decode(stream))
    return underped

def main():
    factory = protocol.ServerFactory()
    factory.protocol = Haderper
    reactor.listenTCP(8000,factory)
    print "[*] Listening on 8000/tcp"
    logger.info("[*] Listening on 8000/tcp")
    reactor.run()

if __name__ == '__main__':
    main()
