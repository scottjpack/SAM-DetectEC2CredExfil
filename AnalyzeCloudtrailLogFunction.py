import os
import boto3
import json
import time
from boto3.dynamodb.conditions import Key, Attr
import StringIO
import gzip
import random
import socket,struct

# 337902548806_CloudTrail_us-east-1_20190322T0500Z_auiiBXjcCAI9OYst.json.gz

# Set up table resources from the env vars.
assumedRoleStateTableName = os.environ['assumedRoleStateTableName']
roleExceptionsTableName = os.environ['roleExceptionsTableName']
exfilAlertLogGroup = os.environ['exfilAlertLogGroup']
dydbResource = boto3.resource("dynamodb")
sessionsTable = dydbResource.Table(assumedRoleStateTableName)
exceptionsTable = dydbResource.Table(roleExceptionsTableName)



""" Thanks StackExchange for helping me avoid creating a deployment package!"""
""" https://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python"""
def addressInNetwork(ip,net):
    ipaddr = struct.unpack('>L',socket.inet_aton(ip))[0]
    netaddr,bits = net.split('/')
    netmask = struct.unpack('>L',socket.inet_aton(netaddr))[0]
    ipaddr_masked = ipaddr & (4294967295<<(32-int(bits)))   # Logical AND of IP address and mask will equal the network address if it matches
    if netmask == netmask & (4294967295<<(32-int(bits))):   # Validate network address is valid for mask
        return ipaddr_masked == netmask
    else:
        print "***WARNING*** Network",netaddr,"not valid with mask /"+bits
        return ipaddr_masked == netmask


def isWhitelisted(RoleArn, SourceIp):
    roleWhitelistResponse = exceptionsTable.get_item(
        Key={
            'roleArn': RoleArn,
        }
    )
    if "Item" not in roleWhitelistResponse.keys():
        # No whitelist configured for this role
        return False
    whitelistResponse = roleWhitelistResponse['Item']
    whitelist = whitelistResponse['whitelist']
    for net in whitelist:
        if addressInNetwork(str(SourceIp), str(net)):
            # print "%s would have fired an alert, but is in the whitelist %s" % (SourceIp, net)
            return True
    return False

def retrieveJsonBodyFromS3(obj):
    """
        Given a tuple (bucketname, key)
        Create an S3 client, retrieve the contents
        Unzip the body, and return as a python object
    """
    s3Client = boto3.client("s3")
    s3_file = s3Client.get_object(
        Bucket=obj[0], 
        Key=obj[1]
    )
    body = s3_file['Body']
    compressedFile = StringIO.StringIO(body.read())
    decompressedFile = gzip.GzipFile(fileobj=compressedFile)
    jsonBody = json.loads(decompressedFile.read())
    return jsonBody



def createSessionState(RoleArn, SessionId, SourceIp="0"):
    # Set ttl 6 hours in the future
    print "Creating initial session state for %s" % RoleArn
    ttl = int(time.time() + 6 * 60 * 60)
    item = {
        "sessionId": SessionId,
        "sourceIp": SourceIp,
        "roleArn": RoleArn,
        "ttl": ttl
    }
    resp = sessionsTable.put_item(
        Item=item
    )

def recordSuspiciousEvent(event):
    cwClient = boto3.client("logs")
    logStreamName = ''.join(random.choice('0123456789ABCDEF') for i in range(16))

    t = int(round(time.time() * 1000))
    logEvent = {
        "timestamp": t,
        "message": event
    }
    cwClient.create_log_stream(
        logGroupName = exfilAlertLogGroup,
        logStreamName = logStreamName
    )
    cwClient.put_log_events(
        logGroupName = exfilAlertLogGroup,
        logStreamName = logStreamName,
        logEvents = [logEvent]
        )
    print "Wrote suspicious event to %s" % logStreamName

def analyzeNonAssumeRecord(SessionId, SourceIp):
    """
    Check CloudTrail events originating from assumed roles.
    If no SourceIP has been previously recorded for the session, record it.
    If the SourceIP doesn't match a previously recorded one...
    We may have a credential exfil, return info on the session to be used in an alert body.
    """
    if not SessionId.startswith("i-"):
        # Not an EC2 assumed role session
        return

    sessionResponse = sessionsTable.get_item(
        Key={
            'sessionId': SessionId,
        }
    )
    if "Item" not in sessionResponse.keys():
        # No recorded session found for this session.
        # Was Exfil detections started less than 6 hours ago?
        print "No session found for %s (%s)" % (SessionId, SourceIp)
        pass
    else:
        session = sessionResponse['Item']
        roleArn = session['roleArn']
        previousSourceIp = session['sourceIp']
        if previousSourceIp == "0":
            # First time seeing this session used since created.
            # Record the source IP
            print "Recording IP for existing session"
            createSessionState(roleArn, SessionId, SourceIp)
            return
        elif previousSourceIp == SourceIp:
            print "Identified activity from AssumedRole with the same as previously identified IP (%s)" % previousSourceIp
            return
        else:
            print "Suspicious behavior here.  Send back the original session info"
            return {"roleArn": roleArn, "sourceIp": previousSourceIp}


def assessCloudtrailEventRecord(event):
    # Identify EC2 AssumeRoles and record new sessions or inspect calls made by AssumedRoles
    # TODO: Store VPC Endpoint ID if relevant
    
    if (event['eventName'] == "AssumeRole" and 
            event['sourceIPAddress'] == "ec2.amazonaws.com" and
            event['eventSource'] == "sts.amazonaws.com"):
        # Fresh EC2 AssumeRole
        # Record the session
        sessionId = event['requestParameters']['roleSessionName']
        roleArn = event['requestParameters']['roleArn']
        createSessionState(roleArn, sessionId)
    elif event['userIdentity']['type'] == "AssumedRole":
        sessionId = event['userIdentity']['arn'].split('/')[-1]
        sourceIp = event['sourceIPAddress']
        violation = analyzeNonAssumeRecord(sessionId, sourceIp)
        if violation is not None:
            # TODO: Check the exceptions table
            if not isWhitelisted(violation['roleArn'], sourceIp):
                alert = {}
                alert['originalSessionInfo'] = violation
                alert['potentialImposterSourceIp'] = sourceIp
                alert['alertMessage'] = "EC2 credentials previously associated with an IP have been used from a source other than the original.  This is indicative of instance compromise and credential exfiltration."
                message = json.dumps(alert)
                recordSuspiciousEvent(message)



def extract_s3file_from_sns_event(event):
    """ 
        Unwrap S3 Records from SNS Records
        Return a list of tuples (bucketname, key)
    """

    s3Files = []
    for snsRecord in event['Records']:
        s3Body = json.loads(snsRecord['Sns']['Message'])
        for s3Record in s3Body['Records']:
            bucketName = s3Record['s3']['bucket']['name']
            key = s3Record['s3']['object']['key']
            s3Files.append((bucketName, key))
    return s3Files

def lambda_handler(event, context):
    cloudtrailFiles = extract_s3file_from_sns_event(event)
    for cloudtrailFile in cloudtrailFiles:
        if not "CloudTrail-Digest" in cloudtrailFile[1]:
            # Don't run digests through the assessment.
            print "Collecting and assessing %s" % cloudtrailFile[1]
            cloudtrailBody = retrieveJsonBodyFromS3(cloudtrailFile)
            for cloudtrailEvent in cloudtrailBody['Records']:
                alerts = assessCloudtrailEventRecord(
                    cloudtrailEvent
                    )
