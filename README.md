# SAM-DetectEC2CredExfil
SAM Application to detect and alert on AWS EC2 Metadata Credential exfiltartion, written by Scott Pack

Background:  EC2 Instances with assigned roles retreive temporary credentials via the metadata service, which is served at 169.254.169.254.  An attacker may, via interactive host access or a SSRF web-application vulnerability, use the EC2 instance as a proxy to the metadata service.  From there the credentials can be retrieved (IE: curl 169.254.169.254/latest/meta-data/iam/security-credentials/<role-name> and use AWS API access to pivot into other parts of the environment.
  
This SAM Application performs stateful analysis of CloudTrail, identifying calls from an EC2 AssumedRole that come from a source other than the first one to be seen after each instance assumed the role.  It does this by storing session info for each AssumeRole call into DynamoDB, saving the first SourceIP seen, and checking every future call against the saved session.

Suspicious activity is written to a CloudWatchLogs group "EC2ExfiltrationLogsGroup"
You probably want to set up an ingest from this CWL group to your SIEM, and create a alert for any events arriving.

EKS/Kubernetes clusters are a common false positive, as kubelets proxy access to the metadata service between each other.
You can create an entry in the "Exceptions" dynamodb table with the subnets your kubernetes workers are in to suppress this case, or any others where you know that credentials will be used from places other than the instance that assumed the role.

Many thanks to Will Bengston, who presented basically everything but the code at BH2018.
....Seriously, no point in me creating an architecture diagram.  Look at Slides 26 & 27.
https://www.peerlyst.com/posts/blackhat-2018-detecting-credential-compromise-in-aws-william-bengtson-lorgor77

Prerequisite: You already need to be collecting CloudTrail into an S3 bucket.
You must create an SNS Topic as an event on the bucket for all ObjectCreate calls.
A tutorial on setting up permissions for that can be found in Step 1 and Step 3 here:
https://docs.aws.amazon.com/AmazonS3/latest/dev/ways-to-add-notification-config-to-bucket.html

Note: This works equally as well on multiple accounts, so if you have bunches of accounts all sending to one S3 bucket, you just need to run this in your CloudTrail aggregation account, not each account individually.  
