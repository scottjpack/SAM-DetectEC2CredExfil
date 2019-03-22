# SAM-DetectEC2CredExfil
SAM Application to detect and alert on AWS EC2 Metadata Credential exfiltartion


  SAM Application for detecting EC2 Credential Compromise.
  Written by Scott Pack.
  Many thanks to Will Bengston, who presented basically everything but the code at BH2018
  ....Seriously, no point in me creating an architecture diagram.  Look at Slides 26 & 27.
  https://www.peerlyst.com/posts/blackhat-2018-detecting-credential-compromise-in-aws-william-bengtson-lorgor77

  The intent here is that you already are aggregating your CloudTrail into an S3 bucket.
  You must create an SNS Topic as an event on the bucket for all ObjectCreate calls.
  A tutorial on setting up permissions for that can be found in Step 1 and Step 3 here:
  https://docs.aws.amazon.com/AmazonS3/latest/dev/ways-to-add-notification-config-to-bucket.html


More documentation to come...
