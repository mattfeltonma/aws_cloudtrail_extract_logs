# AWS Extract CloudTrail Logs from S3
This Python solution extracts CloudTrail logs from S3 for a user specified date range

## What problem does this solve?
CloudTrail log data is often delivered to S3 for long term retention and safe keeping.  When a CloudTrail trail is configured to deliver log data to S3, the log data is sent to S3 approximately every 5 minutes and is compressed into a GZ file.  [Prefixes](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html) are added to the S3 objects to arrange them by date and account number.  Specific date ranges of this data may be needed from time to time for incident response or forensics but extracing a specific date range of data can e challenging.

This Python solution extracts the log entries from S3 and writes them to a flat text file in JSON format for further analysis.  A maximum size can be configured for the output file and the solution will create multiple files as needed.

## Requirements

### Python Runtime and Modules
* [Python 3.6](https://www.python.org/downloads/release/python-360/)
* [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

## Setup
This solution is designed to be run by using an AWS IAM Role.  The role must have list s3:ListBucket and s3:GetObject permissions on the S3 bucket where the CloudTrail logs are stored.  The solution assumes that the bucket is dedicated to CloudTrail and there are no other objects in the bucket using the CloudTrail prefix.

The user specified date and time must be in the format of MM/DD/YYYY

A sample parameters file is included.

## Running
python aws_extract_cloudtrail_logs.py --parameterfile parameters.json [--logfile cloudtrail-extract.log]
