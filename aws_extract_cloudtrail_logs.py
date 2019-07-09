import json
import logging
import sys
import boto3
import re
import gzip
import io

from argparse import ArgumentParser
from datetime import datetime

# Reusable function to create a logging mechanism
def create_logger(logfile=None):

    # Create a logging handler that will write to stdout and optionally to a log file
    stdout_handler = logging.StreamHandler(sys.stdout)
    if logfile != None:
        file_handler = logging.FileHandler(filename=logfile)
        handlers = [file_handler, stdout_handler]
    else:
        handlers = [stdout_handler]

    # Configure logging mechanism
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = handlers
    )

# Get the S3 object and unzip the contents producing a JSON file
def extract_object_contents(bucket_name,key_name):
    
    # Setup Boto3 client to get the objects
    client = boto3.client(
        's3'
    )
    response = client.get_object(
        Bucket = bucket_name,
        Key = key_name
    )
    
    # Store the contents of the file in memory
    object_content = io.BytesIO(response['Body'].read())
    
    # Extract the compressed content and store it in memory
    raw_content =(gzip.GzipFile(fileobj=object_content).read()).decode('UTF-8')
    
    # Read the content in as a string and remove any blank
    json_content = json.loads(raw_content)
    return(json_content)
    
def get_cloudtrail_objects(bucket_name, start_date, end_date):
    
    # Initialize empty list for storage of archived CloudTrail logs object keys
    cloudtrail_keys = []
    
    # Setup paginated Boto3 S3 client to list objects in S3 bucket
    client = boto3.client(
        's3'
    )
    paginator = client.get_paginator('list_objects_v2')
    
    response_iterator = paginator.paginate(
        Bucket=bucket_name
    )
    
    # Go through each returned page and extract object keys that aren't digest files or empty keys
    for page in response_iterator:
        for s3_key in page['Contents']:
            
            # Filter the keys to 
            if 'CloudTrail' in s3_key['Key']:
                if 'CloudTrail-Digest' not in s3_key['Key']:
                    if 'json.gz' in s3_key['Key']:
                    
                        # Extract the date from the S3 prefix and convet it to a datetime object
                        string_date_of_object = re.findall(r'(?<=)\d{4}\/\d{2}\/\d{2}',s3_key['Key'])
                        date_of_object = datetime.strptime(string_date_of_object[0], '%Y/%m/%d')
                    
                        # Pull only the CloudTrail files between a set of dates
                        if start_date <= date_of_object <= end_date:
                            cloudtrail_keys.append(s3_key['Key'])
    
    # Return the listing of CloudTrail logs object keys
    return cloudtrail_keys
    
def exportlogs(log_files,count):
    filename = 'cloudtrail_logs-' + str(count) + '.json'
    with open(filename, 'w+') as f:
        f.write(json.dumps(log_files))
                    
# Main function
def main():
    
    try:
        
        # Intialize empty list to hold CloudTrail records and a counter to increment file names
        cloudtrail_events = []
        count = 0

        
        # Process parameters file
        parser = ArgumentParser()
        parser.add_argument('--parameterfile', type=str, help='JSON file with parameters')
        parser.add_argument('--logfile', type=str, default=None, help='Specify an optional log file')
        args = parser.parse_args()

        with open(args.parameterfile) as json_data:
            config = json.load(json_data)

        # Load parameters into more consumable variables
        user_bucket_name = config['CloudTrailBucket']
        user_maxLogSize = config['MaxFileSize']
        user_start_date = config['StartDate']
        user_end_date = config['EndDate']
        
        # Convert the user-provided dates to a date time object
        try:
            user_start_date = datetime.strptime(user_start_date,'%m/%d/%Y')
            user_end_date = datetime.strptime(user_end_date,'%m/%d/%Y')
        except:
            logging.error('The time in the parameters file must be formatted like MM/DD/YYYY')
            raise
            
        # Setup a logger and optionally a logging file if the user specified
        if args.logfile != None:
            create_logger(args.logfile)
        else:
            create_logger()
            
        # Get a listing of keys from the bucket containing CloudTrail logs
        cloudtrail_keys = get_cloudtrail_objects(
            bucket_name = user_bucket_name,
            start_date = user_start_date,
            end_date = user_end_date
        )
        
        # Loop through each object key, retrieve the data, and add the records to the list
        logging.info('There are ' + str(len(cloudtrail_keys)) + ' files to process witin the date range of ' + config['StartDate'] + ' and ' + config['EndDate'])
        
        for object_key in cloudtrail_keys:
            
            # Get the object and extract the contents
            
            json_object_events = extract_object_contents(
                bucket_name = user_bucket_name,
                key_name = object_key
            )
            
            for event in json_object_events['Records']:
                if sys.getsizeof(cloudtrail_events) < user_maxLogSize:
                    cloudtrail_events.append(event)
                else:
                    logging.info('Max size reached, writing to a file')
                    count+=1
                    exportlogs(cloudtrail_events,count)
                    cloudtrail_events = []
                    cloudtrail_events.append(event)
        logging.info('Writing remaining events to disk...')
        count+=1
        exportlogs(cloudtrail_events,count)

    except Exception as e:
        logging.error('Execution error',exc_info=True)

if __name__ == "__main__":
    main()

