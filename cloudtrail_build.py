#!/bin/python3
"""
At1Security - Adam Shechter

Script to generate resources and start CloudTrail logging on AWS

Resources created:
cloutrail log
s3 bucket
cloudwatch log group
iam role
athena database (if not existing)
athena table in database
"""

import json
import boto3
import sys
import os
import time
import string
import random
import logging


# Initialize logger object
def initialize_logger(output_dir):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # create error file handler and set level to error
    handler = logging.FileHandler(os.path.join(output_dir, "error.log"), "w", encoding=None, delay="true")
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# Create S3 bucket for CloudTrail logging.
def s3_create_bucket():
    try:
        response = s3_client.create_bucket(
            Bucket=s3bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': region_name
            },
        )
        logger.info(response)
    except Exception as e:
        print(e)
        logger.error(e)
    return


# Load s3 bucket policy from file and update with parameters
# Apply new Bucket Policy
def s3_bucket_policy():
    try:
        with open("s3_bucket_policy.json", "r") as f:
            bucket_policy_raw = f.read()
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    bucket_policy = bucket_policy_raw.replace("{{BucketName}}", s3bucket_name).replace("{{AccountID}}", account_id)
    logger.info(bucket_policy)
    try:
        response = s3_client.put_bucket_policy(
            Bucket=s3bucket_name,
            Policy=bucket_policy
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    return


# Create a new log cloudwatch log group for CloudTrail
# Get CloudWatch Log Group ARN and return
def logs_create_log_group():
    try:
        response = logs_client.create_log_group(
            logGroupName=cloudwatch_log_group_name,
            # kmsKeyId='string',
            # tags={
            #     'string': 'string'
            # }
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    try:
        response = logs_client.describe_log_groups(
            logGroupNamePrefix=cloudwatch_log_group_name
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    # print(response['logGroups'][0]['arn'])
    return response['logGroups'][0]['arn']


# Create IAM role and policy for cloudtrail
# Return ARN for IAM role
def create_role_cloudtrail():
    try:
        with open("cloudtrail_assume_role.json", "r") as f:
            assume_role_policy = f.read()
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    try:
        response = iam_client.create_role(
            RoleName=cloudtrail_role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Description='Automated Role for Cloutrail log delivery to Cloudwatch',
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    role_arn = response['Role']['Arn']
    try:
        with open("cloudwatch_role_policy.json", "r") as f:
            role_policy_raw = f.read()
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    role_policy = role_policy_raw.replace("{{log_group_name}}", cloudwatch_log_group_name).replace("{{region}}", region_name).replace("{{accountID}}", account_id)
    logger.info(role_policy)
    time.sleep(5)
    logger.info("creating policy and applying to role")
    try:
        response = iam_client.put_role_policy(
            RoleName=cloudtrail_role_name,
            PolicyName='create_put_logs_cloudtrail',
            PolicyDocument=role_policy
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    return role_arn


# Create a new CloudTrail trail and start logging
def create_trail():
    # KMS encryption currently disabled
    try:
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=s3bucket_name,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=cloudwatch_log_group_arn,
            CloudWatchLogsRoleArn=cloudtrail_role_arn,
            # KmsKeyId='string',
            IsOrganizationTrail=False
        )
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    logger.info(response)
    time.sleep(5)
    logger.info("Starting logging on CloudTrail Trail")
    try:
        response = cloudtrail_client.start_logging(
            Name=response['TrailARN']
        )
    except Exception as e:
        print(e)
        logger.error(e)
    return


# Set up Athena with a new Database (if it doesn't exist)
# generate the SQL schema for CloudTrail in Athena and apply
def athena_set_up():
    try:
        with open("athena_sql_create_table.txt", "r") as f:
            athena_sql_code_raw = f.read()
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    athena_sql_code = athena_sql_code_raw.replace("{{db_name}}", db_name).replace("{{bucket_name}}", s3bucket_name).replace("{{account_id}}", account_id)
    logger.info(athena_sql_code)
    athena_bucket_name = "aws-athena-query-results-" + account_id + "-" + region_name
    s3_create_bucket()
    time.sleep(5)
    output_location = "s3://" + athena_bucket_name
    logger.info("Creating Database")
    try:
        response = athena_client.start_query_execution(
            QueryString="CREATE DATABASE IF NOT EXISTS {{db_name}};".replace("{{db_name}}", db_name),
            # QueryExecutionContext={
            #     'Database': 'string'
            # },
            ResultConfiguration={
                'OutputLocation': output_location
            }
        )
        logger.info(response)
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    time.sleep(5)
    logger.info("Generating CloudTrail Table!")
    try:
        response = athena_client.start_query_execution(
            QueryString=athena_sql_code,
            # QueryExecutionContext={
            #     'Database': 'string'
            # },
            ResultConfiguration={
                'OutputLocation': output_location
            }
        )
        logger.info(response)
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)
    query_execution_id = response['QueryExecutionId']
    logger.info("Waiting for Athena Execution results")
    time.sleep(10)
    try:
        response = athena_client.get_query_results(
            QueryExecutionId=query_execution_id,
        )
        logger.info(response)
    except Exception as e:
        print(e)
        logger.error(e)
    return


# return a random 6 character string for application name
def randomstring():
  chars = string.ascii_lowercase + string.digits
  return ''.join(random.choice(chars) for x in range(6))


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args:
        print("This program generates regional CloudTrail for an AWS account\nusage: [profile_name] [account] [region_name]")
        sys.exit(1)
    else:
        profile_name = args[0]
        account_id = args[1]
        region_name = args[2]
    logger = initialize_logger('./')
    try:
        session = boto3.Session(profile_name=profile_name)
        # Any clients created from this session will use credentials
        ec2_client = session.client('ec2', region_name=region_name)
        cloudtrail_client = session.client('cloudtrail', region_name=region_name)
        s3_client = session.client('s3', region_name=region_name)
        sts_client = session.client('sts', region_name=region_name)
        logs_client = session.client('logs', region_name=region_name)
        iam_client = session.client('iam')
        athena_client = session.client('athena', region_name)
    except Exception as e:
        print(e)
        logger.error(e)
        raise Exception("Error with AWS credentials")
    app_name = "-app-" + randomstring()
    trail_name = "cloudtrail-" + region_name + app_name
    s3bucket_name = "cloudtrail-" + region_name + app_name
    cloudwatch_log_group_name = "cloudtrail-log-" + region_name + app_name
    cloudtrail_role_name = "cloudtrail-put-get-role" + app_name
    db_name = "cloudtrail_db" + app_name
    logger.info("Creating S3 Bucket")
    s3_create_bucket()
    logger.info("Attaching S3 Bucket Policy")
    s3_bucket_policy()
    logger.info("Creating new CloudWatch Log Group")
    cloudwatch_log_group_arn = logs_create_log_group()
    logger.info("Creating new IAM Role for Cloudtrail")
    cloudtrail_role_arn = create_role_cloudtrail()
    time.sleep(20)
    logger.info("Creating CloudTrail Trail")
    create_trail()
    logger.info("Running SQL commands in Athena to set up Database and Table")
    athena_set_up()
    logger.info("All done!\nCloudtrail resources created.")