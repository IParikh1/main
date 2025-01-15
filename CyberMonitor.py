#!/usr/bin/env python
# coding: utf-8

# In[ ]:


"""	
Script Description:
    1.	S3 Bucket Checks: Identifies buckets with public read/write permissions.
	2.	IAM User Policies: Lists all attached IAM user policies.
	3.	EC2 Security Groups: Detects security groups that allow unrestricted access (e.g., 0.0.0.0/0).
"""

import boto3

def check_s3_bucket_public_access():
    """Check if S3 buckets are publicly accessible."""
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    
    for bucket in response.get('Buckets', []):
        bucket_name = bucket['Name']
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                print(f"Bucket {bucket_name} is publicly accessible!")
            else:
                print(f"Bucket {bucket_name} is secure.")

def check_iam_user_policies():
    """Check for overly permissive IAM user policies."""
    iam = boto3.client('iam')
    response = iam.list_users()
    
    for user in response.get('Users', []):
        user_name = user['UserName']
        policies = iam.list_attached_user_policies(UserName=user_name)
        
        for policy in policies.get('AttachedPolicies', []):
            policy_name = policy['PolicyName']
            print(f"User {user_name} has attached policy: {policy_name}")

def check_ec2_security_groups():
    """Check EC2 security groups for overly permissive rules."""
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    
    for sg in response.get('SecurityGroups', []):
        sg_id = sg['GroupId']
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    print(f"Security group {sg_id} allows access from anywhere!")

# Run the checks
if __name__ == "__main__":
    print("Checking S3 buckets for public access...")
    check_s3_bucket_public_access()
    
    print("\nChecking IAM user policies...")
    check_iam_user_policies()
    
    print("\nChecking EC2 security groups...")
    check_ec2_security_groups()


# In[ ]:


"""Azure Resource Misconfiguration Check"""
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

def check_azure_storage_public_access():
    """Check if Azure storage accounts have public access enabled."""
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, "your_subscription_id")

    storage_accounts = storage_client.storage_accounts.list()
    for account in storage_accounts:
        properties = storage_client.storage_accounts.get_properties(account.resource_group, account.name)
        if properties.public_network_access == "Enabled":
            print(f"Storage account {account.name} allows public access.")
        else:
            print(f"Storage account {account.name} is secure.")

# Run the Azure check
if __name__ == "__main__":
    check_azure_storage_public_access()


# In[ ]:


"""AWS Lambda for Real-Time Monitoring"""
import boto3

def lambda_handler(event, context):
    """Triggered by S3 event notifications to detect anomalies."""
    for record in event['Records']:
        bucket_name = record['s3']['bucket']['name']
        object_key = record['s3']['object']['key']

        print(f"Access detected: Bucket={bucket_name}, Object={object_key}")
        if "sensitive-data" in object_key:
            print("ALERT: Sensitive data accessed!")

    return {"status": "ok"}


# In[ ]:


"""Terraform File Scanner for Open Security Groups"""
import hcl2

def scan_terraform_file(file_path):
    """Check Terraform files for open security group rules."""
    with open(file_path, 'r') as f:
        config = hcl2.load(f)

    for resource in config.get('resource', {}).get('aws_security_group', []):
        for rule in resource.get('ingress', []):
            if rule.get('cidr_blocks') == ["0.0.0.0/0"]:
                print(f"Open ingress found in security group: {resource.get('name')}")

# Scan a Terraform file
scan_terraform_file('main.tf')


# In[ ]:


"""Example Anamoly Detection on Login Events"""
from sklearn.ensemble import IsolationForest
import numpy as np

# Sample login data: [login_time_in_seconds, ip_address_as_numeric]
login_data = np.array([
    [300, 123456789],
    [320, 987654321],
    [340, 123456789],
    [50000, 888888888]  # Anomalous
])

# Train Isolation Forest
model = IsolationForest(contamination=0.1)
model.fit(login_data)

# Predict anomalies
predictions = model.predict(login_data)
for i, prediction in enumerate(predictions):
    if prediction == -1:
        print(f"Anomaly detected in login data: {login_data[i]}")


# In[ ]:


"""Real-Time Threat Detection Example: Monitoring AWS CloudTrail Events"""
"""
Steps:
Enable CloudTrail: Ensure CloudTrail is enabled in your AWS account to log API activity
Setup Event Notifications: 
    	1.	Configure CloudTrail to send logs to an S3 bucket.
    	2.	Set up S3 event notifications to trigger a Lambda function
Lambda Function for Threat Detection
"""
"""How to Deploy:
	1.	Create the Lambda Function:
	•	Use the AWS Lambda console or CLI to create the function.
	•	Attach an IAM role with the following permissions:
	•	sns:Publish
	•	s3:ListBucket
	•	s3:GetObject
	2.	Set Up S3 Event Notifications:
	•	In the S3 bucket settings, create an event notification to trigger the Lambda function on object creation (or other events).
	3.	Configure an SNS Topic for Alerts:
	•	Create an SNS topic for alert notifications.
	•	Subscribe your email or phone number to the topic for real-time alerts."""
#AWS Lambda function detects unauthorized API calls (e.g., DeleteBucket on sensitive S3 buckets)
import boto3

def lambda_handler(event, context):
    """Triggered by CloudTrail logs to detect unauthorized actions."""
    sns_client = boto3.client('sns')
    monitored_actions = ["DeleteBucket", "PutBucketAcl"]

    for record in event['Records']:
        event_source = record['eventSource']
        event_name = record['eventName']
        user_identity = record.get('userIdentity', {}).get('arn', 'Unknown User')
        bucket_name = record.get('requestParameters', {}).get('bucketName', 'Unknown Bucket')

        # Detect unauthorized actions
        if event_source == "s3.amazonaws.com" and event_name in monitored_actions:
            alert_message = (
                f"Unauthorized action detected:\n"
                f"Action: {event_name}\n"
                f"Bucket: {bucket_name}\n"
                f"User: {user_identity}"
            )
            print(alert_message)
            
            # Send an alert via SNS
            sns_client.publish(
                TopicArn="your-sns-topic-arn",
                Message=alert_message,
                Subject="Security Alert: Unauthorized S3 Action"
            )

    return {"status": "Processed events"}


# In[ ]:


"""Advanced Detection Logic for Real-Time Threat Detection - Enhanced Threat Detection Using Rules"""
import boto3
from datetime import datetime

# Define suspicious regions and actions
SUSPICIOUS_REGIONS = ["North Korea", "Iran", "Russia"]
MONITORED_ACTIONS = ["DeleteBucket", "CreateUser", "UpdatePolicy"]

def lambda_handler(event, context):
    """Detect advanced threats from CloudTrail logs."""
    sns_client = boto3.client('sns')
    
    for record in event['Records']:
        # Parse the event
        event_time = record['eventTime']
        event_source = record['eventSource']
        event_name = record['eventName']
        user_identity = record.get('userIdentity', {}).get('arn', 'Unknown User')
        source_ip = record.get('sourceIPAddress', 'Unknown IP')
        aws_region = record.get('awsRegion', 'Unknown Region')

        # Detection Logic
        if aws_region in SUSPICIOUS_REGIONS:
            alert_message = (
                f"Suspicious activity detected from region {aws_region}:\n"
                f"Action: {event_name}\n"
                f"User: {user_identity}\n"
                f"Source IP: {source_ip}\n"
                f"Event Time: {event_time}"
            )
            send_alert(sns_client, alert_message)

        if event_name in MONITORED_ACTIONS:
            alert_message = (
                f"Sensitive action detected:\n"
                f"Action: {event_name}\n"
                f"User: {user_identity}\n"
                f"Source IP: {source_ip}\n"
                f"Event Time: {event_time}"
            )
            send_alert(sns_client, alert_message)

    return {"status": "Processed events"}

def send_alert(sns_client, message):
    """Send alerts via SNS."""
    sns_client.publish(
        TopicArn="your-sns-topic-arn",
        Message=message,
        Subject="Security Alert: Suspicious Activity Detected"
    )
    print("Alert sent!")


# In[ ]:


"""Adding Behavioral Analysis
Key Steps:
	1.	Store Historical Activity:
	•	Use a database (e.g., DynamoDB) to log user actions.
	•	Track metrics like API calls, resource access frequency, and geographic locations.
	2.	Compare Against Baselines:
	•	For each event, compare against stored baselines.
	•	Raise alerts for anomalies.

Combining with Real-Time Analytics Services - 
For more scalable and powerful analysis:
	•	AWS Services: Use AWS EventBridge or Kinesis to process and analyze logs in real-time.
	•	SIEM Integration: Integrate with systems like Splunk, QRadar, or Datadog for advanced correlations and dashboards.
"""
import boto3
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('UserBehavior')

def lambda_handler(event, context):
    """Analyze CloudTrail events against behavioral baselines."""
    for record in event['Records']:
        user_identity = record.get('userIdentity', {}).get('arn', 'Unknown User')
        event_name = record['eventName']
        source_ip = record.get('sourceIPAddress', 'Unknown IP')
        event_time = record['eventTime']

        # Fetch user's historical activity
        response = table.get_item(Key={'UserArn': user_identity})
        user_data = response.get('Item', {})

        # Check for anomalies
        if is_anomalous(user_data, event_name, source_ip):
            send_alert(f"Anomaly detected for user {user_identity}: {event_name} from {source_ip} at {event_time}")

        # Update user's activity in the database
        update_user_activity(user_identity, event_name, source_ip)

def is_anomalous(user_data, event_name, source_ip):
    """Simple anomaly detection logic."""
    recent_actions = user_data.get('RecentActions', [])
    recent_ips = user_data.get('RecentIPs', [])

    # Detect unusual actions or IP addresses
    return event_name not in recent_actions or source_ip not in recent_ips

def update_user_activity(user_identity, event_name, source_ip):
    """Update user behavior in the database."""
    table.update_item(
        Key={'UserArn': user_identity},
        UpdateExpression="SET RecentActions = list_append(RecentActions, :new_action), RecentIPs = list_append(RecentIPs, :new_ip)",
        ExpressionAttributeValues={
            ':new_action': [event_name],
            ':new_ip': [source_ip]
        },
        ReturnValues="UPDATED_NEW"
    )


# In[ ]:





# In[ ]:


"""Database Schema for Behavioral Analysis
We’ll use Amazon DynamoDB, a fully managed NoSQL database, to store and analyze user behavior.
The schema will support logging user actions, resource accesses, and IP addresses for anomaly detection.
"""
aws dynamodb create-table \
    --table-name UserBehavior \
    --attribute-definitions AttributeName=UserArn,AttributeType=S \
    --key-schema AttributeName=UserArn,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

""" """
import boto3

def create_user_behavior_table():
    """Create DynamoDB table for storing user behavior."""
    dynamodb = boto3.client('dynamodb')

    table = dynamodb.create_table(
        TableName='UserBehavior',
        KeySchema=[
            {
                'AttributeName': 'UserArn',
                'KeyType': 'HASH'  # Partition key
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'UserArn',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    print(f"Table {table['TableDescription']['TableName']} created successfully.")

create_user_behavior_table()

"""Insert/Update User Behavior - When a user performs an action, update their recent activity: """
def update_user_activity(user_arn, action, ip_address):
    """Update user behavior in DynamoDB."""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('UserBehavior')

    table.update_item(
        Key={'UserArn': user_arn},
        UpdateExpression=(
            "SET RecentActions = list_append(if_not_exists(RecentActions, :empty_list), :action), "
            "RecentIPs = list_append(if_not_exists(RecentIPs, :empty_list), :ip), "
            "LastAccessed = :timestamp"
        ),
        ExpressionAttributeValues={
            ':action': [action],
            ':ip': [ip_address],
            ':timestamp': datetime.utcnow().isoformat(),
            ':empty_list': []
        }
    )

"""Fetch User Behavior - Retrieve the user’s recent activity for comparison: """
def get_user_behavior(user_arn):
    """Fetch user behavior from DynamoDB."""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('UserBehavior')

    response = table.get_item(Key={'UserArn': user_arn})
    return response.get('Item', {})

"""Delete Old Data (Optional Cleanup) - Periodically clean up old entries to prevent unbounded growth: """
def clean_up_user_behavior(user_arn):
    """Remove old activity to maintain a fixed list size."""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('UserBehavior')

    # Fetch existing data
    user_data = get_user_behavior(user_arn)

    # Truncate lists to the last N entries (e.g., 10)
    truncated_actions = user_data.get('RecentActions', [])[-10:]
    truncated_ips = user_data.get('RecentIPs', [])[-10:]

    # Update with truncated lists
    table.update_item(
        Key={'UserArn': user_arn},
        UpdateExpression=(
            "SET RecentActions = :actions, RecentIPs = :ips"
        ),
        ExpressionAttributeValues={
            ':actions': truncated_actions,
            ':ips': truncated_ips
        }
    )



# In[ ]:


"""Deploy the Table and Integrate with Detection Logic -  
Step 1: Deploy the DynamoDB Table
    Use the Python code or AWS CLI command from the previous section to create the UserBehavior table.
Step 2: Integrate the Table with Detection Logic
    Update the Lambda function to use DynamoDB for storing and fetching user behavior:
"""
import boto3
from datetime import datetime

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('UserBehavior')

def lambda_handler(event, context):
    for record in event['Records']:
        user_arn = record.get('userIdentity', {}).get('arn', 'Unknown User')
        event_name = record['eventName']
        source_ip = record.get('sourceIPAddress', 'Unknown IP')
        event_time = record['eventTime']

        # Fetch existing behavior
        user_data = get_user_behavior(user_arn)

        # Check for anomalies
        if is_anomalous(user_data, event_name, source_ip):
            alert_message = f"Anomaly detected for user {user_arn}: {event_name} from {source_ip} at {event_time}"
            send_alert(alert_message)

        # Update user behavior
        update_user_activity(user_arn, event_name, source_ip)

def get_user_behavior(user_arn):
    """Fetch user behavior from DynamoDB."""
    response = table.get_item(Key={'UserArn': user_arn})
    return response.get('Item', {})

def is_anomalous(user_data, event_name, source_ip):
    """Simple anomaly detection logic."""
    recent_actions = user_data.get('RecentActions', [])
    recent_ips = user_data.get('RecentIPs', [])
    return event_name not in recent_actions or source_ip not in recent_ips

def update_user_activity(user_arn, action, ip_address):
    """Update user behavior in DynamoDB."""
    table.update_item(
        Key={'UserArn': user_arn},
        UpdateExpression=(
            "SET RecentActions = list_append(if_not_exists(RecentActions, :empty_list), :action), "
            "RecentIPs = list_append(if_not_exists(RecentIPs, :empty_list), :ip), "
            "LastAccessed = :timestamp"
        ),
        ExpressionAttributeValues={
            ':action': [action],
            ':ip': [ip_address],
            ':timestamp': datetime.utcnow().isoformat(),
            ':empty_list': []
        }
    )

def send_alert(message):
    """Send alert (e.g., via SNS)."""
    sns = boto3.client('sns')
    sns.publish(
        TopicArn="your-sns-topic-arn",
        Message=message,
        Subject="Anomaly Detected"
    )


# In[ ]:


""" Implement DynamoDB Streams for Real-Time Updates
Step 1: Enable DynamoDB Streams
	•	Go to the AWS Management Console, select the UserBehavior table, and enable DynamoDB Streams.
	•	Choose the “New image” option to capture full records of new updates. 
Step 2: Process Streams with Lambda
    •   Attach a new Lambda function to the DynamoDB stream to process updates in real-time.
"""
def process_dynamodb_stream(event, context):
    for record in event['Records']:
        if record['eventName'] == 'INSERT' or record['eventName'] == 'MODIFY':
            user_arn = record['dynamodb']['Keys']['UserArn']['S']
            recent_actions = record['dynamodb']['NewImage']['RecentActions']['L']
            recent_ips = record['dynamodb']['NewImage']['RecentIPs']['L']

            print(f"Stream update for {user_arn}: Actions={recent_actions}, IPs={recent_ips}")

            # Optional: Trigger further analysis or alerts


# In[ ]:


"""Add Machine Learning for Anomaly Detection
Step 1: Train a Model Locally
    •   Train an anomaly detection model using historical logs. For example, use IsolationForest from scikit-learn: 
Step 2: Deploy the Model to Lambda
    •   Package the trained model and load it in the Lambda function:    """
from sklearn.ensemble import IsolationForest
import numpy as np

# Example data: [action_encoded, ip_encoded]
historical_data = np.array([
    [1, 101], [1, 102], [2, 103], [1, 101], [3, 104]  # Normal
])

# Train the model
model = IsolationForest(contamination=0.1)
model.fit(historical_data)

# Save the model to deploy
import joblib
joblib.dump(model, '/tmp/anomaly_model.pkl')


import joblib
# Load the pre-trained model
model = joblib.load('path_to_model/anomaly_model.pkl')

def lambda_handler(event, context):
    for record in event['Records']:
        user_arn = record.get('userIdentity', {}).get('arn', 'Unknown User')
        action = record['eventName']
        ip_address = record.get('sourceIPAddress', '0.0.0.0')

        # Encode action and IP
        action_encoded = hash(action) % 1000
        ip_encoded = hash(ip_address) % 1000

        # Predict anomalies
        prediction = model.predict(np.array([[action_encoded, ip_encoded]]))
        if prediction == -1:
            send_alert(f"Anomaly detected: {user_arn}, {action}, {ip_address}")


# In[ ]:


"""Expanding Machine Learning Logic for Anomaly Detection"""


# In[ ]:


"""Feature Engineering
Key Features for Behavior Analysis:
	•	Action Encodings: Encode API actions (e.g., CreateUser, DeleteBucket) as categorical features.
	•	IP Address Features: Map IPs to geolocations, then encode as numerical features (e.g., latitude, longitude, risk level).
	•	Session Data: Include time-related features such as session length, request intervals, or unusual access times.
"""

import pandas as pd
import geopy

def extract_features(logs):
    """Extract meaningful features from logs."""
    geolocator = geopy.Nominatim(user_agent="geoapi")
    features = []

    for log in logs:
        action = hash(log['action']) % 1000
        ip = log['ip']
        timestamp = pd.to_datetime(log['timestamp'])

        # Extract geolocation data
        location = geolocator.geocode(ip, timeout=10)
        lat = location.latitude if location else 0
        lon = location.longitude if location else 0

        # Add features
        features.append([action, lat, lon, timestamp.hour])
    
    return pd.DataFrame(features, columns=["action", "lat", "lon", "hour"])


# In[ ]:


"""Enhanced ML Model - Multi-Class Anomaly Detection with XGBoost:
Use XGBoost for detecting and classifying anomalies."""

import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Sample labeled data (1 = normal, -1 = anomaly)
data = pd.DataFrame({
    "action": [100, 101, 102, 105, 999],
    "lat": [34.05, 51.51, 48.85, -33.86, 0.0],
    "lon": [-118.24, -0.13, 2.35, 151.21, 0.0],
    "hour": [14, 15, 3, 2, 23],
    "label": [1, 1, 1, -1, -1]
})

X = data[["action", "lat", "lon", "hour"]]
y = data["label"]

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train XGBoost model
model = xgb.XGBClassifier()
model.fit(X_train, y_train)

# Evaluate the model
predictions = model.predict(X_test)
print(classification_report(y_test, predictions))


# In[ ]:


"""Real-Time Feature Extraction in Lambda
Modify the Lambda function to preprocess logs and extract features before making predictions:"""

import joblib
import numpy as np

model = joblib.load('path_to_model/anomaly_model.pkl')

def lambda_handler(event, context):
    for record in event['Records']:
        action = record['eventName']
        ip = record['sourceIPAddress']
        timestamp = record['eventTime']

        # Extract features
        action_encoded = hash(action) % 1000
        lat, lon = extract_geo(ip)  # Implement geolocation mapping
        hour = pd.to_datetime(timestamp).hour

        # Predict anomaly
        features = np.array([[action_encoded, lat, lon, hour]])
        prediction = model.predict(features)

        if prediction == -1:
            send_alert(f"Anomaly detected: {action}, {ip}")


# In[ ]:


"""Alerting Mechanisms"""


# In[ ]:


"""Amazon SNS:
Trigger SNS notifications for detected anomalies (already integrated in previous examples).
	•	Slack Integration:
Send alerts directly to a Slack channel:"""


# In[ ]:


import requests

def send_slack_alert(message, webhook_url):
    payload = {"text": message}
    requests.post(webhook_url, json=payload)


# In[ ]:


get_ipython().system('jupyter nbconvert --to script CyberMonitor.ipynb')


# In[ ]:




