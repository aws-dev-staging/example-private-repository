import os
import time
import boto3
import requests

# -- Environment Variables --

# Local Assets
unique_package_file_name = os.environ.get("UNIQUE_PACKAGE_FILE_NAME")
asset_sha256 = os.environ.get("ASSET_SHA256")

# Private Internal Package Repository
codeartifact_domain = os.environ.get("ExampleDomain")
codeartifact_repo = os.environ.get("InternalRepository")

# Pipeline Exit and Notification
codebuild_id = os.environ.get("CODEBUILD_BUILD_ID")
sns_topic_arn = os.environ.get("SNSTopic")

def main():
    try:
        print("Initiating Security Scan for External Package Repository: " + unique_package_file_name)

        # Instantiate boto3 clients
        codeguru_security_client = boto3.client('codeguru-security')
        codeartifact_client = boto3.client('codeartifact')
        sns_client = boto3.client('sns')
        codebuild_client = boto3.client('codebuild')

        print("Creating CodeGuru Security Upload URL...")

        create_url_input = {"scanName": unique_package_file_name}
        create_url_response = codeguru_security_client.create_upload_url(**create_url_input)
        url = create_url_response["s3Url"]
        artifact_id = create_url_response["codeArtifactId"]

        print("Uploading External Package Repository File...")

        upload_response = requests.put(
            url,
            headers=create_url_response["requestHeaders"],
            data=open(unique_package_file_name, "rb"),
        )

        if upload_response.status_code == 200:
            
            print("Performing CodeGuru Security and Quality Scans...")
            
            scan_input = {
                "resourceId": {
                    "codeArtifactId": artifact_id,
                },
                "scanName": unique_package_file_name,
                "scanType": "Standard", # Express
                "analysisType": "Security" # All
            }
            create_scan_response = codeguru_security_client.create_scan(**scan_input)
            run_id = create_scan_response["runId"]

            print("Retrieving Scan Results...")
            
            get_scan_input = {
                "scanName": unique_package_file_name,
                "runId": run_id,
            }

            print("Analyzing Security and Quality Finding Severities...")

            get_findings_input = {
                "scanName": unique_package_file_name,
                "maxResults": 20,
                "status": "Open",
            }

            while True:
                get_scan_response = codeguru_security_client.get_scan(**get_scan_input)
                if get_scan_response["scanState"] == "InProgress":                
                    get_findings_response = codeguru_security_client.get_findings(**get_findings_input)
                    if "findings" in get_findings_response:
                        for finding in get_findings_response["findings"]:
                            if finding["severity"] != "Low" or finding["severity"] != "Info":
                                print("!!! Medium or High severities found. An email has been sent to the requestor with additional details.")
                                subject = unique_package_file_name + " Medium to High Severy Findings"
                                message = "Please refer to CodeGuru Security scan, " + str(unique_package_file_name)
                                sns_client.publish(
                                    TopicArn=sns_topic_arn,
                                    Subject=subject,
                                    Message=message,
                                )
                                stop_build = codebuild_client.stop_build(id=codebuild_id)
                                exit()
                else:
                    break

            if get_scan_response["scanState"] != "Successful":
                raise Exception(f"CodeGuru Scan {unique_package_file_name} failed")
            else:
                print("Publishing InfoSec Validated Package Repository to Private Internal CodeArtifact...")
        else:
            raise Exception(f"Source failed to upload external package to CodeGuru Security with status {upload_response.status_code}")
    except Exception as error:
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()