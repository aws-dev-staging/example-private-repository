import os
import sys
import time
import boto3
import requests

# -- Environment Variables --

# Local Assets
unique_package_file_name = os.environ.get("UNIQUE_PACKAGE_FILE_NAME")
public_package_file_name = os.environ.get("EXTERNAL_PACKAGE_FILE_NAME")
public_package__name = os.environ.get("EXTERNAL_PACKAGE_NAME")
asset_sha256 = os.environ.get("ASSET_SHA256")

# Private Internal Package Repository
codeartifact_domain = os.environ.get("ExampleDomain")
codeartifact_repo = os.environ.get("InternalRepository")

# Pipeline Exit and Notification
codebuild_id = os.environ.get("CODEBUILD_BUILD_ID")
sns_topic_arn = os.environ.get("SNSTopic")

def main():
    try:
        print("Initiating Security Scan for External Package Repository: " + public_package__name)

        # Instantiate boto3 clients
        codeguru_security_client = boto3.client('codeguru-security')
        codeartifact_client = boto3.client('codeartifact')
        sns_client = boto3.client('sns')
        codebuild_client = boto3.client('codebuild')

        print("Creating CodeGuru Security Upload URL...")

        create_url_input = {"scanName": public_package__name}
        create_url_response = codeguru_security_client.create_upload_url(**create_url_input)
        url = create_url_response["s3Url"]
        artifact_id = create_url_response["codeArtifactId"]

        print("Uploading External Package Repository File...")

        upload_response = requests.put(
            url,
            headers=create_url_response["requestHeaders"],
            data=open(public_package_file_name, "rb"),
        )

        if upload_response.status_code == 200:
            
            print("Performing CodeGuru Security and Quality Scans...")
            
            scan_input = {
                "resourceId": {
                    "codeArtifactId": artifact_id,
                },
                "scanName": public_package__name,
                "scanType": "Standard", # Express
                "analysisType": "Security" # All
            }
            create_scan_response = codeguru_security_client.create_scan(**scan_input)
            run_id = create_scan_response["runId"]

            print("Retrieving Scan Results...")
            
            get_scan_input = {
                "scanName": public_package__name,
                "runId": run_id,
            }

            print("Analyzing Security and Quality Finding Severities...")

            get_findings_input = {
                "scanName": public_package__name,
                "maxResults": 20,
                "status": "Open",
            }

            continue_scan = True
            while continue_scan:
                get_scan_response = codeguru_security_client.get_scan(**get_scan_input)

                if get_scan_response["scanState"] == "InProgress":                
                    get_findings_response = codeguru_security_client.get_findings(**get_findings_input)

                    if "findings" in get_findings_response:
                        for finding in get_findings_response["findings"]:
                            if finding["severity"] != "Low" or finding["severity"] != "Info":
                                print("!== Amazon CodeGuru Security: Medium or High severities found. An email has been sent to the requestor with additional details. ==!")

                                subject = public_package__name + " Medium to High Severy Findings"
                                message = "Please refer to Amazon CodeGuru Security scan: " + str(public_package__name)
                                sns_client.publish(
                                    TopicArn=sns_topic_arn,
                                    Subject=subject,
                                    Message=message,
                                )
                                continue_scan = False
                                sys.exit()
                else:
                    break

            print("Publishing InfoSec Validated Package Repository to Private Internal CodeArtifact...")
            source_path = os.getcwd() + "/" + unique_package_file_name

            with open(source_path, 'rb') as asset_content:
                file_bytes = asset_content.read()

            codeartifact_response = codeartifact_client.publish_package_version(
                domain=codeartifact_domain,
                repository=codeartifact_repo,
                format='generic',
                namespace=public_package__name,
                package=public_package__name,
                packageVersion='Latest',
                assetContent=file_bytes,
                assetName=unique_package_file_name,
                assetSHA256=asset_sha256,
                unfinished=True
            )

            print("CodeArtifact response = " + str(codeartifact_response))
            subject = "InfoSec Approved " + public_package__name
            message = "Please refer to Amazon CodeArtifact private package: " + str(public_package__name)
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject=subject,
                Message=message,
            )
        else:
            raise Exception(f"Source failed to upload external package to CodeGuru Security with status {upload_response.status_code}")
    except Exception as error:
        print(f"Action Failed, reason: {error}")

if __name__ == "__main__":
    main()