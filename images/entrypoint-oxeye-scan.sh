#!/bin/sh

set -e

if [ "$#" -lt 5 ]; then
    echo "Error - Missing argument. Please verify your configuration, or contact support@oxeye.io"
    exit 1
fi

token=$1
host=$2
client_id=$3
secret=$4
workspace_id=$5
release=$6
excludes=$7

if [ -z $release ]; then
    release="release"
fi

# Get Bearer ToKen
bearerToken=$(curl -s -X POST --location "https://${host}/api/auth/api-token" \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data "{
  \"clientId\": \"${client_id}\",
  \"secret\": \"${secret}\"
}")

if echo "$bearerToken" | grep -qi "failed"; then
  echo "Error - failed to authenticate token"
  exit 1
fi

if [ -n "$GITHUB_API_URL" ]; then
    cicd_tool="github"
elif [ -n "$CI_API_V4_URL" ]; then
    cicd_tool="gitlab"
elif [ -n "$JENKINS_URL" ]; then
    cicd_tool="jenkins"
elif [ -n "$BUILD_REPOSITORY_LOCALPATH" ]; then
    cicd_tool="azure"
elif [ -n "$BITBUCKET_CLONE_DIR" ]; then
    cicd_tool="bitbucket"
else
  echo "Error - could not determine environment. aborting..."
  exit 1
fi

git config --global --add safe.directory "*"

# Download Script
curl -s -o /app/scm_scan.py --location "https://${host}/api/scm/script?provider=${cicd_tool}" \
--header "Content-Type: application/json" \
--header "Accept: application/octet-stream" \
--header "Authorization: Bearer ${bearerToken}"

# RUN SCM Scan Script
python /app/scm_scan.py --host $host --repo-token $token --client-id $client_id --secret $secret --workspace-id $workspace_id --release $release --excludes "$excludes"
