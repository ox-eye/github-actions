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

# GITHUB_API_URL exists in github action context
if [ -n "$GITHUB_API_URL" ]; then
    provider="github"
    # /scan-github.sh $token $host $client_id $secret $workspace_id
# CI_API_V4_URL exists in gitlab ci context
elif [ -n "$CI_API_V4_URL" ]; then
    provider="gitlab"
    # /scan-gitlab.sh $token $host $client_id $secret $workspace_id
else
  echo "Error - could not determine environment. aborting..."
  exit 1
fi

# Download Script
curl -s -o /app/scm_scan.py --location "https://${host}/api/scm/script?provider=${provider}" \
--header "Content-Type: application/json" \
--header "Accept: application/octet-stream" \
--header "Authorization: Bearer ${bearerToken}"

# RUN Script
python /app/scm_scan.py --host $host --repo-token $token --client-id $client_id --secret $secret --workspace-id $workspace_id --release $release
