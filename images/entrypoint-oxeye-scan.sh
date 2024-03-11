#!/bin/sh

set -ex

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
partial=$8
scheme=$9

echo "Home: $HOME"
if [ "$scheme" = "http" ]; then
    config_dir="/root/.oxeye"
    config_file="$config_dir/config"
    mkdir -p "$config_dir"
    echo "scheme: http" > "$config_file"
    cat $config_file
else
    scheme="https"
fi

if [ "$scheme" = "http" ]; then
    config_dir="$HOME/.oxeye"
    config_file="$config_dir/config"
    mkdir -p "$config_dir"
    echo "scheme: http" > "$config_file"
    cat $config_file
else
    scheme="https"
fi

# Get Bearer ToKen
bearerToken=$(curl -s -X POST --location "${scheme}://${host}/api/auth/api-token" \
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
curl -s -o /app/scm_scan.py --location "${scheme}://${host}/api/scm/script?provider=${cicd_tool}" \
--header "Content-Type: application/json" \
--header "Accept: application/octet-stream" \
--header "Authorization: Bearer ${bearerToken}"

# RUN SCM Scan Script
default_flags="--host $scheme://$host
    --repo-token $token
    --client-id $client_id
    --secret $secret
    --workspace-id $workspace_id"

scm_scan_flags=$default_flags

if [ -n "$release" ]; then
    scm_scan_flags="$scm_scan_flags --release $release"
fi

if [ -n "$excludes" ]; then
    scm_scan_flags="$scm_scan_flags --excludes $excludes"
fi

if [ "$partial" == "false" ]; then
    scm_scan_flags="$scm_scan_flags --full"
fi

python /app/scm_scan.py $scm_scan_flags
