#!/bin/sh

set -e

command=$1
host=$2
client_id=$3
secret=$4
observer_name=$5
application_name=$6
tag=$7


file_release_results="${GITHUB_WORKSPACE}/release_results.md"
file_release_sarif="${GITHUB_WORKSPACE}/oxeye.sarif"

default_flags="--host $host 
    --client-id $client_id 
    --secret $secret
    --observer $observer_name
    --application $application_name
    --tag $tag
    --output md"

release_flags=$default_flags

if [[ "$command" == "status" ]]
then
    release_flags="$release_flags -w"
fi

if [[ "$command" == "results" ]]
then
    release_flags="$release_flags --file $file_release_results"
fi

/oxctl release $command $release_flags

if [[ "$command" == "results" ]]
then
    cat $file_release_results >$GITHUB_STEP_SUMMARY
    sarif_flags="$default_flags --file $file_release_sarif"
    /oxctl vulnerability sarif $sarif_flags   
fi
