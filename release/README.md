# Oxeye Release Github Action

GitHub Action to detect vulnerabilities and issues during the CI/CD stage of every version release of your application.

## Prerequisites

1. You should have at least one Observer installed in your cluster. You can find instructions on how to install Observer [here]([doc:step-1-configuring-observer](https://docs.oxeye.io/docs/installation-overview)).
2. Your Oxeye account should have Admin permissions.

> 📘 Note
> 
> If you want to deploy Observer as part of your CI/CD process, the optimal place to do so is before deploying and testing your application.

## Commands

There are 3 commands available for this Github Action
* Start: Should be called before the tests are run on the Release
* Status: Returns the status Oxeye scan: "In Progress", "Done", "Timed Out"
* Results: Returns a table of the number Vulnerabilites found per severity

## Inputs

| Variable         | Example Value                         | Description                                                  | Type   | Required - Yes/No | Default Value |
| :--------------- | :------------------------------------ | :----------------------------------------------------------- | :----- | :---------------- | :------------ |
| client-id        | 519bff95-bcf4-gvdf-vdf83-850360c34dg6 | Client ID taken from Oxeye's **Admin Settings**              | String | Yes               | N/A           |
| secret           | 3432a392-345g-44bc-b3d6-bb1gr83dg2c7  | Secret key taken from Oxeye's **Admin Settings**             | String | Yes               | N/A           |
| observer-name    | my_observer                           | Observer name                                                | String | Yes               | N/A           |
| application-name | my_app                                | Application name                                             | String | Yes               | N/A           |
| tag              | my_release                            | The release tag being tested                                 | String | Yes               | N/A           |
| command          | start / status / results              | Oxeye CI/CD command                                          | String | Yes               | N/A           |

## Workflow Summary

A GitHub Actions workflow that has Oxeye Observer integrated with it consists of the following steps:

1. Calling Oxeye GitHub Action with a command to start scanning the application using Observer. (Command: `start`)
2. Deploying your application.
3. Running application tests.
4. Scanning your application with Oxeye Observer.
5. Calling Oxeye GitHub Action with a command to return status once the scan is complete or reaches timeout. (Command: `status`; the status can be **Done** or **Timed Out**.)
6. Once a scan is complete, the results are available for review in GitHub as a table including the number of issues found for each severity. (Command: `results`)

This process takes place every time you deploy a new application release.

## Workflow Example

```
name: Staging deploy and test
on: push
jobs:
  workflow:
    runs-on: ubuntu-latest
    steps:

      - name: Deploy observer (can be done once - not needed as and integral part of this workflow)
        uses: an action using oxeye deployment file
      ...
      - name: Start Oxeye release
        uses: oxeye/github-action@main
        with:
          command: start
          client-id: "519bff95-bcf4-gvdf-vdf83-850360c34dg6"
          secret: "3432a392-345g-44bc-b3d6-bb1gr83dg2c7"
          observer-name: "observer-cicd-test"
          application-name: "observer-cicd-test"
          tag: "observer-cicd-test1"

      - name: Deploy application
        uses: an action to deploy the application

      - name: Application Testing
        uses: an action to run tests

      - name: Check Oxeye Release status
        uses: oxeye/github-action@main
        with:
          command: status
          client-id: "519bff95-bcf4-gvdf-vdf83-850360c34dg6"
          secret: "3432a392-345g-44bc-b3d6-bb1gr83dg2c7"
          observer-name: "observer-cicd-test"
          application-name: "observer-cicd-test"
          tag: "observer-cicd-test1"

      - name: Check Oxeye Release Get Results
        uses: oxeye/github-action@main
        with:
          command: results
          client-id: "519bff95-bcf4-gvdf-vdf83-850360c34dg6"
          secret: "3432a392-345g-44bc-b3d6-bb1gr83dg2c7"
          observer-name: "observer-cicd-test"
          application-name: "observer-cicd-test"
          tag: "observer-cicd-test1"
```

## GitHub Code Scanning support

The Vulnerabilites viewed in GitHub Security tab by integrating with Github Code Scanning,
by adding the following simple step to the workflow after the Oxeye Github Action (Command: `results`)

```
name: Staging deploy and test
on: push
jobs:
  workflow:
    runs-on: ubuntu-latest
    steps:
    ...
      - name: Upload Oxeye Security results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: oxeye.sarif
```