# Oxeye SCAN Github Action

GitHub Action to detect source code vulnerabilities for Python, JavaScript and DOTNET
and find all packages used by in the source code and detect vulnerabilities if any in these packages

## Prerequisites

1. Oxeye Admin account
2. Oxeye API Token with CICD Role.
   The GitHub Action requires utilization of the token, client-id, and secret as inputs.
   These values can be conveyed as strings within the GitHub Action's parameters or can alternatively be securely stored within your repository's secrets for enhanced security.  

## Inputs

| Variable         | Description                                                  | Type   | Required | Default |
| :--------------- | :----------------------------------------------------------- | :----- | :------- | :------ |
| token            | Personal access token (PAT) used to fetch repo info          | String | Yes      |         |
| client-id        | API Token client ID created in Oxeye's console Admin Settings| UUID   | Yes      |         |
| secret           | API Token Secrets created in Oxeye's console Admin Settings  | UUID   | Yes      |         |
| workspace-id     | UUID of oxeye workspace you created in the Oxeye console     | UUID   | Yes      |         |
| release          | release tag                                                  | UUID   | No       |         |

## Workflow Summary

1. Checkout your source code
2. Run Oxeye github Oxeye-Scan action

## Workflow Example

```
name: Check for Vulnerabiliites
on:
  pull_request:

jobs:
  oxeye-scan:
    name: Oxeye SCAN
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Oxeye Scan
        uses: ox-eye/github-actions/oxeye-scan@v0.0.20
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          client-id: ${{ secrets.OXEYE_CICD_CLIENT_ID }}
          secret:  ${{ secrets.OXEYE_CICD_SECRET }}
          workspace-id: '6860b90d-99e1-4bd4-a93a-353da8aa932d'
          release: github.ref
```
