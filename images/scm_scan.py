import argparse
import json
import logging
import os
import shlex
import stat
import subprocess
import sys
import uuid
import re
from git import Repo
from enum import Enum
from typing import Any, Dict, Optional, TypedDict

import pydantic
import requests
from pydantic import BaseModel

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(message)s %(levelname)s %(pathname)s:%(lineno)s %(funcName)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)

logger = logging.getLogger(__name__)


class LightzPreSignedURLs(BaseModel):
    script: str
    config: str


class Provider(Enum):
    GitHub = "github"
    GitLab = "gitlab"
    Jenkins = "jenkins"


REMOTE_URL_REGEX = re.compile(r"(git@|https://)(.*)(:|/)(.*)/(.*)\.git")

# Setup Parameters
class RepositoryParameters(TypedDict):
    provider: str
    server_url: str
    organization: str
    name: str
    description: str
    license: str
    branch: str
    languages: str
    run_id: str
    workdir: str
    arch: str


# GENERAL
SCM_LOG_FILE = "/tmp/scm.log"

# Syft Parameters
SYFT_VERSION = "v0.70.0"
SYFT_INSTALL_FILE_URL = (
    f"https://raw.githubusercontent.com/anchore/syft/main/install.sh"
)
SYFT_INSTALL_FILE_LOCAL = f"/tmp/install_syft.sh"
SYFT_INSTALL_FILE_CMD = f"{SYFT_INSTALL_FILE_LOCAL} -b /usr/local/bin {SYFT_VERSION}"
SYFT_SBOM_FILE = f"/app/oxeye.sbom"

# Lightz Parameters
LIGHTZ_VERSION = "v1.0.3"
LIGHTZ_BINARY_LOCAL = f"/app/lightz-aio"
LIGHTZ_CONFIG_LOCAL = f"/app/lightz-aio.yaml"
LIGHTZ_SARIF_FILE = f"/app/oxeye.sarif"


def parse_arguments() -> argparse.Namespace:
    argument_parser = argparse.ArgumentParser()

    argument_parser.add_argument("--host", required=True, type=str)
    argument_parser.add_argument("--repo-token", required=True, type=str)
    argument_parser.add_argument("--client-id", required=True, type=str)
    argument_parser.add_argument("--secret", required=True, type=str)
    argument_parser.add_argument("--workspace-id", required=True, type=str)
    argument_parser.add_argument("--release", required=True, type=str)
    argument_parser.add_argument("--excludes", required=False, type=str)

    return argument_parser.parse_args()


def get_repository_data(
    url: str, headers: Optional[Dict[str, str]] = None
) -> Optional[Dict[Any, Any]]:
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as err:
        logger.exception(f"Failed getting repository data {err=} {url=} {headers=}")
        return None

    return response.json()


def setup_github(
    github_api_url: str, github_repository: str, repo_token: str
) -> Optional[RepositoryParameters]:
    provider = Provider.GitHub.value
    headers = {"Authorization": f"token {repo_token}"}
    repository_data_url = f"{github_api_url}/repos/{github_repository}"
    if not (
        repository_data := get_repository_data(url=repository_data_url, headers=headers)
    ):
        return None
    if not (
        languages := get_repository_data(
            url=f"{repository_data_url}/languages", headers=headers
        )
    ):
        return None
    if not (server_url := os.getenv("GITHUB_SERVER_URL")):
        return None
    if not (organization := os.getenv("GITHUB_REPOSITORY_OWNER")):
        return None
    if not (repo := os.getenv("GITHUB_REPOSITORY")):
        return None
    if not (branch := os.getenv("GITHUB_REF_NAME")):
        return None
    if not (workdir := os.getenv("GITHUB_WORKSPACE")):
        return None
    if not (arch := os.getenv("RUNNER_ARCH")):
        return None

    description = repository_data.get("description", "None")
    license = repository_data.get("license", "None")
    run_id = str(uuid.uuid4())

    return RepositoryParameters(
        provider=provider,
        server_url=server_url,
        organization=organization,
        name=repo.removeprefix(f"{organization}/"),
        description=description if description else "None",
        license=license if license else "None",
        branch=branch,
        languages=json.dumps(languages),
        run_id=run_id,
        workdir=workdir,
        arch=arch,
    )


def setup_gitlab(
    gitlab_api_url: str, gitlab_project_id: str, repo_token: str
) -> Optional[RepositoryParameters]:
    provider = Provider.GitLab.value
    if not (
        repository_data := get_repository_data(
            url=f"{gitlab_api_url}/projects/{gitlab_project_id}?private_token={repo_token}"
        )
    ):
        return None
    if not (
        languages := get_repository_data(
            url=f"{gitlab_api_url}/projects/{gitlab_project_id}/languages?private_token={repo_token}"
        )
    ):
        return None
    if not (server_url := os.getenv("CI_SERVER_URL")):
        return None
    if not (organization := os.getenv("CI_PROJECT_NAMESPACE")):
        return None
    if not (repo := os.getenv("CI_PROJECT_NAME")):
        return None
    if ci_commit_branch := os.getenv("CI_COMMIT_BRANCH"):
        branch = ci_commit_branch
    elif ci_commit_ref_name := os.getenv("CI_COMMIT_REF_NAME"):
        branch = ci_commit_ref_name
    else:
        return None
    if not (workdir := os.getenv("CI_PROJECT_DIR")):
        return None
    if not (arch := os.getenv("CI_RUNNER_EXECUTABLE_ARCH")):
        return None
    description = repository_data.get("description", "None")
    license = repository_data.get("license", "None")
    run_id = str(uuid.uuid4())

    return RepositoryParameters(
        provider=provider,
        server_url=server_url,
        organization=organization,
        name=repo.removeprefix(f"{organization}/"),
        description=description if description else "None",
        license=license if license else "None",
        branch=branch,
        languages=json.dumps(languages),
        run_id=run_id,
        workdir=workdir,
        arch=arch,
    )


def setup_jenkins() -> Optional[RepositoryParameters]:
    provider = Provider.Jenkins.value
    if not (workdir := os.getenv("WORKSPACE")):
        return None
    if not (repo := Repo(workdir)).bare:
        return None
    if not (origin :=repo.remotes["origin"]):
        return None
    if len(urls:=list(origin.urls)) < 1:
        return None
    match_url = REMOTE_URL_REGEX.search(urls[0])
    if not match_url:
        return None
    server_url = f"https://{match_url.group(2)}"
    organization = match_url.group(4)
    name = match_url.group(5)
    run_id = str(uuid.uuid4())

    return RepositoryParameters(
        provider=provider,
        server_url=server_url,
        organization=organization,
        name=name,
        description="None",
        license="None",
        branch="branch",
        languages="{}",
        run_id=run_id,
        workdir=workdir,
        arch="",
    )


def setup(repo_token: str) -> Optional[RepositoryParameters]:
    if (github_api_url := os.getenv("GITHUB_API_URL")) and (
        github_repository := os.getenv("GITHUB_REPOSITORY")
    ):
        return setup_github(
            github_api_url=github_api_url,
            github_repository=github_repository,
            repo_token=repo_token,
        )
    elif (gitlab_api_url := os.getenv("CI_API_V4_URL")) and (
        gitlab_project_id := os.getenv("CI_PROJECT_ID")
    ):
        return setup_gitlab(
            gitlab_api_url=gitlab_api_url,
            gitlab_project_id=gitlab_project_id,
            repo_token=repo_token,
        )
    elif os.getenv("JENKINS_URL"):
        return setup_jenkins()

    logger.error(f"Error - could not determine environment. aborting...")
    return None


def get_authorization_token(host: str, client_id: str, secret: str) -> str:
    auth_url = f"https://{host}/api/auth/api-token"

    try:
        response = requests.post(
            auth_url, json={"clientId": client_id, "secret": secret}
        )
        response.raise_for_status()
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as err:
        logger.exception(f"Failed getting authorization token {err=} {auth_url=}")
        raise

    return str(response.text)


def get_lightz_presigned_urls(
    host: str, auth_token: str, arch: str, version: str
) -> LightzPreSignedURLs:
    url = f"https://{host}/api/scm/lightz?arch={arch}&version={version}"

    headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return LightzPreSignedURLs.model_validate(response.json())
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as err:
        logger.exception(f"Failed getting pre-signed urls {err=} {url=}")
        raise
    except pydantic.ValidationError as err:
        logger.exception(f"Failed parsing pre-signed urls response{err=} {url=}")
        raise


def download_file(url: str, local_filename: str) -> None:
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as err:
        logger.exception(f"Failed downloading file {err=} {url=}")
        raise

    try:
        with open(local_filename, "wb") as file:
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            except (IOError, OSError):
                logger.exception(f"Error writing to file {local_filename}")
                raise
    except (FileNotFoundError, PermissionError, OSError):
        logger.exception(f"Error opening file {local_filename}")
        raise

    try:
        os.chmod(local_filename, stat.S_IXUSR)
    except:
        logger.exception(f"Could not chmod {local_filename}")
        raise


def run_shell_cmd_with_log(cmd: str, err_msg: str) -> None:
    try:
        with open(SCM_LOG_FILE, "a") as log_file:
            try:
                subprocess.run(
                    cmd,
                    shell=True,
                    check=True,
                    stderr=log_file,
                    stdout=log_file,
                )

            except (subprocess.SubprocessError, subprocess.CalledProcessError):
                logger.exception(f"{err_msg} cmd={cmd}")
                raise
    except (FileNotFoundError, PermissionError, OSError):
        logger.exception(f"Error opening file {SCM_LOG_FILE}")
        raise


def run_shell_cmd_with_result(cmd: str, err_msg: str) -> str:
    try:
        with open(SCM_LOG_FILE, "a") as log_file:
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    check=True,
                    stderr=log_file,
                    stdout=subprocess.PIPE,
                )

            except (subprocess.SubprocessError, subprocess.CalledProcessError):
                logger.exception(f"{err_msg} cmd={cmd}")
                raise
    except (FileNotFoundError, PermissionError, OSError):
        logger.exception(f"Error opening file {SCM_LOG_FILE}")
        raise

    return result.stdout.decode()


def release_start(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    release: str,
) -> None:
    oxctl_cmd = (
        f"/app/oxctl release start "
        f"--host {host} "
        f"--client-id {client_id} "
        f"--secret {secret} "
        f"-a {workspace_id} "
        f"-t {release} "
    )
    run_shell_cmd_with_log(oxctl_cmd, "Failed Start Release")


def upload_result(
    upload_type: str,
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    release: str,
    repo_params: RepositoryParameters,
    file: str,
) -> None:
    oxctl_cmd = (
        f"/app/oxctl upload {upload_type} "
        f"--host {host} "
        f"--client-id {client_id} "
        f"--secret {secret} "
        f"--workspace {workspace_id} "
        f"--repository-provider '{repo_params['provider']}' "
        f"--repository-server-url '{repo_params['server_url']}' "
        f"--repository-organization '{repo_params['organization']}' "
        f"--repository-name '{repo_params['name']}' "
        f"--repository-description '{repo_params['description']}' "
        f"--repository-license '{repo_params['license']}' "
        f"--repository-branch '{repo_params['branch']}' "
        f"--repository-languages '{repo_params['languages']}' "
        f"--repository-run-id '{repo_params['run_id']}' "
        f"--repository-release-tag '{release}' "
        f"--file {file} "
    )
    run_shell_cmd_with_log(oxctl_cmd, "Failed Uploading Result")


def upload_file(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    release: str,
    repo_params: RepositoryParameters,
    entity_type: str,
    upload_file: str,
) -> None:
    oxctl_cmd = (
        f"/app/oxctl uploadURL "
        f"--host {host} "
        f"--client-id {client_id} "
        f"--secret {secret} "
        f"--workspace {workspace_id} "
        f"--repository-provider '{repo_params['provider']}' "
        f"--repository-server-url '{repo_params['server_url']}' "
        f"--repository-organization '{repo_params['organization']}' "
        f"--repository-name '{repo_params['name']}' "
        f"--repository-description '{repo_params['description']}' "
        f"--repository-license '{repo_params['license']}' "
        f"--repository-branch '{repo_params['branch']}' "
        f"--repository-languages '{repo_params['languages']}' "
        f"--repository-run-id '{repo_params['run_id']}' "
        f"--repository-release-tag '{release}' "
        f"--entity-type '{entity_type}' "
    )
    pre_signed_url = run_shell_cmd_with_result(
        oxctl_cmd,
        "Failed Uploading Result",
    )

    try:
        with open(upload_file, "rb") as file:
            try:
                requests.put(pre_signed_url, data=file)
            except (
                requests.exceptions.HTTPError,
                requests.exceptions.RequestException,
            ) as err:
                logger.exception(
                    f"Failed to upload file {pre_signed_url=} {err=}",
                )
    except (FileNotFoundError, PermissionError, OSError):
        logger.exception(f"Error opening upload_file: {upload_file}")
        raise


def download_syft() -> None:
    download_file(SYFT_INSTALL_FILE_URL, SYFT_INSTALL_FILE_LOCAL)
    run_shell_cmd_with_log(
        SYFT_INSTALL_FILE_CMD,
        "Failed installing Package Scanner",
    )


def execute_syft(repo_params: RepositoryParameters, output_file: str) -> None:
    syft_cmd = f"cd {repo_params['workdir']};" f"syft . -q -o spdx-json={output_file} "
    run_shell_cmd_with_log(syft_cmd, "Failed Running Package Scanner")


def run_syft(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    release: str,
    repo_params: RepositoryParameters,
) -> None:
    download_syft()
    execute_syft(
        repo_params=repo_params,
        output_file=SYFT_SBOM_FILE,
    )
    upload_file(
        host=host,
        client_id=client_id,
        secret=secret,
        workspace_id=workspace_id,
        release=release,
        repo_params=repo_params,
        entity_type="CodeScanSyftSPDX",
        upload_file=SYFT_SBOM_FILE,
    )


def download_lightz(
    host: str, client_id: str, secret: str, repo_params: RepositoryParameters
) -> None:
    auth_token = get_authorization_token(host, client_id, secret)

    pre_signed_urls: LightzPreSignedURLs = get_lightz_presigned_urls(
        host=host,
        auth_token=auth_token,
        arch=repo_params["arch"],
        version=LIGHTZ_VERSION,
    )

    download_file(pre_signed_urls.script, LIGHTZ_BINARY_LOCAL)
    download_file(pre_signed_urls.config, LIGHTZ_CONFIG_LOCAL)


def execute_lightz(
    repo_params: RepositoryParameters,
    output_file: str,
    excludes: str,
) -> None:
    logger.info(f"cwd = {os.getcwd}")
    lightz_cmd = (
        f"cd {repo_params['workdir']};"
        f"{LIGHTZ_BINARY_LOCAL} "
        f"--config {LIGHTZ_CONFIG_LOCAL} "
        f"--output {output_file} "
        f"{' '.join(['--exclude ' + shlex.quote(exclude) for exclude in shlex.split(excludes)])} "
        f"--target . "
    )
    run_shell_cmd_with_log(lightz_cmd, "Failed Running Source Code Scan")


def run_lightz(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    release: str,
    repo_params: RepositoryParameters,
    excludes: str,
) -> None:
    download_lightz(
        host=host, client_id=client_id, secret=secret, repo_params=repo_params
    )

    execute_lightz(
        repo_params=repo_params,
        output_file=LIGHTZ_SARIF_FILE,
        excludes=excludes,
    )

    upload_file(
        host=host,
        client_id=client_id,
        secret=secret,
        workspace_id=workspace_id,
        release=release,
        repo_params=repo_params,
        entity_type="CodeScanSemgrep",
        upload_file=LIGHTZ_SARIF_FILE,
    )


def main() -> None:
    arguments: argparse.Namespace = parse_arguments()
    repo_params: Optional[RepositoryParameters] = setup(repo_token=arguments.repo_token)
    if not repo_params:
        sys.exit(1)
    try:
        release_start(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            release=arguments.release,
        )
    except:
        sys.exit(2)
    try:
        run_syft(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            release=arguments.release,
            repo_params=repo_params,
        )
    except:
        sys.exit(3)
    try:
        run_lightz(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            release=arguments.release,
            repo_params=repo_params,
            excludes=arguments.excludes,
        )
    except:
        # Upload Log
        upload_file(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            release=arguments.release,
            repo_params=repo_params,
            entity_type="LightzAioLogs",
            upload_file=SCM_LOG_FILE,
        )
        sys.exit(4)




if __name__ == "__main__":
    main()
