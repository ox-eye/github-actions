import argparse
import logging
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import pydantic
import requests
from git import Repo
from pydantic import BaseModel

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(message)s %(levelname)s "
    "%(pathname)s:%(lineno)s %(funcName)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)

logger = logging.getLogger(__name__)

stop_keepalive_event: threading.Event = threading.Event()


class LightzPreSignedURLs(BaseModel):
    script: str
    config: str


class Provider(Enum):
    BitBucket = "bitbucket"
    GitHub = "github"
    GitLab = "gitlab"
    Jenkins = "jenkins"
    Azure = "azure"


REMOTE_URL_REGEX = re.compile(
    r"(git@|https?://)(.*?@|)(?P<server_url>.*?)(:|/)(?P<organization>.*?)/(?P<name>.*?)(\.git|$)"
)


class RepositoryError(Exception):
    """Base class for all package exceptions."""


class BareRepositoryError(RepositoryError):
    """Thrown if the repository is bare."""


class NoOriginRemoteRepositoryError(RepositoryError):
    """Thrown if the repository has no origin."""


class NoRemoteURLRepositoryError(RepositoryError):
    """Thrown if the repository remote has no url."""


class InvalidRemoteURLRepositoryError(RepositoryError):
    """Thrown if could not parse repository remote url."""


class RepositoryParameters:
    def __init__(
        self,
        workdir: str,
        provider: str,
        description: str,
        branch: str,
    ):
        repo = Repo(workdir)
        if not repo or repo.bare:
            logger.error(f"Got bare repository")
            raise BareRepositoryError
        if not (origin := repo.remotes["origin"]):
            logger.error(f"Could not get origin")
            raise NoOriginRemoteRepositoryError
        if len(urls := list(origin.urls)) < 1:
            logger.error(f"Could not get origin urls")
            raise NoRemoteURLRepositoryError
        match_url = REMOTE_URL_REGEX.search(urls[0])
        if not match_url:
            logger.error(f"Could not parse origin url")
            raise InvalidRemoteURLRepositoryError
        self.provider: str = provider
        self.server_url = f"https://{match_url.group('server_url')}"
        self.organization = match_url.group("organization")
        self.name = match_url.group("name")
        self.description = description
        self.branch = branch


class CicdToolParameters(TypedDict):
    provider: str
    arch: Optional[str]
    workdir: str
    description: str
    branch: str
    source_branch: str
    target_branch: str


# GENERAL
SCM_LOG_LOCATION = "/tmp/scm.log"
LIGHTZ_AIO_LOG_LOCATION = "/tmp/lightz-aio.log"
WORKDIR = "/app"

# Syft Parameters
SYFT_VERSION = "v0.99.0"
SYFT_INSTALL_FILE_URL = (
    f"https://raw.githubusercontent.com/anchore/syft/main/install.sh"
)
SYFT_INSTALL_FILE_LOCAL = f"/tmp/install_syft.sh"
SYFT_INSTALL_FILE_CMD = f"{SYFT_INSTALL_FILE_LOCAL} -b /usr/local/bin {SYFT_VERSION}"
SYFT_SBOM_FILE = f"{WORKDIR}/oxeye.sbom"

# Lightz Parameters
LIGHTZ_VERSION = "v1.0.3"
LIGHTZ_BINARY_LOCAL = f"{WORKDIR}/lightz-aio"
LIGHTZ_BINARY_LOCAL = f"{WORKDIR}/lightz-aio"
LIGHTZ_CONFIG_LOCAL = f"{WORKDIR}/lightz-aio.yaml"
LIGHTZ_SARIF_FILE = f"{WORKDIR}/oxeye.sarif"

# OXCTL
OXCTL_BINARY_LOCAL = f"{WORKDIR}/oxctl"


def parse_arguments() -> argparse.Namespace:
    argument_parser = argparse.ArgumentParser()

    argument_parser.add_argument(
        "--host",
        required=True,
        type=str,
    )
    argument_parser.add_argument(
        "--repo-token",
        required=True,
        type=str,
    )
    argument_parser.add_argument(
        "--client-id",
        required=True,
        type=str,
    )
    argument_parser.add_argument(
        "--secret",
        required=True,
        type=str,
    )
    argument_parser.add_argument(
        "--workspace-id",
        required=True,
        type=str,
    )
    argument_parser.add_argument(
        "--release", required=False, type=str, default="release"
    )
    argument_parser.add_argument(
        "--excludes",
        required=False,
        type=str,
        default="",
    )
    argument_parser.add_argument(
        "--partial",
        required=False,
        action="store_true",
    )

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

    return response.json()  # type:ignore


def setup_github(
    github_api_url: str, github_repository: str, repo_token: str
) -> Optional[CicdToolParameters]:
    headers = {"Authorization": f"token {repo_token}"}
    repository_data_url = f"{github_api_url}/repos/{github_repository}"
    if not (
        repository_data := get_repository_data(url=repository_data_url, headers=headers)
    ):
        return None
    if not (workdir := os.getenv("GITHUB_WORKSPACE")):
        return None
    if not (arch := os.getenv("RUNNER_ARCH")):
        return None

    cicd_tool_parameters = CicdToolParameters(
        provider=Provider.GitHub.value,
        arch=arch,
        workdir=workdir,
        description=repository_data.get("description", "None"),
        branch=os.environ.get("GITHUB_REF_NAME", "NA"),
        # source_branch=os.environ.get("GITHUB_HEAD_REF", ""),
        source_branch="test-schmil-2",
        # target_branch=os.environ.get("GITHUB_BASE_REF", ""),
        target_branch="test-schmil",
    )

    return cicd_tool_parameters


def setup_gitlab(
    gitlab_api_url: str, gitlab_project_id: str, repo_token: str
) -> Optional[CicdToolParameters]:
    if not (
        repository_data := get_repository_data(
            url=f"{gitlab_api_url}/projects/{gitlab_project_id}?private_token={repo_token}"
        )
    ):
        return None
    if not (workdir := os.getenv("CI_PROJECT_DIR")):
        return None
    if not (arch := os.getenv("CI_RUNNER_EXECUTABLE_ARCH")):
        return None

    cicd_tool_parameters = CicdToolParameters(
        provider=Provider.GitLab.value,
        arch=arch,
        workdir=workdir,
        description=repository_data.get("description", "None"),
        branch=os.environ.get("CI_COMMIT_REF_NAME", "NA"),
        source_branch=os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", ""),
        target_branch=os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", ""),
    )
    return cicd_tool_parameters


def setup_jenkins() -> Optional[CicdToolParameters]:
    if not (workdir := os.getenv("WORKSPACE")):
        logger.error(f"Could not get workspace")
        return None

    cicd_tool_parameters = CicdToolParameters(
        provider=Provider.Jenkins.value,
        arch=None,
        workdir=workdir,
        description="None",
        branch="NA",
        source_branch="",
        target_branch="",
    )
    return cicd_tool_parameters


def setup_azure() -> Optional[CicdToolParameters]:
    if not (workdir := os.getenv("BUILD_REPOSITORY_LOCALPATH")):
        logger.error(f"Could not get repository localpath")
        return None
    cicd_tool_parameters = CicdToolParameters(
        provider=Provider.Azure.value,
        arch=None,
        workdir=workdir,
        description="None",
        branch="NA",
        source_branch="",
        target_branch="",
    )

    return cicd_tool_parameters


def setup_bitbucket() -> Optional[CicdToolParameters]:
    if not (workdir := os.getenv("BITBUCKET_CLONE_DIR")):
        logger.error(f"Could not get repository localpath")
        return None

    cicd_tool_parameters = CicdToolParameters(
        provider=Provider.BitBucket.value,
        arch=None,
        workdir=workdir,
        description="None",
        branch="NA",
        source_branch="",
        target_branch="",
    )

    return cicd_tool_parameters


def setup(
    repo_token: str,
) -> Tuple[Optional[CicdToolParameters], Optional[RepositoryParameters]]:
    if (github_api_url := os.getenv("GITHUB_API_URL")) and (
        github_repository := os.getenv("GITHUB_REPOSITORY")
    ):
        cicd_tool_params = setup_github(
            github_api_url=github_api_url,
            github_repository=github_repository,
            repo_token=repo_token,
        )
    elif (gitlab_api_url := os.getenv("CI_API_V4_URL")) and (
        gitlab_project_id := os.getenv("CI_PROJECT_ID")
    ):
        cicd_tool_params = setup_gitlab(
            gitlab_api_url=gitlab_api_url,
            gitlab_project_id=gitlab_project_id,
            repo_token=repo_token,
        )
    elif "JENKINS_URL" in os.environ:
        cicd_tool_params = setup_jenkins()
    elif "BUILD_REPOSITORY_LOCALPATH" in os.environ:
        cicd_tool_params = setup_azure()
    elif "BITBUCKET_CLONE_DIR" in os.environ:
        cicd_tool_params = setup_bitbucket()
    else:
        logger.error(f"Error - could not determine environment. aborting...")
        return None, None

    if not cicd_tool_params:
        return None, None

    repo_params = RepositoryParameters(
        workdir=cicd_tool_params["workdir"],
        provider=cicd_tool_params["provider"],
        description=cicd_tool_params["description"],
        branch=cicd_tool_params["branch"],
    )

    return cicd_tool_params, repo_params


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
    host: str,
    auth_token: str,
    version: str,
    arch: Optional[str] = "amd64",
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


def run_shell_cmd_with_log(
    cmd: str,
    err_msg: str,
    cwd: Optional[str] = None,
    log_location: str = SCM_LOG_LOCATION,
) -> None:
    try:
        with open(log_location, "a") as log_file:
            try:
                subprocess.run(
                    cmd,
                    cwd=cwd,
                    shell=True,
                    check=True,
                    stderr=log_file,
                    stdout=log_file,
                )

            except (subprocess.SubprocessError, subprocess.CalledProcessError):
                logger.exception(f"{err_msg} cmd={cmd}")
                os.system(f"cat {log_location}")
                raise
    except (FileNotFoundError, PermissionError, OSError):
        logger.exception(f"Error opening file {log_location}")
        raise


def run_shell_cmd_with_result(
    cmd: str, err_msg: str, log_location: str = SCM_LOG_LOCATION
) -> str:
    try:
        with open(log_location, "a") as log_file:
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
        logger.exception(f"Error opening file {log_location}")
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
        f"{OXCTL_BINARY_LOCAL} release start "
        f"--host {host} "
        f"--client-id {client_id} "
        f"--secret {secret} "
        f"-a {workspace_id} "
        f"-t {release} "
    )
    run_shell_cmd_with_log(oxctl_cmd, "Failed Start Release")


def upload_file(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    cicd_tool_params: CicdToolParameters,
    repo_params: RepositoryParameters,
    run_id: str,
    release: str,
    entity_type: str,
    upload_file: str,
) -> None:
    oxctl_cmd = (
        f"{OXCTL_BINARY_LOCAL} uploadURL "
        f"--host {host} "
        f"--client-id {client_id} "
        f"--secret {secret} "
        f"--workspace {workspace_id} "
        f"--repository-provider '{repo_params.provider}' "
        f"--repository-server-url '{repo_params.server_url}' "
        f"--repository-organization '{repo_params.organization}' "
        f"--repository-name '{repo_params.name}' "
        f"--repository-description '{repo_params.description}' "
        f"--repository-license ' ' "
        f"--repository-branch '{repo_params.branch}' "
        f"--repository-languages {{}} "
        f"--repository-run-id '{run_id}' "
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


def send_keep_alive(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    provider: str,
) -> None:
    auth_token = get_authorization_token(host, client_id, secret)
    headers = {"Authorization": f"Bearer {auth_token}"}
    url = f"https://{host}/scm/keep-alive"
    scm_keepalive_dto = {"provider": provider, "workspaceId": workspace_id}

    while not stop_keepalive_event.wait(10):
        try:
            response = requests.post(url, headers=headers, data=scm_keepalive_dto)
        except requests.RequestException as e:
            logger.info("Failed to report keep-alive")


def exit_and_stop_keepalive(code: int, keep_alive_thread: threading.Thread) -> None:
    stop_keepalive_event.set()
    keep_alive_thread.join()
    sys.exit(code)


def download_syft() -> None:
    download_file(SYFT_INSTALL_FILE_URL, SYFT_INSTALL_FILE_LOCAL)
    run_shell_cmd_with_log(
        SYFT_INSTALL_FILE_CMD,
        "Failed installing Package Scanner",
    )


def execute_syft(
    workdir: str,
    excludes: str,
    output_file: str,
) -> None:
    syft_cmd = (
        f"syft . -q "
        f"{' '.join(['--exclude ' + shlex.quote(exclude) for exclude in shlex.split(excludes)])} "
        f"-o spdx-json={output_file}"
    )
    run_shell_cmd_with_log(
        cmd=syft_cmd,
        cwd=workdir,
        err_msg="Failed Running Package Scanner",
    )


def run_syft(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    cicd_tool_params: CicdToolParameters,
    repo_params: RepositoryParameters,
    run_id: str,
    release: str,
    excludes: str,
) -> None:
    download_syft()
    execute_syft(
        workdir=cicd_tool_params["workdir"],
        excludes=excludes,
        output_file=SYFT_SBOM_FILE,
    )
    upload_file(
        host=host,
        client_id=client_id,
        secret=secret,
        workspace_id=workspace_id,
        cicd_tool_params=cicd_tool_params,
        repo_params=repo_params,
        run_id=run_id,
        release=release,
        entity_type="CodeScanSyftSPDX",
        upload_file=SYFT_SBOM_FILE,
    )


def download_lightz(
    host: str,
    client_id: str,
    secret: str,
    arch: Optional[str],
) -> None:
    auth_token = get_authorization_token(host, client_id, secret)

    pre_signed_urls: LightzPreSignedURLs = get_lightz_presigned_urls(
        host=host,
        auth_token=auth_token,
        arch=arch,
        version=LIGHTZ_VERSION,
    )

    download_file(pre_signed_urls.script, LIGHTZ_BINARY_LOCAL)
    download_file(pre_signed_urls.config, LIGHTZ_CONFIG_LOCAL)


def get_changed_files(
    workdir: str,
    source_branch: Optional[str] = None,
    target_branch: Optional[str] = None,
) -> List[str]:
    changed_files = []
    temp_branch = "temp_branch"
    repo = Repo(workdir)
    current_sha = repo.head.object.hexsha
    repo.git.fetch()
    repo.git.checkout(source_branch)
    repo.git.checkout(b=temp_branch)
    head_commit = repo.head.commit
    repo.git.config("--global", "user.email", "dummy@dummy.com")
    repo.git.config("--global", "user.name", "Dummy")
    repo.git.merge(target_branch)
    diffs = head_commit.diff()
    for diff in diffs:
        changed_files.append(diff.b_path)
    repo.git.reset("--hard", current_sha)
    repo.git.checkout(source_branch)
    repo.git.branch("-D", temp_branch)

    return changed_files


def execute_lightz(
    workdir: str,
    output_file: str,
    excludes: str,
    partial: bool = False,
    source_branch: Optional[str] = None,
    target_branch: Optional[str] = None,
) -> None:
    partial_file = None
    if partial:
        changed_files = get_changed_files(
            workdir=workdir,
            source_branch=source_branch,
            target_branch=target_branch,
        )
        try:
            partial_file = tempfile.NamedTemporaryFile(mode="w", delete=True)
        except:
            return

        partial_file.write("\n".join(changed_files))
        partial_file.flush()

    lightz_cmd = (
        f"{LIGHTZ_BINARY_LOCAL} "
        f"--config {LIGHTZ_CONFIG_LOCAL} "
        f"--output {output_file} "
        f"{' '.join(['--exclude ' + shlex.quote(exclude) for exclude in shlex.split(excludes)])} "
    )
    if partial and partial_file:
        lightz_cmd = lightz_cmd + f"--scan-only-files-list-path {partial_file.name} "

    lightz_cmd = lightz_cmd + f"--target . "

    print(f"@@@@@@@@@@ {changed_files=}")
    os.system(f"echo #########################;cat {partial_file.name}")

    run_shell_cmd_with_log(
        cmd=lightz_cmd,
        cwd=workdir,
        err_msg="Failed Running Source Code Scan",
        log_location=LIGHTZ_AIO_LOG_LOCATION,
    )

    if partial_file:
        partial_file.close()


def run_lightz(
    host: str,
    client_id: str,
    secret: str,
    workspace_id: str,
    cicd_tool_params: CicdToolParameters,
    repo_params: RepositoryParameters,
    run_id: str,
    release: str,
    excludes: str,
    partial: bool = False,
) -> None:
    download_lightz(
        host=host,
        client_id=client_id,
        secret=secret,
        arch=cicd_tool_params["arch"],
    )

    execute_lightz(
        workdir=cicd_tool_params["workdir"],
        output_file=LIGHTZ_SARIF_FILE,
        excludes=excludes,
        partial=partial,
        source_branch=cicd_tool_params["source_branch"],
        target_branch=cicd_tool_params["target_branch"],
    )

    upload_file(
        host=host,
        client_id=client_id,
        secret=secret,
        workspace_id=workspace_id,
        cicd_tool_params=cicd_tool_params,
        repo_params=repo_params,
        run_id=run_id,
        release=release,
        entity_type="CodeScanSemgrep",
        upload_file=LIGHTZ_SARIF_FILE,
    )


def main() -> None:
    arguments: argparse.Namespace = parse_arguments()
    cicd_tool_params, repo_params = setup(
        repo_token=arguments.repo_token,
    )
    run_id = str(uuid.uuid4())
    if not cicd_tool_params or not repo_params:
        sys.exit(1)

    # start keep-alive
    keep_alive_thread = threading.Thread(
        target=send_keep_alive,
        args=(
            arguments.host,
            arguments.client_id,
            arguments.secret,
            arguments.workspace_id,
            repo_params.provider,
        ),
    )
    keep_alive_thread.daemon = True
    keep_alive_thread.start()

    try:
        release_start(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            release=arguments.release,
        )
    except:
        exit_and_stop_keepalive(2, keep_alive_thread)
    try:
        run_syft(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            cicd_tool_params=cicd_tool_params,
            repo_params=repo_params,
            run_id=run_id,
            release=arguments.release,
            excludes=arguments.excludes,
        )
    except:
        exit_and_stop_keepalive(3, keep_alive_thread)
    try:
        run_lightz(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            cicd_tool_params=cicd_tool_params,
            repo_params=repo_params,
            run_id=run_id,
            release=arguments.release,
            excludes=arguments.excludes,
            partial=arguments.partial,
        )
    except:
        # Upload Lightz AIO Log
        upload_file(
            host=arguments.host,
            client_id=arguments.client_id,
            secret=arguments.secret,
            workspace_id=arguments.workspace_id,
            cicd_tool_params=cicd_tool_params,
            repo_params=repo_params,
            run_id=run_id,
            release=arguments.release,
            entity_type="LightzAioLogs",
            upload_file=LIGHTZ_AIO_LOG_LOCATION,
        )
        exit_and_stop_keepalive(4, keep_alive_thread)
    # Upload Lightz AIO Log
    upload_file(
        host=arguments.host,
        client_id=arguments.client_id,
        secret=arguments.secret,
        workspace_id=arguments.workspace_id,
        cicd_tool_params=cicd_tool_params,
        repo_params=repo_params,
        run_id=run_id,
        release=arguments.release,
        entity_type="LightzAioLogs",
        upload_file=LIGHTZ_AIO_LOG_LOCATION,
    )

    exit_and_stop_keepalive(0, keep_alive_thread)


if __name__ == "__main__":
    main()
