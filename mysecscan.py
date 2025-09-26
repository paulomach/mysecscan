# generate vulnerability report from secscan tool
# compatible with 25.10 cycle

from enum import StrEnum
import logging
import sys
from subprocess import SubprocessError, check_output
from typing import TypedDict

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
handler.setFormatter(formatter)

logger.addHandler(handler)


class TargetType(StrEnum):
    CHARM = "package"
    SNAP = "package"
    ROCK = "container-image"


class Artifact(TypedDict):
    format: str
    product_name: str
    version: str
    channel: str
    target_type: str


def secscan_cmd(
    artifact: Artifact,
    target: str,
    scanner: str,
    cycle: str,
) -> list[str]:
    """Render secscan command.

    Args:
        format: The format of the target (charm, snap, oci).
        target: The target to scan (file path or name).
        scanner: The scanner to use (blackduck, osv, trivy).
        target_type: The type of the target (default: package, or container-image for oci).
    """
    command = [
        "secscan-client",
        "submit",
        "--scanner",
        scanner,
        "--type",
        artifact["target_type"],
        "--format",
        artifact["format"],
        "--wait-and-print",
    ]

    if artifact["target_type"] != "container-image":
        # oci have no channel and ssdlc parameter need to be all set or none
        command.extend(
            [
                "--ssdlc-product-name",
                artifact["product_name"],
                "--ssdlc-cycle",
                cycle,
                "--ssdlc-product-version",
                artifact["version"],
                "--ssdlc-product-channel",
                artifact["channel"],
            ]
        )
    command.append(target)
    return command


def charm_scan(charms: list[Artifact], scanners: set, cycle: str) -> None:
    """Scan charms.

    Args:
        charms: List of charms to scan.
        scanners: Set of scanners to use.
        cycle: The SSDLc cycle to use.
    """
    for artifact in charms:
        charm_name = artifact["product_name"]
        file_name = f"./{charm_name}.charm"
        download_cmd = [
            "juju",
            "download",
            "--no-progress",
            f"--channel={artifact['channel']}",
            f"--filepath={file_name}",
            artifact["product_name"],
        ]
        try:
            logger.info(f"Downloading {charm_name=} from {artifact['channel']=}")
            check_output(download_cmd)
        except SubprocessError:
            logger.exception(f"Failed to download {charm_name}. Skipping it")
            sys.exit(1)

        for scanner in scanners:
            try:
                logger.info(f"Scanning {charm_name=} with {scanner=}")
                stdout = check_output(
                    secscan_cmd(artifact, target=file_name, scanner=scanner, cycle=cycle),
                    text=True,
                )
            except SubprocessError:
                logger.exception(f"Failed to scan {charm_name=} using {scanner=}")
                sys.exit(1)

            with open(f"charm_{charm_name}_{scanner}.report", "w") as fd:
                fd.write(stdout)


def snap_scan(snaps: list[Artifact], scanners: set, cycle: str) -> None:
    """Scan snaps.

    Args:
        snaps: List of snaps artifacts to scan.
        scanners: Set of scanners to use.
        cycle: The SSDLc cycle to use.
    """
    for snap in snaps:
        snap_name = snap["product_name"]
        for scanner in scanners:
            logger.info(f"Scanning {snap_name=} with {scanner=}")
            try:
                check_output(secscan_cmd(snap, target=snap_name, scanner=scanner, cycle=cycle))
            except SubprocessError:
                logger.exception(f"Failed to scan {snap_name=} using {scanner=}")
                sys.exit(1)


def oci_scan(rocks: list[Artifact], scanners: set, cycle: str) -> None:
    for rock in rocks:
        image_name = rock["product_name"]
        registry = rock["channel"]
        tarball_name = f"./{image_name}.tar"
        pull_cmd = [
            "docker",
            "pull",
            registry,
        ]
        save_cmd = [
            "docker",
            "save",
            "-o",
            tarball_name,
            registry,
        ]
        try:
            logger.info(f"Pulling {image_name=}")
            check_output(pull_cmd)
            logger.debug(f"Saving {image_name=} to tarball")
            check_output(save_cmd)
        except SubprocessError:
            logger.exception(f"Failed to pull or save {image_name=}. Skipping it")
            sys.exit(1)

        for scanner in scanners:
            try:
                logger.info(f"Scanning {image_name=} with {scanner=}")
                stdout = check_output(
                    secscan_cmd(
                        rock,
                        target=image_name,
                        scanner=scanner,
                        cycle=cycle,
                    ),
                    text=True,
                )
            except SubprocessError:
                logger.exception(f"Failed to scan {image_name=} using {scanner=}")
                sys.exit(1)

            with open(f"oci_{image_name}_{scanner}.report", "w") as fd:
                fd.write(stdout)


if __name__ == "__main__":
    scanners = {"blackduck", "osv", "trivy"}

    cycle = "25.10"
    logger.info("Scanning charms")
    charms: list[Artifact] = [
        {
            "product_name": "mysql",
            "channel": "8.0/edge",
            "version": "8.0",
            "format": "charm",
            "target_type": TargetType.CHARM,
        },
        {
            "product_name": "mysql-k8s",
            "channel": "8.0/edge",
            "version": "8.0",
            "format": "charm",
            "target_type": TargetType.CHARM,
        },
        {
            "product_name": "mysql-router",
            "channel": "dpe/edge",
            "version": "8.0",
            "format": "charm",
            "target_type": TargetType.CHARM,
        },
        {
            "product_name": "mysql-router-k8s",
            "channel": "8.0/edge",
            "version": "8.0",
            "format": "charm",
            "target_type": TargetType.CHARM,
        },
    ]
    charm_scan(charms, scanners, cycle)

    snaps: list[Artifact] = [
        {
            "product_name": "charmed-mysql",
            "channel": "8.0/edge",
            "version": "8.0",
            "format": "snap",
            "target_type": TargetType.SNAP,
        },
        {
            "product_name": "mysql",
            "channel": "8.0/edge",
            "version": "8.0",
            "format": "snap",
            "target_type": TargetType.SNAP,
        },
    ]

    logger.info("Scanning snaps")
    snap_scan(snaps, scanners, cycle)

    rocks: list[Artifact] = [
        {
            "product_name": "charmed-mysql",
            "channel": "ghcr.io/canonical/charmed-mysql:8.0.43-22.04_edge",
            "version": "8.0.43",
            "format": "oci",
            "target_type": TargetType.ROCK,
        },
        {
            "product_name": "mysql",
            "channel": "ghcr.io/canonical/mysql:8.0.43-24.04_edge",
            "version": "8.0.43",
            "format": "oci",
            "target_type": TargetType.ROCK,
        },
    ]
    logger.info("Scanning OCI images")
    oci_scan(rocks, scanners, cycle)
