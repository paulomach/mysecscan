# generate vulnerability report from secscan tool


from subprocess import SubprocessError, check_output


def secscan_cmd(format: str, target: str, scanner: str, target_type: str = "package") -> list[str]:
    return [
        "secscan-client",
        "submit",
        "--scanner",
        scanner,
        "--type",
        target_type,
        "--format",
        format,
        "--wait-and-print",
        target,
    ]


def charm_scan(charms: dict, scanners: set) -> None:
    """Scan charms."""
    for charm_name, attributes in charms.items():
        file_name = f"./{charm_name}.charm"
        download_cmd = [
            "juju",
            "download",
            "--no-progress",
            f"--channel={attributes['channel']}",
            f"--filepath={file_name}",
            charm_name,
        ]
        try:
            print(f"Downloading {charm_name=}")
            check_output(download_cmd)
        except SubprocessError:
            print(f"Failed to download {charm_name=}. Skipping it")
            continue

        for scanner in scanners:
            try:
                print(f"Scanning {charm_name=} with {scanner=}")
                stdout = check_output(
                    secscan_cmd(format="charm", target=file_name, scanner=scanner), text=True
                )
            except SubprocessError:
                print(f"Failed to scan {charm_name=} using {scanner=}")
                continue

            with open(f"charm_{charm_name}_{scanner}.report", "w") as fd:
                fd.write(stdout)


def snap_scan(snaps: dict, scanners: set) -> None:
    for snap_name in snaps.keys():
        for scanner in scanners:
            print(f"Scanning {snap_name=} with {scanner=}")
            try:
                check_output(secscan_cmd(format="snap", target=snap_name, scanner=scanner))
            except SubprocessError:
                print(f"Failed to scan {snap_name=} using {scanner=}")
                continue


def oci_scan(rocks: dict, scanners: set) -> None:
    for image_name, attributes in rocks.items():
        tarball_name = f"./{image_name}.tar"
        pull_cmd = [
            "docker",
            "pull",
            attributes["registry"],
        ]
        save_cmd = [
            "docker",
            "save",
            "-o",
            tarball_name,
            attributes["registry"],
        ]
        try:
            print(f"Pulling {image_name=}")
            check_output(pull_cmd)
            print(f"Saving {image_name=} to tarball")
            check_output(save_cmd)
        except SubprocessError:
            print(f"Failed to pull or save {image_name=}. Skipping it")
            continue

        for scanner in scanners:
            try:
                print(f"Scanning {image_name=} with {scanner=}")
                stdout = check_output(
                    secscan_cmd(
                        format="oci",
                        target=tarball_name,
                        scanner=scanner,
                        target_type="container-image",
                    ),
                    text=True,
                )
            except SubprocessError:
                print(f"Failed to scan {image_name=} using {scanner=}")
                continue

            with open(f"oci_{image_name}_{scanner}.report", "w") as fd:
                fd.write(stdout)


if __name__ == "__main__":
    scanners = {"blackduck", "osv", "trivy"}

    print("Scanning charms")
    charms = {
        "mysql": {"channel": "8.0/edge"},
        "mysql-k8s": {"channel": "8.0/edge"},
        "mysql-router": {"channel": "dpe/edge"},
        "mysql-router-k8s": {"channel": "8.0/edge"},
    }
    charm_scan(charms, scanners)

    print("Scanning snaps")
    snaps = {
        "charmed-mysql": {"channel": "8.0/edge"},
    }
    snap_scan(snaps, scanners)

    print("Scanning OCI images")
    rocks = {"charmed-mysql": {"registry": "ghcr.io/canonical/charmed-mysql:8.0.41-22.04_edge"}}
    oci_scan(rocks, scanners)
