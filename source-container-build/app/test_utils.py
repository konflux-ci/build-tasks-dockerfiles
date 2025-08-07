import functools
import gzip
import hashlib
import itertools
import os
import shutil
import tarfile

from pathlib import Path
from tarfile import TarInfo
from tempfile import mkdtemp, mkstemp
from typing import Final, Literal, TypedDict

from source_build import JSONBlob, HistoryT, StrPath, DescriptorT

BSISourceDriver = Literal["rpm_dir", "extra_src_dir"]

# Artifact name, artifact content, BSI source driver
LayerCreationParams = tuple[str, bytes, BSISourceDriver]

BlobTypeString = Literal["config", "manifest", "layer"]


class ManifestT(TypedDict):
    schemaVersion: int
    config: DescriptorT
    layers: list[DescriptorT]


def generate_extra_src_tar(artifact_name: str, content: bytes) -> str:
    """Create an extra-src tar archive with sample pip package

    Files used to construct the tar archive are created in current working
    directory.

    :return: path to the generated extra-src tar archive. That is a
        temporary file, caller can remove it after handling.
    """
    origin_dir: Final = os.path.realpath(os.curdir)
    content_dir: Final = mkdtemp(prefix="generate-extra-src-tar-")
    os.chdir(content_dir)
    fd, archive = mkstemp(prefix="fake-extra-src-tar-")
    os.close(fd)

    def _reset(member: TarInfo) -> TarInfo:
        """Do what BSI does"""
        member.uid = member.gid = 0
        member.uname = member.gname = "root"
        member.mtime = 0
        return member

    try:
        pkg_dir = Path("pip")
        pkg_dir.mkdir()
        pkg_file = Path("pip", artifact_name)
        pkg_file.write_bytes(content)

        # note: create uncompressed tar
        with tarfile.open(archive, "w") as f:
            f.add(".", filter=_reset)
    finally:
        os.chdir(origin_dir)
        shutil.rmtree(content_dir)
    return archive


extra_src_file_idx = itertools.cycle("01")


def create_layer_archive(
    artifact_name: str, content: bytes, source_driver: BSISourceDriver, work_dir: str | None = None
) -> str:
    """Create a layer archive including SRPM

    :return: the file path of the generated archive.
    """
    # will change back to current working directory
    origin_dir: Final = os.path.realpath(os.curdir)

    # archive construction happens inside this directory
    content_dir: Final = mkdtemp(prefix="layer-archive-construct-")
    os.chdir(content_dir)

    fd, layer_archive = mkstemp(prefix="layer-archive-", dir=work_dir)
    os.close(fd)

    extra_src_files = ["extra-src-0.tar", "extra-src-61a2c45.tar"]

    try:
        blob_dir = Path("blobs", "sha256")
        blob_dir.mkdir(parents=True)

        if source_driver == "rpm_dir":
            checksum = hashlib.sha256(content).hexdigest()
            blob_dir.joinpath(checksum).write_bytes(content)

            os.mkdir(source_driver)
            Path(source_driver, artifact_name).symlink_to(Path("..", "blobs", "sha256", checksum))
        elif source_driver == "extra_src_dir":
            extra_src_tar = generate_extra_src_tar(artifact_name, content)
            with open(extra_src_tar, "rb") as f:
                checksum = hashlib.file_digest(f, "sha256").hexdigest()
            shutil.copyfile(extra_src_tar, blob_dir.joinpath(checksum))
            os.unlink(extra_src_tar)

            os.mkdir(source_driver)
            extra_src_archive = extra_src_files[int(next(extra_src_file_idx))]
            Path(source_driver, extra_src_archive).symlink_to(Path("..", "blobs", "sha256", checksum))
        else:
            raise ValueError("Unknown source driver. This should not happen.")

        with tarfile.open(layer_archive, "w:gz") as tar:
            tar.add(".")
    finally:
        os.chdir(origin_dir)
        shutil.rmtree(content_dir)

    return layer_archive


def layer_diff_id(archive: str) -> str:
    with gzip.open(archive) as gz:
        return hashlib.file_digest(gz, "sha256").hexdigest()


def oci_image_media_types(blob_type: BlobTypeString) -> str:
    match blob_type:
        case "config":
            return "application/vnd.oci.image.config.v1+json"
        case "manifest":
            return "application/vnd.oci.image.manifest.v1+json"
        case "layer":
            return "application/vnd.oci.image.layer.v1.tar+gzip"
    raise ValueError(f"Unknown type: {blob_type}")


@functools.cache
def oci_image_blob_dir(path: StrPath, algorithm="sha256") -> Path:
    blob_dir = Path(path, "blobs", algorithm)
    blob_dir.mkdir(exist_ok=True, parents=True)
    return blob_dir


def oci_image_write_blob(image_path: StrPath, data: bytes | str, _type: BlobTypeString) -> DescriptorT:
    s = data if isinstance(data, bytes) else data.encode("utf-8")
    checksum = hashlib.sha256(s).hexdigest()
    size = oci_image_blob_dir(image_path).joinpath(checksum).write_bytes(s)
    mt = oci_image_media_types(_type)
    return {"mediaType": mt, "digest": f"sha256:{checksum}", "size": size}


def oci_image_add_layers(image_path: StrPath, layer_archives: list[str]) -> list[DescriptorT]:
    layers_d: list[DescriptorT] = []
    for archive in layer_archives:
        with open(archive, "rb") as f:
            checksum = hashlib.file_digest(f, "sha256").hexdigest()
        dest = Path(oci_image_blob_dir(image_path), checksum)
        shutil.copyfile(archive, dest)
        layers_d.append(
            {
                "mediaType": oci_image_media_types("layer"),
                "digest": f"sha256:{checksum}",
                "size": dest.stat().st_size,
            }
        )
    return layers_d


def create_simple_oci_image(path: str, layers_data: list[LayerCreationParams]) -> None:
    """Create an OCI image as output of a local source build

    :param path: str, create OCI image under this directory.
    :param layers_data: list of layer creation parameters. Each of them represents
        a single layer built by BSI with a specific driver. For details of the source
        drivers, please refer to ``-l`` option of BSI CLI.
    """
    layer_archives = [create_layer_archive(*params) for params in layers_data]
    diff_ids: list[str] = []
    history: list[HistoryT] = []
    for archive in layer_archives:
        diff_ids.append("sha256:" + layer_diff_id(archive))
        history.append({"created": "now", "created_by": "source-build test"})

    dumps = JSONBlob.compact_json_dumps
    config = dumps(
        {
            "config": {},
            "rootfs": {
                "type": "layers",
                "diff_ids": diff_ids,
            },
            "history": history,
        }
    )
    config_descriptor = oci_image_write_blob(path, config, "config")

    layers_d = oci_image_add_layers(path, layer_archives)
    manifest = dumps(
        {
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": layers_d,
        }
    )
    manifest_descriptor = oci_image_write_blob(path, manifest, "manifest")

    index_json = dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]})
    Path(path, "index.json").write_text(index_json.decode("utf-8"))
