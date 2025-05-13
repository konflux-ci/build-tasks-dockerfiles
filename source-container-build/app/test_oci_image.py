import hashlib
import os
import shutil
import tarfile
import tempfile
import unittest

from contextlib import ExitStack
from pathlib import Path
from typing import Final
from source_build import Blob, DescriptorT, OCIImage, BSILayer, Layer
from test_source_build import create_blob
from test_utils import create_layer_archive, create_simple_oci_image
from unittest.mock import Mock


class TestBlob(unittest.TestCase):
    """Test class Blob"""

    def setUp(self):
        self.image_dir = tempfile.mkdtemp()
        self.descriptor = create_blob(self.image_dir, [b"binary data"], "config")
        self.oci_image = OCIImage(self.image_dir)
        self.blob = Blob(self.oci_image, self.descriptor)

    def tearDown(self):
        shutil.rmtree(self.image_dir)

    def test___eq__(self):
        tests: list[tuple[Blob | str, bool]] = [
            ("an object", False),
            (Blob(self.oci_image, self.descriptor.copy()), True),
            (
                Blob(
                    self.oci_image,
                    {
                        "mediaType": self.descriptor["mediaType"],
                        "digest": self.descriptor["digest"] + "1",
                        "size": self.descriptor["size"],
                    },
                ),
                False,
            ),
            (
                Blob(
                    self.oci_image,
                    {
                        "mediaType": self.descriptor["mediaType"],
                        "digest": self.descriptor["digest"],
                        "size": self.descriptor["size"],
                        "annotations": {"type": "build"},
                    },
                ),
                False,
            ),
        ]
        for other_blob, expected in tests:
            eq = self.blob == other_blob
            self.assertEqual(expected, eq)

    def test_raw_content(self):
        content = self.blob.raw_content
        self.assertTrue(isinstance(content, bytes))
        self.assertEqual(id(content), id(self.blob.raw_content))

    def test_to_python(self):
        obj = self.blob.to_python
        self.assertTrue(isinstance(obj, bytes))
        self.assertEqual(id(obj), id(self.blob.raw_content))

    def test_delete(self):
        self.blob.delete()
        self.assertFalse(self.blob.path.exists())

    def test_save_content_has_not_been_read(self):
        blob = Blob(self.oci_image, self.descriptor)
        new_blob = blob.save()
        self.assertEqual(id(blob), id(new_blob))

    def test_save_content_is_updated(self):
        self.blob.raw_content = b"ab"
        new_blob = self.blob.save()
        self.assertNotEqual(id(self.blob), id(new_blob))
        self.assertEqual(b"ab", new_blob.path.read_bytes())
        self.assertEqual(self.blob.descriptor["mediaType"], new_blob.descriptor["mediaType"])
        self.assertNotEqual(self.blob.descriptor["digest"], new_blob.descriptor["digest"])
        self.assertNotEqual(self.blob.descriptor["size"], new_blob.descriptor["size"])

    def test_save_content_is_not_updated(self):
        new_blob = self.blob.save()
        self.assertEqual(id(self.blob), id(new_blob))
        self.assertEqual(self.blob.descriptor["mediaType"], new_blob.descriptor["mediaType"])
        self.assertEqual(self.blob.descriptor["digest"], new_blob.descriptor["digest"])
        self.assertEqual(self.blob.descriptor["size"], new_blob.descriptor["size"])


class TestManifest(unittest.TestCase):
    """Test Manifest blob class"""

    def setUp(self):
        self.oci_image_path = tempfile.mkdtemp(prefix="test_manifest-")
        create_simple_oci_image(
            self.oci_image_path,
            [
                ("libxml2-0.2-1.el9.src.rpm", b"0101", "rpm_dir"),
                ("flask-1.0.tar.gz", b"1010", "extra_src_dir"),
            ],
        )
        oci_image = OCIImage(self.oci_image_path)
        self.manifest = oci_image.index.manifests()[0]

        self.parent_image_path = tempfile.mkdtemp(prefix="tes_manifest_parent_image-")
        create_simple_oci_image(
            self.parent_image_path,
            [
                ("requests-1.23-7.el9.src.rpm", b"110110", "rpm_dir"),
                ("pytest-4.0.tar.gz", b"001001", "extra_src_dir"),
            ],
        )
        oci_image = OCIImage(self.parent_image_path)
        self.parent_image_manifest = oci_image.index.manifests()[0]

    def tearDown(self):
        shutil.rmtree(self.oci_image_path)

    def test_save_when_no_change_to_both_config_and_layers(self):
        # Save directly without any change to config or layers
        new_manifest = self.manifest.save()
        self.assertEqual(new_manifest, self.manifest)
        self.assertEqual(id(new_manifest), id(self.manifest))

    def test_save_when_config_is_updated(self):
        self.manifest.config.to_python["architecture"] = "amd64"
        new_manifest = self.manifest.save()
        self.assertNotEqual(id(new_manifest), id(self.manifest))
        self.assertEqual(new_manifest.config.to_python["architecture"], "amd64")

    def test_save_when_layer_is_changed(self):
        layer = self.manifest.layers[0]
        layer.raw_content += b"new binary data"
        new_manifest = self.manifest.save()
        self.assertNotEqual(new_manifest, self.manifest)
        self.assertNotEqual(id(new_manifest), id(self.manifest))
        self.assertEqual(new_manifest.layers[0].raw_content, layer.raw_content)

    def test_save_layer_without_blob_file(self):
        self.manifest.layers[0].path.unlink()
        with self.assertRaisesRegex(ValueError, expected_regex=""):
            self.manifest.save()

    def test_save_when_prepend_one_and_modify_an_existing_one(self):
        layer: Final = self.manifest.layers[0]
        layer.raw_content += b"new binary data"

        parent_image_layers = self.parent_image_manifest.layers

        parent_image_layer = parent_image_layers[1]
        digest = parent_image_layer.descriptor["digest"]
        shutil.copyfile(parent_image_layer.path, Path(self.oci_image_path, "blobs", *digest.split(":")))
        self.manifest.prepend_layer(parent_image_layer)

        parent_image_layer = parent_image_layers[0]
        digest = parent_image_layer.descriptor["digest"]
        shutil.copyfile(parent_image_layer.path, Path(self.oci_image_path, "blobs", *digest.split(":")))
        self.manifest.prepend_layer(parent_image_layer)

        new_manifest = self.manifest.save()

        self.assertListEqual(new_manifest.layers[0:2], parent_image_layers)
        for layer in new_manifest.layers:
            self.assertTrue(layer.path.exists())

        expected = layer.raw_content
        self.assertEqual(new_manifest.layers[-1].raw_content, expected)

    def test_remove_layer_is_not_found(self):
        layer = self.manifest.layers[-1]
        layer.raw_content += b"101010"
        new_layer = layer.save()
        digest = new_layer.descriptor["digest"]
        with self.assertRaisesRegex(ValueError, expected_regex=f"Layer with digest {digest} does not exist"):
            self.manifest.remove_layer(new_layer)

    def test_remove_layer(self):
        layer = self.manifest.layers[-1]
        self.manifest.remove_layer(layer)
        new_manifest = self.manifest.save()

        self.assertNotEqual(new_manifest, self.manifest)


class TestIndex(unittest.TestCase):

    def setUp(self):
        self.oci_image_path = tempfile.mkdtemp(prefix="test-index-")
        create_simple_oci_image(self.oci_image_path, [("libxml2-0.2-1.el9.src.rpm", b"0101", "rpm_dir")])
        self.oci_image = OCIImage(self.oci_image_path)

    def tearDown(self):
        shutil.rmtree(self.oci_image_path)

    def test_get_manfiests(self):
        manifests = self.oci_image.index.manifests()
        self.assertEqual(len(manifests), 1)
        self.assertTrue(manifests[0].path.exists())

        manifests_2 = self.oci_image.index.manifests()
        self.assertEqual(id(manifests), id(manifests_2))

    def test_save(self):
        manifest = self.oci_image.index.manifests()[0]
        manifest.config.to_python["architecture"] = "amd64"
        self.oci_image.index.save()

        new_manifest = self.oci_image.index.manifests()[0]
        self.assertNotEqual(manifest.descriptor["digest"], new_manifest.descriptor["digest"])
        self.assertEqual(new_manifest.config.to_python["architecture"], "amd64")


class TestBSILayer(unittest.TestCase):
    """Test BSILayer"""

    SRPM_NAME: Final = "requests-1.0.src.rpm"
    SRPM_CONTENT: Final = b"01010110"

    PIP_REQUESTS: Final = "requests-2.31.0.tar.gz"
    PIP_REQUESTS_CONTENT: Final = b"10101010"

    PIP_FLASK: Final = "flask-1.0.1.tar.gz"
    PIP_FLASK_CONTENT: Final = b"00011100"

    def setUp(self) -> None:
        self.work_dir = tempfile.mkdtemp(prefix="test-bsi-layer-")

    def tearDown(self) -> None:
        shutil.rmtree(self.work_dir)

    def _create_broken_tar_archive(self, missing_blob=True, missing_symlink=True) -> str:
        content_dir: Final = tempfile.mkdtemp(dir=self.work_dir)
        origin_dir: Final = os.path.realpath(os.curdir)
        os.chdir(content_dir)

        fd, layer_archive = tempfile.mkstemp(dir=self.work_dir, prefix="layer-archive-")
        os.close(fd)

        with ExitStack() as stack:
            stack.callback(os.chdir, origin_dir)

            if not missing_blob:
                Path("blobs", "sha256").mkdir(parents=True)
                blob_file = Path("blobs", "sha256", "1234")
                blob_file.write_bytes(b"000111")

            blob_file = Path("..", "blobs", "sha256", "4657")

            if not missing_symlink:
                os.mkdir("rpm_dir")
                Path("rpm_dir", "libxml2-2.0.src.rpm").symlink_to(blob_file)

            with tarfile.open(layer_archive, "w") as f:
                f.add(".")

        return layer_archive

    def _generate_layer_descriptor(self, layer_archive: str) -> DescriptorT:
        """Generate OCI descriptor from a file"""
        with open(layer_archive, "rb") as f:
            checksum = hashlib.file_digest(f, "sha256").hexdigest()
        file_size = os.stat(layer_archive).st_size
        return {"mediaType": "tar+gzip", "digest": f"sha256:{checksum}", "size": file_size}

    def _create_a_layer(self, layer_archive: str) -> Layer:
        """Create a simple OCI image with single layer

        :param layer_archive: str, path to a tar archive of a layer.
        """
        oci_image_dir = tempfile.mkdtemp(dir=self.work_dir)

        blob_dir = Path(oci_image_dir, "blobs", "sha256")
        blob_dir.mkdir(parents=True)

        layer_d = self._generate_layer_descriptor(layer_archive)
        dest = blob_dir / layer_d["digest"].removeprefix("sha256:")
        shutil.copyfile(layer_archive, dest)

        oci_image = Mock(path=oci_image_dir)
        return Layer(oci_image, layer_d)

    def test_get_symlink_and_blob_members_via_property(self):
        archive = create_layer_archive(self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir", work_dir=self.work_dir)
        layer = self._create_a_layer(archive)
        bsi_layer = BSILayer(layer)

        self.assertEqual(bsi_layer.symlink_member.name, f"./rpm_dir/{self.SRPM_NAME}")
        checksum = hashlib.sha256(self.SRPM_CONTENT).hexdigest()
        self.assertEqual(bsi_layer.blob_member.name, f"./blobs/sha256/{checksum}")

    def test__eq___type_mismatch(self):
        archive = create_layer_archive(self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir", work_dir=self.work_dir)
        layer = self._create_a_layer(archive)
        bsi_layer = BSILayer(layer)

        class MyBSILayer:
            pass

        self.assertNotEqual(bsi_layer, MyBSILayer())

    def test__eq__(self):
        tests = [
            (self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir"),
            (self.PIP_REQUESTS, self.PIP_REQUESTS_CONTENT, "extra_src_dir"),
        ]

        for params in tests:
            archive = create_layer_archive(*params, work_dir=self.work_dir)
            layer = self._create_a_layer(archive)
            bsi_layer = BSILayer(layer)

            archive = create_layer_archive(*params, work_dir=self.work_dir)
            layer = self._create_a_layer(archive)
            another_bsi_layer = BSILayer(layer)

            self.assertEqual(bsi_layer, another_bsi_layer)

    def test_not__eq__(self):
        tests = [
            (
                (self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir"),
                ("libxml2-0.2.src.rpm", b"000111", "rpm_dir"),
            ),
            (
                (self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir"),
                (self.SRPM_NAME, self.SRPM_CONTENT + b"0101010", "rpm_dir"),
            ),
            (
                (self.SRPM_NAME, self.SRPM_CONTENT, "rpm_dir"),
                (self.PIP_REQUESTS, self.PIP_REQUESTS_CONTENT, "extra_src_dir"),
            ),
            (
                (self.PIP_REQUESTS, self.PIP_REQUESTS_CONTENT, "extra_src_dir"),
                (self.PIP_FLASK, self.PIP_FLASK_CONTENT, "extra_src_dir"),
            ),
            (
                (self.PIP_REQUESTS, self.PIP_REQUESTS_CONTENT, "extra_src_dir"),
                (self.PIP_REQUESTS, self.PIP_REQUESTS_CONTENT + b"101010", "extra_src_dir"),
            ),
        ]

        for one_params, another_params in tests:
            archive = create_layer_archive(*one_params, work_dir=self.work_dir)
            layer = self._create_a_layer(archive)
            bsi_layer = BSILayer(layer)

            archive = create_layer_archive(*another_params, work_dir=self.work_dir)
            layer = self._create_a_layer(archive)
            another_bsi_layer = BSILayer(layer)

            self.assertNotEqual(bsi_layer, another_bsi_layer)

    def test_missing_symlink_member(self):
        archive = self._create_broken_tar_archive(missing_blob=False)
        layer = self._create_a_layer(archive)
        with self.assertRaisesRegex(ValueError, expected_regex="No symlink member is found"):
            BSILayer(layer)

    def test_missing_blob_member(self):
        archive = self._create_broken_tar_archive(missing_symlink=False)
        layer = self._create_a_layer(archive)
        with self.assertRaisesRegex(ValueError, expected_regex="No blob member is found"):
            BSILayer(layer)

    def test_symlink_member_does_not_link_to_blob_member(self):
        archive = self._create_broken_tar_archive(missing_blob=False, missing_symlink=False)
        layer = self._create_a_layer(archive)
        with self.assertRaisesRegex(ValueError, expected_regex=r"Symlink .+ does not link to"):
            BSILayer(layer)
