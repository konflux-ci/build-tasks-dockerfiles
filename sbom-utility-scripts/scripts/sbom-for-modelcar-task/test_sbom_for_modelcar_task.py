import datetime
import json
import sys
import uuid
from pathlib import Path

import pytest
import sbom_for_modelcar_task

TEST_DATA: Path = Path(__file__).parent / "test_data"


@pytest.mark.parametrize("sbom_type", ["cyclonedx", "spdx"])
def test_main(sbom_type: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock out external factors for SPDX (randomness, date and time)
    monkeypatch.setattr(uuid, "uuid4", lambda: "a29a127a-daf6-44d3-a840-4eca194e9b41")
    monkeypatch.setattr(
        sbom_for_modelcar_task,
        "_datetime_utc_now",
        lambda: datetime.datetime(2025, 1, 14, 11, 46, 34, tzinfo=datetime.UTC),
    )

    MODELCAR_IMAGE = "repository.example.com/aipcc/modelcar-image:v1.0@sha256:cc6016b62f25d56507033c48b04517ba40b3490b1e9b01f1c485371311ed42c4"
    BASE_IMAGE = "repository.example.com/aipcc/base-image:v2.3@sha256:96fbb4c227d543011dfff0679a89ce664d1a009654858f2df28be504bc1863c1"
    MODEL_IMAGE = "repository.example.com/aipcc/model-image:v1.1@sha256:087dc7896b97911a582702b45ff1d41ffa3e142d0b000b0fbb11058188293cfc"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "__unused_script_name__",
            "--modelcar-image",
            MODELCAR_IMAGE,
            "--base-image",
            BASE_IMAGE,
            "--model-image",
            MODEL_IMAGE,
            "--sbom-type",
            sbom_type,
        ],
    )
    sbom_for_modelcar_task.main()
    out, _ = capsys.readouterr()

    got_sbom = json.loads(out)
    expect_sbom = json.loads(TEST_DATA.joinpath(f"{sbom_type}.json").read_text())
    assert got_sbom == expect_sbom
