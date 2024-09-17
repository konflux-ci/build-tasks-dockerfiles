import json

with open("./sbom-spdx.json") as f:
    spdx_sbom = json.load(f)

purls = []
for package in spdx_sbom["packages"]:
    for ref in package["externalRefs"]:
        if ref["referenceType"] == "purl":
            purls.append({"purl": ref["referenceLocator"]})

purl_content = {"image_contents": {"dependencies": purls}}

with open("sbom-purl.json", "w") as output_file:
    json.dump(purl_content, output_file, indent=4)
