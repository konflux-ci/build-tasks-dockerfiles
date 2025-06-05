# Script for Contextual SBOM Creation

[This script is WIP.]

## Implemented steps:

### 1. Parent image content is downloaded 
The parent image is identified, runtime architecture is identified and parent
image content is downloaded. The script determines the contextual mechanism will
be used based on presence of the parent image content and its format.

### 2. Downloaded parent image content is processed
<br>

#### Dictionary
**Component image content** - the content of the final component to produced by the
konflux build. This step does not produce component image content, only assumes
that it will be produced and mocks it part for manual testing purposes.<br>
<br>
**Parent image content** - the content of the parent image that was downloaded, and
it is modified by this step.<br>
<br>
**Grandparent image content** - the parent content of the aforementioned downloaded
parent. Parent image is expected to be identified by `package.annotations.comment`:
`{"name":"konflux:container:is_base_image","value":"true"}` . Content may or may not
be identifiable based on the fact if this downloaded parent was or was not
contextualized. If it was contextualized, it will have a `DESCENDANT_OF` of its parent
(**grandgrandparent**).<br>
<br>

#### Overview of the implementation

This must be done to differentiate between component and parent image content.
This modification logic already works with the assumption that matching logic
exist and parent content that is downloaded might be contextualized. At its
build time (contextual or non-contextual), parent image is just another
component using `SPDXRef-image` value as self-reference. If we use it as a
parent during build of the another component, and we download its content
during build of this component, we need to modify parent content to differentiate
it from the upcoming component content.
Set of steps has been implemented for this purpose:
1. **Translation legacy `BUILD_TOOL_OF` into `DESCENDANT_OF` relationship for
parent image content.**<br>
If parent image content bears a base image annotation placed in
`package.annotations.comment` which equals to
`{"name":"konflux:container:is_base_image","value":"true"}`
`BUILD_TOOL_OF` relationship associated with this parent image will be translated
into `DESCENDANT_OF` relationship.
*We just established a proper relationship between parent of this parent (parent
image and grandparent image).*
No edit is done, when this parent image si built from scratch or oci-archive,
or parent SBOM is missing aforementioned `package.annotations.comment` for any
other reason (like SBOM was not produced by konflux?) OR when the parent image
content already has a `DESCENDANT_OF` relationship set - it was contextualized.
This is a sanitation step ensuring that legacy-produced parent content follows
rules of the contextual SBOM ending up with that parent is properly bounded by
`DESCENDANT_OF` relationship to its grandparent image, before final contextual
component content is created. Expected transformation (legacy and/or non-contextual
parent SBOM):
    ```
    from

    {
     "spdxElementId": "SPDXRef-image-registry.access.redhat.com/ubi9", # grandparent image
     "relationshipType": "BUILD_TOOL_OF",
     "relatedSpdxElement": "SPDXRef-image" # this downloaded parent image
    }

    to

    {
     "spdxElementId": "SPDXRef-image", # this downloaded parent image
     "relationshipType": "DESCENDANT_OF",
     "relatedSpdxElement": "SPDXRef-image-registry.access.redhat.com/ubi9", # grandparent image
    }
    ```
2. **Translation of the self-reference `SPDXRef-image` in downloaded parent content
to parent name acquired from component**<br>
Every `spdxElementId` field in relationship in parent image content containing
`spdxElementId: SPDXRef-image` and `relationshipType: CONTAINS` is edited to bear
name of the parent image acquired from the component content. Why from there?
Because in component content (not shown in examples) has typically for this parent
already distinctive name instead of general `SPDXRef-image` because component is
already referencing it by its `DESCENDANT_OF` relationship (implemented in ISV-5858).
*This step intends to explicitly differentiate the parent image content from
the component image content.*
Expected transformation (example displaying piece of relationships of the legacy
non-contextual parent SBOM) assuming that parent image name obtained from built
component is "parent-name-in-component-content":
    ```
    from

    { # grandparent package but we don't know that becuse this SBOM is legacy and/or it was not contextualized
     "spdxElementId": "SPDXRef-image", # this downloaded parent image
     "relationshipType": "CONTAINS",
     "relatedSpdxElement": "SPDXRef-grandparent-package"
    },
    { # parent package but we don't know that becuse this SBOM is legacy and/or it was not contextualized
     "spdxElementId": "SPDXRef-image", # this downloaded parent image
     "relationshipType": "CONTAINS",
     "relatedSpdxElement": "SPDXRef-parent-package"
    },
    { # DESCENDANT_OF acquired in previous step
     "spdxElementId": "SPDXRef-image", # this downloaded parent image
     "relationshipType": "DESCENDANT_OF",
     "relatedSpdxElement": "SPDXRef-image-registry.access.redhat.com/ubi9", # grandparent image
    }
    
    to 
    
    { # parent content (we cannot differentiate grandparent, because as said this parent SBOM was not contextualized)
     "spdxElementId": "SPDXRef-parent-name-in-component-content", # this downloaded parent image - name from component
     "relationshipType": "CONTAINS",
     "relatedSpdxElement": "SPDXRef-grandparent-package"
    },
    { # parent content
     "spdxElementId": "SPDXRef-parent-name-in-component-content", # this downloaded parent image - name from component
     "relationshipType": "CONTAINS",
     "relatedSpdxElement": "SPDXRef-parent-package"
    },
    {
     "spdxElementId": "SPDXRef-parent-name-in-component-content", # this downloaded parent image - name from component
     "relationshipType": "DESCENDANT_OF",
     "relatedSpdxElement": "SPDXRef-image-registry.access.redhat.com/ubi9",
    }
    ```
    Expected transformation (example displaying piece of relationships of the
    contextualized parent SBOM) assuming that parent image name obtained from built
    component:
    ```
    from

    { # grandparent package and we know that because this SBOM was contextualized
      and this package has already proper relationship set with its source
      "spdxElementId": "registry.access.redhat.com/ubi8", # grandgrandparent image
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-grandparent-package"
    },
    { # parent package and we know that because this SBOM was contextualized
      "spdxElementId": "SPDXRef-image", # this downloaded parent image
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-parent-package"
    },
    { 
      "spdxElementId": "SPDXRef-image-registry.access.redhat.com/ubi9", # grandparent image
      "relationshipType": "DESCENDANT_OF",
      "relatedSpdxElement": "registry.access.redhat.com/ubi8", # grandgrandparent image
    }
    { # DESCENDANT_OF already set in parent content because it was contextualized
      "spdxElementId": "SPDXRef-image", # this downloaded parent image
      "relationshipType": "DESCENDANT_OF",
      "relatedSpdxElement": "SPDXRef-image-registry.access.redhat.com/ubi9", # grandparent image
    }
    
    to 
    
    { # unchanged! grandparent content
      "spdxElementId": "registry.access.redhat.com/ubi8",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-grandparent-package"
    },
    { # parent component content
      "spdxElementId": "SPDXRef-parent-name-in-component-content", # this downloaded parent image - name from component
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-parent-package"
    },
    {
      "spdxElementId": "SPDXRef-image-registry.access.redhat.com/ubi9",
      "relationshipType": "DESCENDANT_OF",
      "relatedSpdxElement": "registry.access.redhat.com/ubi8",
    }
    {
      "spdxElementId": "SPDXRef-parent-name-in-component-content", # this downloaded parent image - name from component
      "relationshipType": "DESCENDANT_OF",
      "relatedSpdxElement": "SPDXRef-image-registry.access.redhat.com/ubi9",
    }
    ```

Next steps are not implemented yet:
- remove builders from `packages` and `relationships` fields
- remove SPDXRef-document DESCRIBES relationships SPDXRef-image
relationship before parent will be merged with component content
- SPIKE explore other relationships that might occur (e.g. OTHER)
- matching mechanism between parent SPDXRef-image and component
SPDXRef-image packages
