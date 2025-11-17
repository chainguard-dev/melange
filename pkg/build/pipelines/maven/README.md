<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [maven/configure-mirror](#mavenconfigure-mirror)
- [maven/pombump](#mavenpombump)

## maven/configure-mirror

Configure GCP Maven Central mirror for faster downloads

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## maven/pombump

Run pombump tool to analyze and update versions and properties in a Maven POM file

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| analyze-patch-file | false | Patch file to analyze for recommendations  |  |
| analyze-patches | false | Space-separated list of patches to analyze (groupID@artifactID@version) for recommendations  |  |
| debug | false | Enable debug mode, which will print out the diffs of the pom.xml file after running pombump (patch mode) or detailed analysis (analyze mode)  | false |
| dependencies | false | Dependencies to be used for updating the POM file via command line flag  |  |
| fail-on-bom-conflicts | false | Fail if attempting to patch dependencies controlled by BOMs (analyze mode). Only use for strict BOM enforcement.  | false |
| generate-patch-files | false | Generate recommended patch files from analysis (creates pombump-deps.yaml and pombump-properties.yaml)  | false |
| json-output-file | false | File to save JSON analysis output (analyze mode only)  |  |
| mode | false | Mode of operation: 'patch' to apply changes, 'analyze' to analyze POM and get recommendations  | patch |
| output-deps | false | Output file for recommended dependency patches (analyze mode)  | ./pombump-deps.yaml |
| output-format | false | Output format for analysis: human, json, or yaml  | human |
| output-properties | false | Output file for recommended property patches (analyze mode)  | ./pombump-properties.yaml |
| patch-file | false | Patches file to use for updating the POM file  | ./pombump-deps.yaml |
| pom | false | Path to pom.xml  | pom.xml |
| properties | false | Properties to update / add the POM file via command line flag  |  |
| properties-file | false | Properties file to be used for updating the POM file  | ./pombump-properties.yaml |
| search-properties | false | Search for properties in parent POMs and modules (analyze mode only)  | false |
| show-dependency-tree | false | Display a dependency tree for the existing pom.xml file | false |


<!-- end:pipeline-reference-gen -->