# Release notes for Cluster API Provider Huawei (CAPHW) <RELEASE_VERSION>

[Documentation](https://github.com/HuaweiCloudDeveloper/cluster-api-provider-huawei)

# Changelog since <PREVIOUS_VERSION>

{{with .NotesWithActionRequired -}}
## Urgent Upgrade Notes 

### (Important: Please read before upgrading)

{{range .}}{{println "-" .}} {{end}}
{{end}}

{{- if .Notes -}}
## Changes by Kind
{{ range .Notes}}
### {{.Kind | prettyKind}}

{{range $note := .NoteEntries }}{{println "-" $note}}{{end}}
{{- end -}}
{{- end }}

The images for this release are:
<ADD_IMAGE_HERE>

Thanks to all contributors.
