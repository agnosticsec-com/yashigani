{{/*
  Yashigani Helm chart — template helpers.
  All named templates used across chart templates are defined here.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "yashigani.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars — Kubernetes name length limit.
*/}}
{{- define "yashigani.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label (name + version).
*/}}
{{- define "yashigani.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "yashigani.labels" -}}
helm.sh/chart: {{ include "yashigani.chart" . }}
{{ include "yashigani.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used for matchLabels in Deployments/Services.
*/}}
{{- define "yashigani.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yashigani.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name — uses the chart's own SA unless overridden.
*/}}
{{- define "yashigani.serviceAccountName" -}}
{{- if .Values.serviceAccount -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "yashigani.fullname" . -}}
{{- end -}}
{{- else -}}
yashigani
{{- end -}}
{{- end }}
