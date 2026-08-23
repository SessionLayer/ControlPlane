{{/* Chart name, overridable, used as the app.kubernetes.io/name label value. */}}
{{- define "sessionlayer-controlplane.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-controlplane.fullname" -}}
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

{{- define "sessionlayer-controlplane.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-controlplane.labels" -}}
helm.sh/chart: {{ include "sessionlayer-controlplane.chart" . }}
{{ include "sessionlayer-controlplane.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: control-plane
app.kubernetes.io/part-of: sessionlayer
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
app.kubernetes.io/name carries the unprefixed chart name because the Gateway
and Agent NetworkPolicies select Control Plane pods by exactly this label.
Changing nameOverride here means changing the peer selectors in those charts.
*/}}
{{- define "sessionlayer-controlplane.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sessionlayer-controlplane.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sessionlayer-controlplane.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sessionlayer-controlplane.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* A digest pins the exact bytes; a tag does not. Digest wins when set. */}}
{{- define "sessionlayer-controlplane.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}

{{/*
SANs for the runtime-minted gRPC server certificate. These must cover every
address a Gateway or Agent actually dials, or the peer's TLS handshake fails on
hostname verification rather than on anything that names the cause.
*/}}
{{- define "sessionlayer-controlplane.mtlsHostnames" -}}
{{- $svc := .Values.service.name -}}
{{- $names := list (printf "%s.%s.svc" $svc .Release.Namespace) (printf "%s.%s.svc.cluster.local" $svc .Release.Namespace) $svc "localhost" -}}
{{- $names = concat $names .Values.mtls.extraHostnames -}}
{{- join "," (uniq $names) -}}
{{- end }}
