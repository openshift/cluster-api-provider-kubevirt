#!/bin/bash -ex

KUBE_CLI=${KUBE_CLI:-kubectl}
CNV_NS=${CNV_NS:-openshift-cnv}

${KUBE_CLI} apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${CNV_NS}
EOF

${KUBE_CLI} apply -f - <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-cnv-group
  namespace: ${CNV_NS}
spec:
  targetNamespaces:
  - ${CNV_NS}
EOF

cat <<EOF | ${KUBE_CLI} apply -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/kubevirt-hyperconverged.openshift-cnv: ''
  name: kubevirt-hyperconverged
  namespace: ${CNV_NS}
spec:
  channel: stable
  installPlanApproval: Automatic
  name: kubevirt-hyperconverged
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

${KUBE_CLI} wait installplan -n ${CNV_NS} $(${KUBE_CLI} get subscription -n ${CNV_NS} kubevirt-hyperconverged -o jsonpath='{ .status.installPlanRef.name }') --for=condition=Installed --timeout=10m

${KUBE_CLI} create -f - <<EOF
apiVersion: hco.kubevirt.io/v1beta1
kind: HyperConverged
metadata:
  name: kubevirt-hyperconverged
  namespace: ${CNV_NS}
EOF

${KUBE_CLI} wait hyperconverged -n ${CNV_NS} kubevirt-hyperconverged --for=condition=Available --timeout=10m
