kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: k8s-authorize
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-authorize
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: k8s-authorize
    namespace: kube-system
---
apiVersion: v1
kind: Secret
metadata:
  name: k8s-authorize
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: "k8s-authorize"
type: kubernetes.io/service-account-token

EOF

export TOKEN=$(kubectl -n kube-system get secret sa-k8s-authorize -o=jsonpath={.data.token}|base64 -d)

curl -k -s  https://localhost:10250/configz --header "Authorization: Bearer $TOKEN"    |python -m json.tool




