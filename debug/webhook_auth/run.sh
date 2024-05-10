# https://blog.csdn.net/wanger5354/article/details/121786364
#https://github.com/mfanjie/github-webhook/tree/master
cat >> webhook-config.json <EOF
{
  "kind": "Config",
  "apiVersion": "v1",
  "preferences": {},
  "clusters": [
    {
      "name": "github-authn",
      "cluster": {
        "server": "http://10.0.4.9:9999/auth"
      }
    }
  ],
  "users": [
    {
      "name": "authn-apiserver",
      "user": {
        "token": "secret"
      }
    }
  ],
  "contexts": [
    {
      "name": "webhook",
      "context": {
        "cluster": "github-authn",
        "user": "authn-apiserver"
      }
    }
  ],
  "current-context": "webhook"
}
EOF


# --authentication-token-webhook-config-file=./webhook-config.json




#apiVersion: v1
#users:
#- name: joker
#  user:
#    token: github:ghp_jevHquU4g43m46nczWS0ojxxxxxxxxx