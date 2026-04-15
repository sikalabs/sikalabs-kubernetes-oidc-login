[SikaLabs (sikalabs.com)](https://sikalabs.com) | [Ondrej Sika (sika.io)](https://sika.io)  | [**Skoleni Kubernetes**](https://ondrej-sika.cz/skoleni/kubernetes/) 🚀💻

# sikalabs-kubernetes-oidc-login

## What is sikalabs-kubernetes-oidc-login ?

`sikalabs-kubernetes-oidc-login` is a simple command-line tool that performs OIDC login and outputs Kubernetes ExecCredential for kubectl. It allows users to authenticate with an OIDC provider and obtain the necessary credentials to access Kubernetes clusters.

This project has been heavily inspired by [int128/kubelogin](https://github.com/int128/kubelogin).

## How does it work?

![schema](./schema.svg)

## Installation

### Install via Homebrew

```bash
brew install sikalabs/tap/sikalabs-kubernetes-oidc-login
```

### Install via Go

```bash
go install github.com/sikalabs/sikalabs-kubernetes-oidc-login@latest
```

### Install via slu

```bash
slu install-bin sikalabs-kubernetes-oidc-login
```

### Install via curl

```bash
curl -fsSL https://raw.githubusercontent.com/sikalabs/sikalabs-kubernetes-oidc-login/refs/heads/master/install.sh | sudo sh
```

## Example Usage

Try it from CLI

```bash
sikalabs-kubernetes-oidc-login \
  --oidc-issuer-url https://sso.sikademo.com/realms/sikademo \
  --oidc-client-id kubernetes \
  --oidc-client-secret kubernetes_secret
```

In `kubeconfig.yaml`

```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://rke2.sikademo.com:6443
  name: sikademo
contexts:
- context:
    cluster: sikademo
    user: sikademo
  name: sikademo
current-context: sikademo
users:
- name: sikademo
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: sikalabs-kubernetes-oidc-login
      args:
      - oidc-login
      - get-token
      - --oidc-issuer-url=https://sso.sikademo.com/realms/sikademo
      - --oidc-client-id=kubernetes
      - --oidc-client-secret=kubernetes_secret
      env: null
      interactiveMode: IfAvailable
      provideClusterInfo: false
```

And run standard `kubectl` commands like

```bash
kubectl get nodes
```
