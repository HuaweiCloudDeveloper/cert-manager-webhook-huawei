# cert-manager-webhook-huawei

[简体中文](./README_zh.md)

**cert-manager-webhook-huawei** is a Cert-Manager webhook plugin designed for Huawei Cloud. It supports automatic issuance and management of TLS certificates using the DNS-01 challenge, making it easy to deploy and manage HTTPS services on Huawei Cloud CCE clusters.

## Deployment on CCE

### Deploy nginx-ingress-controller

Deploy the nginx-ingress controller through the Add-on Center in CCE.

> For CCE Turbo clusters: A NAT gateway must be created for the node VPC network.

### Add DNS A Record

Add a DNS A record in Huawei Cloud DNS Hosting Service pointing to the public IP address of the LoadBalancer associated with the nginx-ingress controller.

Taking `cert.example.com` as an example, add DNS resolution configuration on any node:

```sh
kubectl -n kube-system edit configmap coredns
```

Replace `forward . /etc/resolv.conf` with:
``` 
forward . 8.8.8.8 8.8.4.4
```

Then restart CoreDNS:
```sh
kubectl -n kube-system rollout restart deployment coredns
```

Verify domain resolution:
```sh
host cert.example.com
```

Proceed if the domain resolves correctly.

> The domain must be registered and filed according to regulations before resolution.

### Deploy cert-manager

Install cert-manager:
```sh
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.9.1  --set installCRDs=true
```

### Deploy NGINX Cafe Example

1. Clone the NGINX Ingress GitHub repository:
```sh
git clone https://github.com/nginxinc/kubernetes-ingress.git
```

2. Navigate to examples:
```sh
cd ./kubernetes-ingress/examples/ingress-resources/complete-example
```

3. Deploy the NGINX Cafe example:
```sh
kubectl apply -f ./cafe.yaml
```

### Deploy ClusterIssuer (DNS01 Method)

1. Create Huawei Cloud credentials secret:
```sh
kubectl create secret generic huaweicloud-secret --from-literal="accessKey=<Your-accessKey>" --from-literal="secretKey=<Your-secretKey>" -n cert-manager
```

2. Deploy the webhook:
```sh
git clone https://github.com/HuaweiCloudDeveloper/cert-manager-webhook-huawei
cd cert-manager-webhook-huawei
# Modify groupName in charts/huaweicloud-webhook/values.yaml to your actual domain
helm install cert-manager-webhook-huawei ./charts/huaweicloud-webhook -n cert-manager
```

3. Create ClusterIssuer:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: example@email.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt
    solvers:
    - dns01:
        webhook:
            groupName: example.com  # Your domain
            solverName: huawei
            config:
              accessKeyRef:
                key: accessKey
                name: huaweicloud-secret
              regionId: ap-southeast-1  # Your region
              secretKeyRef:
                key: secretKey
                name: huaweicloud-secret
```

4. Verify ClusterIssuer status:
```sh
kubectl get clusterissuer
```
Status should show `Ready`.

### Deploy Ingress

1. Create Ingress resource:
```yaml
apiVersion: networking.k8s.io/v1 
kind: Ingress 
metadata: 
  name: cafe-ingress 
  annotations: 
    cert-manager.io/cluster-issuer: letsencrypt 
    acme.cert-manager.io/http01-edit-in-place: "true" 
    cert-manager.io/issue-temporary-certificate: "true"    
spec: 
  ingressClassName: nginx 
  tls: 
  - hosts: 
    - cert-manager.example.com  # Your domain
    secretName: cafe-secret
  rules: 
  - host: cert-manager.example.com  # Your domain
    http: 
      paths: 
      - path: /tea 
        pathType: Prefix 
        backend: 
          service: 
            name: tea-svc 
            port: 
              number: 80 
      - path: /coffee 
        pathType: Prefix 
        backend: 
          service: 
            name: coffee-svc 
            port: 
              number: 80 
```

2. Verify certificate issuance:
```sh
kubectl get certificates
```
Status should become `Ready: True`.

3. Check certificate requests:
```sh
kubectl get certificaterequests.cert-manager.io
```
Verify `Ready: True` and `Approved: True`.

### Test Ingress

Validate using:
```sh
curl https://cert.example.com/tea
curl https://cert.example.com/coffee
```