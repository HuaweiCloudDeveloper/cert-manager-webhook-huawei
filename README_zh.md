# cert-manager-webhook-huawei

[English](./README.md)

**cert-manager-webhook-huawei** 是一个专为华为云设计的 Cert-Manager Webhook 插件，支持使用 DNS-01 验证方式自动签发和管理 TLS 证书，方便在华为云 CCE 集群中部署和管理 HTTPS 服务。

## 在 CCE 上部署

### 部署 nginx-ingress-controller

通过 CCE 的 **插件中心** 部署 nginx-ingress-controller。

> 对于 **CCE Turbo 集群**：必须为节点所在的 VPC 网络创建 NAT 网关。

---

### 添加 DNS A 记录

在 **华为云 DNS 解析服务** 中添加一条 **DNS A 记录**，指向与 nginx-ingress controller 关联的 LoadBalancer 的公网 IP 地址。

以 `cert.example.com` 为例，在任意节点上添加 DNS 解析配置：

```sh
kubectl -n kube-system edit configmap coredns
```

将以下内容：

```
forward . /etc/resolv.conf
```

替换为：

```
forward . 8.8.8.8 8.8.4.4
```

然后重启 CoreDNS：

```sh
kubectl -n kube-system rollout restart deployment coredns
```

验证域名解析：

```sh
host cert.example.com
```

如果解析结果正确，则继续下一步。

> 注意：域名在解析前必须已**完成备案并符合法规要求**。

---

### 部署 cert-manager

安装 cert-manager：

```sh
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --version v1.9.1 --set installCRDs=true
```

---

### 部署 NGINX Cafe 示例

1. 克隆 NGINX Ingress 仓库：

```sh
git clone https://github.com/nginxinc/kubernetes-ingress.git
```

2. 进入示例目录：

```sh
cd ./kubernetes-ingress/examples/ingress-resources/complete-example
```

3. 部署 NGINX Cafe 示例：

```sh
kubectl apply -f ./cafe.yaml
```

---

### 部署 ClusterIssuer（DNS01 验证方式）

1. 创建华为云凭证 Secret：

```sh
kubectl create secret generic huaweicloud-secret --from-literal="accessKey=<Your AccessKey>" --from-literal="secretKey=<Your SecretKey>" -n cert-manager
```

2. 部署 webhook：

```sh
git clone https://github.com/HuaweiCloudDeveloper/cert-manager-webhook-huawei
cd cert-manager-webhook-huawei
# 修改 charts/huaweicloud-webhook/values.yaml 中的 groupName 为你自己的域名
helm install cert-manager-webhook-huawei ./charts/huaweicloud-webhook -n cert-manager
```

3. 创建 ClusterIssuer：

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
          groupName: example.com  # 你的域名
          solverName: huawei
          config:
            accessKeyRef:
              key: accessKey
              name: huaweicloud-secret
            regionId: ap-southeast-1  # 你的区域
            secretKeyRef:
              key: secretKey
              name: huaweicloud-secret
```

4. 验证 ClusterIssuer 状态：

```sh
kubectl get clusterissuer
```

状态应显示为 `Ready`。

---

### 部署 Ingress

1. 创建 Ingress 资源：

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
    - cert-manager.example.com  # 你的域名
    secretName: cafe-secret
  rules: 
  - host: cert-manager.example.com  # 你的域名
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

2. 验证证书签发状态：

```sh
kubectl get certificates
```

状态应变为 `Ready: True`。

3. 查看证书请求：

```sh
kubectl get certificaterequests.cert-manager.io
```

确认状态为 `Ready: True` 且 `Approved: True`。

---

### 测试 Ingress

使用以下命令验证：

```sh
curl https://cert.example.com/tea
curl https://cert.example.com/coffee
```
