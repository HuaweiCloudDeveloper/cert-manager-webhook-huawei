package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	dns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	dnsMdl "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
)

// GroupName 是 cert-manager 用来识别此 webhook 的 API 组名。
// 它必须通过环境变量来设置。
var GroupName = os.Getenv("GROUP_NAME")

// main 是程序的入口点。
func main() {
	if GroupName == "" {
		panic("GROUP_NAME environment variable must be set")
	}

	// 启动 webhook 服务器，并将我们的 DNS provider 实现注册进去。
	// cert-manager 会通过这个服务器来调用 Present 和 CleanUp 方法。
	cmd.RunWebhookServer(GroupName,
		&huaweiDNSProviderSolver{},
	)
}

// huaweiDNSProviderSolver 结构体实现了 cert-manager 所需的 DNS provider 接口。
type huaweiDNSProviderSolver struct {
	// client 用于与 Kubernetes API Server 通信，主要是为了读取包含 AK/SK 的 Secret。
	client *kubernetes.Clientset
}

// huaweiDNSProviderConfig 结构体用于解析来自 Issuer/ClusterIssuer 配置中的 'provider' 段。
// cert-manager 会将 YAML 配置反序列化到这个结构体中。
type huaweiDNSProviderConfig struct {
	AccessKey cmmetav1.SecretKeySelector `json:"accessKeyRef"`
	SecretKey cmmetav1.SecretKeySelector `json:"secretKeyRef"`
	RegionId string `json:"regionId"`
}

// Name 返回此 DNS provider 的名称，这个名称将用在 Issuer/ClusterIssuer 的 ACME 配置中。
func (h *huaweiDNSProviderSolver) Name() string {
	return "huaweicloud"
}

// Present 方法负责创建 ACME 挑战所需的 TXT 记录。
// 当 cert-manager 需要验证一个域名的所有权时，会调用此方法。
func (h *huaweiDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	huaweiClient, err := h.getHuaweiClient(ch, cfg)
	if err != nil {
		return errors.Wrap(err, "failed to create Huawei Cloud client")
	}

	zoneId, err := h.getZoneId(huaweiClient, ch.ResolvedZone)
	if err != nil {
		return errors.Wrap(err, "failed to get zone id")
	}

	klog.Infof("Preparing to create TXT record for FQDN %s", ch.ResolvedFQDN)
	return h.addTxtRecord(huaweiClient, zoneId, ch.ResolvedFQDN, ch.Key)
}

// CleanUp 方法负责删除之前为 ACME 挑战创建的 TXT 记录。
// 在域名所有权验证成功或失败后，cert-manager 会调用此方法来清理资源。
func (h *huaweiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	huaweiClient, err := h.getHuaweiClient(ch, cfg)
	if err != nil {
		return errors.Wrap(err, "failed to create Huawei Cloud client")
	}

	zoneId, err := h.getZoneId(huaweiClient, ch.ResolvedZone)
	if err != nil {
		return errors.Wrap(err, "failed to get zone id")
	}

	// 首先，根据 FQDN 找到对应的 TXT 记录。
	records, err := h.getTxtRecords(huaweiClient, zoneId, ch.ResolvedFQDN)
	if err != nil {
		return errors.Wrap(err, "failed to get TXT records")
	}

	klog.Infof("Found %d TXT records for FQDN %s, preparing to clean up", len(records), ch.ResolvedFQDN)

	// 遍历所有找到的记录，并删除与挑战密钥匹配的记录。
	for _, record := range records {
		if record.Records == nil || len(*record.Records) == 0 {
			continue
		}

		recordValue := (*record.Records)[0]

		// `ch.Key` 是 cert-manager 提供的期望的 TXT 记录值。
		// 我们只删除值完全匹配的记录，以防误删其他 TXT 记录。
		// 注意：华为云API返回的TXT记录值本身带双引号，我们需要去掉它们再与 ch.Key 比较。
		unquotedRecordValue := strings.Trim(recordValue, "\"")
		if unquotedRecordValue != ch.Key {
			klog.Infof("Skipping record ID %s, its value ('%s') does not match challenge key ('%s')", *record.Id, unquotedRecordValue, ch.Key)
			continue
		}

		klog.Infof("Deleting record ID %s from zone ID %s", *record.Id, zoneId)
		req := &dnsMdl.DeleteRecordSetRequest{
			ZoneId:      zoneId,
			RecordsetId: *record.Id,
		}
		_, err := huaweiClient.DeleteRecordSet(req)
		if err != nil {
			klog.Errorf("Failed to delete record ID %s: %v", *record.Id, err)
			continue
		}
		klog.Infof("Successfully deleted record ID %s", *record.Id)
	}
	return nil
}

// Initialize 在 webhook 启动时被调用一次。
// 主要用于进行一些初始化设置，例如创建 Kubernetes 客户端。
func (h *huaweiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create new kubernetes client")
	}
	h.client = cl
	return nil
}

// loadConfig 将传入的 JSON 配置解码到 'huaweiDNSProviderConfig' 结构体中。
func loadConfig(cfgJSON *extapi.JSON) (huaweiDNSProviderConfig, error) {
	cfg := huaweiDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

// getHuaweiClient 根据配置创建并返回一个华为云 DNS 服务的客户端。
func (h *huaweiDNSProviderSolver) getHuaweiClient(ch *v1alpha1.ChallengeRequest, cfg huaweiDNSProviderConfig) (*dns.DnsClient, error) {
	// 从 Kubernetes Secret 中加载 AK/SK。
	accessKey, err := h.loadSecretData(cfg.AccessKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}
	secretKey, err := h.loadSecretData(cfg.SecretKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	if cfg.RegionId == "" {
		return nil, errors.New("regionId must be set in provider config")
	}

	// 使用 AK/SK 构建认证凭据。
	basicAuth := basic.NewCredentialsBuilder().
		WithAk(string(accessKey)).
		WithSk(string(secretKey)).
		Build()

	// 直接构造 Endpoint URL (例如 https://dns.cn-north-4.myhuaweicloud.com)
	// 这比依赖 SDK 内部的 region 映射更可靠。
	endpoint := fmt.Sprintf("https://dns.%s.myhuaweicloud.com", cfg.RegionId)
	reg := region.NewRegion(cfg.RegionId, endpoint)

	// 使用 Builder 模式构建 DNS 客户端。
	dnsHttpClient := dns.DnsClientBuilder().
		WithRegion(reg).
		WithCredential(basicAuth).
		WithHttpConfig(config.DefaultHttpConfig()).
		Build()

	// SDK v3 需要将 builder 构建的 http client 包装成 DnsClient。
	return dns.NewDnsClient(dnsHttpClient), nil
}

// loadSecretData 从指定的 Secret 中安全地加载数据。
func (h *huaweiDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := h.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret '%s' in namespace '%s'", selector.Name, ns)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("key '%s' not found in secret '%s' in namespace '%s'", selector.Key, selector.Name, ns)
}

// getZoneId 查找并返回给定域名权威 Zone 的 ID。
// 它会依次在公网 Zone 和私网 Zone 中查找。
func (h *huaweiDNSProviderSolver) getZoneId(client *dns.DnsClient, resolvedZone string) (string, error) {
	// 使用 cert-manager 提供的工具函数来找到权威域。
	authZone, err := util.FindZoneByFqdn(context.Background(), resolvedZone, util.RecursiveNameservers)
	if err != nil {
		return "", errors.Wrap(err, "failed to find authoritative zone by fqdn")
	}
	// 去掉结尾的点，以便与华为云 API 返回的 Zone 名称匹配。
	unfqdnAuthZone := util.UnFqdn(authZone)
	klog.Infof("Authoritative zone for %s is %s", resolvedZone, unfqdnAuthZone)

	// 首先尝试在公网 Zone 中查找。
	klog.Info("Attempting to find zone in Public Zones...")
	publicZoneId, err := h.findZoneInPublicZones(client, unfqdnAuthZone)
	if err != nil {
		return "", errors.Wrap(err, "error searching public zones")
	}
	if publicZoneId != "" {
		klog.Infof("Found matching zone in Public Zones: %s", publicZoneId)
		return publicZoneId, nil
	}

	// 如果公网 Zone 中没有，再尝试在私网 Zone 中查找。
	klog.Info("Zone not found in Public Zones, attempting to find in Private Zones...")
	privateZoneId, err := h.findZoneInPrivateZones(client, unfqdnAuthZone)
	if err != nil {
		return "", errors.Wrap(err, "error searching private zones")
	}
	if privateZoneId != "" {
		klog.Infof("Found matching zone in Private Zones: %s", privateZoneId)
		return privateZoneId, nil
	}

	return "", fmt.Errorf("zone '%q' not found in either Public or Private zones in HuaweiCloud DNS", unfqdnAuthZone)
}

// findZoneInPublicZones 遍历所有公网 Zone 以查找匹配项。
func (h *huaweiDNSProviderSolver) findZoneInPublicZones(client *dns.DnsClient, zoneName string) (string, error) {
	req := &dnsMdl.ListPublicZonesRequest{
		Limit: ptr.To[int32](100), // 设置分页大小
	}

	for {
		resp, err := client.ListPublicZones(req)
		if err != nil {
			return "", errors.Wrap(err, "Huawei API call to ListPublicZones failed")
		}

		if resp.Zones != nil {
			for _, zone := range *resp.Zones {
				// 公网 Zone 名称通常以点号结尾，例如 "example.com."。
				if zone.Name != nil && *zone.Name == zoneName+"." {
					return *zone.Id, nil
				}
			}
		}

		if resp.Links == nil || resp.Links.Next == nil || *resp.Links.Next == "" {
			break // 这是最后一页，退出循环。
		}

		nextUrl, err := url.Parse(*resp.Links.Next)
		if err != nil {
			return "", errors.Wrap(err, "failed to parse next page URL for public zones")
		}

		marker := nextUrl.Query().Get("marker")
		if marker == "" {
			klog.Warning("Next page link found, but marker is empty. Stopping pagination.")
			break
		}
		req.Marker = &marker
	}
	return "", nil // 未找到匹配的 Zone
}

// findZoneInPrivateZones 遍历所有私网 Zone 以查找匹配项。
func (h *huaweiDNSProviderSolver) findZoneInPrivateZones(client *dns.DnsClient, zoneName string) (string, error) {
	req := &dnsMdl.ListPrivateZonesRequest{
		Limit:  ptr.To[int32](100),
		Offset: ptr.To[int32](0),
	}

	for {
		resp, err := client.ListPrivateZones(req)
		if err != nil {
			return "", errors.Wrap(err, "Huawei API call to ListPrivateZones failed")
		}

		if resp.Zones != nil {
			for _, zone := range *resp.Zones {
				// 私网 Zone 名称也可能以点号结尾。
				if zone.Name != nil && *zone.Name == zoneName+"." {
					return *zone.Id, nil
				}
			}
		}

		// 处理私网 Zone 的分页逻辑，它使用 'offset' 和 'total_count'。
		if resp.Metadata == nil || resp.Metadata.TotalCount == nil || (*req.Offset+int32(len(*resp.Zones))) >= *resp.Metadata.TotalCount {
			break // 已遍历完所有结果。
		}
		// 增加 offset 以获取下一页。
		*req.Offset += int32(len(*resp.Zones))
	}
	return "", nil // 未找到匹配的 Zone
}

// addTxtRecord 创建 ACME 挑战所需的 TXT 记录。
func (h *huaweiDNSProviderSolver) addTxtRecord(client *dns.DnsClient, zoneId, fqdn, value string) error {
	body := &dnsMdl.CreateRecordSetRequestBody{
		Name: fqdn,
		Type: "TXT",
		// 华为云API要求TXT记录的值本身包含一对双引号。
		Records: []string{fmt.Sprintf("\"%s\"", value)},
		Ttl:     ptr.To[int32](60),
	}

	req := &dnsMdl.CreateRecordSetRequest{
		ZoneId: zoneId,
		Body:   body,
	}

	resp, err := client.CreateRecordSet(req)
	if err != nil {
		// 如果记录已存在，这是正常情况，不应视为错误。
		if strings.Contains(err.Error(), "recordset.duplicate") {
			klog.Infof("TXT record for %s already exists. No action needed.", fqdn)
			return nil
		}
		return errors.Wrap(err, "failed to create TXT record")
	}
	klog.Infof("Successfully created TXT record ID %s for %s", *resp.Id, fqdn)
	return nil
}

// getTxtRecords 查找给定 FQDN 的所有 TXT 记录。
func (h *huaweiDNSProviderSolver) getTxtRecords(client *dns.DnsClient, zoneId, fqdn string) ([]dnsMdl.ListRecordSets, error) {
	req := &dnsMdl.ListRecordSetsByZoneRequest{
		ZoneId: zoneId,
		Name:   &fqdn,
		Type:   ptr.To("TXT"),
	}

	resp, err := client.ListRecordSetsByZone(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list record sets")
	}

	if resp.Recordsets == nil {
		// 即使没有记录，也返回一个空切片而不是nil，以简化调用方的错误处理。
		return []dnsMdl.ListRecordSets{}, nil
	}

	return *resp.Recordsets, nil
}
