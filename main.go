package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	reg "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	dns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	dnsMdl "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&huaweiDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type huaweiDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client       *kubernetes.Clientset
	huaweiClient *dns.DnsClient
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type huaweiDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	AccessKey cmmetav1.SecretKeySelector `json:"accessKeyRef"`
	SecretKey cmmetav1.SecretKeySelector `json:"secretKeyRef"`
	RegionId  string                     `json:"regionId"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (h *huaweiDNSProviderSolver) Name() string {
	return "huawei"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (h *huaweiDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	h.huaweiClient, err = h.getHuaweiClient(ch, cfg)
	if err != nil {
		return err
	}

	zoneId, err := h.getZoneId(ch.ResolvedZone)
	if err != nil {
		return err
	}

	err = h.addTxtRecord(zoneId, ch.ResolvedFQDN, ch.Key)
	if err != nil {
		return err
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (h *huaweiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	h.huaweiClient, err = h.getHuaweiClient(ch, cfg)
	if err != nil {
		return err
	}

	zoneId, err := h.getZoneId(ch.ResolvedZone)
	if err != nil {
		return err
	}

	records, err := h.getRecords(zoneId, ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	for _, record := range records {
		r := *record.Records
		if r[0] != ch.Key {
			continue
		}
		req := &dnsMdl.DeleteRecordSetRequest{}
		req.ZoneId = zoneId
		req.RecordsetId = *record.Id
		resp, err := h.huaweiClient.DeleteRecordSet(req)
		if err != nil {
			return errors.Wrap(err, "failed to delete record")
		}
		klog.Infof("Delete record id %s in Huawei Cloud DNS", *resp.Id)
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (h *huaweiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return errors.Wrap(err, "failed to new kubernetes client")
	}
	h.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (huaweiDNSProviderConfig, error) {
	cfg := huaweiDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (h *huaweiDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := h.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

func (h *huaweiDNSProviderSolver) getHuaweiClient(ch *v1alpha1.ChallengeRequest, cfg huaweiDNSProviderConfig) (*dns.DnsClient, error) {
	accessKey, err := h.loadSecretData(cfg.AccessKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}
	secretKey, err := h.loadSecretData(cfg.SecretKey, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	basicAuth, err := basic.NewCredentialsBuilder().
		WithAk(string(accessKey)).
		WithSk(string(secretKey)).
		SafeBuild()
	if err != nil {
		return nil, err
	}

	reg := reg.NewRegion(cfg.RegionId, fmt.Sprintf("https://dns.%s.myhuaweicloud.com", cfg.RegionId))
	dnsHttpClient, err := dns.DnsClientBuilder().
		WithRegion(reg).
		WithCredential(basicAuth).
		WithHttpConfig(config.DefaultHttpConfig()).
		SafeBuild()
	if err != nil {
		return nil, err
	}
	client := dns.NewDnsClient(dnsHttpClient)
	return client, nil
}

func (h *huaweiDNSProviderSolver) getZoneId(resolvedZone string) (string, error) {
	zoneList := make([]dnsMdl.PrivateZoneResp, 0)

	req := &dnsMdl.ListPrivateZonesRequest{}
	req.Offset = ptr.To[int32](0)
	req.Limit = ptr.To[int32](50)
	totalCount := int32(50)

	for *req.Offset < totalCount {
		resp, err := h.huaweiClient.ListPrivateZones(req)
		if err != nil {
			return "", errors.Wrap(err, "failed to list domains for Huawei Cloud DNS")
		}

		zoneList = append(zoneList, *resp.Zones...)
		totalCount = *resp.Metadata.TotalCount
		req.Offset = ptr.To[int32](*req.Offset + int32(len(*resp.Zones)))
	}

	authZone, err := util.FindZoneByFqdn(context.Background(), resolvedZone, util.RecursiveNameservers)
	if err != nil {
		return "", errors.Wrap(err, "failed to find zone by fqdn")
	}

	var hostedZone dnsMdl.PrivateZoneResp
	for _, item := range zoneList {
		if *item.Name == authZone {
			hostedZone = item
			break
		}
	}
	if *hostedZone.Id == "" {
		return "", fmt.Errorf("zone %s not found in HuaweiCloud DNS", resolvedZone)
	}
	return fmt.Sprintf("%v", *hostedZone.Id), nil
}

func (h *huaweiDNSProviderSolver) addTxtRecord(zoneId, fqdn, key string) error {
	klog.Infof("Huawei Cloud DNS adding TXT record: ZoneID=%s, FQDN=%s, key=%s", zoneId, fqdn, key)
	records := []string{key}
	reqBody := &dnsMdl.CreateRecordSetRequestBody{
		Name:    fqdn,
		Type:    "TXT",
		Records: records,
	}
	req := &dnsMdl.CreateRecordSetRequest{
		Body:   reqBody,
		ZoneId: zoneId,
	}
	resp, err := h.huaweiClient.CreateRecordSet(req)
	if err != nil {
		return errors.Wrap(err, "failed to create txt record")
	}
	klog.Infof("Create %s record named '%s' to '%s' with ttl %d for Huawei Cloud DNS: Record ID=%s", *resp.Type, *resp.Name, resp.Records, *resp.Ttl, *resp.Id)
	return nil
}

func extractRecordName(fqdn, zone string) string {
	if idx := strings.Index(fqdn, "."+zone); idx != -1 {
		return fqdn[:idx]
	}

	return util.UnFqdn(fqdn)
}

func (h *huaweiDNSProviderSolver) getRecords(zoneId, zone, fqdn string) ([]dnsMdl.ListRecordSets, error) {
	recordName := extractRecordName(fqdn, zone)
	req := &dnsMdl.ListRecordSetsByZoneRequest{}
	req.ZoneId = zoneId
	req.Name = &recordName

	req.Offset = ptr.To[int32](0)
	req.Limit = ptr.To[int32](50)
	totalCount := int32(50)

	recordList := make([]dnsMdl.ListRecordSets, 0)
	for *req.Offset < totalCount {
		resp, err := h.huaweiClient.ListRecordSetsByZone(req)
		if err != nil {
			return nil, errors.Wrap(err, "fail to list records for Huawei Cloud DNS")
		}

		for _, recordSet := range *resp.Recordsets {
			if *recordSet.Default {
				continue
			}
			recordList = append(recordList, recordSet)
		}

		totalCount = *resp.Metadata.TotalCount
		req.Offset = ptr.To[int32](*req.Offset + int32(len(*resp.Recordsets)))
	}
	return recordList, nil
}
