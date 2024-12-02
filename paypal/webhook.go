package paypal

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"

	"github.com/go-pay/gopay"
)

var (
	webhookCertCache *x509.Certificate
)

// GetWebhookList https://developer.paypal.com/docs/api/webhooks/#webhooks_get-all
func (c *Client) GetWebhookList(ctx context.Context) (ppRsp *WebhookListRsp, err error) {
	res, bs, err := c.doPayPalGet(ctx, webhookGet)
	if err != nil {
		return nil, err
	}
	ppRsp = &WebhookListRsp{Code: Success}
	ppRsp.Response = new(WebhookList)
	if err = json.Unmarshal(bs, ppRsp.Response); err != nil {
		return nil, fmt.Errorf("[%w]: %v, bytes: %s", gopay.UnmarshalErr, err, string(bs))
	}
	if res.StatusCode != http.StatusOK {
		ppRsp.Code = res.StatusCode
		ppRsp.Error = string(bs)
		ppRsp.ErrorResponse = new(ErrorResponse)
		_ = json.Unmarshal(bs, ppRsp.ErrorResponse)
	}
	return ppRsp, nil
}

// GetWebhookDetails https://developer.paypal.com/docs/api/webhooks/#webhooks_get
func (c *Client) GetWebhookDetails(ctx context.Context, webhookId string) (ppRsp *WebhookGetRsp, err error) {
	if webhookId == gopay.NULL {
		return nil, errors.New("webhook_id is empty")
	}
	uri := fmt.Sprintf(webhookGet, webhookId)
	res, bs, err := c.doPayPalGet(ctx, uri)
	if err != nil {
		return nil, err
	}
	ppRsp = &WebhookGetRsp{Code: Success}
	ppRsp.Response = new(Webhook)
	if err = json.Unmarshal(bs, ppRsp.Response); err != nil {
		return nil, fmt.Errorf("[%w]: %v, bytes: %s", gopay.UnmarshalErr, err, string(bs))
	}
	if res.StatusCode != http.StatusOK {
		ppRsp.Code = res.StatusCode
		ppRsp.Error = string(bs)
		ppRsp.ErrorResponse = new(ErrorResponse)
		_ = json.Unmarshal(bs, ppRsp.ErrorResponse)
	}
	return ppRsp, nil
}

// CreateWebhook https://developer.paypal.com/docs/api/webhooks/#webhooks_create
// func (c *Client) CreateWebhook(callBackURL string, eventTypeList ...string) (result *Webhook, err error) {
// 	var api = c.BuildAPI(kWebHook)
// 	var p = &Webhook{}

// 	var events = make([]*EventType, 0, len(eventTypeList))
// 	for _, name := range eventTypeList {
// 		var event = &EventType{}
// 		event.Name = name
// 		events = append(events, event)
// 	}
// 	p.EventTypes = events

// 	p.URL = callBackURL
// 	err = c.doRequestWithAuth(http.MethodPost, api, p, &result)
// 	return result, err
// }

// DeleteWebhook https://developer.paypal.com/docs/api/webhooks/#webhooks_delete
// func (c *Client) DeleteWebhook(webhookId string) (err error) {
// 	var api = c.BuildAPI(kWebHook, webhookId)
// 	err = c.doRequestWithAuth(http.MethodDelete, api, nil, nil)
// 	return err
// }

// verifyWebhookSignature https://developer.paypal.com/api/rest/webhooks/rest/#link-integratewebhooks
func (c *Client) verifyWebhookSignature(event []byte, webhookId string, headers http.Header) (bool, error) {
	// Extract headers
	transmissionID := headers.Get("paypal-transmission-id")
	timeStamp := headers.Get("paypal-transmission-time")
	webhookSignature := headers.Get("paypal-transmission-sig")
	certURL := headers.Get("paypal-cert-url")

	h := crc32.NewIEEE()
	h.Write(event)
	crc := h.Sum32()

	message := fmt.Sprintf("%s|%s|%s|%d", transmissionID, timeStamp, webhookId, crc)
	fmt.Printf("Original signed message: %s\n", message)

	var err error

	if webhookCertCache == nil {
		webhookCertCache, err = downloadCertFromUrl(certURL)
		if err != nil {
			return false, fmt.Errorf("failed to download certificate: %w", err)
		}
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(webhookSignature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(webhookCertCache.PublicKey.(*rsa.PublicKey), crypto.SHA256, hash[:], signatureBytes)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func downloadCertFromUrl(url string) (*x509.Certificate, error) {

	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}
	defer response.Body.Close()

	pemData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func (c *Client) GetWebhookEvent(webhookId string, w http.ResponseWriter, r *http.Request) (*Event, error) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return nil, fmt.Errorf("invalid request method: %s", r.Method)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	headers := r.Header

	var data Event
	if err := json.Unmarshal(body, &data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return nil, err
	}

	isSignatureValid, err := c.verifyWebhookSignature(body, webhookId, headers)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	if !isSignatureValid {
		w.WriteHeader(http.StatusForbidden)
		return nil, fmt.Errorf("signature is not valid, data: %+v", data)
	}

	w.WriteHeader(http.StatusOK)
	return &data, nil
}
