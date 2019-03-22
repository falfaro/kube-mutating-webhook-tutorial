package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	govalidator "gopkg.in/go-playground/validator.v9"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	v1 "k8s.io/kubernetes/pkg/apis/core/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

type webhookServer struct {
	sidecarConfig *config
	server        *http.Server
}

// Webhook Server parameters
type whSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type config struct {
	Containers []corev1.Container `yaml:"containers"`
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// main mutation process
func (whsvr *webhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request

	var ingress extensionsv1beta1.Ingress
	if err := json.Unmarshal(req.Object.Raw, &ingress); err != nil {
		// Error unmarshalling Ingress
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	var patch []patchOperation

	for tlsIndex, tls := range ingress.Spec.TLS {
		glog.Infof("Length of %s: %v", tls.SecretName, len(tls.Hosts))
		if len(tls.Hosts) == 0 {
			// Need to generate a patch to add a single FQDN Host
			// derived from the Ingress name and BKPR's DNS domain
			glog.Infof("No Hosts for %s", tls.SecretName)
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/tls/%d/hosts", tlsIndex),
				Value: []string{"cafe.eks.felipe-alfaro.com"},
			})
		} else {
			for hostIndex, host := range tls.Hosts {
				if len(host) == 0 {
					// Empty Host: need to generate to replace its value with
					// one derived from the Ingress name and BKPR's domain
					glog.Info("Parsed No Host")
					patch = append(patch, patchOperation{
						Op:    "replace",
						Path:  fmt.Sprintf("/spec/tls/%d/hosts/%d", tlsIndex, hostIndex),
						Value: "cafe.eks.felipe-alfaro.com",
					})
				} else {
					// Check whether Host is a FQDN
					v := govalidator.New()
					if err := v.Var(host, "fqdn"); err == nil {
						glog.Infof("Parsed FQDN Host: %s", host)
					} else {
						// Non-FQDN: need to qualify the Host with BKPR's
						// domain
						newHost := host
						if !strings.HasSuffix(host, ".") {
							newHost += "."
						}
						newHost += "eks.felipe-alfaro.com"
						patch = append(patch, patchOperation{
							Op:    "replace",
							Path:  fmt.Sprintf("/spec/tls/%d/hosts/%d", tlsIndex, hostIndex),
							Value: newHost,
						})
						glog.Infof("Parsed non-FQDN: %s into: %s", host, newHost)
					}
				}
			}
		}
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		glog.Error("Error marshalling patch!")
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("Patch: %v", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
	}
}

// Serve method for webhook server
func (whsvr *webhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	if glog.V(1) {
		// Dump body
		glog.Infof("Body: %s", body)
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}

	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
