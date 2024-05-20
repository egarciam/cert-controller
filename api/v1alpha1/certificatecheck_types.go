package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateCheckSpec defines the desired state of CertificateCheck
type CertificateCheckSpec struct {
	Certificates []CertificateInfo `json:"certificates"`
	// Add any other fields you need to configure the spec
}

// CertificateInfo defines the information about a certificate to check
type CertificateInfo struct {
	SecretName      string `json:"secretName"`
	SecretNamespace string `json:"secretNamespace"`
}

// CertificateCheckStatus defines the observed state of CertificateCheck
type CertificateCheckStatus struct {
	// Add status fields as needed
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CertificateCheck is the Schema for the certificatechecks API
type CertificateCheck struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateCheckSpec   `json:"spec,omitempty"`
	Status CertificateCheckStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificateCheckList contains a list of CertificateCheck
type CertificateCheckList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateCheck `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificateCheck{}, &CertificateCheckList{})
}
