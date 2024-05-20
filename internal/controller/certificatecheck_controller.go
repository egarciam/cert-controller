package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certcheckerv1alpha1 "github.com/egarciam/cert-checker-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// CertificateCheckReconciler reconciles a CertificateCheck object
type CertificateCheckReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certchecker.egarciam.com,resources=certificatechecks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certchecker.egarciam.com,resources=certificatechecks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certchecker.egarciam.com,resources=certificatechecks/finalizers,verbs=update

func (r *CertificateCheckReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("certificatecheck", req.NamespacedName)

	// Fetch the CertificateCheck instance
	instance := &certcheckerv1alpha1.CertificateCheck{}
	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return. Created objects are automatically garbage collected.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// List all secrets in the cluster
	secretList := &corev1.SecretList{}
	if err := r.Client.List(ctx, secretList); err != nil {
		return ctrl.Result{}, err
	}

	// Check certificates in each secret
	for _, secret := range secretList.Items {
		for _, certData := range secret.Data {
			certs, err := r.parseCertificates(certData)
			if err != nil {
				r.Log.Error(err, "Failed to parse certificate", "SecretName", secret.Name, "SecretNamespace", secret.Namespace)
				continue
			}

			for _, cert := range certs {
				if time.Until(cert.NotAfter) < 30*24*time.Hour {
					r.Log.Info("Certificate is expiring soon",
						"SecretName", secret.Name,
						"SecretNamespace", secret.Namespace,
						"ExpiresAt", cert.NotAfter)
				}
			}
		}
	}

	// // Check certificate expiration dates
	// for _, certInfo := range instance.Spec.Certificates {
	// 	cert, err := r.getCertificate(certInfo.SecretName, certInfo.SecretNamespace)
	// 	if err != nil {
	// 		r.Log.Error(err, "Failed to get certificate", "SecretName", certInfo.SecretName, "SecretNamespace", certInfo.SecretNamespace)
	// 		continue
	// 	}

	// 	// Check expiration date
	// 	if time.Until(cert.NotAfter) < 30*24*time.Hour {
	// 		r.Log.Info("Certificate is expiring soon", "SecretName", certInfo.SecretName, "SecretNamespace", certInfo.SecretNamespace, "ExpiresAt", cert.NotAfter)
	// 	}
	// }

	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *CertificateCheckReconciler) getCertificate(secretName, secretNamespace string) (*x509.Certificate, error) {
	secret := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: secretNamespace}, secret)
	if err != nil {
		return nil, err
	}

	certPEM := secret.Data["tls.crt"]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// parseCertificates extracts certificates from the secret data
func (r *CertificateCheckReconciler) parseCertificates(certData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	var rest = certData

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}

func (r *CertificateCheckReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certcheckerv1alpha1.CertificateCheck{}).
		Watches(
			&source.Kind{Type: &corev1.Secret{}},
			&handler.EnqueueRequestForOwner{
				OwnerType:    &certcheckerv1alpha1.CertificateCheck{},
				IsController: true,
			},
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
