/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"errors"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

const kubevirtClusterTemplateImmutableMsg = "KubevirtClusterTemplate spec.template.spec field is immutable. Please create new resource instead."

func (m *KubevirtClusterTemplate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(m).
		Complete()
}

// +kubebuilder:webhook:verbs=create;update,path=/validate-infrastructure-cluster-x-k8s-io-v1alpha1-kubevirtclustertemplate,mutating=false,failurePolicy=fail,matchPolicy=Equivalent,groups=infrastructure.cluster.x-k8s.io,resources=kubevirtclustertemplates,versions=v1alpha1,name=validation.kubevirtclustertemplate.infrastructure.cluster.x-k8s.io,sideEffects=None,admissionReviewVersions=v1beta1

var _ webhook.Validator = &KubevirtClusterTemplate{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type.
func (m *KubevirtClusterTemplate) ValidateCreate() error {
	return nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type.
func (m *KubevirtClusterTemplate) ValidateUpdate(old runtime.Object) error {
	oldCRS := old.(*KubevirtClusterTemplate)
	if !reflect.DeepEqual(m.Spec, oldCRS.Spec) {
		return errors.New(kubevirtClusterTemplateImmutableMsg)
	}
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type.
func (m *KubevirtClusterTemplate) ValidateDelete() error {
	return nil
}