/*
Copyright 2014 The Kubernetes Authors.

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

package rest

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	genericvalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/api/validation/path"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/admission"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/apiserver/pkg/warning"
)

// RESTCreateStrategy 定义了最小验证、可接受的输入和名称生成行为
type RESTCreateStrategy interface {
	runtime.ObjectTyper
	names.NameGenerator                                                // 当设置标准GenerateName字段时使用名称生成器.NameGenerator将在验证之前被调用.
	NamespaceScoped() bool                                             // 该对象是不是属于名称空间
	PrepareForCreate(ctx context.Context, obj runtime.Object)          // 在BeforeCreate函数里调用,以规范化对象.例如:删除不持久化的字段,排序不区分顺序的列表字段,等等.这不应该删除将被认为是验证错误的字段.
	Validate(ctx context.Context, obj runtime.Object) field.ErrorList  // 返回一个带有验证错误或nil的ErrorList.在持久化对象之前填充对象中的默认字段之后调用Validate.这个方法不应该改变对象.
	WarningsOnCreate(ctx context.Context, obj runtime.Object) []string // Validate调用之后运行的,返回一系列的错误信息
	Canonicalize(obj runtime.Object)                                   // WarningsOnCreate 调用之后运行的,在验证后规范化对象.
}

// BeforeCreate ensures that common operations for all resources are performed on creation. It only returns
// errors that can be converted to api.Status. It invokes PrepareForCreate, then Validate.
// It returns nil if the object should be created.
func BeforeCreate(strategy RESTCreateStrategy, ctx context.Context, obj runtime.Object) error {
	objectMeta, kind, kerr := objectMetaAndKind(strategy, obj)
	if kerr != nil {
		return kerr
	}

	// ensure that system-critical metadata has been populated
	if !metav1.HasObjectMetaSystemFieldValues(objectMeta) {
		return errors.NewInternalError(fmt.Errorf("system metadata was not initialized"))
	}

	// ensure the name has been generated
	if len(objectMeta.GetGenerateName()) > 0 && len(objectMeta.GetName()) == 0 {
		return errors.NewInternalError(fmt.Errorf("metadata.name was not generated"))
	}

	// ensure namespace on the object is correct, or error if a conflicting namespace was set in the object
	requestNamespace, ok := genericapirequest.NamespaceFrom(ctx)
	if !ok {
		return errors.NewInternalError(fmt.Errorf("no namespace information found in request context"))
	}
	if err := EnsureObjectNamespaceMatchesRequestNamespace(ExpectedNamespaceForScope(requestNamespace, strategy.NamespaceScoped()), objectMeta); err != nil {
		return err
	}

	strategy.PrepareForCreate(ctx, obj)

	if errs := strategy.Validate(ctx, obj); len(errs) > 0 {
		return errors.NewInvalid(kind.GroupKind(), objectMeta.GetName(), errs)
	}

	// Custom validation (including name validation) passed
	// Now run common validation on object meta
	// Do this *after* custom validation so that specific error messages are shown whenever possible
	if errs := genericvalidation.ValidateObjectMetaAccessor(objectMeta, strategy.NamespaceScoped(), path.ValidatePathSegmentName, field.NewPath("metadata")); len(errs) > 0 {
		return errors.NewInvalid(kind.GroupKind(), objectMeta.GetName(), errs)
	}

	for _, w := range strategy.WarningsOnCreate(ctx, obj) {
		warning.AddWarning(ctx, "", w)
	}

	strategy.Canonicalize(obj)

	return nil
}

// CheckGeneratedNameError checks whether an error that occurred creating a resource is due
// to generation being unable to pick a valid name.
func CheckGeneratedNameError(ctx context.Context, strategy RESTCreateStrategy, err error, obj runtime.Object) error {
	if !errors.IsAlreadyExists(err) {
		return err
	}

	objectMeta, gvk, kerr := objectMetaAndKind(strategy, obj)
	if kerr != nil {
		return kerr
	}

	if len(objectMeta.GetGenerateName()) == 0 {
		// If we don't have a generated name, return the original error (AlreadyExists).
		// When we're here, the user picked a name that is causing a conflict.
		return err
	}

	// Get the group resource information from the context, if populated.
	gr := schema.GroupResource{}
	if requestInfo, found := genericapirequest.RequestInfoFrom(ctx); found {
		gr = schema.GroupResource{Group: gvk.Group, Resource: requestInfo.Resource}
	}

	// If we have a name and generated name, the server picked a name
	// that already exists.
	return errors.NewGenerateNameConflict(gr, objectMeta.GetName(), 1)
}

// objectMetaAndKind retrieves kind and ObjectMeta from a runtime object, or returns an error.
func objectMetaAndKind(typer runtime.ObjectTyper, obj runtime.Object) (metav1.Object, schema.GroupVersionKind, error) {
	objectMeta, err := meta.Accessor(obj)
	if err != nil {
		return nil, schema.GroupVersionKind{}, errors.NewInternalError(err)
	}
	kinds, _, err := typer.ObjectKinds(obj)
	if err != nil {
		return nil, schema.GroupVersionKind{}, errors.NewInternalError(err)
	}
	return objectMeta, kinds[0], nil
}

// NamespaceScopedStrategy has a method to tell if the object must be in a namespace.
type NamespaceScopedStrategy interface {
	// NamespaceScoped returns if the object must be in a namespace.
	NamespaceScoped() bool
}

// AdmissionToValidateObjectFunc converts validating admission to a rest validate object func
func AdmissionToValidateObjectFunc(admit admission.Interface, staticAttributes admission.Attributes, o admission.ObjectInterfaces) ValidateObjectFunc {
	validatingAdmission, ok := admit.(admission.ValidationInterface)
	if !ok {
		return func(ctx context.Context, obj runtime.Object) error { return nil }
	}
	return func(ctx context.Context, obj runtime.Object) error {
		name := staticAttributes.GetName()
		// in case the generated name is populated
		if len(name) == 0 {
			if metadata, err := meta.Accessor(obj); err == nil {
				name = metadata.GetName()
			}
		}

		finalAttributes := admission.NewAttributesRecord(
			obj,
			staticAttributes.GetOldObject(),
			staticAttributes.GetKind(),
			staticAttributes.GetNamespace(),
			name,
			staticAttributes.GetResource(),
			staticAttributes.GetSubresource(),
			staticAttributes.GetOperation(),
			staticAttributes.GetOperationOptions(),
			staticAttributes.IsDryRun(),
			staticAttributes.GetUserInfo(),
		)
		if !validatingAdmission.Handles(finalAttributes.GetOperation()) {
			return nil
		}
		return validatingAdmission.Validate(ctx, finalAttributes, o)
	}
}
