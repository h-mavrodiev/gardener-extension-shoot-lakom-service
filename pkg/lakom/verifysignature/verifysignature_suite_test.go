// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/gardener/gardener/pkg/utils/test"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ggcrstatic "github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociRemote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	// FullRef use the digest instead of the tag.
	signedImageFullRef          string
	newBundleSignedImageFullRef string
	unsignedImageFullRef        string

	// TagRef use the tag instead of the digest for referencing the artifact.
	signedImageTagRef      string
	unsignedImageTagRef    string
	nonExistentImageTagRef string

	// Public key in PEM format for verifying signatures in the fake registry
	publicKey string

	scheme *runtime.Scheme
	mgr    test.FakeManager
)

const (
	signedImageTag          = "signed"
	newBundleSignedImageTag = "newbundlesigned"
	unsignedImageTag        = "unsigned"
)

func TestVerifySignatureSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VerifySignature Suite")
}

var _ = BeforeSuite(func() {
	scheme = runtime.NewScheme()
	Expect(corev1.AddToScheme(scheme)).To(Succeed())
	mgr.Scheme = scheme

	dirPath, err := os.MkdirTemp("", "verifysignature_test")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := os.RemoveAll(dirPath)
		Expect(err).ToNot(HaveOccurred())
	})

	// Tests rely on a fake registry
	registryURL, server := startRegistry()
	DeferCleanup(func() {
		server.Close()
	})

	signedImage, signedImageRef, err := createTestImage(registryURL, signedImageTag)
	Expect(err).ToNot(HaveOccurred())
	newBundleSignedImage, newBundleSignedImageRef, err := createTestImage(registryURL, newBundleSignedImageTag)
	Expect(err).ToNot(HaveOccurred())
	_, unsignedImageRef, err := createTestImage(registryURL, unsignedImageTag)
	Expect(err).ToNot(HaveOccurred())

	signedImageFullRef = signedImageRef.Name()
	newBundleSignedImageFullRef = newBundleSignedImageRef.Name()
	unsignedImageFullRef = unsignedImageRef.Name()

	signedImageTagRef = signedImageRef.Context().Tag(signedImageTag).String()
	unsignedImageTagRef = unsignedImageRef.Context().Tag(unsignedImageTag).String()

	nonExistentImageTagRef = fmt.Sprintf("%s:nonexistant", signedImageRef.Context().Name())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())
	publicKey, err = publicKeyToPEM(privateKey.Public())
	Expect(err).ToNot(HaveOccurred())

	Expect(signImage(signedImage, signedImageFullRef, privateKey)).ToNot(HaveOccurred())
	Expect(signImageNewBundleFormat(newBundleSignedImage, newBundleSignedImageFullRef, privateKey)).ToNot(HaveOccurred())
})

func startRegistry() (*url.URL, *httptest.Server) {
	ginkgoLogger := log.New(GinkgoWriter, "", 0)
	s := httptest.NewServer(registry.New(registry.Logger(ginkgoLogger)))
	u, err := url.Parse(s.URL)
	Expect(err).ToNot(HaveOccurred())

	return u, s
}

func publicKeyToPEM(pub crypto.PublicKey) (string, error) {
	// Marshal the public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	// Encode the PEM block to a string
	pemBytes := pem.EncodeToMemory(pemBlock)

	return string(pemBytes), nil
}

func createTestImage(registryURL *url.URL, tag string) (registryv1.Image, name.Reference, error) {
	// Create image
	i, err := random.Image(512, 1)
	if err != nil {
		return nil, nil, err
	}

	// Create tag
	tagName := fmt.Sprintf("%s/%s:%s", registryURL.Host, "test", tag)
	tagRef, err := name.NewTag(tagName)
	if err != nil {
		return nil, nil, err
	}

	// Write image to registry
	if err = remote.Write(tagRef, i); err != nil {
		return nil, nil, err
	}

	// Get digest
	headResponse, err := remote.Head(tagRef)
	if err != nil {
		return nil, nil, err
	}

	fullRef := tagRef.Context().Name() + "@" + headResponse.Digest.String()

	reference, err := name.ParseReference(fullRef)
	if err != nil {
		return nil, nil, err
	}

	return i, reference, nil
}

func signImage(image registryv1.Image, imageFullRef string, privateKey *ecdsa.PrivateKey) error {
	digest, err := name.NewDigest(imageFullRef)
	if err != nil {
		return err
	}

	signerVerifier, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return err
	}

	payload, signature, err := signature.SignImage(signerVerifier, digest, nil)
	if err != nil {
		return err
	}

	ociSignature, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		return err
	}

	si := signed.Image(image)
	si, err = mutate.AttachSignatureToImage(si, ociSignature)
	if err != nil {
		return err
	}

	return ociRemote.WriteSignatures(digest.Context(), si)
}

// signImageNewBundleFormat signs the image using the cosign v3 new bundle format (Cosign Bundle
// Spec) and attaches it to the image as an OCI 1.1 referrer, mirroring what `cosign sign
// --new-bundle-format` produces for a static public key (no Fulcio certificate, no Rekor entry,
// no TSA timestamp). The message signature is computed over the raw image digest bytes, which is
// what the verifier checks via verify.WithArtifactDigest.
func signImageNewBundleFormat(_ registryv1.Image, imageFullRef string, privateKey *ecdsa.PrivateKey) error {
	digest, err := name.NewDigest(imageFullRef)
	if err != nil {
		return err
	}

	// The sha256 of the image manifest - this is the artifact digest the signature is bound to.
	hash, err := registryv1.NewHash(digest.DigestStr())
	if err != nil {
		return err
	}
	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return err
	}

	signerVerifier, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return err
	}

	// Sign the pre-hashed image digest. This matches sigstore-go's message-signature verification,
	// which calls VerifySignature(sig, <empty>, options.WithDigest(artifactDigest)).
	sig, err := signerVerifier.SignMessage(bytes.NewReader([]byte{}), options.WithDigest(digestBytes))
	if err != nil {
		return err
	}

	// Build the public key hint (base64(sha256(PKIX(pubKey)))) exactly as cosign does.
	pkixPubKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return err
	}
	hashedBytes := sha256.Sum256(pkixPubKey)
	hint := base64.StdEncoding.EncodeToString(hashedBytes[:])

	bundle, err := cbundle.MakeProtobufBundle(hint, nil, nil, nil)
	if err != nil {
		return err
	}
	bundle.Content = &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    digestBytes,
			},
			Signature: sig,
		},
	}

	bundleBytes, err := protojson.Marshal(bundle)
	if err != nil {
		return err
	}

	bundleMediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		return err
	}
	layer := ggcrstatic.NewLayer(bundleBytes, ggcrtypes.MediaType(bundleMediaType))

	return ociRemote.WriteReferrer(digest, bundleMediaType, []registryv1.Layer{layer}, nil)
}
