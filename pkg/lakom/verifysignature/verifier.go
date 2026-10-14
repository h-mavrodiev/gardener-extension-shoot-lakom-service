// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	lakomconfig "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/sync/singleflight"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type directVerifier struct {
	publicKeys lakomconfig.CompletedConfig
	insecure   bool
}

// NewDirectVerifier creates new verifier and returns it.
func NewDirectVerifier(keys lakomconfig.CompletedConfig, allowInsecureRegistries bool) *directVerifier {
	dv := &directVerifier{
		publicKeys: keys,
		insecure:   allowInsecureRegistries,
	}
	return dv
}

// Verify check if artifact is signed by at least one of the configured cosign public keys.
func (r *directVerifier) Verify(ctx context.Context, artifact string, kcr utils.KeyChainReader) (bool, error) {
	opts := []name.Option{}
	if r.insecure {
		opts = append(opts, name.Insecure)
	}
	artifactRef, err := name.ParseReference(artifact, opts...)
	if err != nil {
		return false, err
	}

	keyChain, err := kcr.GetKeyChain()
	if err != nil {
		return false, err
	}

	remoteOpts := ociremote.WithRemoteOptions(
		remote.WithContext(ctx),
		remote.WithUserAgent(constants.ApplicationName),
		remote.WithAuthFromKeychain(keyChain),
	)

	return verify(ctx, artifactRef, r.publicKeys, remoteOpts)
}

func verify(ctx context.Context, artifactRef name.Reference, keys lakomconfig.CompletedConfig, opts ...ociremote.Option) (bool, error) {
	digestRef, ok := artifactRef.(name.Digest)
	if !ok {
		return false, fmt.Errorf("artifact reference is not a digest, reference: %q", artifactRef.Name())
	}

	logger := logf.FromContext(ctx).WithValues("image", artifactRef.Name())

	// signatureFound tracks whether any signature (new-bundle or legacy format) is attached to the
	// artifact at all, so that an unsigned artifact can be distinguished from one whose signatures
	// do not match any of the configured public keys.
	signatureFound := false

	// We need successful verification for at least one key, therefore any other failures can be ignored.
	for _, k := range keys.Keys {
		log := logger.WithValues("keyName", k.Name)
		loadOpts := []signature.LoadOption{}

		if k.Hash != nil {
			loadOpts = append(loadOpts, options.WithHash(*k.Hash))
			log = log.WithValues("hash", k.Hash.String())
		}

		if k.RSAScheme != nil {
			log = log.WithValues("scheme", k.RSAScheme)

			if *k.RSAScheme == lakomconfig.RSASSAPSS {
				loadOpts = append(loadOpts, options.WithRSAPSS(&rsa.PSSOptions{Hash: *k.Hash}))
			}
		}

		verifier, err := signature.LoadVerifierWithOpts(k.Key, loadOpts...)
		if err != nil {
			log.Info("Failed creating verifier", "error", err.Error())
			continue
		}

		// Verify the image signature against the current public key. The new cosign v3 bundle
		// format (OCI 1.1 referrer) is checked first, falling back to the legacy ".sig" tag format.
		verified, found, err := verifyNewBundle(ctx, digestRef, verifier, log, opts...)
		if err != nil {
			return false, err
		}
		signatureFound = signatureFound || found
		if verified {
			log.Info("Image signature successfully verified", "format", "new-bundle")
			return true, nil
		}

		verified, found, err = verifyLegacySignature(ctx, digestRef, verifier, log, opts...)
		if err != nil {
			return false, err
		}
		signatureFound = signatureFound || found
		if verified {
			log.Info("Image signature successfully verified", "format", "legacy")
			return true, nil
		}
	}

	if !signatureFound {
		logger.Info("No signatures found for the artifact")
		return false, nil
	}

	logger.Info("Image signature verification failed for all configured keys")
	return false, nil
}

// verifyLegacySignature verifies the legacy cosign signature (attached as a ".sig" tag) of the
// artifact against the provided verifier. The returned 'found' indicates whether any legacy
// signature is attached to the artifact at all, so that the caller can distinguish an unsigned
// artifact from a signature that does not match the current key.
func verifyLegacySignature(ctx context.Context, artifactRef name.Digest, verifier signature.Verifier, log logr.Logger, opts ...ociremote.Option) (verified bool, found bool, err error) {
	checkedSignatures, _, err := cosign.VerifyImageSignatures(ctx, artifactRef, &cosign.CheckOpts{
		RegistryClientOpts: opts,
		SigVerifier:        verifier,
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		IgnoreSCT:          true,
		IgnoreTlog:         true,
	})
	if err != nil {
		if IsNoSignaturesFound(err) {
			return false, false, nil
		}

		if IsNoMatchingSignatures(err) {
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// Mitigation for https://github.com/gardener/gardener-extension-shoot-lakom-service/issues/25
				// TODO(vpnachev): remove when https://github.com/sigstore/cosign/issues/3133 is fixed and vendored
				log.Info("No matching signatures error detected as canceled or deadline exceeded context", "error", err)
				return false, true, err
			}

			log.Info("No matching legacy signatures found for current public key", "error", err.Error())
			return false, true, nil
		}

		return false, true, err
	}

	if len(checkedSignatures) == 0 {
		// the cosign library is returning an error if the checkedSignatures are 0
		// but this can changed in a future version and break us
		log.Info("Found no valid legacy signatures")
		return false, true, nil
	}

	return true, true, nil
}

// verifyNewBundle verifies the cosign v3 new bundle format signatures (attached as OCI 1.1
// referrers) of the artifact against the provided verifier. It returns verified=true as soon
// as one attached bundle is successfully verified. The returned 'found' indicates whether any
// new-bundle signature is attached to the artifact at all, so that the caller can distinguish an
// artifact without a new-bundle signature (fall back to the legacy format) from a new-bundle
// signature that does not match the current key (try the next key).
func verifyNewBundle(ctx context.Context, artifactRef name.Digest, verifier signature.Verifier, log logr.Logger, opts ...ociremote.Option) (verified bool, found bool, err error) {
	bundles, hash, err := cosign.GetBundles(ctx, artifactRef, opts)
	if err != nil {
		// Both errors indicate that no new bundle format signature is attached to the artifact,
		// which is not a verification failure - the caller falls back to the legacy format.
		if IsNoMatchingAttestations(err) || IsImageTagNotFound(err) {
			return false, false, nil
		}
		return false, false, err
	}

	digestBytes, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return false, true, err
	}
	artifactPolicyOption := sgverify.WithArtifactDigest(hash.Algorithm, digestBytes)

	checkOpts := &cosign.CheckOpts{
		SigVerifier:     verifier,
		ClaimVerifier:   cosign.SimpleClaimVerifier,
		IgnoreSCT:       true,
		IgnoreTlog:      true,
		NewBundleFormat: true,
	}

	for _, bundle := range bundles {
		if _, err := cosign.VerifyNewBundle(ctx, checkOpts, artifactPolicyOption, bundle); err != nil {
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return false, true, err
			}

			log.Info("New bundle signature did not verify for current public key", "error", err.Error())
			continue
		}

		return true, true, nil
	}

	return false, true, nil
}

type cacheVerifier struct {
	cache          SignatureVerificationResultCache
	actualVerifier Verifier
	requestGroup   singleflight.Group
}

// NewCacheVerifier creates cached verifier from the provided cache and verifier.
func NewCacheVerifier(cache SignatureVerificationResultCache, verifier Verifier) *cacheVerifier {
	cv := &cacheVerifier{
		cache:          cache,
		actualVerifier: verifier,
	}
	return cv
}

// Verify check cosign signature of an artifact. Firstly it checks if the cache have an entry
// for the verification state of the artifact and returns it. If the cache have no entry,
// it uses the verifier to do the real verification, persists the result in the cache and return it.
func (r *cacheVerifier) Verify(ctx context.Context, artifact string, kcr utils.KeyChainReader) (bool, error) {
	verified, found := r.cache.GetSignatureVerificationResult(artifact)
	if found {
		metrics.ImageSignatureCache.WithLabelValues(metrics.CacheHit).Inc()
		return verified, nil
	}

	defer r.requestGroup.Forget(artifact)
	v, err, _ := r.requestGroup.Do(artifact, func() (any, error) {
		verified, err := r.actualVerifier.Verify(ctx, artifact, kcr)
		if err != nil {
			return false, err
		}
		return verified, nil
	})
	if err != nil {
		return false, err
	}

	// Casting is safe here
	verified = v.(bool)
	metrics.ImageSignatureCache.WithLabelValues(metrics.CacheMiss).Inc()
	r.cache.StoreSignatureVerificationResult(artifact, verified)
	return verified, nil
}

// IsNoMatchingSignatures checks if error is of type
// [cosign.ErrNoMatchingSignatures].
func IsNoMatchingSignatures(err error) bool {
	var t *cosign.ErrNoMatchingSignatures
	return errors.As(err, &t)
}

// IsNoSignaturesFound checks if error is of type
// [cosign.ErrNoSignaturesFound].
func IsNoSignaturesFound(err error) bool {
	var t *cosign.ErrNoSignaturesFound
	return errors.As(err, &t)
}

// IsNoMatchingAttestations checks if error is of type
// [cosign.ErrNoMatchingAttestations]. It is returned by [cosign.GetBundles]
// when no new bundle format signatures are attached to the artifact.
func IsNoMatchingAttestations(err error) bool {
	var t *cosign.ErrNoMatchingAttestations
	return errors.As(err, &t)
}

// IsImageTagNotFound checks if error is of type
// [cosign.ErrImageTagNotFound]. It is returned by [cosign.GetBundles]
// when the artifact tag cannot be resolved in the registry.
func IsImageTagNotFound(err error) bool {
	var t *cosign.ErrImageTagNotFound
	return errors.As(err, &t)
}
