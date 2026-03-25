package PIOP

import "fmt"

// credentialBuilder hosts the credential statement using BuildWithConstraints.
type credentialBuilder struct {
	opts SimOpts
}

func NewCredentialBuilder(opts SimOpts) StatementBuilder {
	opts.applyDefaults()
	return &credentialBuilder{opts: opts}
}

func (b *credentialBuilder) Build(pub PublicInputs, wit WitnessInputs, _ MaskConfig) (*Proof, error) {
	if err := validatePublics(pub); err != nil {
		return nil, err
	}
	if err := validateWitnesses(wit); err != nil {
		return nil, err
	}
	if pub.BoundB <= 0 {
		return nil, fmt.Errorf("BoundB must be > 0")
	}
	ringQ, omega, ncols, err := loadParamsAndOmega(b.opts)
	if err != nil {
		return nil, fmt.Errorf("load params/omega: %w", err)
	}
	if b.opts.DomainMode == DomainModeExplicit {
		nLeaves := b.opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		ell := b.opts.Ell
		if ncols+ell > int(ringQ.N) {
			return nil, fmt.Errorf("explicit domain: need ncols+ell <= ring dimension (ncols=%d ell=%d ringN=%d)", ncols, ell, ringQ.N)
		}
		derivedOmega, _, derr := deriveExplicitDomain(ringQ.Modulus[0], nLeaves, ncols, ell)
		if derr != nil {
			return nil, fmt.Errorf("explicit domain: %w", derr)
		}
		omega = derivedOmega
	}
	cs, err := BuildCredentialConstraintSetPre(ringQ, pub.BoundB, pub, wit, omega)
	if err != nil {
		return nil, fmt.Errorf("build credential constraint set: %w", err)
	}
	proof, err := BuildWithConstraints(pub, wit, cs, b.opts, FSModeCredential)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func (b *credentialBuilder) Verify(pub PublicInputs, proof *Proof) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	if err := validatePublics(pub); err != nil {
		return false, err
	}
	// Constraint set can be left empty for credential verify; the verifier replays FS using proof metadata.
	cs := ConstraintSet{}
	return VerifyWithConstraints(proof, cs, pub, b.opts, FSModeCredential)
}

var _ StatementBuilder = (*credentialBuilder)(nil)
