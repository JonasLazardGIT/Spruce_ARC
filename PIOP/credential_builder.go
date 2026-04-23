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
	opts := b.opts
	for attempt := 0; attempt < 4; attempt++ {
		ringQ, omega, ncols, err := loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("load params/omega: %w", err)
		}
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = ncols
		}
		if len(omega) < witnessNCols {
			return nil, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
		}
		omegaWitness := append([]uint64(nil), omega[:witnessNCols]...)
		if opts.DomainMode == DomainModeExplicit {
			nLeaves := opts.NLeaves
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			ell := opts.Ell
			if ncols+ell > int(ringQ.N) {
				return nil, fmt.Errorf("explicit domain: need ncols+ell <= ring dimension (ncols=%d ell=%d ringN=%d)", ncols, ell, ringQ.N)
			}
			omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, witnessNCols, ncols, ell, pub.HashRelation)
			if err != nil {
				return nil, fmt.Errorf("explicit witness omega: %w", err)
			}
			_, rowInputs, _, _, _, _, _, _, buildErr := buildCredentialRows(ringQ, pub.HashRelation, wit, opts, pub.BoundB, pub.X0CoeffBound)
			if buildErr != nil {
				return nil, fmt.Errorf("build credential rows: %w", buildErr)
			}
			required := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
			if required > ncols {
				opts = bumpExplicitPCSNCols(opts, required)
				continue
			}
		}
		cs, err := BuildCredentialConstraintSetPre(ringQ, pub.BoundB, pub, wit, omegaWitness, opts)
		if err != nil {
			return nil, fmt.Errorf("build credential constraint set: %w", err)
		}
		proof, err := BuildWithConstraints(pub, wit, cs, opts, FSModeCredential)
		if err != nil {
			return nil, err
		}
		return proof, nil
	}
	return nil, fmt.Errorf("could not stabilize explicit PCS width for credential rows")
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
