package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// FS personalization string for credential-mode statements.
const FSModeCredential = "PACS-Credential"

type preparedCredentialBuild struct {
	rows                  []*ring.Poly
	rowInputs             []lvcs.RowInput
	rowLayout             RowLayout
	decsParams            decs.Params
	maskRowOffset         int
	maskRowCount          int
	witnessCount          int
	witnessNCols          int
	omega                []uint64
	omegaWitness         []uint64
	domainPoints         []uint64
	skipConstraintRebuild bool
}

// BuildWithConstraints proves a credential-mode statement from explicit
// publics/witnesses and a custom constraint set (F-polys).
func BuildWithConstraints(pub PublicInputs, wit WitnessInputs, set ConstraintSet, opts SimOpts, personalization string) (*Proof, error) {
	return buildWithConstraintsPrepared(pub, wit, set, opts, personalization, nil)
}

func buildWithConstraintsPrepared(pub PublicInputs, wit WitnessInputs, set ConstraintSet, opts SimOpts, personalization string, prepared *preparedCredentialBuild) (*Proof, error) {
	opts.applyDefaults()
	if personalization == "" {
		personalization = FSModeCredential
	}
	if opts.Credential {
		// Credential path: build rows, commit, derive mask config, and run FS with supplied constraints/publics.
		ringQ, omega, ncols, err := loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("load params/omega: %w", err)
		}
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = ncols
		}
		if ncols < witnessNCols {
			return nil, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", ncols, witnessNCols)
		}
		var domainPoints []uint64
		if opts.DomainMode == DomainModeExplicit {
			if opts.NLeaves <= 0 {
				opts.NLeaves = int(ringQ.N)
			}
			if ncols+opts.Ell > int(ringQ.N) {
				return nil, fmt.Errorf("explicit domain: need ncols+ell <= ring dimension (ncols=%d ell=%d ringN=%d)", ncols, opts.Ell, ringQ.N)
			}
			var derr error
			omega, domainPoints, derr = deriveExplicitDomainForRelation(ringQ.Modulus[0], opts.NLeaves, witnessNCols, ncols, opts.Ell, pub.HashRelation)
			if derr != nil {
				return nil, fmt.Errorf("explicit domain: %w", derr)
			}
		}
		if len(omega) < witnessNCols {
			return nil, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
		}
		omegaWitness := append([]uint64(nil), omega[:witnessNCols]...)
		if opts.DomainMode == DomainModeExplicit && pub.HashRelation != "" {
			nLeaves := opts.NLeaves
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			derivedWitnessOmega, derr := deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, witnessNCols, ncols, opts.Ell, pub.HashRelation)
			if derr != nil {
				return nil, fmt.Errorf("derive explicit witness omega: %w", derr)
			}
			omegaWitness = derivedWitnessOmega
		}
		if len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0 {
			return nil, fmt.Errorf("empty constraint set for credential mode")
		}
		// Map witness inputs to rows/layout/decs params.
		var rows []*ring.Poly
		var rowInputs []lvcs.RowInput
		var rowLayout RowLayout
		var decsParams decs.Params
		var maskRowOffset, maskRowCount, witnessCount int
		if prepared != nil {
			rows = prepared.rows
			rowInputs = prepared.rowInputs
			rowLayout = prepared.rowLayout
			decsParams = prepared.decsParams
			maskRowOffset = prepared.maskRowOffset
			maskRowCount = prepared.maskRowCount
			witnessCount = prepared.witnessCount
			if prepared.witnessNCols > 0 {
				witnessNCols = prepared.witnessNCols
				if len(omega) < witnessNCols {
					return nil, fmt.Errorf("prepared witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
				}
				omegaWitness = append([]uint64(nil), omega[:witnessNCols]...)
			}
			if len(prepared.omega) > 0 {
				omega = append([]uint64(nil), prepared.omega...)
				ncols = len(omega)
				if ncols < witnessNCols {
					return nil, fmt.Errorf("prepared lvcs omega len=%d < witness ncols=%d", ncols, witnessNCols)
				}
			}
			if len(prepared.domainPoints) > 0 {
				domainPoints = append([]uint64(nil), prepared.domainPoints...)
			}
			if len(prepared.omegaWitness) > 0 {
				if len(prepared.omegaWitness) != witnessNCols {
					return nil, fmt.Errorf("prepared witness omega len=%d want %d", len(prepared.omegaWitness), witnessNCols)
				}
				omegaWitness = append([]uint64(nil), prepared.omegaWitness...)
			}
		} else {
			useShowingRows := opts.CoeffPacking && wit.CoeffNativeShowing != nil
			if useShowingRows {
				params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
				if perr != nil {
					return nil, fmt.Errorf("load prf params: %w", perr)
				}
				groupRounds := opts.PRFGroupRounds
				if set.PRFLayout != nil && set.PRFLayout.GroupRounds > 0 {
					groupRounds = set.PRFLayout.GroupRounds
				}
				if groupRounds <= 0 {
					groupRounds = 1
				}
				var prfLayout *PRFLayout
				var prfCompanionLayout *PRFCompanionLayout
				rows, rowInputs, rowLayout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, _, err = BuildCredentialRowsShowing(ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, groupRounds, opts)
				if err != nil {
					return nil, fmt.Errorf("build showing rows: %w", err)
				}
				set.PRFLayout = prfLayout
				set.PRFCompanionLayout = prfCompanionLayout
			} else {
				rows, rowInputs, rowLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, err = buildCredentialRows(ringQ, pub.HashRelation, wit, opts, pub.BoundB)
			}
			if err != nil {
				return nil, fmt.Errorf("build credential rows: %w", err)
			}
		}
		if set.PRFLayout != nil {
			return nil, fmt.Errorf("legacy PRF layout is no longer supported")
		}
		if opts.DomainMode == DomainModeExplicit {
			requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
			if requiredPCSNCols > ncols {
				return nil, fmt.Errorf("explicit pcs width %d is too small for committed row degree; need at least %d", ncols, requiredPCSNCols)
			}
		}
		if cerr := ValidateRowDependencyClosure(rowLayout, set.PRFLayout, witnessCount); cerr != nil {
			return nil, fmt.Errorf("row dependency closure: %w", cerr)
		}
		if cerr := ValidatePRFCompanionLayout(set.PRFCompanionLayout, witnessCount); cerr != nil {
			return nil, fmt.Errorf("prf companion layout: %w", cerr)
		}
		var root [16]byte
		var pk *lvcs.ProverKey
		var oracleLayout lvcs.OracleLayout
		var sigShortness *SigShortnessProof
		var sigShortnessBindingDigest []byte
		labels := BuildPublicLabels(pub)
		labelsDigest := computeLabelsDigest(labels)

		parAlg := set.ParallelAlgDeg
		aggAlg := set.AggregatedAlgDeg
		_, _, maskTarget, maskBound, maskCfg, err := deriveMaskingConfig(ringQ, opts, parAlg, aggAlg, omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("derive masking config: %w", err)
		}
		if opts.Eta <= 0 {
			return nil, fmt.Errorf("invalid Eta=%d", opts.Eta)
		}
		decsParams = decs.Params{Degree: maskCfg.DQ, Eta: opts.Eta, NonceBytes: 16}

		rho := opts.Rho
		if rho <= 0 {
			rho = 1
		}
		maskRowCount = rho

		// Preserve the base witness polynomials (without PACS masks).
		origWitnessCount := witnessCount
		witnessPolys := rows[:origWitnessCount]
		companionRowInputs := append([]lvcs.RowInput(nil), rowInputs[:origWitnessCount]...)

		// Small-field params (theta>1) if needed.
		var sfK *kf.Field
		var sfChi []uint64
		var sfOmegaS1 []uint64
		var sfMuInv []uint64
		sfNCols := ncols
		pcsGeometry := makeLegacyPCSGeometry(witnessNCols, sfNCols, opts.Theta, opts.Ell, len(witnessPolys), witnessCount, maskRowOffset, maskRowCount)

		if opts.Theta > 1 {
			sf, sfErr := deriveSmallFieldParamsNoRows(ringQ, omegaWitness, opts.Theta)
			if sfErr != nil {
				return nil, fmt.Errorf("small-field params: %w", sfErr)
			}
			sfK = sf.K
			sfChi = sf.Chi
			sfOmegaS1 = append([]uint64(nil), sf.OmegaS1.Limb...)
			sfMuInv = append([]uint64(nil), sf.MuInv.Limb...)
			sfNCols = len(omega)
		}

		q := ringQ.Modulus[0]
		// Sample PACS masks (base field and, when θ>1, the K-masks).
		var maskPolys []*ring.Poly
		var maskPolysK []*KPoly
		maskPolyCoeffs := make([]*ring.Poly, rho)
		maskCoeffRows := make([][]uint64, rho)
		if opts.Theta > 1 {
			if sfK == nil {
				return nil, fmt.Errorf("missing K field for theta=%d", opts.Theta)
			}
			maskPolysK = SampleIndependentMaskPolynomialsK(ringQ, sfK, rho, maskTarget, omegaWitness)
			if len(maskPolysK) != rho {
				return nil, fmt.Errorf("expected %d K masks, got %d", rho, len(maskPolysK))
			}
			maskPolys = make([]*ring.Poly, rho)
			for i := 0; i < rho; i++ {
				coeffs := firstLimbCoeffs(maskPolysK[i], q)
				maskCoeffRows[i] = coeffs
				if len(coeffs) > int(ringQ.N) {
					continue
				}
				coeff := ringQ.NewPoly()
				copy(coeff.Coeffs[0], coeffs)
				maskPolyCoeffs[i] = coeff
				ntt := coeff.CopyNew()
				ringQ.NTT(ntt, ntt)
				maskPolys[i] = ntt
			}
		} else {
			if opts.DomainMode == DomainModeExplicit && maskTarget >= int(ringQ.N) {
				maskCoeffRows = SampleIndependentMaskPolynomialCoeffs(q, rho, maskTarget, omegaWitness)
				maskPolys = make([]*ring.Poly, rho)
				for i := 0; i < rho; i++ {
					if len(maskCoeffRows[i]) <= int(ringQ.N) {
						coeff := ringQ.NewPoly()
						copy(coeff.Coeffs[0], maskCoeffRows[i])
						maskPolyCoeffs[i] = coeff
						ntt := coeff.CopyNew()
						ringQ.NTT(ntt, ntt)
						maskPolys[i] = ntt
					}
				}
			} else {
				maskPolys = SampleIndependentMaskPolynomials(ringQ, rho, maskTarget, omegaWitness)
				for i := 0; i < rho; i++ {
					coeff := ringQ.NewPoly()
					ringQ.InvNTT(maskPolys[i], coeff)
					maskPolyCoeffs[i] = coeff
					maskCoeffRows[i] = trimCoeffsCopy(coeff.Coeffs[0], q)
				}
			}
		}

		// Rebuild row heads on Ω and wire PACS mask rows as true polynomials.
		if opts.Theta > 1 {
			if sfK == nil {
				return nil, fmt.Errorf("missing K field for theta=%d", opts.Theta)
			}
			pcsRows, pcsErr := buildSmallFieldPCSRows(
				ringQ,
				omegaWitness,
				len(omega),
				opts.Ell,
				sfK,
				kf.Elem{Limb: append([]uint64(nil), sfOmegaS1...)},
				witnessPolys,
				maskPolysK,
				maskTarget,
			)
			if pcsErr != nil {
				return nil, fmt.Errorf("small-field pcs rows: %w", pcsErr)
			}
			rowInputs = pcsRows.RowInputs
			witnessCount = pcsRows.WitnessCount
			maskRowOffset = pcsRows.MaskRowOffset
			maskRowCount = pcsRows.MaskRowCount
			pcsGeometry = pcsRows.PCSGeometry
		} else {
			maskRowCount = rho
			maskRowOffset = witnessCount
			expectedRows := witnessCount + rho
			if len(rows) != expectedRows {
				return nil, fmt.Errorf("row count mismatch: got %d want %d (witness=%d rho=%d)", len(rows), expectedRows, witnessCount, rho)
			}
			rowInputs = make([]lvcs.RowInput, expectedRows)
			if opts.DomainMode == DomainModeExplicit {
				for i := 0; i < witnessCount; i++ {
					head, herr := rowHeadOnOmega(ringQ, omega, rows[i], len(omega))
					if herr != nil {
						return nil, fmt.Errorf("row %d head on omega: %w", i, herr)
					}
					rowInputs[i] = lvcs.RowInput{Head: head}
					if opts.Credential {
						rowInputs[i].Poly = rows[i]
						rowInputs[i].PolyCoeffs = trimCoeffsCopy(rows[i].Coeffs[0], q)
					}
				}
			} else {
				tmpNTT := ringQ.NewPoly()
				for i := 0; i < witnessCount; i++ {
					ringQ.NTT(rows[i], tmpNTT)
					head := append([]uint64(nil), tmpNTT.Coeffs[0][:len(omega)]...)
					for j := range head {
						head[j] %= q
					}
					rowInputs[i] = lvcs.RowInput{Head: head}
				}
			}
			for i := 0; i < rho; i++ {
				head := make([]uint64, len(omega))
				coeffs := maskCoeffRows[i]
				for j, w := range omega {
					head[j] = EvalPoly(coeffs, w%q, q)
				}
				rowInputs[maskRowOffset+i] = lvcs.RowInput{Head: head, Poly: maskPolyCoeffs[i], PolyCoeffs: coeffs}
			}
			pcsGeometry = makeLegacyPCSGeometry(witnessNCols, sfNCols, opts.Theta, opts.Ell, len(witnessPolys), witnessCount, maskRowOffset, maskRowCount)
		}
		if rowDeg := rowOracleDegreeFloor(ringQ, rowInputs, opts.Ell); rowDeg > decsParams.Degree {
			decsParams.Degree = rowDeg
		}
		// Commit rows to get root/pk/layout using possibly updated rowInputs/layout.
		root, pk, oracleLayout, err = commitRows(ringQ, rowInputs, opts.Ell, decsParams, witnessCount, maskRowOffset, maskRowCount, domainPoints)
		if err != nil {
			return nil, fmt.Errorf("commit rows: %w", err)
		}
		pcsGeometry.OracleLayout = oracleLayout
		if rowLayoutHasCoeffNativeSig(rowLayout) && rowLayoutCoeffNativeUsesLiteralPacked(rowLayout) && wit.CoeffNativeShowing != nil {
			pcsNCols := ncols
			if pcsNCols <= 0 {
				pcsNCols = witnessNCols
			}
			sigShortness, sigShortnessBindingDigest, err = buildSigShortnessProofV6(
				ringQ,
				pk,
				root,
				rowLayout,
				wit.CoeffNativeShowing,
				pub,
				omegaWitness,
				witnessNCols,
				pcsNCols,
				opts,
			)
			if err != nil {
				return nil, fmt.Errorf("build sig shortness V6: %w", err)
			}
		}

		// Rebuild constraints to match paper-defined F_j(P,Theta). In θ>1 mode the
		// committed oracle rows are transposed into the §5.4 layer layout, so
		// replay constraint rebuilding must use the witness polynomials.
		skipConstraintRebuild := prepared != nil && prepared.skipConstraintRebuild && rowLayoutHasCoeffNativeSig(rowLayout)
		if !skipConstraintRebuild {
			constraintRows := pk.RowPolys
			if opts.Theta > 1 {
				constraintRows = make([]*ring.Poly, len(witnessPolys))
				for i := range witnessPolys {
					if witnessPolys[i] == nil {
						continue
					}
					p := ringQ.NewPoly()
					ring.Copy(witnessPolys[i], p)
					ringQ.NTT(p, p)
					constraintRows[i] = p
				}
			}
			if opts.Credential && len(constraintRows) > 0 {
				rebuiltEmpty := len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0
				if len(pub.Ac) > 0 && len(pub.B) > 0 && len(pub.A) == 0 {
					preRows, cerr := buildCredentialConstraintSetPreFromRows(ringQ, pub.BoundB, pub, rowLayout, constraintRows, omegaWitness, opts.DomainMode)
					if cerr != nil {
						return nil, cerr
					}
					if rebuiltEmpty {
						set = preRows
					} else {
						set.FparInt = append([]*ring.Poly{}, preRows.FparInt...)
						set.FparIntCoeffs = append([][]uint64{}, preRows.FparIntCoeffs...)
						set.FparNorm = append([]*ring.Poly{}, preRows.FparNorm...)
						set.FparNormCoeffs = append([][]uint64{}, preRows.FparNormCoeffs...)
						set.FaggInt = append([]*ring.Poly{}, preRows.FaggInt...)
						set.FaggIntCoeffs = append([][]uint64{}, preRows.FaggIntCoeffs...)
						set.FaggNorm = append([]*ring.Poly{}, preRows.FaggNorm...)
						set.FaggNormCoeffs = append([][]uint64{}, preRows.FaggNormCoeffs...)
						set.ParallelAlgDeg = preRows.ParallelAlgDeg
						set.AggregatedAlgDeg = preRows.AggregatedAlgDeg
					}
				} else if len(pub.A) > 0 && len(pub.B) > 0 {
					postRows, cerr := rebuildPostSignConstraintSetWithBridges(ringQ, pub, rowLayout, constraintRows, omegaWitness, opts, root, set.PRFLayout, set.PRFCompanionLayout)
					if cerr != nil {
						return nil, cerr
					}
					if rebuiltEmpty {
						set.FparInt = append([]*ring.Poly{}, postRows.FparInt...)
						set.FparIntCoeffs = append([][]uint64{}, postRows.FparIntCoeffs...)
					} else {
						if len(set.FparInt) < len(postRows.FparInt) {
							return nil, fmt.Errorf("constraint set too small for post-sign prefix: have %d want >=%d", len(set.FparInt), len(postRows.FparInt))
						}
						copy(set.FparInt[:len(postRows.FparInt)], postRows.FparInt)
						if len(set.FparIntCoeffs) < len(set.FparInt) {
							expanded := make([][]uint64, len(set.FparInt))
							copy(expanded, set.FparIntCoeffs)
							set.FparIntCoeffs = expanded
						}
						for i := 0; i < len(postRows.FparInt); i++ {
							set.FparIntCoeffs[i] = nil
						}
						if len(postRows.FparIntCoeffs) > 0 {
							copy(set.FparIntCoeffs[:len(postRows.FparInt)], postRows.FparIntCoeffs)
						}
					}
					set.FparNorm = append([]*ring.Poly{}, postRows.FparNorm...)
					set.FparNormCoeffs = append([][]uint64{}, postRows.FparNormCoeffs...)
					set.FaggInt = append([]*ring.Poly{}, postRows.FaggInt...)
					set.FaggIntCoeffs = append([][]uint64{}, postRows.FaggIntCoeffs...)
					set.FaggNorm = append([]*ring.Poly{}, postRows.FaggNorm...)
					set.FaggNormCoeffs = append([][]uint64{}, postRows.FaggNormCoeffs...)
					if postRows.ParallelAlgDeg > set.ParallelAlgDeg {
						set.ParallelAlgDeg = postRows.ParallelAlgDeg
					}
					if postRows.AggregatedAlgDeg > set.AggregatedAlgDeg {
						set.AggregatedAlgDeg = postRows.AggregatedAlgDeg
					}
				}

				// PRF constraints are replayed via the companion layout only.
			}
		}

		// Assemble MaskingFSInput and run.
		mfsIn := MaskingFSInput{
			RingQ:              ringQ,
			Opts:               opts,
			Omega:              omega,
			OmegaWitness:       omegaWitness,
			DomainPoints:       domainPoints,
			Root:               root,
			PK:                 pk,
			OracleLayout:       oracleLayout,
			RowLayout:          rowLayout,
			FparInt:            set.FparInt,
			FparNorm:           set.FparNorm,
			FaggInt:            set.FaggInt,
			FaggNorm:           set.FaggNorm,
			FparIntCoeffs:      set.FparIntCoeffs,
			FparNormCoeffs:     set.FparNormCoeffs,
			FaggIntCoeffs:      set.FaggIntCoeffs,
			FaggNormCoeffs:     set.FaggNormCoeffs,
			PRFCompanionLayout: set.PRFCompanionLayout,
			PRFCompanionRows:   companionRowInputs,
			PRFTagPublic:       copyInt64Matrix(pub.Tag),
			PRFNoncePublic:     copyInt64Matrix(pub.Nonce),
			RowInputs:          rowInputs,
			// Theta>1 derives row heads from PK and layout on Ω.
			WitnessPolys:      witnessPolys,
			MaskPolys:         maskPolys,
			MaskPolyCoeffs:    maskCoeffRows,
			MaskPolysK:        maskPolysK,
			MaskRowOffset:     maskRowOffset,
			MaskRowCount:      maskRowCount,
			PCSGeometry:       pcsGeometry,
			MaskDegreeTarget:  maskTarget,
			MaskDegreeBound:   maskBound,
			Personalization:   personalization,
			NCols:             witnessNCols,
			PCSNCols:          sfNCols,
			LVCSNCols:         sfNCols,
			DecsParams:        decsParams,
			LabelsDigest:      labelsDigest,
			SigShortnessBindingDigest: sigShortnessBindingDigest,
			SmallFieldChi:     sfChi,
			SmallFieldOmegaS1: sfOmegaS1,
			SmallFieldMuInv:   sfMuInv,
			SmallFieldK:       sfK,
		}
		proof, err := RunMaskingFS(mfsIn)
		if err != nil {
			return nil, fmt.Errorf("RunMaskingFS: %w", err)
		}
		proof.HashRelation = pub.HashRelation
		proof.LabelsDigest = labelsDigest
		proof.PRFLayout = nil
		if proof.PRFCompanion != nil && proof.PRFCompanion.Layout == nil {
			proof.PRFCompanion.Layout = clonePRFCompanionLayout(set.PRFCompanionLayout)
		}
		if sigShortness != nil {
			proof.SigShortness = sigShortness
			if serr := VerifySigShortnessProof(proof, ringQ, omegaWitness, pub, opts); serr != nil {
				return nil, fmt.Errorf("build sig shortness self-check: %w", serr)
			}
		}
		return proof, nil
	}
	return nil, fmt.Errorf("unsupported non-credential BuildWithConstraints path")
}

// VerifyWithConstraints replays the verifier transcript for a built proof.
func VerifyWithConstraints(proof *Proof, set ConstraintSet, pub PublicInputs, opts SimOpts, personalization string) (bool, error) {
	opts.applyDefaults()
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	if personalization == "" {
		personalization = FSModeCredential
	}
	if opts.Credential {
		if proof.PRFLayout != nil {
			return false, fmt.Errorf("legacy PRF layout is no longer supported")
		}
		if set.PRFCompanionLayout == nil && proof.PRFCompanion != nil {
			set.PRFCompanionLayout = clonePRFCompanionLayout(proof.PRFCompanion.Layout)
		}
		labels := BuildPublicLabels(pub)
		digest := computeLabelsDigest(labels)
		if len(proof.LabelsDigest) == 0 {
			proof.LabelsDigest = digest
		} else if !equalByteSlices(digest, proof.LabelsDigest) {
			return false, fmt.Errorf("labels digest mismatch")
		}
		if proof.NColsUsed == 0 && opts.NCols > 0 {
			proof.NColsUsed = opts.NCols
		}
		if proof.LVCSNColsUsed == 0 {
			if opts.LVCSNCols > 0 {
				proof.LVCSNColsUsed = opts.LVCSNCols
			} else if proof.NColsUsed > 0 {
				proof.LVCSNColsUsed = proof.NColsUsed
			}
		}
		ringQ, omega, _, err := loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return false, fmt.Errorf("load params for replay: %w", err)
		}
		var domainPoints []uint64
		witnessNCols := ringQ.N
		if opts.NCols > 0 {
			witnessNCols = opts.NCols
		}
		if proof.NColsUsed > 0 {
			witnessNCols = proof.NColsUsed
		}
		lvcsNCols := witnessNCols
		if opts.LVCSNCols > 0 {
			lvcsNCols = opts.LVCSNCols
		}
		if proof.LVCSNColsUsed > 0 {
			lvcsNCols = proof.LVCSNColsUsed
		}
		if witnessNCols <= 0 {
			return false, fmt.Errorf("invalid witness ncols=%d for replay", witnessNCols)
		}
		if lvcsNCols <= 0 {
			return false, fmt.Errorf("invalid lvcs ncols=%d for replay", lvcsNCols)
		}
		if lvcsNCols < witnessNCols {
			return false, fmt.Errorf("invalid replay ncols: lvcs=%d < witness=%d", lvcsNCols, witnessNCols)
		}
		omegaWitness := omega
		if proof.DomainMode == DomainModeExplicit || opts.DomainMode == DomainModeExplicit {
			ell := len(proof.Tail)
			nLeaves := proof.NLeavesUsed
			if nLeaves <= 0 {
				nLeaves = opts.NLeaves
			}
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			if lvcsNCols+ell > int(ringQ.N) {
				return false, fmt.Errorf("explicit domain: need lvcsNCols+ell <= ring dimension (lvcsNCols=%d ell=%d ringN=%d)", lvcsNCols, ell, ringQ.N)
			}
			var derr error
			omega, domainPoints, derr = deriveExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, witnessNCols, lvcsNCols, ell, pub.HashRelation)
			if derr != nil {
				return false, fmt.Errorf("explicit domain: %w", derr)
			}
			if len(omega) == 0 || len(domainPoints) == 0 {
				return false, fmt.Errorf("explicit replay config requires non-empty omega and domain points")
			}
			if len(omega) < witnessNCols {
				return false, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
			}
			omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, witnessNCols, lvcsNCols, ell, pub.HashRelation)
			if err != nil {
				return false, fmt.Errorf("explicit witness omega: %w", err)
			}
		} else {
			if len(omega) < lvcsNCols {
				return false, fmt.Errorf("row-polynomial domain: omega len=%d < lvcs ncols=%d", len(omega), lvcsNCols)
			}
			if len(omega) > lvcsNCols {
				omega = append([]uint64(nil), omega[:lvcsNCols]...)
			}
			omegaWitness = omega
		}
		if len(omegaWitness) < witnessNCols {
			return false, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omegaWitness), witnessNCols)
		}
		if len(omegaWitness) > witnessNCols {
			omegaWitness = append([]uint64(nil), omegaWitness[:witnessNCols]...)
		}
		witnessRows := proof.RowLayout.SigCount
		if witnessRows <= 0 {
			witnessRows = proof.PCSGeometry.LogicalWitnessPolys
		}
		if witnessRows <= 0 {
			witnessRows = proof.MaskRowOffset
		}
		if witnessRows > 0 {
			if err := ValidateRowDependencyClosure(proof.RowLayout, nil, witnessRows); err != nil {
				return false, fmt.Errorf("replay row dependency closure: %w", err)
			}
			if err := ValidatePRFCompanionLayout(set.PRFCompanionLayout, witnessRows); err != nil {
				return false, fmt.Errorf("replay prf companion layout: %w", err)
			}
		}

		var (
			eval              ConstraintEvaluator
			evalK             KConstraintEvaluator
			rowCount          int
			haveCred          bool
			havePRF           bool
			K                 *kf.Field
			boundRows         []int
			carryRows         []int
			boundB            int64
			carryBound        int64
			prfCompanionEval  ConstraintEvaluator
			prfCompanionEvalK KConstraintEvaluator
		)
		if proof.Theta > 1 {
			if len(proof.Chi) == 0 {
				return false, fmt.Errorf("missing Chi for K replay")
			}
			k, err := kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
			if err != nil {
				return false, fmt.Errorf("kfield.New: %w", err)
			}
			K = k
		}
		// Build post-sign evaluator when A is present.
		if len(pub.A) > 0 {
			if !rowLayoutHasCoeffNativeSig(proof.RowLayout) {
				return false, fmt.Errorf("only the retained literal-packed showing layouts are supported")
			}
			cfgLayout := proof.RowLayout.CoeffNativeSig
			if !rowLayoutCoeffNativeUsesLiteralPacked(proof.RowLayout) {
				return false, fmt.Errorf("unsupported active coeff-native model %q; only the literal-packed protocol remains", cfgLayout.Model)
			}
			if cfgLayout.PackedSigComponents <= 0 || cfgLayout.PackedSigBlocks <= 0 || cfgLayout.PackedSigBlockWidth <= 0 {
				return false, fmt.Errorf("invalid literal packed coeff-native layout: comps=%d blocks=%d width=%d", cfgLayout.PackedSigComponents, cfgLayout.PackedSigBlocks, cfgLayout.PackedSigBlockWidth)
			}
			cfgPost, cerr := newTransformBridgePostSignConfig(ringQ, pub, proof.RowLayout, omegaWitness, domainPoints, pub.BoundB, set.PRFLayout, set.PRFCompanionLayout, opts)
			if cerr != nil {
				return false, cerr
			}
			eval = cfgPost.CoreEvaluator()
			if proof.Theta > 1 && K != nil {
				ek, err := cfgPost.CoreKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = ek
			}
			rowCount = literalPackedPostSignReplayRowCount(proof.RowLayout)
			haveCred = true

		} else if set.PRFLayout == nil && (len(pub.Ac) > 0 || len(pub.Com) > 0 || len(pub.B) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0) {
			cfgPre, cerr := newPreSignTransformBridgeConfig(ringQ, pub, proof.RowLayout, omegaWitness, domainPoints, pub.BoundB)
			if cerr != nil {
				return false, cerr
			}
			eval = cfgPre.CoreEvaluator()
			if proof.Theta > 1 && K != nil {
				ek, err := cfgPre.CoreKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = ek
			}
			boundRows = nil
			carryRows = nil
			boundB = pub.BoundB
			carryBound = 1
			rowCount = 0
			for _, idx := range []int{
				proof.RowLayout.IdxM1,
				proof.RowLayout.IdxM2,
				proof.RowLayout.IdxRU0,
				proof.RowLayout.IdxRU1,
				proof.RowLayout.IdxR,
				proof.RowLayout.IdxR0,
				proof.RowLayout.IdxR1,
				proof.RowLayout.IdxK0,
				proof.RowLayout.IdxK1,
				proof.RowLayout.IdxCarrierM,
				proof.RowLayout.IdxCarrierPreRU,
				proof.RowLayout.IdxCarrierPreR,
				proof.RowLayout.IdxCarrierCtr,
				proof.RowLayout.IdxCarrierK,
				proof.RowLayout.IdxMHat1,
				proof.RowLayout.IdxMHat2,
				proof.RowLayout.IdxRHat0,
				proof.RowLayout.IdxRHat1,
				proof.RowLayout.IdxMSigmaR1,
				proof.RowLayout.IdxR0R1,
				proof.RowLayout.IdxMSigmaR1Hat,
				proof.RowLayout.IdxR0R1Hat,
			} {
				if idx+1 > rowCount {
					rowCount = idx + 1
				}
			}
			haveCred = true

			// Pre-sign now reuses the showing transform-bridge hash machinery, but
			// only for the non-sign replay-facing hats.
		}
		if set.PRFCompanionLayout != nil && proof.PRFCompanion != nil {
			cfgCompanion := PRFCompanionBridgeConfig{
				Ring:         ringQ,
				Layout:       set.PRFCompanionLayout,
				DomainPoints: domainPoints,
				OmegaWitness: omegaWitness,
				Seed2:        append([]byte(nil), proof.Digests[1]...),
				BridgeChecks: copyMatrix(proof.PRFCompanion.BridgeChecks),
			}
			if err := cfgCompanion.verifyDigest(proof.PRFCompanion); err != nil {
				return false, err
			}
			if proof.PRFCompanion.BridgeInQ {
				prfCompanionEval = cfgCompanion.Evaluator()
				if proof.Theta > 1 && K != nil {
					ek, err := cfgCompanion.KEvaluator(K)
					if err != nil {
						return false, err
					}
					prfCompanionEvalK = ek
				}
			}
			traceRows := set.PRFCompanionLayout.StartRow + set.PRFCompanionLayout.PackedRows
			if traceRows > rowCount {
				rowCount = traceRows
			}
			havePRF = true
		}
		if prfCompanionEval != nil {
			eval = composeEvaluators(eval, prfCompanionEval)
			if proof.Theta > 1 && K != nil && prfCompanionEvalK != nil {
				evalK = composeKEvaluators(evalK, prfCompanionEvalK)
			}
		}
		if !haveCred && !havePRF {
			return false, fmt.Errorf("no evaluators available for replay")
		}
		replayFparCoeffs := append(append([][]uint64{}, set.FparIntCoeffs...), set.FparNormCoeffs...)
		replayFaggCoeffs := append(append([][]uint64{}, set.FaggIntCoeffs...), set.FaggNormCoeffs...)
		if len(replayFparCoeffs) == 0 && len(proof.FparCoeffDebug) > 0 {
			replayFparCoeffs = copyMatrix(proof.FparCoeffDebug)
		}
		if len(replayFaggCoeffs) == 0 && len(proof.FaggCoeffDebug) > 0 {
			replayFaggCoeffs = copyMatrix(proof.FaggCoeffDebug)
		}
		replay := &ConstraintReplay{
			Eval:       eval,
			EvalK:      evalK,
			RowCount:   rowCount,
			BoundRows:  boundRows,
			CarryRows:  carryRows,
			BoundB:     boundB,
			CarryBound: carryBound,
			Fpar:       append(append([]*ring.Poly{}, set.FparInt...), set.FparNorm...),
			Fagg:       append(append([]*ring.Poly{}, set.FaggInt...), set.FaggNorm...),
			FparCoeffs: replayFparCoeffs,
			FaggCoeffs: replayFaggCoeffs,
		}
		if proof.HashRelation == credential.HashRelationBBTran {
			if len(pub.Ac) > 0 && len(pub.A) == 0 {
				replay.FparOverrideIdxs = []int{9, 10}
			} else if rowLayoutHasCoeffNativeSig(proof.RowLayout) {
				replayBlocks := rowLayoutReplayBlockCount(proof.RowLayout)
				if replayBlocks <= 0 {
					replayBlocks = 1
				}
				replay.FparOverrideIdxs = []int{replayBlocks, replayBlocks + 1}
			}
		}

		okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, replay)
		if err != nil || !(okLin && okEq4 && okSum) {
			return okLin && okEq4 && okSum, err
		}
		if set.PRFCompanionLayout != nil && proof.PRFCompanion != nil {
			if !proof.PRFCompanion.BridgeInQ {
				if err := verifyPRFCompanionBridgeFromOpening(ringQ, set.PRFCompanionLayout, proof, omegaWitness, domainPoints); err != nil {
					return false, err
				}
			}
			params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
			if perr != nil {
				return false, fmt.Errorf("load prf params: %w", perr)
			}
			if cerr := verifyPRFCompanionOpenings(set.PRFCompanionLayout, proof, params, pub.Tag, pub.Nonce); cerr != nil {
				return false, cerr
			}
		}
		if err := VerifySigShortnessProof(proof, ringQ, omegaWitness, pub, opts); err != nil {
			return false, fmt.Errorf("verify sig shortness: %w", err)
		}
		return true, nil
	}
	return false, fmt.Errorf("unsupported non-credential VerifyWithConstraints path")
}
