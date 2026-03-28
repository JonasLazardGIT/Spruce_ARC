package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
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
		ringQ, omega, ncols, err := loadParamsAndOmega(opts)
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
			omega, domainPoints, derr = deriveExplicitDomain(ringQ.Modulus[0], opts.NLeaves, ncols, opts.Ell)
			if derr != nil {
				return nil, fmt.Errorf("explicit domain: %w", derr)
			}
		}
		if len(omega) < witnessNCols {
			return nil, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
		}
		omegaWitness := append([]uint64(nil), omega[:witnessNCols]...)
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
		} else {
			useShowingRows := false
			if wit.Extras != nil {
				// Legacy non-companion PRF path only. The live companion route is
				// driven by coeff-native showing rows and grouped witness rebuild.
				_, useShowingRows = wit.Extras["prf_sbox"]
			}
			if opts.CoeffPacking && wit.CoeffNativeShowing != nil {
				useShowingRows = true
			}
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
				rows, rowInputs, rowLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, err = buildCredentialRows(ringQ, wit, opts)
			}
			if err != nil {
				return nil, fmt.Errorf("build credential rows: %w", err)
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
			tmpNTT := ringQ.NewPoly()
			for i := 0; i < witnessCount; i++ {
				ringQ.NTT(rows[i], tmpNTT)
				head := append([]uint64(nil), tmpNTT.Coeffs[0][:len(omega)]...)
				for j := range head {
					head[j] %= q
				}
				rowInputs[i] = lvcs.RowInput{Head: head}
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

		// Rebuild constraints to match paper-defined F_j(P,Theta). In θ>1 mode the
		// committed oracle rows are transposed into the §5.4 layer layout, so
		// semantic constraint rebuilding must use the semantic witness polynomials.
		skipConstraintRebuild := prepared != nil && prepared.skipConstraintRebuild && rowLayoutHasCoeffNativeSig(rowLayout) && !rowLayoutCoeffNativeUsesSemanticRewrite(rowLayout)
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
				// Rebuild pre-sign constraints when their publics are present.
				if len(pub.Ac) > 0 && len(pub.Com) > 0 && len(pub.RI0) > 0 && len(pub.RI1) > 0 && len(pub.B) > 0 && len(pub.T) > 0 {
					csRows, cerr := buildCredentialConstraintSetPreFromRows(ringQ, pub.BoundB, pub, rowLayout, constraintRows, omegaWitness, opts.DomainMode)
					if cerr != nil {
						return nil, fmt.Errorf("rebuild credential constraints from rows: %w", cerr)
					}
					if len(set.FparInt) < len(csRows.FparInt) {
						return nil, fmt.Errorf("constraint set too small: have %d want >=%d", len(set.FparInt), len(csRows.FparInt))
					}
					copy(set.FparInt[:len(csRows.FparInt)], csRows.FparInt)
					set.FparNorm = csRows.FparNorm
					if len(set.FparIntCoeffs) < len(set.FparInt) {
						expanded := make([][]uint64, len(set.FparInt))
						copy(expanded, set.FparIntCoeffs)
						set.FparIntCoeffs = expanded
					}
					for i := 0; i < len(csRows.FparInt); i++ {
						set.FparIntCoeffs[i] = nil
					}
					if len(csRows.FparIntCoeffs) > 0 {
						copy(set.FparIntCoeffs[:len(csRows.FparInt)], csRows.FparIntCoeffs)
					}
					set.FparNormCoeffs = csRows.FparNormCoeffs

					// Pre-sign non-signature NTT↔coef bridge is enabled only in
					// explicit-domain mode. In the row-polynomial mode, aggregated degree=2 can
					// exceed the ring-backed dQ budget.
					if opts.DomainMode == DomainModeExplicit {
						preBridge, preBridgeCoeffs, preBridgeErr := buildPreSignNonSigBridgeConstraintsFormal(
							ringQ,
							constraintRows,
							omegaWitness,
							rowLayout,
							root,
							signatureNTTBridgeChecks,
						)
						if preBridgeErr != nil {
							return nil, fmt.Errorf("pre-sign non-signature bridge: %w", preBridgeErr)
						}
						if len(preBridge) > 0 {
							if len(set.FaggNormCoeffs) < len(set.FaggNorm) {
								expanded := make([][]uint64, len(set.FaggNorm))
								copy(expanded, set.FaggNormCoeffs)
								set.FaggNormCoeffs = expanded
							}
							set.FaggNorm = append(set.FaggNorm, preBridge...)
							set.FaggNormCoeffs = append(set.FaggNormCoeffs, preBridgeCoeffs...)
							if set.AggregatedAlgDeg < 2 {
								set.AggregatedAlgDeg = 2
							}
						}
					}
				}
				// Rebuild post-sign constraints only when the public signature/hash
				// statement is present.
				if len(pub.A) > 0 && len(pub.B) > 0 {
					postRows, cerr := rebuildPostSignConstraintSetWithBridges(ringQ, pub, rowLayout, constraintRows, omegaWitness, opts, root)
					if cerr != nil {
						return nil, cerr
					}
					if rebuiltEmpty {
						set.FparInt = append([]*ring.Poly{}, postRows.FparInt...)
						set.FparIntCoeffs = append([][]uint64{}, postRows.FparIntCoeffs...)
					} else if rowLayoutCoeffNativeUsesSemanticRewrite(rowLayout) {
						if err := replaceShowingPostSignPrefix(&set, postRows); err != nil {
							return nil, fmt.Errorf("replace semantic post-sign prefix: %w", err)
						}
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

				// Rebuild PRF constraints when legacy layout + tag are present.
				if set.PRFLayout != nil && len(pub.Tag) > 0 {
					params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
					if perr != nil {
						return nil, fmt.Errorf("load prf params: %w", perr)
					}
					mode := set.PRFLayout.Mode
					if mode == "" {
						mode = PRFLayoutModeSBox
					}
					groupRounds := set.PRFLayout.GroupRounds
					if groupRounds <= 0 {
						groupRounds = 1
					}
					var (
						prfSet       ConstraintSet
						expectedFpar int
					)
					if mode != PRFLayoutModeSBox {
						return nil, fmt.Errorf("unsupported PRF layout mode %q", mode)
					}
					prfSet, perr = BuildPRFConstraintSetSBox(ringQ, params, constraintRows, set.PRFLayout, pub.Tag, pub.Nonce, omegaWitness)
					sboxCount, cerr := prf.SBoxOutputCountGrouped(params, groupRounds)
					if cerr != nil {
						return nil, fmt.Errorf("grouped PRF count: %w", cerr)
					}
					expectedFpar = sboxCount + params.LenTag
					if set.PRFLayout.KeyBind {
						expectedFpar += params.LenKey
					}
					if perr != nil {
						return nil, fmt.Errorf("rebuild prf constraints from rows: %w", perr)
					}
					if expectedFpar != len(prfSet.FparInt) {
						return nil, fmt.Errorf("unexpected PRF Fpar count: got %d want %d (mode=%s)", len(prfSet.FparInt), expectedFpar, mode)
					}
					if len(prfSet.FparIntCoeffs) > 0 && len(prfSet.FparIntCoeffs) != expectedFpar {
						return nil, fmt.Errorf("unexpected PRF formal coeff count: got %d want %d (mode=%s)", len(prfSet.FparIntCoeffs), expectedFpar, mode)
					}
					if len(set.FparInt) < expectedFpar {
						return nil, fmt.Errorf("constraint set too small for PRF suffix: have %d want >=%d", len(set.FparInt), expectedFpar)
					}
					suffixStart := len(set.FparInt) - expectedFpar
					copy(set.FparInt[suffixStart:], prfSet.FparInt)
					if len(set.FparIntCoeffs) < len(set.FparInt) {
						expanded := make([][]uint64, len(set.FparInt))
						copy(expanded, set.FparIntCoeffs)
						set.FparIntCoeffs = expanded
					}
					for i := suffixStart; i < len(set.FparInt); i++ {
						set.FparIntCoeffs[i] = nil
					}
					if len(prfSet.FparIntCoeffs) > 0 {
						copy(set.FparIntCoeffs[suffixStart:], prfSet.FparIntCoeffs)
					}
				}
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
			SmallFieldChi:     sfChi,
			SmallFieldOmegaS1: sfOmegaS1,
			SmallFieldMuInv:   sfMuInv,
			SmallFieldK:       sfK,
		}
		proof, err := RunMaskingFS(mfsIn)
		if err != nil {
			return nil, fmt.Errorf("RunMaskingFS: %w", err)
		}
		proof.LabelsDigest = labelsDigest
		proof.PRFLayout = set.PRFLayout
		if proof.PRFCompanion != nil && proof.PRFCompanion.Layout == nil {
			proof.PRFCompanion.Layout = clonePRFCompanionLayout(set.PRFCompanionLayout)
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
		if set.PRFLayout == nil && proof.PRFLayout != nil {
			set.PRFLayout = clonePRFLayout(proof.PRFLayout)
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
		ringQ, omega, _, err := loadParamsAndOmega(opts)
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
			omega, domainPoints, derr = deriveExplicitDomain(ringQ.Modulus[0], nLeaves, lvcsNCols, ell)
			if derr != nil {
				return false, fmt.Errorf("explicit domain: %w", derr)
			}
			if len(omega) == 0 || len(domainPoints) == 0 {
				return false, fmt.Errorf("explicit replay config requires non-empty omega and domain points")
			}
			if len(omega) < witnessNCols {
				return false, fmt.Errorf("witness omega len=%d < witness ncols=%d", len(omega), witnessNCols)
			}
			omegaWitness = append([]uint64(nil), omega[:witnessNCols]...)
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
			witnessRows = proof.MaskRowOffset
		}
		if witnessRows > 0 {
			if err := ValidateRowDependencyClosure(proof.RowLayout, proof.PRFLayout, witnessRows); err != nil {
				return false, fmt.Errorf("replay row dependency closure: %w", err)
			}
			if err := ValidatePRFCompanionLayout(set.PRFCompanionLayout, witnessRows); err != nil {
				return false, fmt.Errorf("replay prf companion layout: %w", err)
			}
		}

		var tNTT *ring.Poly
		var tThetaNTT *ring.Poly
		if len(pub.T) > 0 {
			tCoeff := ringQ.NewPoly()
			q := int64(ringQ.Modulus[0])
			for i := 0; i < ringQ.N && i < len(pub.T); i++ {
				v := pub.T[i]
				if v < 0 {
					v += q
				}
				tCoeff.Coeffs[0][i] = uint64(v % q)
			}
			tNTT = ringQ.NewPoly()
			ring.Copy(tCoeff, tNTT)
			ringQ.NTT(tNTT, tNTT)
			thetaT, err := thetaPolyFromNTT(ringQ, tNTT, omegaWitness)
			if err != nil {
				return false, fmt.Errorf("theta T: %w", err)
			}
			tThetaNTT = thetaT
		}
		var packSelNTT []uint64
		if selNTT, _, err := buildPackingSelectorNTT(ringQ, omegaWitness); err == nil {
			packSelNTT = append([]uint64(nil), selNTT.Coeffs[0]...)
		}

		thetaAc := make([][]*ring.Poly, len(pub.Ac))
		for i := range pub.Ac {
			thetaAc[i] = make([]*ring.Poly, len(pub.Ac[i]))
			for j := range pub.Ac[i] {
				theta, err := thetaPolyFromNTT(ringQ, pub.Ac[i][j], omegaWitness)
				if err != nil {
					return false, fmt.Errorf("theta Ac[%d][%d]: %w", i, j, err)
				}
				thetaAc[i][j] = theta
			}
		}
		thetaCom := make([]*ring.Poly, len(pub.Com))
		for i := range pub.Com {
			theta, err := thetaPolyFromNTT(ringQ, pub.Com[i], omegaWitness)
			if err != nil {
				return false, fmt.Errorf("theta Com[%d]: %w", i, err)
			}
			thetaCom[i] = theta
		}
		thetaA := make([][]*ring.Poly, len(pub.A))
		for i := range pub.A {
			thetaA[i] = make([]*ring.Poly, len(pub.A[i]))
			for j := range pub.A[i] {
				theta, err := thetaPolyFromNTT(ringQ, pub.A[i][j], omegaWitness)
				if err != nil {
					return false, fmt.Errorf("theta A[%d][%d]: %w", i, j, err)
				}
				thetaA[i][j] = theta
			}
		}
		// When signatures span multiple packed blocks, rebuild Θ(A) per block.
		var thetaABlocks [][][]*ring.Poly
		if proof.RowLayout.SigBlocks > 1 {
			blocks := proof.RowLayout.SigBlocks
			if blocks <= 0 {
				return false, fmt.Errorf("invalid SigBlocks=%d in proof layout", blocks)
			}
			if blocks*witnessNCols != int(ringQ.N) {
				return false, fmt.Errorf("signature block layout mismatch: SigBlocks*ncols=%d*%d != ringN=%d", blocks, witnessNCols, ringQ.N)
			}
			q := ringQ.Modulus[0]
			thetaABlocks = make([][][]*ring.Poly, blocks)
			for b := 0; b < blocks; b++ {
				thetaABlocks[b] = make([][]*ring.Poly, len(pub.A))
				start := b * witnessNCols
				end := start + witnessNCols
				for i := range pub.A {
					thetaABlocks[b][i] = make([]*ring.Poly, len(pub.A[i]))
					for j := range pub.A[i] {
						pNTT := pub.A[i][j]
						if pNTT == nil || len(pNTT.Coeffs) == 0 || len(pNTT.Coeffs[0]) < end {
							continue
						}
						head := append([]uint64(nil), pNTT.Coeffs[0][start:end]...)
						for idx := range head {
							head[idx] %= q
						}
						coeffs := Interpolate(omegaWitness, head, q)
						theta := ringQ.NewPoly()
						copy(theta.Coeffs[0], coeffs)
						ringQ.NTT(theta, theta)
						thetaABlocks[b][i][j] = theta
					}
				}
			}
		}
		var thetaRI0, thetaRI1 []*ring.Poly
		if len(pub.RI0) > 0 {
			theta, err := thetaPolyFromNTT(ringQ, pub.RI0[0], omegaWitness)
			if err != nil {
				return false, fmt.Errorf("theta RI0: %w", err)
			}
			thetaRI0 = []*ring.Poly{theta}
		}
		if len(pub.RI1) > 0 {
			theta, err := thetaPolyFromNTT(ringQ, pub.RI1[0], omegaWitness)
			if err != nil {
				return false, fmt.Errorf("theta RI1: %w", err)
			}
			thetaRI1 = []*ring.Poly{theta}
		}
		thetaB := make([]*ring.Poly, len(pub.B))
		for i := range pub.B {
			theta, err := thetaPolyFromNTT(ringQ, pub.B[i], omegaWitness)
			if err != nil {
				return false, fmt.Errorf("theta B[%d]: %w", i, err)
			}
			thetaB[i] = theta
		}

		var (
			eval               ConstraintEvaluator
			evalK              KConstraintEvaluator
			rowCount           int
			haveCred           bool
			havePRF            bool
			K                  *kf.Field
			boundRows          []int
			carryRows          []int
			boundB             int64
			carryBound         int64
			postBoundsEval     ConstraintEvaluator
			postBoundsEvalK    KConstraintEvaluator
			deferPostBounds    bool
			postBoundsComposed bool
			nonSigBridgeEval   ConstraintEvaluator
			nonSigBridgeEvalK  KConstraintEvaluator
			sigChainEval       ConstraintEvaluator
			sigChainEvalK      KConstraintEvaluator
			prfCompanionEval   ConstraintEvaluator
			prfCompanionEvalK  KConstraintEvaluator
			sigChainEnd        int
			boundChainEnd      int
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
			if rowLayoutHasCoeffNativeSig(proof.RowLayout) {
				cfgLayout := proof.RowLayout.CoeffNativeSig
				if !rowLayoutCoeffNativeUsesLiteralPacked(proof.RowLayout) {
					return false, fmt.Errorf("unsupported active coeff-native model %q; only the literal-packed protocol remains", cfgLayout.Model)
				}
				if cfgLayout.PackedSigComponents <= 0 || cfgLayout.PackedSigBlocks <= 0 || cfgLayout.PackedSigBlockWidth <= 0 {
					return false, fmt.Errorf("invalid literal packed coeff-native layout: comps=%d blocks=%d width=%d", cfgLayout.PackedSigComponents, cfgLayout.PackedSigBlocks, cfgLayout.PackedSigBlockWidth)
				}
				postBoundRows := postSignBoundRowIndices(proof.RowLayout)
				boundRows = append([]int(nil), postBoundRows...)
				boundB = pub.BoundB
				if rowLayoutCoeffNativeUsesSemanticRewrite(proof.RowLayout) {
					cfgPost, cerr := newSemanticRewritePostSignConfig(ringQ, pub, proof.RowLayout, omegaWitness, domainPoints, pub.BoundB)
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
					postBoundsEval = cfgPost.BoundsEvaluator()
					if proof.Theta > 1 && K != nil {
						bk, berr := cfgPost.BoundsKEvaluator(K)
						if berr != nil {
							return false, berr
						}
						postBoundsEvalK = bk
					}
					deferPostBounds = true
					rowCount = proof.RowLayout.SigCount
					if rowCount <= 0 {
						rowCount = literalPackedPostSignReplayRowCount(proof.RowLayout)
					}
					haveCred = true
					if !rowLayoutCoeffNativeUsesSemanticRewrite(proof.RowLayout) && hasPostSignNonSigFamilies(proof.RowLayout) && (proof.DomainMode == DomainModeExplicit || opts.DomainMode == DomainModeExplicit) {
						fams := postSignNonSigFamilies(proof.RowLayout)
						cfgNonSigBridge := NonSigNTTBridgeConfig{
							Ring:         ringQ,
							Omega:        omegaWitness,
							DomainPoints: domainPoints,
							Layout:       proof.RowLayout,
							Families:     fams,
							Root:         proof.Root,
							BridgeChecks: signatureNTTBridgeChecks,
						}
						nonSigBridgeEval = cfgNonSigBridge.NonSigBridgeEvaluator()
						if proof.Theta > 1 && K != nil {
							ek, err := cfgNonSigBridge.NonSigBridgeKEvaluator(K)
							if err != nil {
								return false, err
							}
							nonSigBridgeEvalK = ek
						}
					}
				} else if pub.BoundB > 0 {
					cfgPacked, cerr := buildLiteralPackedPostSignConfig(ringQ, pub, proof.RowLayout, omegaWitness, domainPoints, opts)
					if cerr != nil {
						return false, cerr
					}
					eval = cfgPacked.LiteralPackedPostSignEvaluator()
					if proof.Theta > 1 && K != nil {
						ek, err := cfgPacked.LiteralPackedPostSignKEvaluator(K)
						if err != nil {
							return false, err
						}
						evalK = ek
					}
					if rowLayoutCoeffNativeUsesCompressedNonSigScalars(proof.RowLayout) {
						specCert, err := v3NonSigScalarCertSpec(ringQ.Modulus[0], pub.BoundB)
						if err != nil {
							return false, fmt.Errorf("v3 non-sign scalar cert spec: %w", err)
						}
						cfgCert := PostSignScalarCertConfig{
							Ring:              ringQ,
							Spec:              specCert,
							MsgSumRow:         cfgLayout.PostSignMsgSumRow,
							RndSumRow:         cfgLayout.PostSignRndSumRow,
							X1Row:             cfgLayout.PostSignX1Row,
							UScalarCertBase:   cfgLayout.UScalarCertBase,
							UScalarCertCount:  cfgLayout.UScalarCertCount,
							X0ScalarCertBase:  cfgLayout.X0ScalarCertBase,
							X0ScalarCertCount: cfgLayout.X0ScalarCertCount,
							X1ScalarCertBase:  cfgLayout.X1ScalarCertBase,
							X1ScalarCertCount: cfgLayout.X1ScalarCertCount,
							RowsPerScalar:     cfgLayout.NonSigCertRowsPerScalar,
						}
						postBoundsEval = cfgCert.PostSignScalarCertEvaluator()
						if proof.Theta > 1 && K != nil {
							bk, berr := cfgCert.PostSignScalarCertKEvaluator(K)
							if berr != nil {
								return false, berr
							}
							postBoundsEvalK = bk
						}
						deferPostBounds = true
						if end := cfgLayout.UScalarCertBase + cfgLayout.UScalarCertCount*cfgLayout.NonSigCertRowsPerScalar; cfgLayout.UScalarCertBase >= 0 && end > boundChainEnd {
							boundChainEnd = end
						}
						if end := cfgLayout.X0ScalarCertBase + cfgLayout.X0ScalarCertCount*cfgLayout.NonSigCertRowsPerScalar; cfgLayout.X0ScalarCertBase >= 0 && end > boundChainEnd {
							boundChainEnd = end
						}
						if end := cfgLayout.X1ScalarCertBase + cfgLayout.X1ScalarCertCount*cfgLayout.NonSigCertRowsPerScalar; cfgLayout.X1ScalarCertBase >= 0 && end > boundChainEnd {
							boundChainEnd = end
						}
					} else {
						if proof.RowLayout.MsgRangeBase < 0 || proof.RowLayout.RndRangeBase < 0 || proof.RowLayout.X1RangeBase < 0 {
							return false, fmt.Errorf("literal packed path missing non-signature bound-chain rows")
						}
						specBound, err := nonSigBoundLinfSpec(ringQ.Modulus[0], pub.BoundB)
						if err != nil {
							return false, fmt.Errorf("non-signature bound chain spec: %w", err)
						}
						rowsPerBound := inferNonSigBoundRowsPer(proof.RowLayout)
						chainBases := make([]int, 0, cfgLayout.UCount+cfgLayout.X0Count+1)
						for i := 0; i < cfgLayout.UCount; i++ {
							chainBases = append(chainBases, proof.RowLayout.MsgRangeBase+i*rowsPerBound)
						}
						for i := 0; i < cfgLayout.X0Count; i++ {
							chainBases = append(chainBases, proof.RowLayout.RndRangeBase+i*rowsPerBound)
						}
						chainBases = append(chainBases, proof.RowLayout.X1RangeBase)
						cfgBoundChain := NonSigBoundChainConfig{
							Ring:         ringQ,
							Spec:         specBound,
							ChainBases:   chainBases,
							Omega:        omegaWitness,
							DomainPoints: domainPoints,
						}
						if rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) && cfgLayout.ScalarBundleCount > 0 {
							cfgBoundChain.SourceSlots = append(append(clonePRFSlots(cfgLayout.USlots), clonePRFSlots(cfgLayout.X0Slots)...), cfgLayout.X1Slot)
						} else {
							cfgBoundChain.SourceRows = postBoundRows
						}
						postBoundsEval = cfgBoundChain.NonSigBoundChainEvaluator()
						if proof.Theta > 1 && K != nil {
							bk, berr := cfgBoundChain.NonSigBoundChainKEvaluator(K)
							if berr != nil {
								return false, berr
							}
							postBoundsEvalK = bk
						}
						deferPostBounds = true
						msgEnd := proof.RowLayout.MsgRangeBase + cfgLayout.UCount*rowsPerBound
						rndEnd := proof.RowLayout.RndRangeBase + cfgLayout.X0Count*rowsPerBound
						x1End := proof.RowLayout.X1RangeBase + rowsPerBound
						if msgEnd > boundChainEnd {
							boundChainEnd = msgEnd
						}
						if rndEnd > boundChainEnd {
							boundChainEnd = rndEnd
						}
						if x1End > boundChainEnd {
							boundChainEnd = x1End
						}
					}
					rowCount = literalPackedPostSignReplayRowCount(proof.RowLayout)
					if boundChainEnd > rowCount {
						rowCount = boundChainEnd
					}
					haveCred = true
				} else {
					cfgPacked, cerr := buildLiteralPackedPostSignConfig(ringQ, pub, proof.RowLayout, omegaWitness, domainPoints, opts)
					if cerr != nil {
						return false, cerr
					}
					eval = cfgPacked.LiteralPackedPostSignEvaluator()
					if proof.Theta > 1 && K != nil {
						ek, err := cfgPacked.LiteralPackedPostSignKEvaluator(K)
						if err != nil {
							return false, err
						}
						evalK = ek
					}
					rowCount = literalPackedPostSignReplayRowCount(proof.RowLayout)
					haveCred = true
				}
				if proof.RowLayout.PackedSigChainRowsPerGroup > 0 && proof.RowLayout.PackedSigChainBase >= 0 {
					spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
					if err != nil {
						return false, fmt.Errorf("signature chain spec: %w", err)
					}
					wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(spec, opts, proof.RowLayout.PackedSigChainGroupSize)
					if err != nil {
						return false, fmt.Errorf("signature packed chain rows-per-group: %w", err)
					}
					if proof.RowLayout.PackedSigChainRowsPerGroup != wantRowsPer {
						return false, fmt.Errorf("invalid signature packed chain rows-per-group=%d want %d", proof.RowLayout.PackedSigChainRowsPerGroup, wantRowsPer)
					}
					cfgBounds := SigCoeffBoundsConfig{
						Ring:               ringQ,
						Spec:               spec,
						PackedSourceBase:   cfgLayout.PackedSigBase,
						PackedSourceCount:  cfgLayout.PackedSigCount,
						PackedChainBase:    proof.RowLayout.PackedSigChainBase,
						PackedGroupCount:   proof.RowLayout.PackedSigChainGroupCount,
						PackedGroupSize:    proof.RowLayout.PackedSigChainGroupSize,
						PackedRowsPerGroup: proof.RowLayout.PackedSigChainRowsPerGroup,
						Omega:              omegaWitness,
						DomainPoints:       domainPoints,
						Layout:             proof.RowLayout,
						Root:               proof.Root,
						BridgeChecks:       0,
					}
					sigChainEval = cfgBounds.SigCoeffBoundsEvaluator()
					sigChainEnd = cfgBounds.PackedChainBase + cfgBounds.PackedGroupCount*cfgBounds.PackedRowsPerGroup
					if proof.Theta > 1 && K != nil {
						ek, err := cfgBounds.SigCoeffBoundsKEvaluator(K)
						if err != nil {
							return false, err
						}
						sigChainEvalK = ek
					}
				}
			} else {
				return false, fmt.Errorf("only the retained literal-packed showing layouts are supported")
			}
		} else if set.PRFLayout == nil && (len(pub.Ac) > 0 || len(pub.Com) > 0 || len(pub.B) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0) {
			preBoundRows := preSignBoundRowIndices(proof.RowLayout)
			if len(preBoundRows) == 0 {
				preBoundRows = rowLayoutPreSignBoundRows(RowLayout{})
			}
			preCarryRows := preSignCarryRowIndices(proof.RowLayout)
			if len(preCarryRows) == 0 {
				preCarryRows = rowLayoutPreSignCarryRows(RowLayout{})
			}
			cfgEval := CredentialConstraintConfig{
				Ring:          ringQ,
				Ac:            thetaAc,
				B:             thetaB,
				Com:           thetaCom,
				RI0:           thetaRI0,
				RI1:           thetaRI1,
				Bound:         pub.BoundB,
				CarryBound:    1,
				TPublicNTT:    tThetaNTT,
				PackingNCols:  witnessNCols,
				PackingSelNTT: packSelNTT,
				IdxM1:         rowLayoutPostSignM1(proof.RowLayout),
				IdxM2:         rowLayoutPostSignM2(proof.RowLayout),
				IdxRU0:        rowLayoutPreSignRU0(proof.RowLayout),
				IdxRU1:        rowLayoutPreSignRU1(proof.RowLayout),
				IdxR:          rowLayoutPostSignR(proof.RowLayout),
				IdxR0:         rowLayoutPostSignR0(proof.RowLayout),
				IdxR1:         rowLayoutPostSignR1(proof.RowLayout),
				IdxK0:         rowLayoutPreSignK0(proof.RowLayout),
				IdxK1:         rowLayoutPreSignK1(proof.RowLayout),
				IdxT:          -1,
				BoundRows:     preBoundRows,
				CarryRows:     preCarryRows,
				Omega:         omegaWitness,
				DomainPoints:  domainPoints,
			}
			cfgK := CredentialConstraintConfig{
				Ring:         ringQ,
				Ac:           thetaAc,
				B:            thetaB,
				Com:          thetaCom,
				RI0:          thetaRI0,
				RI1:          thetaRI1,
				Bound:        pub.BoundB,
				CarryBound:   1,
				TPublicNTT:   tThetaNTT,
				PackingNCols: witnessNCols,
				IdxM1:        rowLayoutPostSignM1(proof.RowLayout),
				IdxM2:        rowLayoutPostSignM2(proof.RowLayout),
				IdxRU0:       rowLayoutPreSignRU0(proof.RowLayout),
				IdxRU1:       rowLayoutPreSignRU1(proof.RowLayout),
				IdxR:         rowLayoutPostSignR(proof.RowLayout),
				IdxR0:        rowLayoutPostSignR0(proof.RowLayout),
				IdxR1:        rowLayoutPostSignR1(proof.RowLayout),
				IdxK0:        rowLayoutPreSignK0(proof.RowLayout),
				IdxK1:        rowLayoutPreSignK1(proof.RowLayout),
				IdxT:         -1,
				BoundRows:    preBoundRows,
				CarryRows:    preCarryRows,
				Omega:        omegaWitness,
			}
			eval = cfgEval.CredentialEvaluator()
			if proof.Theta > 1 && K != nil {
				ek, err := cfgK.CredentialKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = ek
			}
			boundRows = append([]int(nil), cfgEval.BoundRows...)
			carryRows = append([]int(nil), cfgEval.CarryRows...)
			boundB = cfgEval.Bound
			carryBound = cfgEval.CarryBound
			rowCount = cfgEval.IdxK1 + 1
			for _, idx := range cfgEval.BoundRows {
				if idx+1 > rowCount {
					rowCount = idx + 1
				}
			}
			for _, idx := range cfgEval.CarryRows {
				if idx+1 > rowCount {
					rowCount = idx + 1
				}
			}
			haveCred = true

			if hasPreSignNonSigFamilies(proof.RowLayout) && (proof.DomainMode == DomainModeExplicit || opts.DomainMode == DomainModeExplicit) {
				fams := preSignNonSigFamilies(proof.RowLayout)
				cfgNonSigBridge := NonSigNTTBridgeConfig{
					Ring:         ringQ,
					Omega:        omegaWitness,
					DomainPoints: domainPoints,
					Layout:       proof.RowLayout,
					Families:     fams,
					Root:         proof.Root,
					BridgeChecks: signatureNTTBridgeChecks,
				}
				nonSigBridgeEval = cfgNonSigBridge.NonSigBridgeEvaluator()
				if proof.Theta > 1 && K != nil {
					ek, err := cfgNonSigBridge.NonSigBridgeKEvaluator(K)
					if err != nil {
						return false, err
					}
					nonSigBridgeEvalK = ek
				}
				for _, fam := range fams {
					if fam.Blocks <= 0 || fam.ComponentCount <= 0 {
						continue
					}
					for b := 0; b < fam.Blocks; b++ {
						nIdx := fam.Block0Base + fam.ComponentCount - 1
						if b > 0 {
							nIdx = fam.ExtraNTTBase + (b-1)*fam.ComponentCount + (fam.ComponentCount - 1)
						}
						cIdx := fam.CoeffBase + b*fam.ComponentCount + (fam.ComponentCount - 1)
						if nIdx+1 > rowCount {
							rowCount = nIdx + 1
						}
						if cIdx+1 > rowCount {
							rowCount = cIdx + 1
						}
					}
				}
			}
		}
		// Build PRF evaluator when layout is present.
		if set.PRFLayout != nil && len(pub.Tag) > 0 {
			params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
			if err != nil {
				return false, fmt.Errorf("load prf params: %w", err)
			}
			cfgPRF, err := NewPRFConstraintConfig(ringQ, params, set.PRFLayout, pub.Tag, pub.Nonce, omegaWitness, domainPoints)
			if err != nil {
				return false, fmt.Errorf("prf config: %w", err)
			}
			evalPRF := cfgPRF.PRFEvaluator()
			eval = composeEvaluators(eval, evalPRF)
			if proof.Theta > 1 && K != nil {
				ek, err := cfgPRF.PRFKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = composeKEvaluators(evalK, ek)
			}
			if deferPostBounds && postBoundsEval != nil {
				eval = composeEvaluators(eval, postBoundsEval)
				if proof.Theta > 1 && K != nil && postBoundsEvalK != nil {
					evalK = composeKEvaluators(evalK, postBoundsEvalK)
				}
				postBoundsComposed = true
			}
			mode := set.PRFLayout.Mode
			if mode == "" {
				mode = PRFLayoutModeSBox
			}
			if mode != PRFLayoutModeSBox {
				return false, fmt.Errorf("unsupported PRF layout mode %q", mode)
			}
			groupRounds := set.PRFLayout.GroupRounds
			if groupRounds <= 0 {
				groupRounds = 1
			}
			sboxCount, cerr := prf.SBoxOutputCountGrouped(params, groupRounds)
			if cerr != nil {
				return false, fmt.Errorf("grouped PRF count: %w", cerr)
			}
			traceRows := set.PRFLayout.StartIdx + set.PRFLayout.LenKey + sboxCount
			if set.PRFLayout.PackedRows && set.PRFLayout.WitnessRows > 0 {
				traceRows = set.PRFLayout.StartIdx + set.PRFLayout.WitnessRows
			}
			if traceRows > rowCount {
				rowCount = traceRows
			}
			havePRF = true
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
		if deferPostBounds && postBoundsEval != nil && !postBoundsComposed {
			eval = composeEvaluators(eval, postBoundsEval)
			if proof.Theta > 1 && K != nil && postBoundsEvalK != nil {
				evalK = composeKEvaluators(evalK, postBoundsEvalK)
			}
			postBoundsComposed = true
		}

		// Non-signature bridge families are replayed before signature bridge
		// to match the constraint append order in BuildWithConstraints.
		if nonSigBridgeEval != nil {
			eval = composeEvaluators(eval, nonSigBridgeEval)
			if proof.Theta > 1 && K != nil && nonSigBridgeEvalK != nil {
				evalK = composeKEvaluators(evalK, nonSigBridgeEvalK)
			}
		}

		// Append signature ℓ∞ chain constraints last (after post bounds and PRF).
		if sigChainEval != nil {
			eval = composeEvaluators(eval, sigChainEval)
			if proof.Theta > 1 && K != nil && sigChainEvalK != nil {
				evalK = composeKEvaluators(evalK, sigChainEvalK)
			}
			if sigChainEnd > rowCount {
				rowCount = sigChainEnd
			}
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
			FparCoeffs: append(append([][]uint64{}, set.FparIntCoeffs...), set.FparNormCoeffs...),
			FaggCoeffs: append(append([][]uint64{}, set.FaggIntCoeffs...), set.FaggNormCoeffs...),
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
		return true, nil
	}
	return false, fmt.Errorf("unsupported non-credential VerifyWithConstraints path")
}
