package main

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
)

const (
	publicationFinalistCount = 12
	publicationFQBits        = 20
	publicationRadixGroup    = 1024
	publicationLambdaBits    = 256
	// BarSets remains a packed matrix in the strict paper accounting.  Its
	// payload carries the same 10-byte rows/columns/bit-width frame produced by
	// DECS.PackUintMatrix; unlike VTargets, that frame is not reconstructed.
	publicationPackedMatrixFrameBytes = 10
)

type publicationRelationVariant struct {
	ID             string
	Rows           int
	ParallelDegree int
	Radix          int
	Digits         int
}

var publicationShowingRelations = []publicationRelationVariant{
	{ID: "r7-l5", Rows: 487, ParallelDegree: 9, Radix: 7, Digits: 5},
	{ID: "r11-l4", Rows: 423, ParallelDegree: 11, Radix: 11, Digits: 4},
}

type publicationPhaseGeometry struct {
	L            int
	LogicalRows  int
	DDECS        int
	DQ           int
	Layers       int
	MaskMu       int
	MaskNu       int
	OpeningRows  int
	QueryCount   int
	OpeningPCols int
}

type publicationPhaseChoice struct {
	Tuning   credential.IntGenISISTuningPreset
	Raw      [4]float64
	ProofMax int
	Paper    int
	Grinding uint64
	Work     uint64
	MinSlack float64
}

type publicationPhaseChoiceCacheEntry struct {
	Choice publicationPhaseChoice
	OK     bool
}

type publicationSearchCache struct {
	radixBytes    map[int]int
	frontierNodes map[[2]int]int
	nRoots        map[string]int
}

func newPublicationSearchCache() *publicationSearchCache {
	return &publicationSearchCache{
		radixBytes: make(map[int]int), frontierNodes: make(map[[2]int]int), nRoots: make(map[string]int),
	}
}

func tunePublicationCandidateLock() (publicationCandidateLock, error) {
	presets, err := publicationV4Presets()
	if err != nil {
		return publicationCandidateLock{}, err
	}
	source, err := publicationCurrentSourceBinding()
	if err != nil {
		return publicationCandidateLock{}, err
	}
	envelope := publicationInitialEnvelope()
	lock := publicationCandidateLock{
		Schema: publicationCandidateLockSchemaV4, Version: publicationCandidateLockVersion,
		Status:          "analytic_complete_measurement_pending",
		SearchAlgorithm: "publication-v4 exact envelope; exact integer N/eta roots; exact minimal kappa; R7/L5 and R11/L4; admissible monotonic pruning",
		Ranking:         publicationRankingOrder(), Envelope: envelope,
		CounterBound: "minimal unsigned LEB128 on wire; four uint64 values give a deterministic 40-byte maximum",
		MerkleBound:  "exact DECS.MerkleFrontierWorstCaseNodesV3(NLeaves,Ell)",
		Source:       source, NoLivePresetRewrite: true, PresetCount: len(presets),
		Stopping: publicationStoppingEvidence{
			WinnerInterior: true, NearFrontierInterior: true, ExactIntegerRoots: true,
			AdmissibleLowerBoundsApplied: true, ProjectionMeasurementPending: true,
			BoundaryExpansionRule:  "if the winner or a candidate within 0.25% of its primary showing-proof bound reaches an expandable upper boundary, expand that column dimension by 16, theta by 2, or ell by 4; require the same winner away from expandable upper boundaries in two consecutive expanded envelopes; certified lower support floors are recorded but are not unresolved search regions",
			SupportFloorsCertified: true,
		},
	}
	var finalResults []publicationPresetSearchResult
	var previousWinnerKeys []string
	lastExpandedDimensions := make(map[string]bool)
	stableExpanded := 0
	hadExpansion := false
	stopped := false
	for iteration := 0; iteration < 7; iteration++ {
		lock.EnvelopesSearched = append(lock.EnvelopesSearched, envelope)
		results := make([]publicationPresetSearchResult, 0, len(presets))
		winnerKeys := make([]string, 0, len(presets))
		upperDimensions := make(map[string]bool)
		for _, preset := range presets {
			result, searchErr := searchPublicationPreset(preset, envelope)
			if searchErr != nil {
				return publicationCandidateLock{}, searchErr
			}
			results = append(results, result)
			winnerKeys = append(winnerKeys, publicationTuningKey(result.Winner))
			for _, hit := range result.ExpandableBoundaryHits {
				upperDimensions[hit] = true
			}
		}
		finalResults = results
		sameWinners := len(previousWinnerKeys) == len(winnerKeys)
		if sameWinners {
			for i := range winnerKeys {
				if winnerKeys[i] != previousWinnerKeys[i] {
					sameWinners = false
					break
				}
			}
		}
		if hadExpansion && len(upperDimensions) == 0 && sameWinners {
			stableExpanded++
		} else if hadExpansion {
			stableExpanded = 0
		}
		if hadExpansion && stableExpanded >= 2 {
			stopped = true
			break
		}
		if !hadExpansion && len(upperDimensions) == 0 {
			// Even an initially interior frontier is checked in two genuinely
			// larger envelopes before an optimization claim is permitted.
			upperDimensions = map[string]bool{
				"l_issuance_upper": true, "l_showing_upper": true,
				"theta_upper": true, "ell_upper": true,
			}
		}
		if len(upperDimensions) != 0 {
			lastExpandedDimensions = upperDimensions
		} else if hadExpansion {
			// A second identical expansion is required to certify stability even
			// after the competitive frontier has moved into the interior.
			upperDimensions = lastExpandedDimensions
		}
		next, expanded := publicationExpandEnvelope(envelope, upperDimensions)
		if !expanded {
			lock.Stopping.UnresolvedBoundaries = append(lock.Stopping.UnresolvedBoundaries, "no_supported_upper_dimension_for_boundary_expansion")
			break
		}
		hadExpansion = true
		previousWinnerKeys = winnerKeys
		envelope = next
	}
	if !stopped && len(lock.Stopping.UnresolvedBoundaries) == 0 {
		lock.Stopping.UnresolvedBoundaries = append(lock.Stopping.UnresolvedBoundaries, "boundary_expansion_iteration_cap")
	}
	lock.Envelope = envelope
	lock.Presets = finalResults
	for i := range lock.Presets {
		lock.Presets[i].EnvelopesSearched = append([]publicationSearchEnvelope(nil), lock.EnvelopesSearched...)
	}
	lock.Stopping.StableExpandedEnvelopes = stableExpanded
	lock.Stopping.WinnerInterior = true
	lock.Stopping.NearFrontierInterior = true
	fieldProfilePending := false
	for _, result := range lock.Presets {
		if !result.WinnerInterior {
			lock.Stopping.WinnerInterior = false
		}
		if len(result.ExpandableBoundaryHits) != 0 {
			lock.Stopping.NearFrontierInterior = false
		}
		if result.Winner.ManifestStatus != "pinned_validated" {
			fieldProfilePending = true
		}
	}
	if len(lock.Stopping.UnresolvedBoundaries) != 0 || !stopped {
		lock.Status = "analytic_unresolved_boundary_no_optimization_claim"
	} else if fieldProfilePending {
		lock.Status = "analytic_field_profile_generation_required"
	}
	if err := finalizePublicationCandidateLock(&lock); err != nil {
		return publicationCandidateLock{}, err
	}
	return lock, nil
}

func publicationExpandEnvelope(envelope publicationSearchEnvelope, dimensions map[string]bool) (publicationSearchEnvelope, bool) {
	next := envelope
	expanded := false
	if dimensions["l_issuance_upper"] {
		next.LIssuanceMax += 16
		expanded = true
	}
	if dimensions["l_showing_upper"] {
		next.LShowingMax += 16
		expanded = true
	}
	if dimensions["theta_upper"] {
		next.ThetaMax += 2
		expanded = true
	}
	if dimensions["ell_upper"] {
		next.EllMax += 4
		expanded = true
	}
	return next, expanded
}

func publicationTuningKey(binding publicationCandidateBinding) string {
	return fmt.Sprintf("%+v|%+v", binding.Issuance, binding.Showing)
}

func searchPublicationPreset(preset credential.IntGenISISPreset, envelope publicationSearchEnvelope) (publicationPresetSearchResult, error) {
	cache := newPublicationSearchCache()
	if err := publicationPrimitiveWidthGate(preset); err != nil {
		return publicationPresetSearchResult{}, err
	}
	required := preset.TargetTheoremBits
	q := uint64(credential.IntGenISISSharedModulusQ)
	logQ := math.Log2(float64(q))
	candidateCount := 0
	eligibleCount := 0
	top := make([]publicationCandidateBinding, 0, publicationFinalistCount)
	boundaryBest := make(map[string]publicationCandidateBinding, 8)
	issueChoices := make(map[[3]int]publicationPhaseChoiceCacheEntry)
	showChoices := make(map[string]publicationPhaseChoiceCacheEntry)
	add := func(binding publicationCandidateBinding) {
		eligibleCount++
		for _, facet := range publicationCandidateBoundaryFacets(binding, envelope) {
			incumbent, exists := boundaryBest[facet]
			if !exists || publicationBindingLess(binding, incumbent) {
				boundaryBest[facet] = binding
			}
		}
		for _, incumbent := range top {
			if publicationSameTuning(binding, incumbent) {
				return
			}
		}
		position := sort.Search(len(top), func(i int) bool { return publicationBindingLess(binding, top[i]) })
		if position >= publicationFinalistCount {
			return
		}
		top = append(top, publicationCandidateBinding{})
		copy(top[position+1:], top[position:])
		top[position] = binding
		if len(top) > publicationFinalistCount {
			top = top[:publicationFinalistCount]
		}
	}

	for _, relation := range publicationShowingRelations {
		for showL := envelope.LShowingMin; showL <= envelope.LShowingMax; showL++ {
			for issueL := envelope.LIssuanceMin; issueL <= envelope.LIssuanceMax; issueL++ {
				for theta := envelope.ThetaMin; theta <= envelope.ThetaMax; theta++ {
					for ell := envelope.EllMin; ell <= envelope.EllMax; ell++ {
						issueGeometry, geometryErr := publicationGeometry(issueL, theta, ell, 49, 9)
						if geometryErr != nil {
							continue
						}
						showGeometry, geometryErr := publicationGeometry(showL, theta, ell, relation.Rows, relation.ParallelDegree)
						if geometryErr != nil {
							continue
						}
						issueBase := preset.Issuance
						issueBase.LVCSNCols, issueBase.Theta, issueBase.Ell = issueL, theta, ell
						showBase := preset.Showing
						showBase.LVCSNCols, showBase.Theta, showBase.Ell = showL, theta, ell
						showBase.SigShortnessRadix, showBase.SigShortnessDigits = relation.Radix, relation.Digits
						showBase.CompressedRows = 1
						issueKey := [3]int{issueL, theta, ell}
						issueEntry, exists := issueChoices[issueKey]
						if !exists {
							issueEntry.Choice, issueEntry.OK = publicationBestPhaseChoice(cache, issueBase, issueGeometry, required, envelope, logQ)
							issueChoices[issueKey] = issueEntry
						}
						showKey := fmt.Sprintf("%s:%d:%d:%d", relation.ID, showL, theta, ell)
						showEntry, exists := showChoices[showKey]
						if !exists {
							showEntry.Choice, showEntry.OK = publicationBestPhaseChoice(cache, showBase, showGeometry, required, envelope, logQ)
							showChoices[showKey] = showEntry
						}
						issueChoice, issueOK := issueEntry.Choice, issueEntry.OK
						showChoice, showOK := showEntry.Choice, showEntry.OK
						if !issueOK || !showOK {
							continue
						}
						candidateCount++
						binding, projectErr := publicationProjectBinding(preset, issueChoice, showChoice)
						if projectErr == nil {
							add(binding)
						}
					}
				}
			}
		}
	}

	// Explicitly include the live seed and the best historical broad-grid seed.
	// They are projected through the same corrected aggregate-Q gates and never
	// receive incumbent preference in the ordering.
	for _, seed := range publicationSeedTunings(preset) {
		candidateCount++
		binding, seedErr := publicationProjectExplicitSeed(cache, preset, seed)
		if seedErr == nil {
			add(binding)
		}
	}
	if len(top) == 0 {
		return publicationPresetSearchResult{}, fmt.Errorf("%s: no publication-v4 candidate survives the exact aggregate-Q gates", preset.CanonicalID)
	}
	finalists := make([]publicationCandidateBinding, len(top))
	for i := range top {
		materialized, err := publicationMaterializeProjectedBinding(top[i], preset)
		if err != nil {
			return publicationPresetSearchResult{}, err
		}
		finalists[i] = materialized
	}
	winner := finalists[0]
	boundaryHits := publicationBoundaryHitsFromWitnesses(top[0], boundaryBest)
	supportFloorHits, expandableBoundaryHits := publicationSplitBoundaryHits(boundaryHits)
	winnerInterior := publicationBindingInterior(winner, envelope)
	return publicationPresetSearchResult{
		CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
		ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), CandidateCount: candidateCount,
		EligibleCount: eligibleCount, Winner: winner, Finalists: finalists,
		MeasurementStatus: "top-12 analytic finalists; fresh execution pending; projected tuples are not adopted",
		BoundaryHits:      boundaryHits, SupportFloorHits: supportFloorHits, ExpandableBoundaryHits: expandableBoundaryHits,
		WinnerInterior: winnerInterior, CertifiedSupportFloors: publicationCertifiedSupportFloors(envelope),
		LowerBoundExclusions: []string{
			"LVCSNCols < 32 is excluded by the user-frozen NCols=32 setting and the supported publication LVCS envelope",
			"theta < 5 is outside the approved publication extension-field search support floor",
			"ell < 6 is outside the approved publication DECS opening search support floor",
			"rounds 2 and 3 are pruned only when even kappa=13 cannot reach the native per-round target",
			"for each structural tuple, every kappa4 class uses the exact smallest feasible integer NLeaves; larger N within that class cannot reduce the primary bound",
			"for each NLeaves, every kappa1 class is reduced to the smallest exact eta and equal-eta classes keep the least grinding",
			"all four kappa values are exact in [0,13]; no aggregate theorem-term or phase-sum penalty is introduced",
		},
	}, nil
}

func publicationBestPhaseChoice(cache *publicationSearchCache, base credential.IntGenISISTuningPreset, geometry publicationPhaseGeometry, required float64, envelope publicationSearchEnvelope, logQ float64) (publicationPhaseChoice, bool) {
	raw2 := float64(base.Theta) * logQ
	k2, ok := publicationRequiredKappa(required, raw2)
	if !ok {
		return publicationPhaseChoice{}, false
	}
	raw3 := publicationRawRound3(credential.IntGenISISSharedModulusQ, base.Theta, geometry.DQ)
	k3, ok := publicationRequiredKappa(required, raw3)
	if !ok {
		return publicationPhaseChoice{}, false
	}
	minimumN := publicationMaxInt(base.LVCSNCols+2*base.Ell, geometry.DDECS+2)
	nCandidates := make(map[int]struct{}, envelope.KappaMax-envelope.KappaMin+1)
	for nominalK4 := envelope.KappaMin; nominalK4 <= envelope.KappaMax; nominalK4++ {
		n, found := publicationMinimumN(cache, minimumN, envelope.NLeavesMax, base.Ell, geometry.DDECS, required-float64(nominalK4))
		if found {
			nCandidates[n] = struct{}{}
		}
	}
	var best publicationPhaseChoice
	foundBest := false
	for nLeaves := range nCandidates {
		raw4 := credential.Log2Binom(uint64(nLeaves), uint64(base.Ell)) - credential.Log2Binom(uint64(geometry.DDECS), uint64(base.Ell))
		k4, feasible := publicationRequiredKappa(required, raw4)
		if !feasible {
			continue
		}
		eta, k1, feasible := publicationMinimumEtaKappa(required, nLeaves, geometry.DDECS, logQ)
		if !feasible {
			continue
		}
		tuning := base
		tuning.NLeaves, tuning.Eta = nLeaves, eta
		tuning.Kappa = [4]int{k1, k2, k3, k4}
		raw := publicationRawRounds(tuning, geometry)
		slack := math.Inf(1)
		grinding := uint64(0)
		for i := range tuning.Kappa {
			slack = math.Min(slack, raw[i]+float64(tuning.Kappa[i])-required)
			grinding += uint64(1) << uint(tuning.Kappa[i])
		}
		if slack < -1e-8 {
			continue
		}
		proofMax, paper, work, err := publicationPhaseProjection(cache, tuning, geometry)
		if err != nil {
			continue
		}
		choice := publicationPhaseChoice{Tuning: tuning, Raw: raw, ProofMax: proofMax, Paper: paper, Grinding: grinding, Work: work, MinSlack: slack}
		if !foundBest || publicationPhaseChoiceLess(choice, best) {
			best, foundBest = choice, true
		}
	}
	return best, foundBest
}

func publicationPhaseChoiceLess(left, right publicationPhaseChoice) bool {
	if left.ProofMax != right.ProofMax {
		return left.ProofMax < right.ProofMax
	}
	if left.Paper != right.Paper {
		return left.Paper < right.Paper
	}
	if left.Grinding != right.Grinding {
		return left.Grinding < right.Grinding
	}
	if left.Work != right.Work {
		return left.Work < right.Work
	}
	if math.Abs(left.MinSlack-right.MinSlack) > 1e-12 {
		return left.MinSlack > right.MinSlack
	}
	return publicationPhaseTuningLexicographic(left.Tuning, right.Tuning)
}

func publicationPhaseTuningLexicographic(left, right credential.IntGenISISTuningPreset) bool {
	l := []int{left.LVCSNCols, left.NLeaves, left.Eta, left.Theta, left.Ell, left.Kappa[0], left.Kappa[1], left.Kappa[2], left.Kappa[3]}
	r := []int{right.LVCSNCols, right.NLeaves, right.Eta, right.Theta, right.Ell, right.Kappa[0], right.Kappa[1], right.Kappa[2], right.Kappa[3]}
	for i := range l {
		if l[i] != r[i] {
			return l[i] < r[i]
		}
	}
	return false
}

func publicationPrimitiveWidthGate(preset credential.IntGenISISPreset) error {
	for phase, tuning := range map[string]credential.IntGenISISTuningPreset{"issuance": preset.Issuance, "showing": preset.Showing} {
		if tuning.FSOutputBits <= 0 || tuning.FSOutputBits%8 != 0 || tuning.FSOutputBits != tuning.FSCollisionBits || tuning.FSOutputBits != tuning.DECSHashBits {
			return fmt.Errorf("%s %s actual/accounted FS/hash widths are not one byte-aligned value", preset.CanonicalID, phase)
		}
		if tuning.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 || !tuning.AggregateROQueryCapLog2Set && preset.ThreatModel.AggregateROQueryCapLog2Set {
			return fmt.Errorf("%s %s is not an aggregate-Q publication-v4 transcript", preset.CanonicalID, phase)
		}
	}
	width := float64(preset.Showing.FSOutputBits)
	if preset.ThreatModel.AggregateROQueryCapLog2Set {
		target := preset.ThreatModel.TargetResidualBits
		if width-2*preset.ThreatModel.AggregateROQueryCapLog2+1e-12 < target+8 {
			return fmt.Errorf("%s collision width does not reserve the eight-bit algebraic split", preset.CanonicalID)
		}
		if float64(preset.Showing.DECSTapeBits)-preset.ThreatModel.AggregateROQueryCapLog2+1e-12 < target {
			return fmt.Errorf("%s tape width fails the aggregate-Q guessing gate", preset.CanonicalID)
		}
	} else if width/2+1e-12 < preset.ThreatModel.TargetWorkFactorBits || float64(preset.Showing.DECSTapeBits)+1e-12 < preset.ThreatModel.TargetWorkFactorBits {
		return fmt.Errorf("%s work-factor primitive width gate failed", preset.CanonicalID)
	}
	return nil
}

func publicationGeometry(l, theta, ell, rows, parallelDegree int) (publicationPhaseGeometry, error) {
	if l < 32 || theta <= 1 || ell <= 0 || rows <= 0 || parallelDegree <= 0 {
		return publicationPhaseGeometry{}, fmt.Errorf("invalid publication geometry")
	}
	_, _, dq := PIOP.ComputeDQBranchBounds(parallelDegree, 8, 32, ell)
	layers := (rows + l - 1) / l
	mu := (dq + l - 1) / l
	nu := (dq + mu - 1) / mu
	replayRows := layers * (32 + theta)
	maskRows := (mu + 1) * theta
	openingRows := replayRows + maskRows
	queries := (layers + 1) * theta
	if queries <= 0 || queries >= openingRows || nu <= 0 || nu > l {
		return publicationPhaseGeometry{}, fmt.Errorf("invalid publication opening geometry")
	}
	return publicationPhaseGeometry{
		L: l, LogicalRows: rows, DDECS: l + ell - 1, DQ: dq, Layers: layers,
		MaskMu: mu, MaskNu: nu, OpeningRows: openingRows, QueryCount: queries,
		OpeningPCols: openingRows - queries,
	}, nil
}

func publicationRawRound3(q uint64, theta, dq int) float64 {
	return math.Log2(math.Pow(float64(q), float64(theta))-32) - math.Log2(float64(dq))
}

func publicationRequiredKappa(required, raw float64) (int, bool) {
	k := int(math.Ceil(required - raw - 1e-12))
	if k < 0 {
		k = 0
	}
	return k, k <= 13
}

func publicationMinimumN(cache *publicationSearchCache, low, high, ell, ddecs int, requiredRaw float64) (int, bool) {
	if requiredRaw < 0 {
		requiredRaw = 0
	}
	key := fmt.Sprintf("%d:%d:%d:%d:%.12f", low, high, ell, ddecs, requiredRaw)
	if n, ok := cache.nRoots[key]; ok {
		return n, n > 0
	}
	predicate := func(n int) bool {
		return credential.Log2Binom(uint64(n), uint64(ell))-credential.Log2Binom(uint64(ddecs), uint64(ell))+1e-12 >= requiredRaw
	}
	if low > high || !predicate(high) {
		cache.nRoots[key] = 0
		return 0, false
	}
	left, right := low, high
	for left < right {
		mid := left + (right-left)/2
		if predicate(mid) {
			right = mid
		} else {
			left = mid + 1
		}
	}
	cache.nRoots[key] = left
	return left, true
}

func publicationMinimumEtaKappa(required float64, nLeaves, ddecs int, logQ float64) (int, int, bool) {
	binom := credential.Log2Binom(uint64(nLeaves), uint64(ddecs+2))
	bestEta, bestK := math.MaxInt, 0
	for k := 0; k <= 13; k++ {
		eta := int(math.Ceil((required-float64(k)+binom)/logQ - 1e-12))
		if eta < 1 {
			eta = 1
		}
		raw := float64(eta)*logQ - binom
		if raw+float64(k)+1e-9 < required {
			eta++
		}
		if eta < bestEta || eta == bestEta && k < bestK {
			bestEta, bestK = eta, k
		}
	}
	return bestEta, bestK, bestEta != math.MaxInt
}

func publicationProjectBinding(preset credential.IntGenISISPreset, issueChoice, showChoice publicationPhaseChoice) (publicationCandidateBinding, error) {
	issue, show := issueChoice.Tuning, showChoice.Tuning
	minimumSlack := math.Min(issueChoice.MinSlack, showChoice.MinSlack)
	if minimumSlack < -1e-8 || issue.Theta != show.Theta || issue.Ell != show.Ell {
		return publicationCandidateBinding{}, fmt.Errorf("native round gate failed")
	}
	tagElements, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return publicationCandidateBinding{}, fmt.Errorf("unknown PRF profile")
	}
	presentationOverhead := 8 + (tagElements*publicationFQBits+7)/8
	grinding := issueChoice.Grinding + showChoice.Grinding
	binding := publicationCandidateBinding{
		CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
		Issuance: issue, Showing: show,
		SelectionStatus: "projected_measurement_pending",
		Projection: &publicationCandidateProjection{
			ShowingProofMaxBytes: showChoice.ProofMax, PresentationMaxBytes: showChoice.ProofMax + presentationOverhead,
			ShowingPaperBytes: showChoice.Paper, CombinedProofMaxBytes: issueChoice.ProofMax + showChoice.ProofMax,
			CombinedPaperBytes: issueChoice.Paper + showChoice.Paper, ExpectedGrindingWork: grinding,
			ProjectedWorkUnits: issueChoice.Work + showChoice.Work, MinimumSecuritySlack: minimumSlack,
			RawRoundBitsIssuance: issueChoice.Raw, RawRoundBitsShowing: showChoice.Raw,
			RequiredNativeRoundBits: preset.TargetTheoremBits,
		},
	}
	if issue == preset.Issuance && show == preset.Showing {
		binding.SelectionStatus = "adopted_manifest_measurement_pending"
	}
	return binding, nil
}

// publicationMaterializeProjectedBinding performs the comparatively expensive
// field-profile, manifest and content-digest work only for the bounded retained
// frontier. The exhaustive inner loop remains a lightweight integer/size scan.
func publicationMaterializeProjectedBinding(binding publicationCandidateBinding, base credential.IntGenISISPreset) (publicationCandidateBinding, error) {
	candidate := base
	candidate.Issuance, candidate.Showing = binding.Issuance, binding.Showing
	candidate.LVCSNCols = binding.Showing.LVCSNCols
	candidate.MaxNLeaves = publicationMaxInt(binding.Issuance.NLeaves, binding.Showing.NLeaves)
	profile, ok := kf.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, binding.Showing.Theta)
	if ok && binding.Issuance.Theta == binding.Showing.Theta {
		digest, err := profile.DigestHex(32)
		if err != nil {
			return publicationCandidateBinding{}, err
		}
		candidate.FieldProfileID, candidate.FieldProfileDigest = profile.ID, digest
		if err := credential.ValidateIntGenISISPresetManifest(candidate); err != nil {
			return publicationCandidateBinding{}, fmt.Errorf("prospective publication manifest: %w", err)
		}
		binding.ManifestStatus = "pinned_validated"
		binding.ManifestDigest = credential.IntGenISISPresetManifestDigest(candidate)
	} else {
		binding.ManifestStatus = "field_profile_generation_required"
		binding.ManifestDigest = ""
		binding.SelectionStatus = "projected_field_profile_pending"
	}
	digest, err := publicationDigest(binding)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	binding.CandidateDigest = digest
	return binding, nil
}

func publicationPresetFromBinding(binding publicationCandidateBinding) (credential.IntGenISISPreset, error) {
	preset, ok := credential.LookupIntGenISISPublicationPreset(binding.CanonicalID)
	if !ok || preset.PublicationLabel != binding.PublicationLabel {
		return credential.IntGenISISPreset{}, fmt.Errorf("unknown publication candidate identity %q", binding.CanonicalID)
	}
	preset.Issuance, preset.Showing = binding.Issuance, binding.Showing
	preset.LVCSNCols = binding.Showing.LVCSNCols
	preset.MaxNLeaves = publicationMaxInt(binding.Issuance.NLeaves, binding.Showing.NLeaves)
	profile, ok := kf.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, binding.Showing.Theta)
	if !ok || binding.Issuance.Theta != binding.Showing.Theta {
		return credential.IntGenISISPreset{}, fmt.Errorf("candidate %s has no shared pinned theta profile", binding.CanonicalID)
	}
	digest, err := profile.DigestHex(32)
	if err != nil {
		return credential.IntGenISISPreset{}, err
	}
	preset.FieldProfileID, preset.FieldProfileDigest = profile.ID, digest
	if err := credential.ValidateIntGenISISPresetManifest(preset); err != nil {
		return credential.IntGenISISPreset{}, err
	}
	if got := credential.IntGenISISPresetManifestDigest(preset); got != binding.ManifestDigest {
		return credential.IntGenISISPreset{}, fmt.Errorf("candidate %s manifest digest=%s want binding %s", binding.CanonicalID, got, binding.ManifestDigest)
	}
	return preset, nil
}

func publicationRawRounds(tuning credential.IntGenISISTuningPreset, geometry publicationPhaseGeometry) [4]float64 {
	q := float64(credential.IntGenISISSharedModulusQ)
	return [4]float64{
		float64(tuning.Eta)*math.Log2(q) - credential.Log2Binom(uint64(tuning.NLeaves), uint64(geometry.DDECS+2)),
		float64(tuning.Theta*tuning.Rho) * math.Log2(q),
		publicationRawRound3(credential.IntGenISISSharedModulusQ, tuning.Theta, geometry.DQ),
		credential.Log2Binom(uint64(tuning.NLeaves), uint64(tuning.Ell)) - credential.Log2Binom(uint64(geometry.DDECS), uint64(tuning.Ell)),
	}
}

func publicationPhaseProjection(cache *publicationSearchCache, tuning credential.IntGenISISTuningPreset, geometry publicationPhaseGeometry) (int, int, uint64, error) {
	radix := func(count int) int { return publicationRadixQBytes(cache, count) }
	rBytes := radix(tuning.Eta * (geometry.DDECS + 1))
	qBytes := radix(tuning.Theta * geometry.DQ)
	vElements := tuning.Theta * (geometry.LogicalRows + geometry.MaskNu)
	vBytes := radix(vElements)
	barBytes := radix(geometry.QueryCount * tuning.Ell)
	pBytes := radix(tuning.Ell * geometry.OpeningPCols)
	key := [2]int{tuning.NLeaves, tuning.Ell}
	authNodes, ok := cache.frontierNodes[key]
	if !ok {
		var err error
		authNodes, err = decs.MerkleFrontierWorstCaseNodesV3(tuning.NLeaves, tuning.Ell)
		if err != nil {
			return 0, 0, 0, err
		}
		cache.frontierNodes[key] = authNodes
	}
	hashBytes, tapeBytes := tuning.DECSHashBits/8, tuning.DECSTapeBits/8
	authBytes := authNodes * hashBytes
	tapesBytes := tuning.Ell * tapeBytes
	canonicalMax := 10 + hashBytes + (tuning.SaltBits+7)/8 + 40 + rBytes + qBytes + vBytes + barBytes + pBytes + authBytes + tapesBytes
	depth := 0
	for size := 1; size < tuning.NLeaves; size <<= 1 {
		depth++
	}
	// This mirrors PIOP.applyStrictV3PaperAccounting exactly. Each bucket is
	// independently byte-framed, so ceilings are applied per bucket rather
	// than after summing bits. Q omits only its transcript-fixed constant term;
	// R is full, V is ragged, and authentication uses the paper's per-opening
	// path bound (the canonical wire separately uses the exact multiproof bound).
	paperR := publicationBitsToBytes(float64(tuning.Eta*(geometry.DDECS+1)) * math.Log2(float64(credential.IntGenISISSharedModulusQ)))
	paperQ := publicationBitsToBytes(float64(tuning.Rho*tuning.Theta*geometry.DQ) * math.Log2(float64(credential.IntGenISISSharedModulusQ)))
	paperV := publicationBitsToBytes(float64(tuning.Theta * (geometry.LogicalRows + geometry.MaskNu) * publicationFQBits))
	paperBar := publicationPackedMatrixFrameBytes + publicationBitsToBytes(float64(geometry.QueryCount*tuning.Ell*publicationFQBits))
	paperP := publicationBitsToBytes(float64(tuning.Ell * geometry.OpeningPCols * publicationFQBits))
	paperAuth := publicationBitsToBytes(float64(tuning.Ell * depth * tuning.DECSHashBits))
	paperTapes := publicationBitsToBytes(float64(tuning.Ell * tuning.DECSTapeBits))
	positionBytes := (tuning.Ell*depth + 7) / 8
	fixed := 16 + (tuning.SaltBits+7)/8 + (tuning.DECSHashBits+7)/8 + (2*publicationLambdaBits+7)/8 +
		publicationSmallFieldMetadataBytes() + positionBytes + 1 + publicationVarintSize(tuning.Ell) + publicationVarintSize(depth) + 1 + 1
	// Canonical v4 reconstructs the showing shortness descriptor from the
	// manifest and rejects a transmitted SigShortness payload, so its paper
	// bucket is exactly zero.
	paper := fixed + paperR + paperQ + paperV + paperBar + paperP + paperAuth + paperTapes
	work := uint64(tuning.NLeaves)*uint64(geometry.OpeningRows) + uint64(tuning.Theta)*uint64(geometry.DQ)
	return canonicalMax, paper, work, nil
}

func publicationBitsToBytes(bits float64) int {
	if bits <= 0 {
		return 0
	}
	return int(math.Ceil(bits / 8))
}

func publicationVarintSize(value int) int {
	if value < 0 {
		value = -value
	}
	size := 1
	for uint64(value) >= 0x80 {
		size++
		value >>= 7
	}
	return size
}

func publicationFramedStringBytes(value string) int { return 8 + len(value) }

func publicationSmallFieldMetadataBytes() int {
	omission := publicationFramedStringBytes("smallfield_2025_transcript_omission_v3") +
		publicationFramedStringBytes(PIOP.SmallField2025TranscriptOmissionModeCanonicalV3) + 5*8
	return publicationFramedStringBytes("smallfield_2025_lvcs_proof_v2") +
		publicationFramedStringBytes(credential.IntGenISISTranscriptProtocolV4) +
		publicationFramedStringBytes(PIOP.SmallField2025StatusLive) +
		publicationFramedStringBytes(PIOP.SmallField2025HeadDomainV2) +
		12*8 + 2*8 + (8 + sha256.Size) + (8 + omission) + (8 + sha256.Size)
}

func publicationRadixQBytes(cache *publicationSearchCache, count int) int {
	if value, ok := cache.radixBytes[count]; ok {
		return value
	}
	q := new(big.Int).SetUint64(credential.IntGenISISSharedModulusQ)
	total := 0
	for remaining := count; remaining > 0; {
		group := remaining
		if group > publicationRadixGroup {
			group = publicationRadixGroup
		}
		limit := new(big.Int).Exp(q, big.NewInt(int64(group)), nil)
		limit.Sub(limit, big.NewInt(1))
		total += (limit.BitLen() + 7) / 8
		remaining -= group
	}
	cache.radixBytes[count] = total
	return total
}

type publicationExplicitSeed struct {
	Issuance credential.IntGenISISTuningPreset
	Showing  credential.IntGenISISTuningPreset
}

func publicationSeedTunings(preset credential.IntGenISISPreset) []publicationExplicitSeed {
	// Keep the live incumbent as two complete phase tuples. Several publication
	// presets intentionally use different issuance/showing N, eta, or kappa;
	// flattening them to the showing tuple would mean the incumbent was never
	// actually compared by the search.
	seeds := []publicationExplicitSeed{{Issuance: preset.Issuance, Showing: preset.Showing}}
	switch preset.PublicationLabel {
	case credential.IntGenISISPublicationLabelBQ96Q96, credential.IntGenISISPublicationLabelBQ128Q64:
		seeds = append(seeds, publicationSharedExplicitSeed(preset, 43, 43, 917504, 53, 10, 13, [4]int{13, 2, 8, 13}, 7, 5))
	case credential.IntGenISISPublicationLabelWF128:
		seeds = append(seeds, publicationSharedExplicitSeed(preset, 42, 42, 966656, 46, 7, 8, [4]int{11, 0, 8, 13}, 11, 4))
	case credential.IntGenISISPublicationLabelBQ128Q128:
		seeds = append(seeds, publicationSharedExplicitSeed(preset, 55, 55, 851968, 68, 13, 18, [4]int{7, 6, 12, 13}, 11, 4))
	}
	return seeds
}

func publicationSharedExplicitSeed(preset credential.IntGenISISPreset, issueL, showL, nLeaves, eta, theta, ell int, kappa [4]int, radix, digits int) publicationExplicitSeed {
	issue, show := preset.Issuance, preset.Showing
	issue.LVCSNCols, issue.NLeaves, issue.Eta, issue.Theta, issue.Ell, issue.Kappa = issueL, nLeaves, eta, theta, ell, kappa
	show.LVCSNCols, show.NLeaves, show.Eta, show.Theta, show.Ell, show.Kappa = showL, nLeaves, eta, theta, ell, kappa
	show.SigShortnessRadix, show.SigShortnessDigits = radix, digits
	show.CompressedRows = 1
	return publicationExplicitSeed{Issuance: issue, Showing: show}
}

func publicationProjectExplicitSeed(cache *publicationSearchCache, preset credential.IntGenISISPreset, seed publicationExplicitSeed) (publicationCandidateBinding, error) {
	var relation publicationRelationVariant
	found := false
	for _, candidate := range publicationShowingRelations {
		if candidate.Radix == seed.Showing.SigShortnessRadix && candidate.Digits == seed.Showing.SigShortnessDigits {
			relation, found = candidate, true
			break
		}
	}
	if !found {
		return publicationCandidateBinding{}, fmt.Errorf("unsupported seed relation")
	}
	issueGeometry, err := publicationGeometry(seed.Issuance.LVCSNCols, seed.Issuance.Theta, seed.Issuance.Ell, 49, 9)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	showGeometry, err := publicationGeometry(seed.Showing.LVCSNCols, seed.Showing.Theta, seed.Showing.Ell, relation.Rows, relation.ParallelDegree)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	issue, show := seed.Issuance, seed.Showing
	makeChoice := func(tuning credential.IntGenISISTuningPreset, geometry publicationPhaseGeometry) (publicationPhaseChoice, error) {
		raw := publicationRawRounds(tuning, geometry)
		slack, grinding := math.Inf(1), uint64(0)
		for i := range tuning.Kappa {
			slack = math.Min(slack, raw[i]+float64(tuning.Kappa[i])-preset.TargetTheoremBits)
			grinding += uint64(1) << uint(tuning.Kappa[i])
		}
		if slack < -1e-8 {
			return publicationPhaseChoice{}, fmt.Errorf("seed fails native round gate")
		}
		proofMax, paper, work, err := publicationPhaseProjection(cache, tuning, geometry)
		return publicationPhaseChoice{Tuning: tuning, Raw: raw, ProofMax: proofMax, Paper: paper, Grinding: grinding, Work: work, MinSlack: slack}, err
	}
	issueChoice, err := makeChoice(issue, issueGeometry)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	showChoice, err := makeChoice(show, showGeometry)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	return publicationProjectBinding(preset, issueChoice, showChoice)
}

func publicationBindingLess(left, right publicationCandidateBinding) bool {
	l, r := left.Projection, right.Projection
	if l.ShowingProofMaxBytes != r.ShowingProofMaxBytes {
		return l.ShowingProofMaxBytes < r.ShowingProofMaxBytes
	}
	if l.PresentationMaxBytes != r.PresentationMaxBytes {
		return l.PresentationMaxBytes < r.PresentationMaxBytes
	}
	if l.ShowingPaperBytes != r.ShowingPaperBytes {
		return l.ShowingPaperBytes < r.ShowingPaperBytes
	}
	if l.CombinedProofMaxBytes != r.CombinedProofMaxBytes {
		return l.CombinedProofMaxBytes < r.CombinedProofMaxBytes
	}
	if l.CombinedPaperBytes != r.CombinedPaperBytes {
		return l.CombinedPaperBytes < r.CombinedPaperBytes
	}
	if l.ExpectedGrindingWork != r.ExpectedGrindingWork {
		return l.ExpectedGrindingWork < r.ExpectedGrindingWork
	}
	if l.ProjectedWorkUnits != r.ProjectedWorkUnits {
		return l.ProjectedWorkUnits < r.ProjectedWorkUnits
	}
	if math.Abs(l.MinimumSecuritySlack-r.MinimumSecuritySlack) > 1e-12 {
		return l.MinimumSecuritySlack > r.MinimumSecuritySlack
	}
	return publicationTuningLexicographic(left, right)
}

func publicationTuningLexicographic(left, right publicationCandidateBinding) bool {
	l := []int{left.Showing.SigShortnessRadix, left.Showing.SigShortnessDigits, left.Showing.LVCSNCols, left.Issuance.LVCSNCols,
		left.Showing.NLeaves, left.Issuance.NLeaves, left.Showing.Eta, left.Issuance.Eta, left.Showing.Theta, left.Showing.Ell,
		left.Showing.Kappa[0], left.Showing.Kappa[1], left.Showing.Kappa[2], left.Showing.Kappa[3],
		left.Issuance.Kappa[0], left.Issuance.Kappa[1], left.Issuance.Kappa[2], left.Issuance.Kappa[3]}
	r := []int{right.Showing.SigShortnessRadix, right.Showing.SigShortnessDigits, right.Showing.LVCSNCols, right.Issuance.LVCSNCols,
		right.Showing.NLeaves, right.Issuance.NLeaves, right.Showing.Eta, right.Issuance.Eta, right.Showing.Theta, right.Showing.Ell,
		right.Showing.Kappa[0], right.Showing.Kappa[1], right.Showing.Kappa[2], right.Showing.Kappa[3],
		right.Issuance.Kappa[0], right.Issuance.Kappa[1], right.Issuance.Kappa[2], right.Issuance.Kappa[3]}
	for i := range l {
		if l[i] != r[i] {
			return l[i] < r[i]
		}
	}
	return left.CandidateDigest != "" && right.CandidateDigest != "" && left.CandidateDigest < right.CandidateDigest
}

func publicationSameTuning(left, right publicationCandidateBinding) bool {
	return left.CanonicalID == right.CanonicalID && left.Issuance == right.Issuance && left.Showing == right.Showing
}

func publicationMaxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func publicationBindingInterior(binding publicationCandidateBinding, envelope publicationSearchEnvelope) bool {
	t := binding.Showing
	return binding.Issuance.LVCSNCols >= envelope.LIssuanceMin && binding.Issuance.LVCSNCols < envelope.LIssuanceMax &&
		t.LVCSNCols >= envelope.LShowingMin && t.LVCSNCols < envelope.LShowingMax &&
		t.Theta >= envelope.ThetaMin && t.Theta < envelope.ThetaMax && t.Ell >= envelope.EllMin && t.Ell < envelope.EllMax
}

func publicationSplitBoundaryHits(hits []string) (supportFloors, expandable []string) {
	for _, hit := range hits {
		if strings.HasSuffix(hit, "_lower") {
			supportFloors = append(supportFloors, hit)
		} else {
			expandable = append(expandable, hit)
		}
	}
	return supportFloors, expandable
}

func publicationCertifiedSupportFloors(envelope publicationSearchEnvelope) []publicationSupportFloorCertification {
	return []publicationSupportFloorCertification{
		{Dimension: "l_issuance_lower", Minimum: envelope.LIssuanceMin, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
		{Dimension: "l_showing_lower", Minimum: envelope.LShowingMin, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
		{Dimension: "theta_lower", Minimum: envelope.ThetaMin, Basis: "approved_publication_extension_field_support_floor"},
		{Dimension: "ell_lower", Minimum: envelope.EllMin, Basis: "approved_publication_decs_opening_support_floor"},
	}
}

func publicationCandidateBoundaryFacets(binding publicationCandidateBinding, envelope publicationSearchEnvelope) []string {
	checks := []struct {
		name string
		hit  bool
	}{
		{"l_issuance_lower", binding.Issuance.LVCSNCols == envelope.LIssuanceMin},
		{"l_issuance_upper", binding.Issuance.LVCSNCols == envelope.LIssuanceMax},
		{"l_showing_lower", binding.Showing.LVCSNCols == envelope.LShowingMin},
		{"l_showing_upper", binding.Showing.LVCSNCols == envelope.LShowingMax},
		{"theta_lower", binding.Showing.Theta == envelope.ThetaMin},
		{"theta_upper", binding.Showing.Theta == envelope.ThetaMax},
		{"ell_lower", binding.Showing.Ell == envelope.EllMin},
		{"ell_upper", binding.Showing.Ell == envelope.EllMax},
	}
	out := make([]string, 0, len(checks))
	for _, check := range checks {
		if check.hit {
			out = append(out, check.name)
		}
	}
	return out
}

func publicationBoundaryHitsFromWitnesses(winner publicationCandidateBinding, best map[string]publicationCandidateBinding) []string {
	if winner.Projection == nil {
		return []string{"empty_frontier"}
	}
	threshold := float64(winner.Projection.ShowingProofMaxBytes) * 1.0025
	out := make([]string, 0, len(best))
	for facet, witness := range best {
		if witness.Projection != nil && float64(witness.Projection.ShowingProofMaxBytes) <= threshold {
			out = append(out, facet)
		}
	}
	sort.Strings(out)
	return out
}

func publicationNearFrontierBoundaryHits(finalists []publicationCandidateBinding, envelope publicationSearchEnvelope) []string {
	if len(finalists) == 0 || finalists[0].Projection == nil {
		return []string{"empty_frontier"}
	}
	threshold := float64(finalists[0].Projection.ShowingProofMaxBytes) * 1.0025
	seen := make(map[string]struct{})
	for _, finalist := range finalists {
		if finalist.Projection == nil || float64(finalist.Projection.ShowingProofMaxBytes) > threshold {
			continue
		}
		checks := map[string]bool{
			"l_issuance_upper": finalist.Issuance.LVCSNCols == envelope.LIssuanceMax,
			"l_showing_upper":  finalist.Showing.LVCSNCols == envelope.LShowingMax,
			"theta_lower":      finalist.Showing.Theta == envelope.ThetaMin,
			"theta_upper":      finalist.Showing.Theta == envelope.ThetaMax,
			"ell_lower":        finalist.Showing.Ell == envelope.EllMin,
			"ell_upper":        finalist.Showing.Ell == envelope.EllMax,
		}
		for name, hit := range checks {
			if hit {
				seen[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for hit := range seen {
		out = append(out, hit)
	}
	sort.Strings(out)
	return out
}
