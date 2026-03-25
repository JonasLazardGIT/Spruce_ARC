# Preimage_Sampler

`Preimage_Sampler/` provides the high-precision FFT and cyclotomic arithmetic
used by the NTRU sampler.

It is not an operator-facing package. Its role is to support the trapdoor
sampler and embedding code used by `ntru/`.

## Main Responsibilities

- arbitrary-precision complex arithmetic
- coefficient/evaluation-domain transforms
- cyclotomic field element manipulation
- helper routines used by the NTRU preimage sampler

## Main Entry Points

- `NewBigComplexFromFloat`
- `NewFieldElemBig`
- `FFTBig`
- `IFFTBig`
- `fftAny`

The main retained types are:

- `BigComplex`
- `CyclotomicFieldElem`

## Current Invariants

- this package exists to support the shipped NTRU sampler path
- it shares the same ring and field assumptions as the rest of the credential
  stack
- it is a math support layer, not a standalone protocol surface

## Read Next

- [../ntru/README.md](../ntru/README.md)
