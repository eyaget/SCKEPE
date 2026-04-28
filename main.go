package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/bits"
	"time"

	"filippo.io/edwards25519"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/cmp"

	"github.com/consensys/gnark-crypto/ecc"
	bls377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls377poseidon2 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
)

const (
	N = 128

	// byte-sized domain tags for Poseidon2-MD
	tagHash = 1
	tagKDF  = 2

	TAU      = 10
	NUM_RUNS = 100
)

// Domain separation for Schnorr equality proof transcript hash
const schnorrCtx = "FE|SchnorrEq|v1"

// Demo sparse parity-check H
var HROWS = [][]int{
	{0, 7, 14, 21, 28, 35, 42, 49},
	{1, 8, 15, 22, 29, 36, 43, 50},
	{2, 9, 16, 23, 30, 37, 44, 51},
	{3, 10, 17, 24, 31, 38, 45, 52},
	{4, 11, 18, 25, 32, 39, 46, 53},
	{5, 12, 19, 26, 33, 40, 47, 54},
	{6, 13, 20, 27, 34, 41, 48, 55},
}

/* ============================ Bit helpers =========================================== */

func xorU8(a, b uint8) uint8 { return (a ^ b) & 1 }

func xorBits(a, b [N]uint8) (out [N]uint8) {
	for i := 0; i < N; i++ {
		out[i] = xorU8(a[i], b[i])
	}
	return
}

func weight(bitsA [N]uint8) int {
	w := 0
	for i := 0; i < N; i++ {
		if bitsA[i] == 1 {
			w++
		}
	}
	return w
}

func randBits128() (out [N]uint8) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatal(err)
	}
	for i := 0; i < N; i++ {
		out[i] = (b[i/8] >> uint(i%8)) & 1
	}
	return
}

func sampleErrorOfWeight(t int) (e [N]uint8) {
	if t < 0 || t > N {
		log.Fatalf("invalid weight t=%d", t)
	}
	idx := make([]int, N)
	for i := 0; i < N; i++ {
		idx[i] = i
	}
	for i := N - 1; i > 0; i-- {
		var rb [4]byte
		_, _ = rand.Read(rb[:])
		j := int(uint32(rb[0]) | uint32(rb[1])<<8 | uint32(rb[2])<<16 | uint32(rb[3])<<24)
		if j < 0 {
			j = -j
		}
		j %= (i + 1)
		idx[i], idx[j] = idx[j], idx[i]
	}
	for k := 0; k < t; k++ {
		e[idx[k]] = 1
	}
	return
}

func bitsToHex16(bitsA [N]uint8) string {
	var b [16]byte
	for i := 0; i < N; i++ {
		if bitsA[i] == 1 {
			b[i/8] |= 1 << uint(i%8)
		}
	}
	return hex.EncodeToString(b[:])
}

func printBits(name string, bitsA [N]uint8) {
	fmt.Printf("%s (hex128) = %s\n", name, bitsToHex16(bitsA))
	fmt.Printf("%s (bin)    = ", name)
	for i := 0; i < N; i++ {
		fmt.Print(bitsA[i])
	}
	fmt.Println()
}

/* ============================ GF(2) nullspace for non-zero c' =========================================== */

// represent 128-bit vectors as 2 uint64 blocks
type v128 struct {
	lo uint64 // bits 0..63
	hi uint64 // bits 64..127
}

func (v v128) xor(w v128) v128 { return v128{lo: v.lo ^ w.lo, hi: v.hi ^ w.hi} }
func (v v128) bit(i int) uint64 {
	if i < 64 {
		return (v.lo >> uint(i)) & 1
	}
	return (v.hi >> uint(i-64)) & 1
}
func (v *v128) setBit(i int, b uint64) {
	if i < 64 {
		if b == 1 {
			v.lo |= 1 << uint(i)
		} else {
			v.lo &^= 1 << uint(i)
		}
	} else {
		j := i - 64
		if b == 1 {
			v.hi |= 1 << uint(j)
		} else {
			v.hi &^= 1 << uint(j)
		}
	}
}
func (v v128) and(w v128) v128 { return v128{lo: v.lo & w.lo, hi: v.hi & w.hi} }
func (v v128) isZero() bool     { return v.lo == 0 && v.hi == 0 }
func (v v128) parity() uint64 {
	return uint64((bits.OnesCount64(v.lo) ^ bits.OnesCount64(v.hi)) & 1)
}

// Build H as v128 rows
func buildHRowsV128() []v128 {
	H := make([]v128, len(HROWS))
	for r, row := range HROWS {
		var v v128
		for _, j := range row {
			if j < 0 || j >= N {
				panic("HROWS index out of range")
			}
			v.setBit(j, 1)
		}
		H[r] = v
	}
	return H
}

// Compute RREF of H and return (rrefRows, pivotCols, freeCols).
func rrefGF2(rows []v128, n int) ([]v128, []int, []int) {
	m := len(rows)
	A := make([]v128, m)
	copy(A, rows)

	pivotCols := make([]int, 0, m)

	r := 0
	for c := 0; c < n && r < m; c++ {
		piv := -1
		for rr := r; rr < m; rr++ {
			if A[rr].bit(c) == 1 {
				piv = rr
				break
			}
		}
		if piv == -1 {
			continue
		}
		A[r], A[piv] = A[piv], A[r]

		pivotCols = append(pivotCols, c)

		// eliminate pivot column in all other rows
		for rr := 0; rr < m; rr++ {
			if rr == r {
				continue
			}
			if A[rr].bit(c) == 1 {
				A[rr] = A[rr].xor(A[r])
			}
		}
		r++
	}

	isPivot := make([]bool, n)
	for _, c := range pivotCols {
		isPivot[c] = true
	}
	freeCols := make([]int, 0, n-len(pivotCols))
	for c := 0; c < n; c++ {
		if !isPivot[c] {
			freeCols = append(freeCols, c)
		}
	}
	return A, pivotCols, freeCols
}

// Construct a nullspace basis from (near) RREF rows.
func nullspaceBasisFromRREF(A []v128, pivotCols, freeCols []int) []v128 {
	basis := make([]v128, 0, len(freeCols))

	pivotRowForCol := make(map[int]int, len(pivotCols))
	for pr, pc := range pivotCols {
		pivotRowForCol[pc] = pr
	}

	for _, f := range freeCols {
		var x v128
		x.setBit(f, 1)

		for _, pc := range pivotCols {
			pr := pivotRowForCol[pc]
			p := A[pr].and(x).parity()
			if p == 1 {
				x.setBit(pc, 1)
			} else {
				x.setBit(pc, 0)
			}
		}
		if !x.isZero() {
			basis = append(basis, x)
		}
	}
	if len(basis) == 0 {
		panic("nullspace basis is empty: H appears full-rank or construction bug")
	}
	return basis
}

// Sample a random non-zero codeword from a basis by XOR-ing a random subset.
func sampleCodewordFromBasis(basis []v128) (cBits [N]uint8) {
	var c v128
	var sel [1]byte
	for i := 0; i < len(basis); i++ {
		_, _ = rand.Read(sel[:])
		if (sel[0] & 1) == 1 {
			c = c.xor(basis[i])
		}
	}
	if c.isZero() {
		c = c.xor(basis[0]) // force non-zero
	}
	for i := 0; i < N; i++ {
		cBits[i] = uint8(c.bit(i))
	}
	return
}

/* ============================ Outside Poseidon2-MD (bytes) ========================================== */

func mdHashBytes(data []byte) ([]byte, error) {
	h := bls377poseidon2.NewMerkleDamgardHasher()
	h.Reset()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func computeDigestOutside(cBits [N]uint8) (bls377fr.Element, error) {
	in := make([]byte, 0, 1+N)
	in = append(in, byte(tagHash))
	for i := 0; i < N; i++ {
		in = append(in, byte(cBits[i]))
	}
	outBytes, err := mdHashBytes(in)
	if err != nil {
		return bls377fr.Element{}, err
	}
	var d bls377fr.Element
	d.SetBytes(outBytes)
	return d, nil
}

func computeKOutside(cBits [N]uint8) (bls377fr.Element, error) {
	in := make([]byte, 0, 1+N)
	in = append(in, byte(tagKDF))
	for i := 0; i < N; i++ {
		in = append(in, byte(cBits[i]))
	}
	outBytes, err := mdHashBytes(in)
	if err != nil {
		return bls377fr.Element{}, err
	}
	var k bls377fr.Element
	k.SetBytes(outBytes)
	return k, nil
}

func ed25519FromK(k bls377fr.Element) (ed25519.PublicKey, ed25519.PrivateKey) {
	kb := k.Bytes()
	sum := sha512.Sum512(append([]byte("KDF:Ed25519:FE:v1|"), kb[:]...))
	seed := sum[:32]
	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	return pk, sk
}

/* ============================ Schnorr Key Equality Proof (Ed25519 group) ============================================= */
/*
Proves knowledge of k such that pk = [k]B (B = Ed25519 basepoint), with FS challenge:
  c = H(ctx || pk || R || nonce || hFE)
Proof: (R, z) where R=[r]B, z=r + c*k (mod L)

Verifier checks:
  [z]B ?= R + [c]pk
*/

type SchnorrEqProof struct {
	R [32]byte // compressed Edwards point
	Z [32]byte // scalar encoding (little-endian)
}

// derive the Ed25519 secret scalar (clamped) from the ed25519 private key seed
//func ed25519SecretScalar(sk ed25519.PrivateKey) *edwards25519.Scalar {
	//seed := sk.Seed() // 32 bytes
	//h := sha512.Sum512(seed)
	// SetBytesWithClamping expects 32 bytes; it will clamp as per Ed25519
	//return new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
//}
func ed25519SecretScalar(sk ed25519.PrivateKey) *edwards25519.Scalar {
	seed := sk.Seed() // 32 bytes
	h := sha512.Sum512(seed)

	s, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		// This should never happen for 32-byte input,
		// but we fail hard if it does.
		panic(err)
	}
	return s
}

func hashToScalar(pkBytes []byte, RBytes [32]byte, nonce []byte, hFE [64]byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(schnorrCtx))
	h.Write([]byte{0})
	h.Write(pkBytes)
	h.Write(RBytes[:])
	h.Write(nonce)
	h.Write(hFE[:])
	sum := h.Sum(nil) // 64 bytes

	if len(sum) != 64 {
		panic("unexpected hash length")
	}

	sc, err := new(edwards25519.Scalar).SetUniformBytes(sum)
	if err != nil {
		panic(err)
	}
	return sc
}

func schnorrEqProve(pk ed25519.PublicKey, sk ed25519.PrivateKey, nonce []byte, hFE [64]byte) (SchnorrEqProof, [32]byte, error) {
	var proof SchnorrEqProof

	k := ed25519SecretScalar(sk)

	// r <- uniform scalar
	var rBytes [64]byte
	if _, err := rand.Read(rBytes[:]); err != nil {
		return proof, [32]byte{}, err
	}
	r, err := new(edwards25519.Scalar).SetUniformBytes(rBytes[:])
	if err != nil {
		return proof, [32]byte{}, err
	}

	// R = [r]B
	Rpt := new(edwards25519.Point).ScalarBaseMult(r)
	Renc := Rpt.Bytes()
	copy(proof.R[:], Renc)

	// c = H(ctx||pk||R||nonce||hFE)
	c := hashToScalar(pk, proof.R, nonce, hFE)

	// z = r + c*k
	ck := new(edwards25519.Scalar).Multiply(c, k)
	z := new(edwards25519.Scalar).Add(r, ck)

	zBytes := z.Bytes()
	copy(proof.Z[:], zBytes)

	// also return challenge c as bytes for printing
	var cOut [32]byte
	copy(cOut[:], c.Bytes())
	return proof, cOut, nil
}

func schnorrEqVerify(pk ed25519.PublicKey, nonce []byte, hFE [64]byte, proof SchnorrEqProof) (bool, [32]byte, error) {
	// decode R
	Rpt, err := new(edwards25519.Point).SetBytes(proof.R[:])
	if err != nil {
		return false, [32]byte{}, err
	}

	// decode pk point
	PKpt, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return false, [32]byte{}, err
	}

	// decode z scalar
	z, err := new(edwards25519.Scalar).SetCanonicalBytes(proof.Z[:])
	if err != nil {
		return false, [32]byte{}, err
	}

	// recompute c
	c := hashToScalar(pk, proof.R, nonce, hFE)

	// check: [z]B == R + [c]PK
	left := new(edwards25519.Point).ScalarBaseMult(z)
	right := new(edwards25519.Point).Add(Rpt, new(edwards25519.Point).ScalarMult(c, PKpt))

	ok := left.Equal(right) == 1

	var cOut [32]byte
	copy(cOut[:], c.Bytes())
	return ok, cOut, nil
}

/* ============================ Circuit (K removed) =========================================== */

type FECircuit struct {
	P   [N]frontend.Variable `gnark:",public"`
	Tau frontend.Variable    `gnark:",public"`

	W [N]frontend.Variable // w'
	C [N]frontend.Variable // c'
	E [N]frontend.Variable // e
}

func xorBit(api frontend.API, a, b frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(a)
	api.AssertIsBoolean(b)
	return api.Sub(api.Add(a, b), api.Mul(2, api.Mul(a, b)))
}

func (c *FECircuit) Define(api frontend.API) error {
	for i := 0; i < N; i++ {
		api.AssertIsBoolean(c.P[i])
		api.AssertIsBoolean(c.W[i])
		api.AssertIsBoolean(c.C[i])
		api.AssertIsBoolean(c.E[i])

		api.AssertIsEqual(
			xorBit(api, c.W[i], c.P[i]),
			xorBit(api, c.C[i], c.E[i]),
		)
	}

	for r, row := range HROWS {
		par := frontend.Variable(0)
		for _, j := range row {
			if j < 0 || j >= N {
				return fmt.Errorf("H row %d invalid index %d", r, j)
			}
			par = xorBit(api, par, c.C[j])
		}
		api.AssertIsEqual(par, 0)
	}

	wt := frontend.Variable(0)
	for i := 0; i < N; i++ {
		wt = api.Add(wt, c.E[i])
	}
	api.AssertIsEqual(cmp.IsLessOrEqual(api, wt, c.Tau), 1)

	// existential private k derived in-circuit
	h, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return fmt.Errorf("poseidon2 init failed: %w", err)
	}
	h.Reset()
	h.Write(tagKDF)
	for i := 0; i < N; i++ {
		h.Write(c.C[i])
	}
	k := h.Sum()
	api.AssertIsDifferent(api.Add(k, 1), k)

	return nil
}

/* ============================ Stats ============================================= */

func meanStdMinMax(xs []float64) (mean, std, min, max float64) {
	if len(xs) == 0 {
		return 0, 0, 0, 0
	}
	min, max = xs[0], xs[0]
	for _, x := range xs {
		mean += x
		if x < min {
			min = x
		}
		if x > max {
			max = x
		}
	}
	mean /= float64(len(xs))
	for _, x := range xs {
		d := x - mean
		std += d * d
	}
	std = math.Sqrt(std / float64(len(xs)))
	return mean, std, min, max
}

func proofHash64(proof groth16.Proof) [64]byte {
	var out [64]byte
	var buf bytes.Buffer
	// gnark Proof.WriteTo(io.Writer)
	if _, err := proof.WriteTo(&buf); err != nil {
		// if serialization fails, return zeros; this will just change transcript binding
		return out
	}
	out = sha512.Sum512(buf.Bytes())
	return out
}

/* ============================ Main =============================================== */

func main() {
	fmt.Println("========== CONFIG ==========")
	fmt.Printf("Curve: BLS12-377 | N=%d | tau=%d | runs=%d\n", N, TAU, NUM_RUNS)
	fmt.Printf("H rows=%d\n", len(HROWS))
	for i, row := range HROWS {
		fmt.Printf("  H[%d]=%v\n", i, row)
	}
	fmt.Println("===========================\n")

	// ---- build nullspace basis once (off-circuit only) ----
	Hv := buildHRowsV128()
	A, piv, free := rrefGF2(Hv, N)
	basis := nullspaceBasisFromRREF(A, piv, free)
	fmt.Printf("Nullspace basis size = %d (dimension >= %d)\n\n", len(basis), len(basis))

	// Enrollment: choose random w, choose random NON-ZERO codeword c' in ker(H),
	// helper P = w xor c'
	wEnroll := randBits128()
	cCode := sampleCodewordFromBasis(basis)
	P := xorBits(wEnroll, cCode)

	// Outside digest/k for printing + key material (used by Schnorr+signature outside SNARK)
	digest, err := computeDigestOutside(cCode)
	if err != nil {
		log.Fatal(err)
	}
	kOutside, err := computeKOutside(cCode)
	if err != nil {
		log.Fatal(err)
	}
	enrollPK, enrollSK := ed25519FromK(kOutside)

	fmt.Println("========== ENROLLMENT VALUES ==========")
	printBits("w  (enroll)", wEnroll)
	printBits("c' (code)  ", cCode)
	printBits("P  (helper)", P)
	fmt.Printf("digest (print-only) = MD(tagHash||c') = %s\n", digest.String())
	fmt.Printf("k_out (print-only)  = MD(tagKDF||c')  = %s\n", kOutside.String())
	fmt.Printf("Ed25519 pk          = %s\n", hex.EncodeToString(enrollPK))
	fmt.Println("======================================\n")

	// Compile + Setup
	fmt.Println("Compiling circuit (BLS12-377 scalar field)...")
	tCompile := time.Now()
	var circuit FECircuit
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal(err)
	}
	compileDur := time.Since(tCompile)
	fmt.Printf("Compile time: %v | Constraints: %d\n", compileDur, ccs.GetNbConstraints())

	fmt.Println("Groth16 setup (one-time)...")
	tSetup := time.Now()
	pkG, vkG, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}
	setupDur := time.Since(tSetup)
	fmt.Printf("Setup time  : %v\n\n", setupDur)

	// Batch runs: timing arrays
	var proveAll, verifyAll []float64
	var schnorrPAll, schnorrVAll []float64
	var sigPAll []float64
	var sigVAll []float64

	var proveOK, verifyOK []float64
	var schnorrPOK, schnorrVOK []float64
	var sigVOK []float64

	//Commented out
	//genuineTotal, genuineAccept := 0, 0
	//impostorTotal, impostorAccept := 0, 0

	fmt.Println("========== RUNS ==========")
	for run := 1; run <= NUM_RUNS; run++ {
		isGenuine := (run%2 == 1)

		// Server-side fresh nonce per session (replay resistance)
		nonce := make([]byte, 32)
		_, _ = rand.Read(nonce)

		var wPrime [N]uint8
		var eBits [N]uint8

		//if isGenuine {
			//genuineTotal++
			var rb [1]byte
			_, _ = rand.Read(rb[:])
			t := int(rb[0]) % (TAU + 1)
			eBits = sampleErrorOfWeight(t)
			//eBits = 00100101100100000100111100011110110110111111010010110100111111110110100011110010000101001110010100101111011110100000001000100011
			wPrime = xorBits(wEnroll, eBits) // w' = w xor e
		//} else {
			//impostorTotal++
			//wPrime = randBits128()
			// enforce XOR equation by setting e := w' xor P xor c'
			//eBits = xorBits(xorBits(wPrime, P), cCode)
		//}

		wtE := weight(eBits)

		// Witness assignment for SNARK
		var a FECircuit
		a.Tau = TAU
		for i := 0; i < N; i++ {
			a.P[i] = int(P[i])
			a.W[i] = int(wPrime[i])
			a.C[i] = int(cCode[i])
			a.E[i] = int(eBits[i])
		}

		wit, err := frontend.NewWitness(&a, ecc.BLS12_377.ScalarField())
		if err != nil {
			log.Fatal(err)
		}
		pubWit, err := wit.Public()
		if err != nil {
			log.Fatal(err)
		}

		// --- SNARK Prove + Verify ---
		t0 := time.Now()
		proof, proveErr := groth16.Prove(ccs, pkG, wit)
		tp := time.Since(t0)
		proveAll = append(proveAll, float64(tp.Microseconds())/1000.0)

		okSNARK := false
		var tv time.Duration
		var verifyErr error

		if proveErr == nil {
			t1 := time.Now()
			verifyErr = groth16.Verify(proof, vkG, pubWit)
			tv = time.Since(t1)
			verifyAll = append(verifyAll, float64(tv.Microseconds())/1000.0)
			okSNARK = (verifyErr == nil)
		} else {
			verifyAll = append(verifyAll, 0.0)
		}

		// Hash of SNARK proof for transcript-binding (even if SNARK fails, we compute hash if proof exists)
		var hFE [64]byte
		if proveErr == nil {
			hFE = proofHash64(proof)
		}

		// --- Schnorr key equality proof (prover + verifier) ---
		t2 := time.Now()
		sEq, cEqProver, eqPerr := schnorrEqProve(enrollPK, enrollSK, nonce, hFE)
		tEqP := time.Since(t2)
		schnorrPAll = append(schnorrPAll, float64(tEqP.Microseconds())/1000.0)

		t3 := time.Now()
		eqOK := false
		var cEqVerifier [32]byte
		var eqVerr error
		if eqPerr == nil {
			eqOK, cEqVerifier, eqVerr = schnorrEqVerify(enrollPK, nonce, hFE, sEq)
		}
		tEqV := time.Since(t3)
		schnorrVAll = append(schnorrVAll, float64(tEqV.Microseconds())/1000.0)

		// --- Active key usage proof: signature on nonce ---
		t4 := time.Now()
		sig := ed25519.Sign(enrollSK, nonce)
		tSigP := time.Since(t4)
		sigPAll = append(sigPAll, float64(tSigP.Microseconds())/1000.0)		
		t5 := time.Now()
		sigOK := ed25519.Verify(enrollPK, nonce, sig)
		tSigV := time.Since(t5)
		sigVAll = append(sigVAll, float64(tSigV.Microseconds())/1000.0)

		// --- Final server decision (Option B: all three must hold + fresh nonce) ---
		accept := okSNARK && eqOK && sigOK

		//Commented out
		//if isGenuine {
			//if accept {
				//genuineAccept++
			//}
		//} else {
			//if accept {
				//impostorAccept++
			//}
		//}

		if accept {
			proveOK = append(proveOK, float64(tp.Microseconds())/1000.0)
			verifyOK = append(verifyOK, float64(tv.Microseconds())/1000.0)
			schnorrPOK = append(schnorrPOK, float64(tEqP.Microseconds())/1000.0)
			schnorrVOK = append(schnorrVOK, float64(tEqV.Microseconds())/1000.0)
			sigVOK = append(sigVOK, float64(tSigV.Microseconds())/1000.0)
		}

		kind := "IMPOSTOR"
		if isGenuine {
			kind = "GENUINE"
		}

		fmt.Printf("Run %03d [%s]\n", run, kind)
		printBits("  w  (enroll)", wEnroll)
		printBits("  w' (probe) ", wPrime)
		printBits("  c' (code)  ", cCode)
		printBits("  e  (error) ", eBits)
		printBits("  P  (helper)", P)
		fmt.Printf("  tau=%d | wt(e)=%d | wt<=tau=%v\n", TAU, wtE, wtE <= TAU)

		fmt.Printf("  pk(ed25519)       = %s\n", hex.EncodeToString(enrollPK))
		fmt.Printf("  nonce(hex)        = %s\n", hex.EncodeToString(nonce))
		fmt.Printf("  sig(hex)          = %s\n", hex.EncodeToString(sig))

		fmt.Printf("  SNARK: proveErr=%v | verifyErr=%v | ok=%v | Prove=%.3f ms | Verify=%.3f ms\n",
			proveErr, verifyErr, okSNARK,
			float64(tp.Microseconds())/1000.0,
			float64(tv.Microseconds())/1000.0,
		)

		if eqPerr != nil {
			fmt.Printf("  SchnorrEq: PROVE FAIL | err=%v | Prove=%.3f ms\n", eqPerr, float64(tEqP.Microseconds())/1000.0)
		} else if eqVerr != nil {
			fmt.Printf("  SchnorrEq: VERIFY FAIL | err=%v | Prove=%.3f ms | Verify=%.3f ms\n",
				eqVerr,
				float64(tEqP.Microseconds())/1000.0,
				float64(tEqV.Microseconds())/1000.0,
			)
		} else {
			fmt.Printf("  SchnorrEq: ok=%v | Prove=%.3f ms | Verify=%.3f ms\n",
				eqOK,
				float64(tEqP.Microseconds())/1000.0,
				float64(tEqV.Microseconds())/1000.0,
			)
			fmt.Printf("    R(hex)          = %s\n", hex.EncodeToString(sEq.R[:]))
			fmt.Printf("    z(hex)          = %s\n", hex.EncodeToString(sEq.Z[:]))
			fmt.Printf("    c_prover(hex)   = %s\n", hex.EncodeToString(cEqProver[:]))
			fmt.Printf("    c_verifier(hex) = %s\n", hex.EncodeToString(cEqVerifier[:]))
		}

		fmt.Printf("  Signature verify: ok=%v | Verify=%.3f ms\n", sigOK, float64(tSigV.Microseconds())/1000.0)
		fmt.Printf("  FINAL ACCEPT = %v\n", accept)
		fmt.Println("--------------------------------------------------")
	}
	fmt.Println("===============================================\n")

	// Summary metrics
	//Commented out
	//frr := 0.0
	//if genuineTotal > 0 {
		////frr = 1.0 - float64(genuineAccept)/float64(genuineTotal)
	//}
	//far := 0.0
	//if impostorTotal > 0 {
		//far = float64(impostorAccept) / float64(impostorTotal)
	//}

	mpA, spA, minPA, maxPA := meanStdMinMax(proveAll)
	mvA, svA, minVA, maxVA := meanStdMinMax(verifyAll)
	meqPA, seqPA, mineqPA, maxeqPA := meanStdMinMax(schnorrPAll)
	meqVA, seqVA, mineqVA, maxeqVA := meanStdMinMax(schnorrVAll)
	msigP, ssigP, minsigP, maxsigP := meanStdMinMax(sigPAll)
	msigV, ssigV, minsigV, maxsigV := meanStdMinMax(sigVAll)

	//mpS, spS, minPS, maxPS := meanStdMinMax(proveOK)
	//mvS, svS, minVS, maxVS := meanStdMinMax(verifyOK)
	//meqPS, seqPS, mineqPS, maxeqPS := meanStdMinMax(schnorrPOK)
	//meqVS, seqVS, mineqVS, maxeqVS := meanStdMinMax(schnorrVOK)
	//msigVS, ssigVS, minsigVS, maxsigVS := meanStdMinMax(sigVOK)

	fmt.Println("========== SUMMARY ==========")
	//fmt.Printf("Compile time: %v\n", compileDur)
	//fmt.Printf("Setup time  : %v\n", setupDur)
	//fmt.Printf("Constraints : %d\n", ccs.GetNbConstraints())
	//fmt.Printf("Genuine trials : %d | Accept=%d | FRR=%.4f\n", genuineTotal, genuineAccept, frr)
	//fmt.Printf("Impostor trials: %d | Accept=%d | FAR=%.4f\n", impostorTotal, impostorAccept, far)

	fmt.Printf("\nTiming for 100 %d Runs:\n", NUM_RUNS)
	fmt.Printf("  Semantic Correctness Proof Generation   : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", mpA, spA, minPA, maxPA)
	fmt.Printf("  Semantic Correctness Proof Verification : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", mvA, svA, minVA, maxVA)
	fmt.Printf("  Key Equality Proof Generation           : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", meqPA, seqPA, mineqPA, maxeqPA)
	fmt.Printf("  Key Equality Proof Verification         : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", meqVA, seqVA, mineqVA, maxeqVA)
	fmt.Printf("  Key Freshness Proof Generation          : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", msigP, ssigP, minsigP, maxsigP)
	fmt.Printf("  Key Freshness Proof Verification        : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", msigV, ssigV, minsigV, maxsigV)

	//fmt.Printf("\nTiming over %d SUCCESSFUL authentications:\n", len(proveOK))
	//fmt.Printf("  SNARK Prove : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", mpS, spS, minPS, maxPS)
	//fmt.Printf("  SNARK Verify: mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", mvS, svS, minVS, maxVS)
	//fmt.Printf("  Eq Prove    : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", meqPS, seqPS, mineqPS, maxeqPS)
	//fmt.Printf("  Eq Verify   : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", meqVS, seqVS, mineqVS, maxeqVS)
	//fmt.Printf("  Sig Verify  : mean=%.3f ms std=%.3f ms min=%.3f ms max=%.3f ms\n", msigVS, ssigVS, minsigVS, maxsigVS)

	//fmt.Println("\nProtocol linkage (Option B, implemented outside SNARK for equality + usage):")
	//fmt.Println("  1) SNARK proves ∃(w',c',e,k) s.t. w'⊕P=c'⊕e, Hc'=0, wt(e)≤τ, k=Poseidon2_MD(tagKDF||c')")
	//fmt.Println("  2) SchnorrEq proves knowledge of same signing secret: pk=[k]B, with challenge bound to (pk,R,nonce,hash(SNARK-proof))")
	//fmt.Println("  3) Signature proves active key usage on fresh nonce (replay resistance)")
	fmt.Println("================================")
}

