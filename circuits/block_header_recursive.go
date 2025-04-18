package circuits

import (
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/readygo67/BlockHeaderProver/utils"
	"math/big"
)

type BlockHeaderRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	BeginHash Hash `gnark:",public"`
	RelayHash Hash
	EndHash   Hash `gnark:",public"`

	FirstVk      plonk.VerifyingKey[FR, G1El, G2El]
	FirstProof   plonk.Proof[FR, G1El, G2El]
	FirstWitness plonk.Witness[FR]

	SecondVk      plonk.VerifyingKey[FR, G1El, G2El]
	SecondProof   plonk.Proof[FR, G1El, G2El]
	SecondWitness plonk.Witness[FR]

	RecursiveVkFp utils.FingerPrint[FR] `gnark:",public"`
	UnitVkFpBytes utils.FingerPrintBytes
}

func (c *BlockHeaderRecursiveCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	// check fingerprints
	{
		uintVkFp := utils.FingerPrintFromBytes[FR](c.UnitVkFpBytes)
		firstVkFp, err := utils.InCircuitFingerPrint[FR, G1El, G2El](api, &c.FirstVk)
		if err != nil {
			return err
		}
		vkFpInFirstWitness := RetrieveU254ValueFromElement[FR](api, c.FirstWitness.Public[64])
		api.AssertIsEqual(firstVkFp, vkFpInFirstWitness) //check the first

		isFirstVkRecursive := api.IsZero(api.Sub(firstVkFp, c.RecursiveVkFp.Val))
		isFirstVkUnit := api.IsZero(api.Sub(firstVkFp, uintVkFp.Val))
		api.Println("is first vk recursive", isFirstVkRecursive)
		api.Println("is first vk unit", isFirstVkUnit)
		api.AssertIsEqual(api.Add(isFirstVkRecursive, isFirstVkUnit), 1) //firstVk must be one of {recursive, unit}

		//second vk must be unit
		secondVkFp, err := utils.InCircuitFingerPrint[FR, G1El, G2El](api, &c.SecondVk)
		isSecondVkUnit := api.IsZero(api.Sub(secondVkFp, uintVkFp.Val))
		api.AssertIsEqual(isSecondVkUnit, 1)
	}

	//check proofs
	{
		verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
		if err != nil {
			return err
		}

		err = verifier.AssertProof(c.FirstVk, c.FirstProof, c.FirstWitness, plonk.WithCompleteArithmetic())
		if err != nil {
			return err
		}

		err = verifier.AssertProof(c.SecondVk, c.SecondProof, c.SecondWitness, plonk.WithCompleteArithmetic())
		if err != nil {
			return err
		}
	}

	//check relation
	{
		//c.BeginHash == firstWitness.BeginHash
		for i := 0; i < HashLen; i++ {
			api.AssertIsEqual(c.BeginHash[i].Val, c.FirstWitness.Public[i].Limbs[0])
		}

		//c.RelayHash == firstWitness.EndHash == secondWitness.BeginHash
		for i := 0; i < HashLen; i++ {
			api.AssertIsEqual(c.RelayHash[i].Val, c.FirstWitness.Public[HashLen+i].Limbs[0])
			api.AssertIsEqual(c.RelayHash[i].Val, c.SecondWitness.Public[i].Limbs[0])
		}

		//c.EndHash == secondWitness.EndHash
		for i := 0; i < HashLen; i++ {
			api.AssertIsEqual(c.EndHash[i].Val, c.SecondWitness.Public[HashLen+i].Limbs[0])
		}
	}

	return nil
}

func NewBlockHeaderRecursiveCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	unitCcs constraint.ConstraintSystem,
	unitVkFpBytes utils.FingerPrintBytes,
) frontend.Circuit {
	return &BlockHeaderRecursiveCircuit[FR, G1El, G2El, GtEl]{
		FirstVk:      plonk.PlaceholderVerifyingKey[FR, G1El, G2El](unitCcs),
		FirstProof:   plonk.PlaceholderProof[FR, G1El, G2El](unitCcs),
		FirstWitness: plonk.PlaceholderWitness[FR](unitCcs),

		SecondVk:      plonk.PlaceholderVerifyingKey[FR, G1El, G2El](unitCcs),
		SecondProof:   plonk.PlaceholderProof[FR, G1El, G2El](unitCcs),
		SecondWitness: plonk.PlaceholderWitness[FR](unitCcs),

		UnitVkFpBytes: unitVkFpBytes,
	}
}

func NewBlockHeaderRecursiveAssignment[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	firstVk, secondVk native_plonk.VerifyingKey,
	firstProof, secondProof native_plonk.Proof,
	firstWitness, secondWitness witness.Witness,

	recursiveVkFp utils.FingerPrint[FR],
	beginHash [HashLen]byte,
	relayHash [HashLen]byte,
	endHash [HashLen]byte,
) (frontend.Circuit, error) {
	_firstVk, err := plonk.ValueOfVerifyingKey[FR, G1El, G2El](firstVk)
	if err != nil {
		return nil, err
	}
	_secondVk, err := plonk.ValueOfVerifyingKey[FR, G1El, G2El](secondVk)
	if err != nil {
		return nil, err
	}

	_firstProof, err := plonk.ValueOfProof[FR, G1El, G2El](firstProof)
	if err != nil {
		return nil, err
	}

	_secondProof, err := plonk.ValueOfProof[FR, G1El, G2El](secondProof)
	if err != nil {
		return nil, err
	}
	_firstWitness, err := plonk.ValueOfWitness[FR](firstWitness)
	if err != nil {
		return nil, err
	}
	_secondWitness, err := plonk.ValueOfWitness[FR](secondWitness)
	if err != nil {
		return nil, err
	}

	_beginHash := Hash{}
	for i := 0; i < HashLen; i++ {
		_beginHash[i] = uints.NewU8(beginHash[i])
	}
	_relayHash := Hash{}
	for i := 0; i < HashLen; i++ {
		_relayHash[i] = uints.NewU8(relayHash[i])
	}
	_endHash := Hash{}
	for i := 0; i < HashLen; i++ {
		_endHash[i] = uints.NewU8(endHash[i])
	}

	return &BlockHeaderRecursiveCircuit[FR, G1El, G2El, GtEl]{
		BeginHash:     _beginHash,
		RelayHash:     _relayHash,
		EndHash:       _endHash,
		FirstVk:       _firstVk,
		FirstProof:    _firstProof,
		FirstWitness:  _firstWitness,
		SecondVk:      _secondVk,
		SecondProof:   _secondProof,
		SecondWitness: _secondWitness,
		RecursiveVkFp: recursiveVkFp,
	}, nil
}

func RetrieveU254ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	rs := RetrieveVarsFromElements(api, []emulated.Element[FR]{e})
	r := rs[0]

	var fr FR
	if fr.Modulus().BitLen() > 254 {
		rcheck := rangecheck.New(api)
		rcheck.Check(r, 254)
	}

	return r
}

func RetrieveVarsFromElements[FR emulated.FieldParams](
	api frontend.API, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) []frontend.Variable {
	var fr FR
	bitsPerLimb := int(fr.BitsPerLimb())

	var maxBits int
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = fr.Modulus().BitLen()
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	n := len(witnessValues)
	for i := 0; i < n; i++ {
		nbLimbs := len(witnessValues[i].Limbs)
		for j := nbEffectiveLimbs; j < nbLimbs; j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	rst := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		rst[i] = composed
	}

	return rst
}
