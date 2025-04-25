package main

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/lightec-xyz/common/operations"
	"github.com/readygo67/BlockHeaderProver/circuits"
	"github.com/readygo67/BlockHeaderProver/utils"
)

var (
	_headers = []string{
		"01000000b5fbf970bf362cc3203d71022d0764ce966a9d5cee7615354e273624000000008c209cca50575be7aad6faf11c26af9d91fc91f9bf953c1e7d4fca44e44be3fa3d286f49ffff001d2e18e5ed",
		"010000003c668f799ca5472fd05b8d43c574469fbec46ae3ffec010cdf6ee31100000000a97c6e691b813753248aa4614e4d3a34a3d1471e6ad863a392ccf4687d857a30f92b6f49ffff001d22239e3b",
		"010000001588b0752fb18960bf8b1728964d091b638e35e3a2c9ed32991da8c300000000cf18302909e57a7687e38d109ff19d01e85fd0f5517ffe821055765193ca51da162f6f49ffff001d16a2ddc4",
	}

	unitCcsFile      = "../testdata/block_header_unit.ccs"
	unitPkFile       = "../testdata/block_header_unit.pk"
	unitVkFile       = "../testdata/block_header_unit.vk"
	recursiveCcsFile = "../testdata/block_header_recursive.ccs"
	recursivePkFile  = "../testdata/block_header_recursive.pk"
	recursiveVkFile  = "../testdata/block_header_recursive.vk"
	toxicValue       = []byte{05, 06, 07} //seed for srs
)

func main() {
	err := setupUnit()
	if err != nil {
		panic(err)
	}

	err = setupRecursive()
	if err != nil {
		panic(err)
	}

	unitProofs, unitWitness, err := buildUnitProofs()
	if err != nil {
		panic(err)
	}

	_, _, err = buildRecursiveProof(unitProofs, unitWitness)
	if err != nil {
		panic(err)
	}

}

func setupUnit() error {
	circuit := circuits.NewBlockHeaderUnitCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]()
	ccs, err := operations.NewConstraintSystem(circuit)
	if err != nil {
		return err
	}
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	srs, lsrs, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed(toxicValue))
	if err != nil {
		return err
	}

	pk, vk, err := operations.PlonkSetup(ccs, &srs, &lsrs)
	if err != nil {
		return err
	}

	err = operations.WriteCcs(ccs, unitCcsFile)
	if err != nil {
		return err
	}
	err = operations.WritePk(pk, unitPkFile)
	if err != nil {
		return err
	}
	err = operations.WriteVk(vk, unitVkFile)
	if err != nil {
		return err
	}

	_, err = utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	if err != nil {
		return err
	}

	fmt.Printf("successfully setup block_header_unit circuit\n")
	return nil
}

func setupRecursive() error {
	unitCcs, err := operations.ReadCcs(unitCcsFile)
	if err != nil {
		return err
	}

	unitVk, err := operations.ReadVk(unitVkFile)
	if err != nil {
		return err
	}

	unitVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](unitVk)
	if err != nil {
		return err
	}

	circuit := circuits.NewBlockHeaderRecursiveCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitCcs,
		unitVkFpBytes,
	)

	ccs, err := operations.NewConstraintSystem(circuit)
	if err != nil {
		return err
	}
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	srs, lsrs, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed(toxicValue))
	if err != nil {
		return err
	}

	pk, vk, err := operations.PlonkSetup(ccs, &srs, &lsrs)
	if err != nil {
		return err
	}

	err = operations.WriteCcs(ccs, recursiveCcsFile)
	if err != nil {
		return err
	}
	err = operations.WritePk(pk, recursivePkFile)
	if err != nil {
		return err
	}
	err = operations.WriteVk(vk, recursiveVkFile)
	if err != nil {
		return err
	}
	fmt.Printf("successfully setup block_header_recursive circuit\n")
	return nil
}

func buildUnitProofs() ([]native_plonk.Proof, []witness.Witness, error) {
	headers := make([][]byte, len(_headers))
	hashes := make([][32]byte, len(_headers))

	proofs := make([]native_plonk.Proof, len(_headers))
	witness := make([]witness.Witness, len(_headers))

	for i, h := range _headers {
		headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(headers[i])
	}

	ccs, err := operations.ReadCcs(unitCcsFile)
	if err != nil {
		return nil, nil, err
	}

	pk, err := operations.ReadPk(unitPkFile)
	if err != nil {
		return nil, nil, err
	}

	vk, err := operations.ReadVk(unitVkFile)
	if err != nil {
		return nil, nil, err
	}

	vkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](vk)
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < len(headers); i++ {
		assignment := circuits.NewBlockHeaderUnitAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](hashes[i], [80]byte(headers[i]), vkFpBytes)
		proof, wit, err := operations.PlonkProve(ccs, pk, assignment, false)
		if err != nil {
			return nil, nil, err
		}

		err = operations.PlonkVerify(vk, proof, wit, false)
		if err != nil {
			return nil, nil, err
		}

		proofFile := fmt.Sprintf("../testdata/block_header_unit_%v_%v.proof", i, i+1)
		witnessFile := fmt.Sprintf("../testdata/block_header_unit_%v_%v.wtns", i, i+1)

		err = operations.WriteProof(proof, proofFile)
		if err != nil {
			panic(err)
		}
		err = operations.WriteWitness(wit, witnessFile)
		if err != nil {
			panic(err)
		}

		proofs[i] = proof
		witness[i] = wit

	}
	return proofs, witness, nil
}

func buildRecursiveProof(unitProofs []native_plonk.Proof, unitWitnesses []witness.Witness) (native_plonk.Proof, witness.Witness, error) {
	//Build the first recursive proof
	headers := make([][]byte, len(_headers))
	hashes := make([][32]byte, len(_headers))

	recursiveProofs := []native_plonk.Proof{}
	recursiveWitnesses := []witness.Witness{}

	for i, h := range _headers {
		headers[i], _ = hex.DecodeString(h)
		hashes[i] = chainhash.DoubleHashH(headers[i])
	}
	beginHash := [32]byte(headers[0][4:36])

	unitVk, err := operations.ReadVk(unitVkFile)
	if err != nil {
		return nil, nil, err
	}

	recursiveVk, err := operations.ReadVk(recursiveVkFile)
	if err != nil {
		return nil, nil, err
	}

	recursiveVkFpBytes, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](recursiveVk)
	if err != nil {
		return nil, nil, err
	}

	recursiveVkFp := utils.FingerPrintFromBytes[sw_bn254.ScalarField](recursiveVkFpBytes)

	assignment, err := circuits.NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
		unitVk, unitVk,
		unitProofs[0], unitProofs[1],
		unitWitnesses[0], unitWitnesses[1],
		recursiveVkFp,
		beginHash,
		hashes[0],
		hashes[1],
	)

	recursiveCcs, err := operations.ReadCcs(recursiveCcsFile)
	if err != nil {
		return nil, nil, err
	}

	recursivePk, err := operations.ReadPk(recursivePkFile)
	if err != nil {
		return nil, nil, err
	}

	proof, witness, err := operations.PlonkProve(recursiveCcs, recursivePk, assignment, false)
	if err != nil {
		return nil, nil, err
	}

	err = operations.PlonkVerify(recursiveVk, proof, witness, false)
	if err != nil {
		return nil, nil, err
	}

	recursiveProofs = append(recursiveProofs, proof)
	recursiveWitnesses = append(recursiveWitnesses, witness)

	for i := 2; i < len(_headers); i++ {
		assignment, err = circuits.NewBlockHeaderRecursiveAssignment[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](
			recursiveVk, unitVk,
			recursiveProofs[i-2], unitProofs[i],
			recursiveWitnesses[i-2], unitWitnesses[i],
			recursiveVkFp,
			beginHash,
			hashes[i-1],
			hashes[i],
		)

		proof, witness, err = operations.PlonkProve(recursiveCcs, recursivePk, assignment, false)
		if err != nil {
			return nil, nil, err
		}

		err = operations.PlonkVerify(recursiveVk, proof, witness, false)
		if err != nil {
			return nil, nil, err
		}

		recursiveProofs = append(recursiveProofs, proof)
		recursiveWitnesses = append(recursiveWitnesses, witness)

	}

	return recursiveProofs[len(recursiveProofs)-1], recursiveWitnesses[len(recursiveWitnesses)-1], nil

}
