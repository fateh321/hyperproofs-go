package main

import "C"
import (
	// "flag"
	"fmt"
	// "sync"
	// "testing"
	// "time"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/vcs"
	"github.com/hyperproofs/gipa-go/batch"
	"github.com/hyperproofs/gipa-go/cm"
// 	"bytes"
	"encoding/json"
// 	"encoding/binary"
)

// //VCS used to store proofs
// var vc = vcs.VCS{}
//
// //export initVc
// func initVc() int64{
// fmt.Println("Hello, go-World!")
// L := uint8(16)
// // N := uint64(1) << L
//
// K := 1024 // Number of transactions
// txnLimit := uint64(K)
// vc.KeyGenLoad(16, L, "/home/srisht/junk/shard/hyperproofs-go/pkvk-17", txnLimit)
// return 0
// }
//
// //the following function is supposed to update the proof tree and commit values once aggregation for the previous round is completed.
// //export updateShardProofTree
// func updateShardProofTree(address []uint64, []delta int64) int64 {
// // 	updateindex := uint64(10)
// // 	delta := int64(10)
// // 	var delta_f mcl.Fr
// 	delta_f.SetInt64(delta)
// 	vc.UpdateProofTree(address, delta_f)
// 	return 0
// }
//
// func pushAddressDelta(address uint64, delta int64){
// }
//
// func getShardCommitment() {
// }
//
// func getAggProof(address vec){
// }
//
// func verifyAggProof(proof) bool{
// }
// //export BenchmarkVCSCommit
// func BenchmarkVCSCommit() int64{
// 	L := uint8(17)
// 	txnLimit := uint64(1024)
// 	N := uint64(1) << L
// 	// K := txnLimit
// 	// vcs := vc.VCS{}
// 	vc.KeyGenLoad(16, L, "/home/srisht/junk/shard/hyperproofs-go/pkvk-17", txnLimit)
//
// 	aFr := vcs.GenerateVector(N)
// 	// dt := time.Now()
// 	vc.Commit(aFr, uint64(L))
// 	// duration := time.Since(dt)
// 	// out := fmt.Sprintf("BenchmarkVCS/%d/Commit;%d%40d ns/op", L, txnLimit, duration.Nanoseconds())
// 	// fmt.Println(vc.SEP)
// 	// fmt.Println(out)
// 	// fmt.Println(vc.SEP)
// 	// return out
// 	return 0
//
// }
type SerialSingleProof struct {
    proof [][]byte
}
func SerializeSingleProof(input []mcl.G1) SerialSingleProof{
    output := SerialSingleProof {}
    len := len(input)
    proof := make([][]byte,len)
    for i:=0; i<len; i++{
        proof[i] = input[i].Serialize()
    }
    output.proof = proof
    return output
}

func DeserializeSingleProof(input SerialSingleProof) ([]mcl.G1, error){
        len := len(input.proof)
        output := make([]mcl.G1, len)
        for i:=0; i<len; i++{
            err := output[i].Deserialize(input.proof[i])
            if err != nil {
                return output,err
            }
        }
        return output, nil
}
type SerialBatchProof struct {
    T []byte
    GipaKzgProofL [][][]byte
    GipaKzgProofR [][][]byte
    GipaKzgProofA  []byte
    GipaKzgProofB  []byte
    GipaKzgProofW  []byte
    GipaKzgProofV  []byte
    GipaKzgProofPi1  []byte
    GipaKzgProofPi2  []byte
}
func SerializeBatchProof (input batch.Proof) SerialBatchProof{
    output := SerialBatchProof {}
    T := input.T.Serialize()
    lenL := len(input.GipaKzgProof.L)
    L := make ([][][]byte, lenL)
    for i:=0; i<lenL; i++{
        L[i] = make([][]byte, 3)
        for j:=0; j<3; j++ {
            L[i][j] = input.GipaKzgProof.L[i].Com[j].Serialize()
        }
    }
    lenR := len(input.GipaKzgProof.R)
        R := make ([][][]byte, lenR)
        for i:=0; i<lenR; i++{
            R[i] = make([][]byte, 3)
            for j:=0; j<3; j++ {
                R[i][j] = input.GipaKzgProof.R[i].Com[j].Serialize()
            }
        }
    A := input.GipaKzgProof.A[0].Serialize()
    B := input.GipaKzgProof.B[0].Serialize()
    W := input.GipaKzgProof.W.Serialize()
    V := input.GipaKzgProof.V.Serialize()
    Pi1 := input.GipaKzgProof.Pi1.Serialize()
    Pi2 := input.GipaKzgProof.Pi2.Serialize()

    output.T = T
    output.GipaKzgProofL = L
    output.GipaKzgProofR = R
    output.GipaKzgProofA = A
    output.GipaKzgProofB = B
    output.GipaKzgProofW = W
    output.GipaKzgProofV = V
    output.GipaKzgProofPi1 = Pi1
    output.GipaKzgProofPi2 = Pi2
    return output
}

func DeserializeBatchProof(input SerialBatchProof) (batch.Proof, error){
    output := batch.Proof{}
    var T mcl.GT
    err := T.Deserialize(input.T)
    if err == nil {
        output.T = T
    } else {
    fmt.Println("oops, error while deserialising", err)
    return  output,err
    }

    lenL := len(input.GipaKzgProofL)
    L := make([]cm.Com, lenL)
    for i:=0; i<lenL; i++{
        for j:=0; j<3; j++ {
            err = L[i].Com[j].Deserialize(input.GipaKzgProofL[i][j])
            if err != nil {
                return output,err
            }
        }
    }
    output.GipaKzgProof.L = L

    lenR := len(input.GipaKzgProofR)
    R := make([]cm.Com, lenR)
    for i:=0; i<lenR; i++{
        for j:=0; j<3; j++ {
            err = R[i].Com[j].Deserialize(input.GipaKzgProofR[i][j])
            if err != nil {
                return output,err
            }
        }
    }
    output.GipaKzgProof.R = R

    var A [1]mcl.G1
    err = A[0].Deserialize(input.GipaKzgProofA)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.A = A

    var B [1]mcl.G2
    err = B[0].Deserialize(input.GipaKzgProofB)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.B = B

    var W mcl.G1
    err = W.Deserialize(input.GipaKzgProofW)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.W = W

    var V mcl.G2
    err = V.Deserialize(input.GipaKzgProofV)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.V = V

    var Pi1 mcl.G1
    err = Pi1.Deserialize(input.GipaKzgProofPi1)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.Pi1 = Pi1

    var Pi2 mcl.G2
    err = Pi2.Deserialize(input.GipaKzgProofPi2)
    if err != nil {
        return output,err
    }
    output.GipaKzgProof.Pi2 = Pi2

    return output,nil

}
func main1() {
    fmt.Println("Hello, go-World!")
    var vc = vcs.VCS{}
    L := uint8(22)
    // N := uint64(1) << L

    K := 1024 // Number of transactions
    txnLimit := uint64(K)
    vc.KeyGenLoad(16, L, "/home/srisht/libhyper/hyperproofs-go/pkvk-22", txnLimit)
    a := make([]mcl.Fr, vc.N)
    x := int64(0)
    var x_f mcl.Fr
    x_f.SetInt64(x)
    fmt.Println("array is empty",a[1].IsEqual(&x_f))
    vc.OpenAll(a)
    digest := vc.Commit(a, uint64(vc.L))
//     fmt.Println("can we retrieve commitment",digest.IsEqual(&vc.ProofTree[1][0]))

//     updateindex := uint64(10)
//     delta := int64(10)
    digestVec := make([]mcl.G1, K+1)
    digestVec[0]=digest
    updateindex := make([]uint64,K)
    delta := make([]int64,K)
    delta_f := make([]mcl.Fr,K)
    updateindex2 := make([]uint64,K)
    delta2 := make([]int64,K)
    delta_f2 := make([]mcl.Fr,K)
    proofVec := make([][]mcl.G1, K)

    for i := 0; i<K; i++{
        updateindex[i] = uint64(i)
        updateindex2[i] = uint64(0)
        delta[i] = int64(i)
        delta2[i] = int64(0)
        delta_f[i].SetInt64(delta[i])
        delta_f2[i].SetInt64(delta2[i])
        vc.UpdateProofTree(updateindex[i], delta_f[i])
        digestVec[i+1] = vc.UpdateCom(digestVec[i], updateindex[i], delta_f[i])
//         proofVec[i] = vc.GetProofPath(updateindex[i])
    }

//     vc.UpdateProofTreeBulk(updateindex, delta_f)
//     digest = vc.UpdateComVec(digest, updateindex, delta_f)

    for i := 0; i<K; i++{
        proofVec[i] = vc.GetProofPath(updateindex2[0])
    }

//     delta_f.SetInt64(delta)
//     vc.UpdateProofTree(updateindex, delta_f)
//     digest = vc.UpdateCom(digest, updateindex, delta_f)

//     fmt.Println("can we retrieve commitment",digest.IsEqual(&vc.ProofTree[0][0]))
//     fmt.Println("can we use commitment",vc.Verify(digest, updateindex, delta_f, vc.GetProofPath(updateindex)))
//     updateindex2 := uint64(13)
//     delta2 := int64(13)
//     var delta_f2 mcl.Fr
//     delta_f2.SetInt64(delta2)
//     vc.UpdateProofTree(updateindex2, delta_f2)

//     digest = vc.UpdateCom(digest, updateindex2, delta_f2)
//     digestTemp := digest
//     fmt.Println("can we retrieve commitment",digest.IsEqual(&vc.ProofTree[0][0]))
//     fmt.Println("can we use commitment 2",vc.Verify(digest, updateindex2, delta_f2, vc.GetProofPath(updateindex2)))


//     df := make([]mcl.Fr, 2)
//     ui := make([]uint64, 2)
//     pv := make([][]mcl.G1, 2)
//     df[0] = delta_f
//     df[1] = delta_f2
//     ui[0] = updateindex
//     ui[1] = updateindex2
//     pv[0] = vc.GetProofPath(updateindex)
//     pv[1] = vc.GetProofPath(updateindex2)
//     digestVec = append(digestVec[:0], digestVec[1:]...)
    aggProof := vc.AggProve(updateindex2, proofVec)
    // var wg sync.WaitGroup
    // wg.Add(1)
    // var result bool
    // go func(){
    //     result = vc.AggVerify(aggProof, digestVec[K], updateindex2, delta_f2)
    //     defer wg.Done()
    // }()
    // var aggProof2 batch.Proof
    // wg.Add(1)
    // go func(){
    //     aggProof2 = vc.AggProve(updateindex2, proofVec)
    //     defer wg.Done()
    // }()

    // wg.Wait()
    // result2 := vc.AggVerify(aggProof2, digestVec[K], updateindex2, delta_f2)
    // fmt.Println("verify before:",result, result2)

    b := SerializeBatchProof(aggProof)
    bj, errj := json.Marshal(b)
    if errj != nil {
        fmt.Println("fuck1",errj)
    }
    fmt.Println("length of proof is",len(bj))
//     dec := gob.NewDecoder(&network)
    // var xxj SerialBatchProof

    // errj = json.Unmarshal(bj, &xxj)

    // xx, err := DeserializeBatchProof(xxj)
    // if err != nil {
    //     fmt.Println("fuck2",err)
    // }
    // fmt.Println("verify after:",vc.AggVerify(xx, digestVec[K], updateindex2, delta_f2))
}

func main2(){
    fmt.Println("Hello, go-World!")
    var vc = vcs.VCS{}
    L := uint8(18)
    // N := uint64(1) << L

    K := 256 // Number of transactions
    txnLimit := uint64(K)
    vc.KeyGenLoad(16, L, "/home/srisht/junk/shard/hyperproofs-go/pkvk-18", txnLimit)
    a := make([]mcl.Fr, vc.N)
    x := int64(0)
    var x_f mcl.Fr
    x_f.SetInt64(x)
    fmt.Println("array is empty",a[1].IsEqual(&x_f))
    vc.OpenAll(a)
//     digest := vc.Commit(a, 16)
//     fmt.Println("can we retrieve commitment",digest.IsEqual(&vc.ProofTree[1][0]))

//     updateindex := uint64(10)
//     delta := int64(9)
//     var delta_f2 mcl.Fr
//     delta_f2.SetInt64(delta)
//     b := make([]byte,32)
//     binary.LittleEndian.PutUint64(b, uint64(120000000))
//     b := []byte{12,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}
//     var delta_f mcl.Fr

//     delta_f.SetInt64(delta)
//     delta_f.SetLittleEndian(b)
//     mcl.FrAdd(&delta_f,&delta_f2,&delta_f)
//     st := delta_f.GetString(10)
//     fmt.Println(st)
//     fmt.Println(b)
//     updateindex := make([]uint64,K)
//     delta := make([]int64,K)
//     delta_f := make([]mcl.Fr,K)
//     updateindex2 := make([]uint64,K)
//     delta2 := make([]int64,K)
//     delta_f2 := make([]mcl.Fr,K)
//     proofVec := make([][]mcl.G1, K)
//
}

func main(){
    fmt.Println("Hello, go-World!")
    var vc = vcs.VCS{}
    L := uint8(24)
    // N := uint64(1) << L

    K := 2048 // Number of transactions
    txnLimit := uint64(K)
    vc.KeyGenLoad(16, L, "/data/ubuntu/libhyper/hyperproofs-go/pkvk-18", txnLimit)
    a := make([]mcl.Fr, vc.N)
    for i := 0; i<int(vc.N); i++{
        x := int64(100000000)
        var x_f mcl.Fr
        x_f.SetInt64(x)
        a[i] = x_f
    }
    vc.OpenAll(a)
    digest := vc.Commit(a, 16)
    proof := vc.GetProofPath(uint64(3))
    serialSingleProof := SerializeSingleProof(proof)
    byteSingleProof, err := json.Marshal(serialSingleProof)
    if err != nil {
        fmt.Println("fuck1",err)
    }
    fmt.Println("length of single proof is",len(byteSingleProof))
    var decodeSingleProofByte SerialSingleProof
    err = json.Unmarshal(byteSingleProof, &decodeSingleProofByte)
    decodeSingleProof, err1 := DeserializeSingleProof(decodeSingleProofByte)
    if err1 != nil {
        fmt.Println("fuck2",err1)
    }
    x := int64(100000000)
    var x_f mcl.Fr
    x_f.SetInt64(x)
    fmt.Println("verifying single proof:",vc.Verify(digest, uint64(3), x_f, decodeSingleProof))
    updateindex:= make([]uint64,2048)
    proofVec := make([][]mcl.G1, K)
    for i := 0; i<K; i++{
        updateindex[i] = uint64(i)
        proofVec[i] = vc.GetProofPath(updateindex[i])
    }
    aggProof := vc.AggProve(updateindex, proofVec)
    b := SerializeBatchProof(aggProof)
    bj, errj := json.Marshal(b)
    if errj != nil {
        fmt.Println("fuck1",errj)
    }
    fmt.Println("length of proof is",len(bj))

}