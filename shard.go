package main

import "C"
import (
	// "flag"
	"fmt"
	// "testing"
	// "time"

	"github.com/alinush/go-mcl"
	"github.com/hyperproofs/hyperproofs-go/vcs"
	"github.com/hyperproofs/gipa-go/batch"
    "github.com/hyperproofs/gipa-go/cm"
    "encoding/json"
)


//VCS used to store proofs
var vc = vcs.VCS{}
var shardNum = uint64(4)
var beginRound uint64
var digest = make([]map[uint64]mcl.G1, shardNum)
var prevDigest = make([]mcl.G1, shardNum)
// var prePrevDigest = make([]mcl.G1, shardNum)
// these two slices should be of same length for every shard
var addressBuffer = make([][]uint64, shardNum)
var deltaBuffer = make([][]mcl.Fr, shardNum)

var addressBuffer2 []uint64
var deltaBuffer2 []mcl.Fr

//this slice keeps track of the addresses and balances for which we have to create and submit AggProof
var addressCommitBuffer = make([][]uint64, shardNum)
// var balanceCommitBuffer = make([][]mcl.Fr, shardNum)

var verifyAddressBuffer = make([][]uint64, shardNum)
var verifyBalanceBuffer = make([][]mcl.Fr, shardNum)

//export initVc
func initVc(round uint64) int64{
    beginRound = round
    fmt.Println("Hello, go-World!")
    L := uint8(18)
    // N := uint64(1) << L

    K := 256 // Number of transactions, ideally 1024
    txnLimit := uint64(K)
    vc.KeyGenLoad(16, L, "/home/srisht/libhyper/hyperproofs-go/pkvk-18", txnLimit)
    a := make([]mcl.Fr, vc.N)
    vc.OpenAll(a)
    for i := uint64(0); i < shardNum; i++ {
        digest[i] = make(map[uint64]mcl.G1)
        digest[i][round] = vc.Commit(a, uint64(vc.L))
        prevDigest[i] = digest[i][round]
        // prevPrevDigest[i] = digest[i][round]
    }

    return 0
}

//export prevDigestResetVc
func prevDigestResetVc() int64{
    for i := uint64(0); i < shardNum; i++ {
        prevDigest[i] = digest[i][uint64(0)]
        // prevPrevDigest[i] = digest[i][uint64(0)]
    }

    return 0
}

//export pushAddressDeltaVc
func pushAddressDeltaVc(address uint64, deltaString string, shard uint64) int64{
    // delta := []byte(deltaString)
    var delta_f mcl.Fr
    // fmt.Println("byte version looks like", []byte(uint64(12)))
    delta_f.SetString(deltaString, 10)
    if !delta_f.IsZero(){
        addressBuffer[shard] = append(addressBuffer[shard], address)
        deltaBuffer[shard] = append(deltaBuffer[shard], delta_f)    
    }
    
    return 0
}

//export resetAddressDeltaVc
func resetAddressDeltaVc(shard uint64) int64{
    addressBuffer[shard] = nil
    deltaBuffer[shard] = nil
    return 0
}

//export pushAddressCommitVc
func pushAddressCommitVc(address uint64, shard uint64) int64{
    addressCommitBuffer[shard] = append(addressCommitBuffer[shard], address)
    return 0
}

//export resetAddressCommitVc
func resetAddressCommitVc(shard uint64) int64{
    addressCommitBuffer[shard] = nil
    return 0
}

//export pushAddressBalanceVerifyVc
func pushAddressBalanceVerifyVc(address uint64, balanceString string, shard uint64) int64{
    // balance := []byte(balanceString)
    var balance_f mcl.Fr
    balance_f.SetString(balanceString,10)
    verifyBalanceBuffer[shard] = append(verifyBalanceBuffer[shard], balance_f)
    verifyAddressBuffer[shard] = append(verifyAddressBuffer[shard], address)
    return 0
}
//export resetAddressBalanceVerifyVc
func resetAddressBalanceVerifyVc(shard uint64) int64{
    verifyBalanceBuffer[shard] = nil
    verifyAddressBuffer[shard] = nil
    return 0
}
//export aggVc
func aggVc(nativeShard uint64) (*C.char, bool){
    fmt.Println("Aggregation started")
    x, y := AggAndExport(nativeShard)
    return x,y
}

// internal function
func AggAndExport(nativeShard uint64)(*C.char, bool){
    var output []byte

    K := uint64(len(addressCommitBuffer[nativeShard]))
    fmt.Println("the value of addressCommitBuffer is",K)
    if K > vc.TxnLimit{
        addressCommitBuffer[nativeShard] = nil
        fmt.Println("transactions exceed limit!")
        return C.CString(string(output)), false
    }

    proofVec := make([][]mcl.G1, vc.TxnLimit)
    //add the required proofs. If K < txnLimit, pad with dummy proofs
    for i := uint64(0); i<vc.TxnLimit; i++{
        if i < K {
            proofVec[i] = vc.GetProofPath(addressCommitBuffer[nativeShard][i])
        } else {
            proofVec[i] = vc.GetProofPath(uint64(5))
            addressCommitBuffer[nativeShard] = append(addressCommitBuffer[nativeShard], uint64(5))
        }

    }


    aggProof := vc.AggProve(addressCommitBuffer[nativeShard], proofVec)
    serialAggProof := SerializeBatchProof(aggProof)
    byteAggProof, err := json.Marshal(serialAggProof)
    addressCommitBuffer[nativeShard] = nil
    if err != nil {
        fmt.Println("Serialisation of aggregated proof failed",err)
        return C.CString(string(output)), false
    }
    return C.CString(string(byteAggProof)), true

}
//export commitVc
func commitVc(nativeShard uint64, round uint64)int64{
    // updateShardProofTree(nativeShard)
    updateDigest(nativeShard, round)
    return 0
}

//export updateShardProofTreeVc
func updateShardProofTreeVc(nativeShard uint64)int64{
    fmt.Println("yello")
    updateShardProofTree(nativeShard)
    return 0
}

//export verifyProofVc
func verifyProofVc (proofString string, shard uint64, round uint64) bool {
    proof := []byte(proofString)
    if len(verifyAddressBuffer[shard])!= len(verifyBalanceBuffer[shard]) {
        fmt.Println("verify buffers length not equal")
        verifyAddressBuffer[shard] = nil
        verifyBalanceBuffer[shard] = nil
        return false
    }

    K := uint64(len(verifyAddressBuffer[shard]))

    if K > vc.TxnLimit {
     fmt.Println("verify buffers length exceeding limit")
     verifyAddressBuffer[shard] = nil
     verifyBalanceBuffer[shard] = nil
     return false
    }
    var tempProof SerialBatchProof

    errj := json.Unmarshal(proof, &tempProof)

    finalProof, err := DeserializeBatchProof(tempProof)
    if err != nil || errj != nil {
        fmt.Println("Deserialization falied during verification",err)
        verifyAddressBuffer[shard] = nil
        verifyBalanceBuffer[shard] = nil
        return false
    }
    for i := K; i<vc.TxnLimit; i++{
        // temp := []byte("1")
        var temp_f mcl.Fr
        temp_f.SetInt64(int64(0))
        verifyAddressBuffer[shard] = append(verifyAddressBuffer[shard],uint64(5))
        verifyBalanceBuffer[shard] = append(verifyBalanceBuffer[shard],temp_f)

    }
    fmt.Println("verify address buffer is",verifyAddressBuffer[shard])
    fmt.Println("verify balance buffer is",verifyBalanceBuffer[shard])
    result := vc.AggVerify(finalProof, prevDigest[shard], verifyAddressBuffer[shard], verifyBalanceBuffer[shard])
    verifyAddressBuffer[shard] = nil
    verifyBalanceBuffer[shard] = nil
    return result
}

//export demoProof
func demoProof() *C.char{
    initVc(uint64(0))
    updateindex := make([]uint64,vc.TxnLimit)
    delta := make([]int64,vc.TxnLimit)
    delta_f := make([]mcl.Fr,vc.TxnLimit)
    proofVec := make([][]mcl.G1, vc.TxnLimit)

    for i := uint64(0); i<vc.TxnLimit; i++{
        updateindex[i] = uint64(i)
        delta[i] = int64(i)
        delta_f[i].SetInt64(delta[i])
        vc.UpdateProofTree(updateindex[i], delta_f[i])
        digest[0][uint64(0)] = vc.UpdateCom(digest[0][uint64(0)], updateindex[i], delta_f[i])
    }

    for i := uint64(0); i<vc.TxnLimit; i++{
        proofVec[i] = vc.GetProofPath(updateindex[0])
    }
    aggProof := vc.AggProve(updateindex, proofVec)
    serialAggProof := SerializeBatchProof(aggProof)
    byteAggProof, err := json.Marshal(serialAggProof)

    var output []byte
    if err != nil {
        fmt.Println("Serialisation of aggregated proof failed",err)
        return C.CString(string(output))
    }
//     fmt.Println(string(byteAggProof))
     return C.CString(string(byteAggProof))
}

//export demoVerify
func demoVerify(proofString string)bool{
    proof := []byte(proofString)
    var tempProof SerialBatchProof

    errj := json.Unmarshal(proof, &tempProof)

    finalProof, err := DeserializeBatchProof(tempProof)
    if err != nil || errj != nil {
        fmt.Println("Deserialization falied during verification",err)
        return false
    }
    updateindex := make([]uint64,vc.TxnLimit)
    delta := make([]int64,vc.TxnLimit)
    delta_f := make([]mcl.Fr,vc.TxnLimit)

    for i := uint64(0); i<vc.TxnLimit; i++{
        updateindex[i] = uint64(i)
        delta[i] = int64(i)
        delta_f[i].SetInt64(delta[i])
    }
    result := vc.AggVerify(finalProof, digest[0][uint64(0)], updateindex, delta_f)
//     fmt.Println(result)
    return result
}
//first update proof tree
//internal function
func updateShardProofTree(nativeShard uint64){
    if len(addressBuffer2)==len(deltaBuffer2) {
        fmt.Println("length of addressBuffer2 is", len(deltaBuffer2))
        if len(deltaBuffer2) > 0 {
            fmt.Println("addresses being updated in tree are ", deltaBuffer2)
            vc.UpdateProofTreeBulk(addressBuffer2, deltaBuffer2)
            addressBuffer2 = nil 
            deltaBuffer2 = nil 
        }

    } else {
        fmt.Println("address delta buffer not equal, couldn't update prooftree!")
    }
}
//then update all the digests and flush the buffer
//internal function
func updateDigest(nativeShard uint64, round uint64) {
    fmt.Println("***************updating digest*********")
    //first, drain the native shard buffer in a separate buffer
    fmt.Println("length of addressBuffer2 before append is", len(addressBuffer2))
    addressBuffer2 = append(addressBuffer2, addressBuffer[nativeShard]...)
    deltaBuffer2 = append(deltaBuffer2, deltaBuffer[nativeShard]...)
    fmt.Println("length of addressBuffer2 after append is", len(addressBuffer2))
    for i := uint64(0); i < shardNum; i++ {
        if len(addressBuffer[i])==len(deltaBuffer[i])  {
            prevDigest[i] = digest[i][round]
            if len(deltaBuffer[i]) > 0 {
                if round > beginRound{
                    digest[i][round] = vc.UpdateComVec(digest[i][round-1], addressBuffer[i], deltaBuffer[i])
                } else{
                    // prevPrevDigest[i] = prevDigest[i]
                    fmt.Println("addressBuffer for update digest looks like", addressBuffer)
                    // prevDigest[i] = digest[i][round]
                    digest[i][round] = vc.UpdateComVec(digest[i][round], addressBuffer[i], deltaBuffer[i])
                }

            } else {
                if round > beginRound{
                    digest[i][round] = digest[i][round-1]
                }

            }

        }else{
            fmt.Println("address delta buffer not equal!")
        }
        addressBuffer[i] = nil
        deltaBuffer[i] = nil
    }
}




//internal struct
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

//internal function
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

//internal function
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
func main() {
// proof := demoProof()
// fmt.Println("proof looks like", len(proof))
// fmt.Println("verify", demoVerify(proof))
// fmt.Println("init:",initVc(uint64(0)))
// fmt.Println("verify:",demoVerify(demoProof()))
}

//export BenchmarkVCSCommit
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
//the following function is supposed to update the proof tree and commit values once aggregation for the previous round is completed.
//export-not updateShardProofTree
// func commitShardProofTree(address []uint64, []delta int64) int64 {
// // 	updateindex := uint64(10)
// // 	delta := int64(10)
// // 	var delta_f mcl.Fr
// 	delta_f.SetInt64(delta)
// 	vc.UpdateProofTree(address, delta_f)
// 	return 0
// }


