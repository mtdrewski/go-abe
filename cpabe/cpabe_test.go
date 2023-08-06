package cpabe_test

import (
	"testing"

	"github.com/mtdrewski/go-abe/cpabe"
)

func TestSetup(t *testing.T) {
	pk, msk := cpabe.Setup()

	//test if h == g^Beta
	gBeta := pk.Pairing.NewG1().PowZn(pk.G, msk.Beta)
	if !pk.H.Equals(gBeta) {
		t.Errorf("%d is not equal %d", pk.H, gBeta)
	}

	//test if f^b=g
	fBeta := pk.Pairing.NewG1().PowZn(pk.F, msk.Beta)
	if !pk.G.Equals(fBeta) {
		t.Errorf("%d is not equal %d", pk.G, fBeta)
	}

	//test e(g^alpha,g) == e(g,g)^alpha
	eggAlpha := pk.Pairing.NewGT().Pair(msk.Galpha, pk.G)
	if !eggAlpha.Equals(pk.EggAlpha) {
		t.Errorf("%d is not equal %d", eggAlpha, pk.EggAlpha)
	}
}
