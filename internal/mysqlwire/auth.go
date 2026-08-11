package mysqlwire

import "crypto/sha1"

// NativePassword computes the mysql_native_password response:
//
//	SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw)))
//
// An empty password produces an empty response, which is how the protocol
// expresses "no password".
func NativePassword(scramble []byte, password string) []byte {
	if password == "" {
		return nil
	}
	if len(scramble) > 20 {
		scramble = scramble[:20]
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(scramble)
	h.Write(h2[:])
	s := h.Sum(nil)
	out := make([]byte, len(s))
	for i := range out {
		out[i] = h1[i] ^ s[i]
	}
	return out
}

// ScrambleOldPassword computes the pre-4.1 ("mysql_old_password") auth response
// from the first 8 bytes of the scramble. This is the algorithm that modern
// drivers removed and that this whole proxy exists to speak.
//
// The algorithm is the one implemented in go-sql-driver/mysql (MPL-2.0), which
// cannot be called from here for two reasons. Its scrambleOldPassword, pwHash
// and myRnd are unexported — the package exports a database/sql driver, not
// protocol helpers — so there is nothing to import. And a database/sql
// connection is the wrong shape regardless: the proxy has to keep the socket
// after authentication in order to relay it, which that API never hands back.
//
// Verified against a real server: PWHash is pinned to MySQL's own
// OLD_PASSWORD() output, and the full exchange runs against MySQL 5.5 and 5.6
// in the integration suite.
func ScrambleOldPassword(scramble []byte, password string) []byte {
	if password == "" {
		return nil
	}
	if len(scramble) > 8 {
		scramble = scramble[:8]
	}
	hashPw := PWHash([]byte(password))
	hashSc := PWHash(scramble)

	r := newMyRnd(hashPw[0]^hashSc[0], hashPw[1]^hashSc[1])
	var out [8]byte
	for i := range out {
		out[i] = r.NextByte() + 64
	}
	mask := r.NextByte()
	for i := range out {
		out[i] ^= mask
	}
	return out[:]
}

// PWHash is MySQL's pre-4.1 password hash — the value OLD_PASSWORD() prints as
// its two words in hex. Spaces and tabs in the password are skipped, which is
// part of the original algorithm and not an accident.
func PWHash(password []byte) (result [2]uint32) {
	var add uint32 = 7
	result[0] = 1345345333
	result[1] = 0x12345671
	for _, c := range password {
		if c == ' ' || c == '\t' {
			continue
		}
		tmp := uint32(c)
		result[0] ^= (((result[0] & 63) + add) * tmp) + (result[0] << 8)
		result[1] += (result[1] << 8) ^ result[0]
		add += tmp
	}
	result[0] &= 0x7FFFFFFF
	result[1] &= 0x7FFFFFFF
	return
}

const myRndMaxValue = 0x3FFFFFFF

// myRnd is MySQL's pre-4.1 pseudo-random generator, seeded from the password
// and scramble hashes.
type myRnd struct{ seed1, seed2 uint32 }

func newMyRnd(seed1, seed2 uint32) *myRnd {
	return &myRnd{seed1 % myRndMaxValue, seed2 % myRndMaxValue}
}

func (r *myRnd) NextByte() byte {
	r.seed1 = (r.seed1*3 + r.seed2) % myRndMaxValue
	r.seed2 = (r.seed1 + r.seed2 + 33) % myRndMaxValue
	return byte(uint64(r.seed1) * 31 / myRndMaxValue)
}
