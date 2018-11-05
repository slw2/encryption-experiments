The scenario is as follows. Some client C is communicating with a host H, using symmetric encryption with pre-shared keys. The cipher uses 64-bit blocks, and we will write
E(h<b1,...,b8>) = h<c1,...,c8> to mean that the 8-byte block h<b1,...,b8> encrypts to h<c1,...,c8i> under the unknown key. The block mode is CBC. We may assume that the cipher cannot be broken directly. The client is attempting to send one piece of highly secret information, a sequence of bytes (padded to a multiple of 8) that we will call
h<m1,m2,...,m8n>; we will intercept and block the ciphertext, after which the client will try again and again with the same plaintext.

Conveniently, we have placed some malicious software on the client’s computer which allows us to add a preﬁx, of up to 8 bytes, to the plaintext, and we can vary the preﬁx for every communication the client makes.

Our attack, which comes from the family called blockwise-adapative chosen plaintext attacks and is also known as a chosen-boundary attack, works as follows.

Suppose that we force the 7-byte preﬁx h<0,0,0,0,0,0,0> onto the plaintext; the ﬁrst 16 bytes of the ciphertext must therefore be h<iv1,...,iv8,c1,...,c8> where the ﬁrst eight are the IV and
E(h<iv1 ⊕ 0, iv2 ⊕ 0, ...,iv7 ⊕ 0, iv8 ⊕ m1>) = h<c1,...,c8>.

After observing h<c1,...,c8>, we can determine m1 as follows:

For each byte x:

(i) make the host encrypt the preﬁx h<0,0,0,0,0,0,0,x>

(ii) look only at the second cipher block, and see which one matches h<c1,...,c8>. The block that matches came from encrypting h<0,0,0,0,0,0,0,m1>.

Then we can repeat, ﬁrst forcing the preﬁx h<0,0,0,0,0,0> to get a target cipher block which encrypts h<iv1 ⊕ 0, iv2 ⊕ 0, ...,iv6 ⊕ 0, iv7 ⊕ m1, iv8 ⊕ m2>, then trying all preﬁxes of the form h<0,0,0,0,0,0,m1,x> and looking for a match. The process can continue to recover the entire ﬁrst message block, and then move onto subsequent blocks, remembering that under CBC each plaintext block is xor-ed with the last cipher block, prior to encryption.

The defence against this attack is the IV: in the simplest form described above, the attack only works if the IV is the same for every message. If the IV is completely unpredictable, the attack cannot be used, because it depends on spotting a match in the cipher blocks, something which will not happen more often than random. But if the IV is variable but predictable (with a reasonable probability of correctness), the attack can be adapted, by xor-ing the predicted IV with the preﬁx block, cancelling the eﬀect of the IV altogether. The “BEAST” attack works because (in the relevant context) SSL/TLS defaults to using the last cipher block of the previous message as the IV of the next, making it completely predictable.