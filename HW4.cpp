#include "stdafx.h"
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include"..\openssl-1.0.2e-vs2015\include\openssl\bn.h"
#include"..\openssl-1.0.2e-vs2015\include\openssl\dh.h"
#include"..\openssl-1.0.2e-vs2015\include\openssl\evp.h"
using namespace std;
int main()
{
	char *c_str;//ノ块计沮
	BIGNUM    *p, *q, *multiple;//玻ネ1024bits借计p㎝160bits借计q
	BIGNUM    *h; 
	BIGNUM    *d;
	BIGNUM    *r;
	BIGNUM    *s;
	BIGNUM    *v;
	BIGNUM    *w;
	BIGNUM    *dv;
	BIGNUM    *SHA;
	BIGNUM    *u1,*u2;
	BIGNUM    *d_mul_r;
	BIGNUM    *sha_add_dr;
	BIGNUM    *alpha, *beta;
	BIGNUM    *KE, *KE_inverse;
	BIGNUM    *alpha_exp_u1, *beta_exp_u2;
	BN_CTX *ctx; /* used internally by the bignum lib */
	string x= "5db51497557623b";//plaintest
	p = BN_new();
	q = BN_new();
 	h = BN_new();
	d = BN_new();
	r = BN_new();
	s = BN_new();
	v = BN_new();
	w = BN_new();
 	u1 = BN_new();
	u2 = BN_new();
	dv = BN_new();
	KE = BN_new();
	SHA = BN_new();
	beta = BN_new();
	alpha = BN_new();
	d_mul_r = BN_new();
	ctx = BN_CTX_new();
	multiple = BN_new();
	KE_inverse = BN_new();
	sha_add_dr = BN_new();
	beta_exp_u2 = BN_new();
	alpha_exp_u1 = BN_new();

	//////////////////////////////////////////////////////////////////
	/////////////////////////*key generation*/////////////////////////
	//////////////////////////////////////////////////////////////////
	cout << "Generate a prime p and a prime q........";
	BN_generate_prime_ex(q, 160, 0, NULL, NULL, NULL);
	BN_generate_prime_ex(multiple, 864, 0, NULL, NULL, NULL);//2^1024=2^160 * 2^864
	BN_add_word(multiple, 1);//multiple=multiple+1
	BN_mul(p, q, multiple, ctx);//膀计*案计=膀计
	BN_add_word(p, 1);//p=p+1//案计
    int a=BN_is_prime_ex(p,1024, ctx, NULL);
	while (a!=1)//p琌借计ゎ
	{
		BN_generate_prime_ex(multiple, 864, 0, NULL, NULL, NULL);
		BN_add_word(multiple, 1);//multiple=multiple+1
		BN_mul(p, q, multiple, ctx);
		BN_add_word(p, 1);//p=p+1
	    a = BN_is_prime_ex(p, 1024, ctx, NULL);
	}
	c_str = BN_bn2dec(p); cout << "\n\np: " << c_str << "\n\n\n";
	c_str = BN_bn2dec(q); cout << "q: " << c_str << "\n\n\n";
	BN_sub_word(p, 1);//p=p-1
	BN_set_bit(h,1);// h < p - 1 //硄盽砞h=2
	BN_div(dv, NULL, p,q,ctx);
	BN_mod_exp(alpha, h, dv, p, ctx);//alpha = h ^ ((p - 1) / q) mod p
	c_str = BN_bn2dec(alpha); cout << "alpha: " << c_str << "\n\n\n";
	BN_add_word(p, 1);//p=p+1
	BN_rand_range(d, q);// h < q 
	BN_mod_exp(beta, alpha, d, p, ctx);//beta = alpha^d mod p 
	c_str = BN_bn2dec(beta); cout << "beta: " << c_str << "\n\n\n";
	
	//////////////////////////////////////////////////////////////////
	//////////////////////////////*sign*//////////////////////////////
	//////////////////////////////////////////////////////////////////
	//hash function//
	const EVP_MD *md;
	unsigned char* md_value = new unsigned char[20];
	md = EVP_sha1();
	EVP_Digest(x.c_str(), x.size()*sizeof(char), md_value, NULL, md, NULL);
	EVP_cleanup();
	SHA =BN_bin2bn(md_value, 20, NULL);
	c_str = BN_bn2dec(SHA); cout << "SHA(x): " << c_str << "\n\n\n";

	BN_rand_range(KE, q);// KE < q 
	BN_mod_exp(r, alpha, KE, p, ctx);//alpha^kE mod p
	BN_mod(r, r, q, ctx); //r = (alpha^kE mod p) mod q
	c_str = BN_bn2dec(r); cout << "r: " << c_str << "\n\n\n";
	BN_mod_inverse(KE_inverse, KE, q, ctx); //KE_inverse = KE猭はじ mod q
	BN_mul(d_mul_r, d, r, ctx);//d_mul_r=d*r
	BN_add(sha_add_dr, SHA, d_mul_r);//sha_add_dr=SHA+d*r
	BN_mod_mul(s, KE_inverse, sha_add_dr, q, ctx);//s = ( KE^(-1)*(SHA + d*r)) mod q 
	c_str = BN_bn2dec(s); cout << "s: " << c_str << "\n\n\n";

	//////////////////////////////////////////////////////////////////
	/////////////////////////////*verify*/////////////////////////////
	//////////////////////////////////////////////////////////////////
	BN_mod_inverse(w, s, q, ctx); //w = s猭はじ mod q
	c_str = BN_bn2dec(w); cout << "w: " << c_str << "\n\n\n";
	BN_mod_mul(u1, w, SHA, q, ctx);//u1 = w * SHA mod q
	BN_mod_mul(u2, w, r, q, ctx);//u2 = w * r mod q
	BN_exp(alpha_exp_u1, alpha, u1, ctx);// alpha_exp_u1 = alpha^u1
	BN_exp(beta_exp_u2, beta, u2, ctx);// beta_exp_u2 = beta^u2
	BN_mod_mul(v, alpha_exp_u1, beta_exp_u2, p, ctx);
	BN_mod(v, v, q, ctx);//v = (( alpha^u1 * beta^u2 ) mod p ) mod q 
	c_str = BN_bn2dec(v); cout << "v: " << c_str << "\n\n\n";
	if (BN_cmp(r, v) == 0)
		cout << "valid signature. " << c_str << "\n";
	else
		cout << "invalid signature. " << c_str << "\n";

 	system("pause");
	return 0;
}

