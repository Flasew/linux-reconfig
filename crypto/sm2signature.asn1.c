/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for sm2signature
 */
#include <linux/asn1_ber_bytecode.h>
#include "sm2signature.asn1.h"

enum sm2signature_actions {
	ACT_sm2_get_signature_r = 0,
	ACT_sm2_get_signature_s = 1,
	NR__sm2signature_actions = 2
};

static const asn1_action_t sm2signature_action_table[NR__sm2signature_actions] = {
	[   0] = sm2_get_signature_r,
	[   1] = sm2_get_signature_s,
};

static const unsigned char sm2signature_machine[] = {
	// Sm2Signature
	[   0] = ASN1_OP_MATCH,
	[   1] = _tag(UNIV, CONS, SEQ),
	[   2] =  ASN1_OP_MATCH_ACT,		// sig_r
	[   3] =  _tag(UNIV, PRIM, INT),
	[   4] =  _action(ACT_sm2_get_signature_r),
	[   5] =  ASN1_OP_MATCH_ACT,		// sig_s
	[   6] =  _tag(UNIV, PRIM, INT),
	[   7] =  _action(ACT_sm2_get_signature_s),
	[   8] = ASN1_OP_END_SEQ,
	[   9] = ASN1_OP_COMPLETE,
};

const struct asn1_decoder sm2signature_decoder = {
	.machine = sm2signature_machine,
	.machlen = sizeof(sm2signature_machine),
	.actions = sm2signature_action_table,
};