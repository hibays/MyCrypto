# -*- coding: utf-8 -*-

def main(
	setting=dict(
		aes_en_de_ebc_ts=True,
		des_en_de_ts=True,
		ecc_en_de_ts=True,
		rc4_en_de_ts=True,
			  rsa_ts=True,
		zuc_en_de_ts=True,
		sm4_en_de_ts=True,
		chacha20_en_ts=True,
	),
	**opinion
) :
	if opinion :
		setting = {k:v for k,v in setting.items()}
		setting.update(opinion)
		
	te = '\n'.join((
		r'try:',
		r'	from .tests.{0} import main',
		r'	main()',
		r'except:',
		r'	from .tests.tsm import test',
		r'	test("Testing Error on `{0}`")',
		r'	print()',
		r'	from traceback import format_exc',
		r'	print("\t"+format_exc(9).replace("\n", "\n\t"))',
		r'	print("\tSkipped!\n")',
	)).format
	
	for k,v in setting.items() :
		if v : exec(te(k))
