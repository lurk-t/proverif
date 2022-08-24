============== PREAMBLE (ProVerif install and test of current LURK-T ProVerif specification)

- LURK-T ProVerif development (protocol, threat model, queries) are the current tls13-lib-LURK-T_proverif.pvl and file-queries.pv

- the initial baseline for the current file-lib.pvl and tls13-LURK-T_proverif.pv files is https://github.com/Inria-Prosecco/reftls/tree/master/pv 
(i.e., tls-lib-draft20.pvl and tls13-draft20-only.pv)

- ProVerif latest version should be installed following instructions on : https://prosecco.gforge.inria.fr/personal/bblanche/proverif/ 

- Starting the automatic proof with one of the following commands 1) or 2) : 

1) "proverif_excutable -lib tls13-lib-LURK-T_proverif.pvl tls13-LURK-T_proverif.pv >> textfile_with_results.txt"

OR (slower alternative to also get attack graph traces generated as separate files in an existing folder "folder-graphs/", for the queries supposed to be "false"): 
(Graphviz might be required)

2) "proverif_excutable -graph folder-graphs/ -lib tls13-lib-LURK-T_proverif.pvl tls13-LURK-T_proverif.pv >> textfile_with_results.txt"

- filter the results (cat textfile_with_results.txt | grep RES) or check the summary of queries results at the end of textfile_with_results.txt.

============= SUMMARY OF RESULTS (with focus only on TLS1.3) - see also comments in .pvl and .pv for some of the results

--------------------------------------------------------------
Verification summary:

Query event(ClientFinished(TLS12,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) ==> event(ServerFinished(TLS12,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) is true.

Query event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) ==> event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5)) is false.

Query not event(ServerFinished(TLS12,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) is true.

Query not event(ClientFinished(TLS12,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) is true.

Query not event(ServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) is false.

Query not event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5)) is false.

Query not event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,m_17,o_16,ck_10,sk_7,cb_5,ms_7)) is false.

Query event(ClientAEKeyLeaked(TLS13,cr_19,sr_12,psk_18,p_8)) ==> (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) is true.

Query event(ClientAEKeyLeaked(TLS13,cr_19,sr_12,psk_18,p_8)) ==> (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is false.

Query event(ClientAEKeyLeaked(TLS13,cr_19,sr_12,psk_18,p_8)) ==> event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is false.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) is false.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) is true.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is false.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) is false.

Query not event(MatchingChannelBinding(TLS13,cr_19,sr_12,p_8,TLS13,cr'_5,sr'_3,p'_3)) is true.

Query not event(MatchingResumptionSecret(TLS13,cr_19,sr_12,p_8,TLS13,cr'_5,sr'_3,p'_3)) is true.

Query not event(MatchingAEKey(TLS13,cr_19,sr_12,p_8,TLS13,cr'_5,sr'_3,p'_3)) is true.

Query event(ClientAEKeyLeaked(TLS13,cr_19,sr_12,psk_18,p_8)) ==> (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query inj-event(TLS13Server_rcvd_CV(cr_19,sr_12,p_8)) ==> (inj-event(CryptoService_rcvd_cr_sr(cr_19,sr_12,p_8)) ==> inj-event(TLS13Server_sent_cr_sr_CS(cr_19,sr_12,p_8))) is true.

Query inj-event(TLS13_recvd_CV(cr_19,sr_12,p_8,log_12)) ==> inj-event(CS_sent_CV(cr_19,sr_12,p_8,log_12)) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> (inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) ==> (inj-event(TLS13_recvd_CV(cr_19,sr_12,p_8,log_12)) ==> (inj-event(CS_sent_CV(cr_19,sr_12,p_8,log_12)) ==> inj-event(TLS13_sent_cr_sr_to_CS(cr_19,sr_12,p_8,log_12))))) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> (inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) ==> (inj-event(TLS13Server_rcvd_CV(cr_19,sr_12,p_8)) ==> (inj-event(CryptoService_rcvd_cr_sr(cr_19,sr_12,p_8)) ==> inj-event(TLS13Server_sent_cr_sr_CS(cr_19,sr_12,p_8))))) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query inj-event(ClientFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5,ms_7)) ==> (inj-event(PreServerFinished(TLS13,cr_19,sr_12,psk_18,p_8,o_16,m_17,ck_10,sk_7,cb_5)) ==> (inj-event(TLS13Server_rcvd_CV(cr_19,sr_12,p_8)) ==> (inj-event(CryptoService_sent_CV(cr_19,sr_12,p_8)) ==> inj-event(TLS13Server_sent_cr_sr_CS(cr_19,sr_12,p_8))))) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query attacker_p1(m_c(TLS13,cr_19,sr_12,p_8,psk_18)) ==> (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesAE(cr_19,sr_12,p_8,TLS13,WeakAE)) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query attacker_p1(m_c0(TLS13,cr_19,psk_18)) ==> psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)) || event(ClientOffersAE(cr_19,WeakAE)) is true.

Query event(ClientReceives(TLS13,cr_19,sr_12,psk_18,p_8,n_7,ad_7,m_17)) ==> event(ServerSends(TLS13,cr_19,sr_12,psk_18,p_8,n_7,ad_7,m_17)) || (event(WeakOrCompromisedKey(p_8)) && (psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)))) || event(ServerChoosesAE(cr_19,sr_12,p_8,TLS13,WeakAE)) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query event(ServerReceives(TLS13,cr_19,sr_12,psk_18,p_8,n_7,ad_7,m_17)) ==> event(ClientSends(TLS13,cr_19,sr_12,psk_18,p_8,n_7,ad_7,m_17)) || psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)) || event(ServerChoosesAE(cr_19,sr_12,p_8,TLS13,WeakAE)) || event(ServerChoosesKEX(cr_19,sr_12,p_8,TLS13,DHE_13(WeakDH,e))) || event(ServerChoosesHash(cr'_5,sr'_3,p_8,TLS13,WeakHash)) is true.

Query event(ServerReceives0(TLS13,cr_19,psk_18,n_7,ad_7,m_17)) ==> event(ClientSends0(TLS13,cr_19,psk_18,n_7,ad_7,m_17)) || psk_18 = NoPSK || event(CompromisedPreSharedKey(psk_18)) || event(ClientOffersAE(cr_19,WeakAE)) is true.

--------------------------------------------------------------

