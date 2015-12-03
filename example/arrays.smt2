(set-option :produce-models true) ; enable model generation

(declare-const x (_ BitVec 64))
(declare-const a1 (Array (_ BitVec 64) (_ BitVec 64)))

(assert (= (select a1 x) x))
;(assert (not (= (select a1 x) x)))

(check-sat)
(get-model)
