# Coding Standards

Unless stated otherwise, we follow the [Zeth coding standards](https://github.com/clearmatics/zeth/blob/master/CODING_STANDARDS.md).

## Naming conventions

- When necessary, type parameters related to the base application and to Zecale are distinguished by using a `n` (for "nested") and a `w` (for "wrapping") prefix. For instance:
    - `nppT`: Type parameter representing the public parameters defining the nested curve (i.e. the curve over which "nested proofs" are generated. If a pairing-friendly amicable chain is used, `nppT` refers to the first curve of the chain)
    - `nsnarkT`: Type parameter representing the SNARK scheme used to generate the nested arguments
    - `wppT`: Type parameter representing the public parameters defining the wrapping curve (i.e. the curve over which the "nested proofs" are verified - and the wrapping proof is generated. If a pairing-friendly amicable chain is used, `wppT` refers to the last curve of the chain)
    - `wsnarkT`: Type parameter representing the SNARK scheme used to generate the wrapping argument
