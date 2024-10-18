from collections import namedtuple
from py_ecc.bls12_381 import curve_order
from py_ecc.typing import Point2D

from kzg import KZGProver, KZGVerifier


Proof = namedtuple("Proof", ["commitment", "proof"])


class VerkleTreeOperator:
    def __init__(self, curve_order:int):
        self.curve_order = curve_order

    def hashCurvePoint(self, point:Point2D) -> int:
        return int(point[0]) % self.curve_order


class LeafNode:
    def __init__(self, value:int):
        self.value = value

    def get_value(self) -> int:
        return self.value
    
    def __len__(self) -> int:
        return 1


class VerkleTreeNode(VerkleTreeOperator):
    def __init__(self, curve_order:int, children:list[int], kzg_prover:KZGProver):
        self.children = children
        self.kzg_prover = kzg_prover
        
        self.values = [child.get_value() for child in children]
        self.poly = self.kzg_prover.arr_to_poly([(i, v) for i, v in enumerate(self.values)])
        self.commitment = self.kzg_prover.commit_poly(self.poly)

        super().__init__(curve_order)
    
    def get_value(self) -> int:
        return self.hashCurvePoint(self.commitment)
    
    def __len__(self) -> int:
        l = 0
        for child in self.children:
            l += len(child)
        return l
    
    def generate_proof(self, path:dict) -> dict:
        if type(path) == list:
            assert type(self.children[0]) == LeafNode, "Path is not empty but this is a leaf node"
            proof = self.kzg_prover.generate_batch_proof(self.poly, path)
            return Proof(self.commitment, proof)
        
        res = {}

        if len(path) == 1:
            i = list(path.keys())[0]
            point = (i, self.children[i].get_value())
            proof = self.kzg_prover.generate_one_point_proof(self.poly, point)
            res[-1] = Proof(self.commitment, proof)
        else:
            points = [(i, self.children[i].get_value()) for i in path.keys()]
            proof = self.kzg_prover.generate_batch_proof(self.poly, points)
            res[-1] = Proof(self.commitment, proof)
        
        for i, subpath in path.items():
            child_proof = self.children[i].generate_proof(subpath)
            res[i] = child_proof
        
        return res


class VerkleTreeVerifier(VerkleTreeOperator):
    def __init__(self, root:Point2D, kzg_verifier:KZGVerifier):
        self.root = root
        self.kzg_verifier = kzg_verifier

        super().__init__(curve_order)

    def validate_proof(self, path:dict, proof:dict):
        assert self.root == proof[-1].commitment, "The root commitment is not the same as the proof commitment"
        self._validate_proof(path, proof)

    def _validate_proof(self, path:dict, proof:dict):
        if type(path) == list:
            self.kzg_verifier.verify_batch_proof(proof.commitment, path, proof.proof)
            return
        
        current_proof = proof[-1]
        if len(path) == 1:
            i = list(path.keys())[0]
            point = (i, self.hashCurvePoint(proof[i].commitment))
            self.kzg_verifier.verify_one_point_proof(current_proof.commitment, point, current_proof.proof, self.kzg_verifier.SRS_2)
        else:
            points = [(i, self.hashCurvePoint(proof[i].commitment)) for i in path.keys()]
            self.kzg_verifier.verify_batch_proof(current_proof.commitment, points, current_proof.proof)

        for i, subpath in path.items():
            self._validate_proof(subpath, proof[i])
