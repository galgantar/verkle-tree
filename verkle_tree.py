from collections import namedtuple
from py_ecc.bls12_381 import curve_order
from py_ecc.typing import Point2D

from kzg import KZGProver, KZGVerifier

import random
from math import floor, ceil
from kzg import TrustedEntity
import galois


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
    def __init__(self, curve_order:int, children:list, kzg_prover:KZGProver):
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
    
    def generate_proof(self, path:dict | list) -> dict | Proof:
        if isinstance(path, list):
            assert isinstance(self.children[0], LeafNode), "Path is not empty but this is a leaf node"
            proof = self.kzg_prover.generate_batch_proof(self.poly, path)
            return Proof(self.commitment, proof)
        
        # dokaz je slovar, ki ima pri kljuću -1 shranjen dokaz, da vrednosti otrok trenutnega
        # vozlišča pripadajo polinomu, ki je shranjen v self.commitment
        # V ključih iz intervala [1, len(self.children) - 1] so rekurzivno shranjeni dokazi za vozlišča,
        # ki so otroci self
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

    def validate_proof(self, path:dict | list, proof:dict | Proof):
        if isinstance(proof, tuple):
            assert self.root == proof.commitment, "The root commitment is not the same as the proof commitment"
        else:
            assert self.root == proof[-1].commitment, "The root commitment is not the same as the proof commitment"
        self._validate_proof(path, proof)

    def _validate_proof(self, path:dict | list, proof:dict | Proof):
        if isinstance(path, list):
            self.kzg_verifier.verify_batch_proof(proof.commitment, path, proof.proof)
            return
        
        current_proof = proof[-1]
        if len(path) == 1:
            i = list(path.keys())[0]
            if isinstance(proof[i], dict):
                point = (i, self.hashCurvePoint(proof[i][-1].commitment))
            else:
                point = (i, self.hashCurvePoint(proof[i].commitment))
            self.kzg_verifier.verify_one_point_proof(current_proof.commitment, point, current_proof.proof, self.kzg_verifier.SRS_2)
        else:
            points = []
            for i in path.keys():
                if isinstance(proof[i], dict):
                    points.append((i, self.hashCurvePoint(proof[i][-1].commitment)))
                else:
                    points.append((i, self.hashCurvePoint(proof[i].commitment)))
            self.kzg_verifier.verify_batch_proof(current_proof.commitment, points, current_proof.proof)

        for i, subpath in path.items():
            self._validate_proof(subpath, proof[i])
            # if isinstance(proof[i], dict):
            #     self._validate_proof(subpath, proof[i])
            # else:
            #     print("PASSING")
            #     pass


def build_mock_tree(depth:int, width:int, kzg_prover:KZGProver) -> VerkleTreeNode:
    if depth == 1:
        return LeafNode(random.randint(1, curve_order))
    
    t1 = build_mock_tree(depth - 1, width, kzg_prover)
    t2 = build_mock_tree(depth - 1, width, kzg_prover)
    l = [t1 for _ in range(floor(width / 2))] + [t2 for _ in range(ceil(width / 2))]
    # Vrednosti v seznamu morajo biti različne - polinom ne sme biti konstanten -
    # na vsakem nivoju naključno premešamo vrednsoti, da poskrbimo, da polinom na 
    # nivoju, ki je za eno višji od trenutnega ni konstanten
    random.shuffle(l)
    a = VerkleTreeNode(curve_order, l, kzg_prover)
    return a
    
def build_path(tree:VerkleTreeNode) -> dict | list:
    if isinstance(tree, LeafNode):
        return [(0, tree.get_value())]

    if isinstance(tree.children[0], LeafNode):
        return [(0, tree.children[0].get_value()), (1, tree.children[1].get_value())]
    
    return {0: build_path(tree.children[0])}

if __name__ == "__main__":
    GF = galois.GF(curve_order)

    SRS_degree = 30
    kzg_trusted_entity = TrustedEntity(GF, curve_order, SRS_degree)
    kzg_prover = KZGProver(GF, curve_order, SRS_degree, kzg_trusted_entity.SRS_1, kzg_trusted_entity.SRS_2)
    kzg_verifier = KZGVerifier(GF, curve_order, SRS_degree, kzg_prover.SRS_1, kzg_prover.SRS_2)

    depth = 2
    width = 30
    root = build_mock_tree(depth, width, kzg_prover)
    verifier = VerkleTreeVerifier(root.commitment, kzg_verifier)
    path = build_path(root)
    print("Path", path)
    proof = root.generate_proof(path)
    print("Proof", proof)
    print("Number of elements:", len(root))

    verifier.validate_proof(path, proof)
