import hashlib


class LeafMerkleNode:
    def __init__(self, value: int):
        self.value = value

    def __len__(self):
        return 1
    
    def get_proof(self, path: list[str]):
        return []
    
    def validate_proof(self, path: list[str], proof: list[bytes]):
        pass
    
    def _validate_proof(self, path: list[str], proof: list[bytes]):
        pass

class MerkleTreeNode:
    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.value = self.hash(left.value, right.value)

    def hash(self, v1, v2):
        return hashlib.shake_256(str(v1).encode() + str(v2).encode()).digest(128)

    def __len__(self):
        return len(self.left) + len(self.right)
    
    def get_proof(self, path: list[str]):
        if len(path) == 1:
            if path[0] == 'left':
                return [self.right.value]
            else:
                return [self.left.value]
        
        if path[0] == 'left':
            return [self.right.value] + self.left.get_proof(path[1:])
        else:
            return [self.left.value] + self.right.get_proof(path[1:])

    def validate_proof(self, path: list[str], proof: list[bytes]):
        if len(path) == 1:
            if path[0] == 'left':
                assert self.hash(proof[0], self.right.value) == self.value, "Invalid hash at leaf node"
            else:
                assert self.hash(self.left.value, proof[0]) == self.value
        else:
            if path[0] == 'left':
                assert self.hash(proof[0], self.right.value) == self.value
                self.left.validate_proof(path[1:], proof[1:])
            else:
                assert self.hash(self.left.value, proof[0]) == self.value
                self.right.validate_proof(path[1:], proof[1:])

def build_tree(depth: int):
    if depth == 1:
        return LeafMerkleNode("0"*127 + "1")
    else:
        child = build_tree(depth - 1)
        return MerkleTreeNode(child, child)

if __name__ == "__main__":
    depth = 10
    
    tree = build_tree(depth)
    path = ['left'] * (depth - 1)
    proof = tree.get_proof(path)
    print(proof)
    print(tree.left.left.value)
    print(len(tree))
    tree.validate_proof(path, proof)
