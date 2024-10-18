import random
from py_ecc.bls12_381 import G1, G2, Z1, add, multiply, neg, pairing, eq
from galois import Poly, FieldArray
from py_ecc.typing import Point2D


class TrustedEntity:
   def __init__(self, GF:FieldArray, curve_order:int, SRS_degree:int):
        self.GF = GF
        self.curve_order = curve_order
        self.SRS_1, self.SRS_2 = self.generate_SRS(SRS_degree)

   def generate_SRS(self, SRS_degree:int) -> tuple[list[Point2D], list[Point2D]]:
        tau = self.GF(random.randint(1, self.curve_order))
        SRS_1 = [multiply(G1, int(tau ** i)) for i in range(SRS_degree + 1)]
        SRS_2 = [multiply(G2, int(tau ** i)) for i in range(SRS_degree + 1)]
        del tau
        return SRS_1, SRS_2


class KZGOperator:
    def __init__(self, GF:FieldArray, curve_order:int, SRS_degree:int, SRS_1:list[Point2D], SRS_2:list[Point2D]):
        self.GF = GF
        self.curve_order = curve_order
        self.SRS_degree = SRS_degree
        self.SRS_1 = SRS_1
        self.SRS_2 = SRS_2

    def lagrange_base(self, j:int, x_arr:list[int], length:int) -> Poly:
        res = self.GF(1)
        for k in range(length):
            if k == j:
                continue
            q = Poly([self.GF(1), -x_arr[k]], self.GF) // (x_arr[j] - x_arr[k])
            res *= q
        return res

    def lagrange_interpolation(self, x_arr:list[FieldArray], y_arr:list[FieldArray]) -> Poly:
        length = len(x_arr)
        res = self.GF(0)
        for i in range(length):
            res += y_arr[i] * self.lagrange_base(i, x_arr, length)
        return res
    
    def evaluate_with_SRS(self, polynomial:Poly, SRS:list[Point2D]) -> Point2D:
        res = Z1
        for c_i, tau_i in zip(reversed(polynomial.coeffs), SRS):
            res = add(res, multiply(tau_i, int(c_i)))
        return res


class KZGProver(KZGOperator):
    def __init__(self, GF:FieldArray, curve_order:int, SRS_degree:int, SRS_1:list[Point2D], SRS_2:list[Point2D]):
        super().__init__(GF, curve_order, SRS_degree, SRS_1, SRS_2)

    def arr_to_poly(self, arr:list[tuple[int, int]]) -> Poly:
        x_arr = [self.GF(x) for x, _ in arr]
        y_arr = [self.GF(y) for _, y in arr]
        return self.lagrange_interpolation(x_arr, y_arr)

    def commit_poly(self, polynomial:Poly) -> Point2D:
        return self.evaluate_with_SRS(polynomial, self.SRS_1)

    def generate_one_point_proof(self, polynomial:Poly, point:tuple[int, int]) -> Point2D:
        z = self.GF(point[0])
        v = self.GF(point[1])
        
        num = polynomial - Poly([v], self.GF)
        denom = Poly([1, -z], self.GF)

        assert num % denom == 0, "The polynomial does not pass through the point"
        w_x =  num // denom
        w = self.evaluate_with_SRS(w_x, self.SRS_1)
        return w
    
    def generate_batch_proof(self, polynomial:Poly, points:list[tuple[int, int]]) -> Point2D:
        x_arr = [self.GF(x) for x, _ in points]
        y_arr = [self.GF(y) for _, y in points]
        # r = polinom stopnje len(points) - 1, ki gre skozi vse tocke - manjse stopnje ne more bit za splosne tocke
        r_x = self.lagrange_interpolation(x_arr, y_arr)

        num = polynomial - r_x
        denom = self.GF(1)
        for z in x_arr:
            denom *= Poly([1, -z], self.GF)

        assert num % denom == 0, "The polynomial does not pass through all the points"
        psi_x = num // denom
        w_B = self.evaluate_with_SRS(psi_x, self.SRS_1)
        return w_B


class KZGVerifier(KZGOperator):
    def __init__(self, GF:FieldArray, curve_order:int, SRS_degree:int, SRS_1:list[Point2D], SRS_2:list[Point2D]):
        super().__init__(GF, curve_order, SRS_degree, SRS_1, SRS_2)

    def verify_one_point_proof(self, commitment:Point2D, point:tuple[int, int], proof:Point2D, SRS_2:list[Point2D]):
        x = self.GF(point[0])
        y = self.GF(point[1])

        lhs = pairing(G2, add(commitment, neg(multiply(G1, int(y)))))
        rhs = pairing(add(SRS_2[1], neg(multiply(G2, int(x)))), proof)
        assert eq(lhs, rhs), "The proof is invalid"

    def verify_batch_proof(self, commitment:Point2D, points:list[tuple[int, int]], proof:Point2D):
        x_arr = [self.GF(x) for x, _ in points]
        y_arr = [self.GF(y) for _, y in points]
        # degree of r_x is len(points) - 1 so it satisfies degree < |points|
        r_x = self.lagrange_interpolation(x_arr, y_arr)

        z_x = Poly([1], self.GF)
        for z in x_arr:
            z_x *= Poly([self.GF(1), -z], self.GF)
        
        z_tau = self.evaluate_with_SRS(z_x, self.SRS_2)  
        r_tau = self.evaluate_with_SRS(r_x, self.SRS_1)
        
        lhs = pairing(G2, commitment)
        rhs = pairing(z_tau, proof) * pairing(G2, r_tau)
        assert eq(lhs, rhs), "The proof is invalid"
