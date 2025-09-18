Fr_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # Modulus of the scalar field of alt_bn128


class Fr:
    def __init__(self, value):
        if isinstance(value, Fr):
            value = value.value
        self.value = value % Fr_modulus

    def __add__(self, other):
        return Fr(self.value + other.value)

    def __mul__(self, other):
        return Fr(self.value * other.value)

    def __neg__(self):
        return Fr(Fr_modulus - self.value)

    def __sub__(self, other):
        return self + (-other)

    def __eq__(self, other):
        return self.value == other.value

    def __str__(self):
        return f"Fr({self.value})"

    def invert(self):
        return self.pow(Fr_modulus - 2)

    def __div__(self, other):
        return self * other.invert()

    def __truediv__(self, other):
        return self * other.invert()

    def __neg__(self):
        return Fr(Fr_modulus - self.value)

    def pow(self, power):
        power = power % (Fr_modulus - 1)
        return Fr(pow(self.value, power, Fr_modulus))

    def __repr__(self):
        return self.__str__()


class PlonkCircuitBuilder:
    def __init__(self):
        self.w_l = []
        self.w_r = []
        self.w_o = []
        self.q_m = []
        self.q_l = []
        self.q_r = []
        self.q_o = []
        self.q_c = []
        self.variables = []
        self.zero_index = self.add_variable(Fr(0))
        self.create_fixed_witness_gate(self.zero_index, Fr(0))

    def get_circuit_size(self):
        return len(self.q_m)

    def replace_variables(self, new_variables):
        assert len(new_variables) == len(self.variables)
        self.variables = new_variables

    def _format_fr_short(self, fr_value):
        """
        Return a string for the field element using the shorter of
        its positive or negative representative.
        """
        if fr_value is None:
            return "None"
        v = fr_value.value if isinstance(fr_value, Fr) else int(fr_value)
        if v == 0:
            return "0"
        neg = (Fr_modulus - v) % Fr_modulus
        pos_str = str(v)
        neg_str = "-" + str(neg)
        return neg_str if len(neg_str) < len(pos_str) else pos_str

    def add_variable(self, variable_value):
        self.variables.append(variable_value)
        return len(self.variables) - 1

    def create_fixed_witness_gate(self, variable_index, witness_value):
        self.q_m.append(Fr(0))
        self.q_l.append(Fr(-1))
        self.q_r.append(Fr(0))
        self.q_o.append(Fr(0))
        self.q_c.append(Fr(witness_value))
        self.w_l.append(variable_index)
        self.w_r.append(0)
        self.w_o.append(0)

    def create_boolean_gate(self, variable_index):
        self.q_m.append(Fr(1))
        self.q_l.append(Fr(-1))
        self.q_r.append(Fr(0))
        self.q_o.append(Fr(0))
        self.q_c.append(Fr(0))
        self.w_l.append(variable_index)
        self.w_r.append(variable_index)
        self.w_o.append(0)

    def create_xor_gate(self, left_index, right_index, output_index):
        # Enforce: 2ab - a - b + c = 0  where c = a XOR b
        # The witnesses are expected to have been constrained to be 0 or 1 by the caller
        self.q_m.append(Fr(2))
        self.q_l.append(Fr(-1))
        self.q_r.append(Fr(-1))
        self.q_o.append(Fr(1))
        self.q_c.append(Fr(0))
        self.w_l.append(left_index)
        self.w_r.append(right_index)
        self.w_o.append(output_index)

    def create_2bit_xor_gate(self, left_index, right_index, output_index):
        assert left_index < len(self.variables)
        assert right_index < len(self.variables)
        assert output_index < len(self.variables)
        assert left_index >= 0
        assert right_index >= 0
        assert output_index >= 0
        value_left = self.variables[left_index].value
        value_right = self.variables[right_index].value
        value_output = self.variables[output_index].value
        value_left_low = value_left & 1
        value_left_high = value_left >> 1
        value_right_low = value_right & 1
        value_right_high = value_right >> 1
        value_output_low = value_output & 1
        value_output_high = value_output >> 1
        left_low_index = self.add_variable(Fr(value_left_low))
        left_high_index = self.add_variable(Fr(value_left_high))
        right_low_index = self.add_variable(Fr(value_right_low))
        right_high_index = self.add_variable(Fr(value_right_high))
        output_low_index = self.add_variable(Fr(value_output_low))
        output_high_index = self.add_variable(Fr(value_output_high))
        self.create_xor_gate(left_low_index, right_low_index, output_low_index)
        self.create_xor_gate(left_high_index, right_high_index, output_high_index)
        self.create_boolean_gate(output_low_index)
        self.create_boolean_gate(output_high_index)
        self.create_boolean_gate(left_low_index)
        self.create_boolean_gate(left_high_index)
        self.create_boolean_gate(right_low_index)
        self.create_boolean_gate(right_high_index)

    def create_generic_gate(
        self, left_index, right_index, output_index, q_m, q_l, q_r, q_o, q_c
    ):
        self.q_m.append(q_m)
        self.q_l.append(q_l)
        self.q_r.append(q_r)
        self.q_o.append(q_o)
        self.q_c.append(q_c)
        self.w_l.append(left_index)
        self.w_r.append(right_index)
        self.w_o.append(output_index)

    def create_64_bit_xor_gate(self, left_index, right_index, output_index):
        assert left_index < len(self.variables)
        assert right_index < len(self.variables)
        assert output_index < len(self.variables)
        assert left_index >= 0
        assert right_index >= 0
        assert output_index >= 0
        value_left = self.variables[left_index].value
        value_right = self.variables[right_index].value
        value_output = self.variables[output_index].value
        assert value_left.bit_length() <= 64
        assert value_right.bit_length() <= 64
        assert value_output.bit_length() <= 64
        current_left_accumulator = value_left
        current_right_accumulator = value_right
        current_output_accumulator = value_output
        current_left_index = left_index
        current_right_index = right_index
        current_output_index = output_index
        for i in range(31):
            # Take the lowest two bits of each accumulator
            current_left_bits = current_left_accumulator & 3
            current_right_bits = current_right_accumulator & 3
            current_output_bits = current_output_accumulator & 3
            # Compute the new accumulators
            new_left_accumulator = current_left_accumulator >> 2
            new_right_accumulator = current_right_accumulator >> 2
            new_output_accumulator = current_output_accumulator >> 2
            # Add variables to the circuit
            new_left_accumulator_index = self.add_variable(Fr(new_left_accumulator))
            new_right_accumulator_index = self.add_variable(Fr(new_right_accumulator))
            new_output_accumulator_index = self.add_variable(Fr(new_output_accumulator))
            low_bits_left_index = self.add_variable(Fr(current_left_bits))
            low_bits_right_index = self.add_variable(Fr(current_right_bits))
            low_bits_output_index = self.add_variable(Fr(current_output_bits))
            # Create accumulation gates
            self.create_generic_gate(
                current_left_index,
                new_left_accumulator_index,
                low_bits_left_index,
                Fr(0),
                Fr(1),
                Fr(-4),
                Fr(-1),
                Fr(0),
            )  # current_accumulator_left - 4 * new_accumulator_left - low_bits_left == 0
            self.create_generic_gate(
                current_right_index,
                new_right_accumulator_index,
                low_bits_right_index,
                Fr(0),
                Fr(1),
                Fr(-4),
                Fr(-1),
                Fr(0),
            )  # current_accumulator_right - 4 * new_accumulator_right - low_bits_right == 0
            self.create_generic_gate(
                current_output_index,
                new_output_accumulator_index,
                low_bits_output_index,
                Fr(0),
                Fr(1),
                Fr(-4),
                Fr(-1),
                Fr(0),
            )  # current_accumulator_output - 4 * new_accumulator_output - low_bits_output == 0
            # Create a 2bit xor gate
            self.create_2bit_xor_gate(
                low_bits_left_index, low_bits_right_index, low_bits_output_index
            )
            # Update the current indices
            current_left_index = new_left_accumulator_index
            current_right_index = new_right_accumulator_index
            current_output_index = new_output_accumulator_index
            current_left_accumulator = new_left_accumulator
            current_right_accumulator = new_right_accumulator
            current_output_accumulator = new_output_accumulator
        # Create a final 2bit xor gate
        self.create_2bit_xor_gate(
            current_left_index, current_right_index, current_output_index
        )

    def check_circuit(self):
        circuit_size = len(self.q_m)
        for i in range(circuit_size):
            if (
                self.q_m[i] * self.variables[self.w_l[i]] * self.variables[self.w_r[i]]
                + self.q_l[i] * self.variables[self.w_l[i]]
                + self.q_r[i] * self.variables[self.w_r[i]]
                + self.q_o[i] * self.variables[self.w_o[i]]
                + self.q_c[i]
            ) != Fr(0):
                return False
        return True

    def get_variables(self):
        return self.variables

    def print_gates(self, show_values=False):
        """
        Print all gates in the circuit in a readable form.

        Each gate enforces: q_m*a*b + q_l*a + q_r*b + q_o*c + q_c == 0

        Args:
            show_values (bool): If True, also prints the witness values for a, b, c.
                                 Defaults to False to avoid leaking witness information.
        """
        gate_count = len(self.q_m)
        for gate_index in range(gate_count):
            left_witness_index = self.w_l[gate_index]
            right_witness_index = self.w_r[gate_index]
            output_witness_index = self.w_o[gate_index]

            qm_fr = self.q_m[gate_index]
            ql_fr = self.q_l[gate_index]
            qr_fr = self.q_r[gate_index]
            qo_fr = self.q_o[gate_index]
            qc_fr = self.q_c[gate_index]

            qm_s = self._format_fr_short(qm_fr)
            ql_s = self._format_fr_short(ql_fr)
            qr_s = self._format_fr_short(qr_fr)
            qo_s = self._format_fr_short(qo_fr)
            qc_s = self._format_fr_short(qc_fr)

            # Build human-readable constraint expression with omitted zero selectors
            def add_term(coeff_str, body_str, is_first):
                if coeff_str == "0":
                    return "", is_first
                is_negative = coeff_str.startswith("-")
                magnitude = coeff_str[1:] if is_negative else coeff_str
                if is_first:
                    prefix = "-" if is_negative else ""
                else:
                    prefix = " - " if is_negative else " + "
                if body_str:
                    # Omit the explicit coefficient when it is 1 for cleaner output
                    term = body_str if magnitude == "1" else f"{magnitude}*{body_str}"
                else:
                    term = magnitude
                return prefix + term, False

            expr = ""
            first = True
            term, first = add_term(
                qm_s, f"w[{left_witness_index}]*w[{right_witness_index}]", first
            )
            expr += term
            term, first = add_term(ql_s, f"w[{left_witness_index}]", first)
            expr += term
            term, first = add_term(qr_s, f"w[{right_witness_index}]", first)
            expr += term
            term, first = add_term(qo_s, f"w[{output_witness_index}]", first)
            expr += term
            term, first = add_term(qc_s, "", first)
            expr += term
            if expr == "":
                expr = "0"

            line = f"gate {gate_index}: {expr} == 0"

            # Detect known gate patterns
            if (
                qm_fr == Fr(2)
                and ql_fr == Fr(-1)
                and qr_fr == Fr(-1)
                and qo_fr == Fr(1)
                and qc_fr == Fr(0)
            ):
                line += "  # XOR gate"
            elif (
                qm_fr == Fr(1)
                and ql_fr == Fr(-1)
                and qr_fr == Fr(0)
                and qo_fr == Fr(0)
                and qc_fr == Fr(0)
            ):
                line += "  # BOOLEAN gate"

            if show_values:
                left_fr = (
                    self.variables[left_witness_index]
                    if left_witness_index < len(self.variables)
                    else None
                )
                right_fr = (
                    self.variables[right_witness_index]
                    if right_witness_index < len(self.variables)
                    else None
                )
                output_fr = (
                    self.variables[output_witness_index]
                    if output_witness_index < len(self.variables)
                    else None
                )
                line += (
                    " | a="
                    + self._format_fr_short(left_fr)
                    + ", b="
                    + self._format_fr_short(right_fr)
                    + ", c="
                    + self._format_fr_short(output_fr)
                )

            print(line)


# -------------------- Tests --------------------
import unittest


class TestCircuitInitialization(unittest.TestCase):
    def test_check_circuit_on_fresh_circuit(self):
        circuit = PlonkCircuitBuilder()
        self.assertTrue(circuit.check_circuit())

    def test_64_bit_xor_gate(self):
        circuit = PlonkCircuitBuilder()
        import random

        left_value = random.randint(0, 2**64 - 1)
        right_value = random.randint(0, 2**64 - 1)
        output_value = left_value ^ right_value
        left_index = circuit.add_variable(Fr(left_value))
        right_index = circuit.add_variable(Fr(right_value))
        output_index = circuit.add_variable(Fr(output_value))
        circuit.create_64_bit_xor_gate(left_index, right_index, output_index)
        circuit.print_gates(show_values=True)
        self.assertTrue(circuit.check_circuit())
        self.assertEqual(circuit.variables[output_index].value, output_value)


if __name__ == "__main__":
    unittest.main()
