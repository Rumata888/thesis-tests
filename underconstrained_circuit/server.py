#!/usr/bin/env python3
import socket
import threading
import logging
import re
from typing import List

from plonk_circuit import PlonkCircuitBuilder, Fr
from flag import flag


HOST = "0.0.0.0"
PORT = 1337
RECV_BUF = 4096
SOCKET_TIMEOUT_SECONDS = 600

PROMPT = "> "
START_MESSAGE = "Please send me the variables for the 64-bit xor circuit"
NOT_ENOUGH_VALUES = "Not enough values provided. Expected {expected}, got {got}."
TOO_MANY_VALUES = "Too many values provided. Expected {expected}, got {got}. Using the first {expected}."
DECODE_ERROR = "Error decoding message. Please send ASCII text containing integers."
CIRCUIT_UNSAT = "Circuit is not satisfied. Try again."
SUCCESS_MESSAGE = "Congratulations! Here is your flag: {flag}"
FAIL_MESSAGE = "Inputs xor to the output. This does not break the circuit. Try again."


def build_xor_circuit():
    circuit = PlonkCircuitBuilder()
    left_index = circuit.add_variable(Fr(0))
    right_index = circuit.add_variable(Fr(0))
    output_index = circuit.add_variable(Fr(0))
    circuit.create_64_bit_xor_gate(left_index, right_index, output_index)
    return circuit, left_index, right_index, output_index


def parse_ints_from_buffer(buffer: str) -> List[int]:
    return [int(x) for x in re.findall(r"[-+]?\d+", buffer)]


def handle_client(conn: socket.socket, addr):
    try:
        conn.settimeout(SOCKET_TIMEOUT_SECONDS)
        # Build circuit and determine variable count
        circuit, left_idx, right_idx, out_idx = build_xor_circuit()
        var_count = len(circuit.variables)

        # Send initial prompt
        conn.sendall(
            (START_MESSAGE + f" (send {var_count} integers)\n" + PROMPT).encode()
        )

        buffer = ""
        values: List[int] = []
        while True:
            try:
                data = conn.recv(RECV_BUF)
            except socket.timeout:
                return
            if not data:
                return
            try:
                chunk = data.decode()
            except UnicodeDecodeError:
                conn.sendall((DECODE_ERROR + "\n" + PROMPT).encode())
                continue
            buffer += chunk
            values = parse_ints_from_buffer(buffer)
            if len(values) < var_count:
                # Ask for more until we have enough
                remaining = var_count - len(values)
                conn.sendall((f"Need {remaining} more integers...\n" + PROMPT).encode())
                continue
            break

        if len(values) > var_count:
            conn.sendall(
                (
                    TOO_MANY_VALUES.format(expected=var_count, got=len(values)) + "\n"
                ).encode()
            )
            values = values[:var_count]

        # Replace variables
        new_variables = [Fr(v) for v in values]
        circuit.replace_variables(new_variables)

        # Check circuit satisfaction
        if not circuit.check_circuit():
            conn.sendall((CIRCUIT_UNSAT + "\n").encode())
            return

        # Check that inputs do NOT xor to output
        left_val = circuit.variables[left_idx].value
        right_val = circuit.variables[right_idx].value
        out_val = circuit.variables[out_idx].value

        if (left_val ^ right_val) != out_val:
            conn.sendall((SUCCESS_MESSAGE.format(flag=flag) + "\n").encode())
        else:
            conn.sendall((FAIL_MESSAGE + "\n").encode())
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()


def serve_forever():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(8)
        logging.info(f"Listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = s.accept()
                logging.info(f"Accepted connection from {addr}")
                t = threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                )
                t.start()
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    serve_forever()
