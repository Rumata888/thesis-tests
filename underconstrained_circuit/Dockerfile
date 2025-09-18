FROM python:3.10-slim

# Create non-root user
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

# Workdir and permissions
RUN mkdir -p /home/crypto && chown -R crypto:crypto /home/crypto
WORKDIR /home/crypto
USER crypto

# Copy service files
COPY server.py /home/crypto/
COPY plonk_circuit.py /home/crypto/
COPY flag.py /home/crypto/

# Expose service port
EXPOSE 1337

# Run server
CMD ["python3", "/home/crypto/server.py"]


