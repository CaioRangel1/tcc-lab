#!/bin/sh
# Gera a autoridade certificadora (CA) do laboratório, o certificado do servidor
# e os certificados das estações de trabalho dos operadores.
# Só gera o que ainda não existe, para não invalidar certificados já emitidos.
# As extensões seguem a validação estrita do Python 3.13+ (VERIFY_X509_STRICT).
set -e
cd /certs

# ---------- Autoridade certificadora do laboratório ----------
if [ ! -f ca.crt ]; then
  echo "Gerando CA do laboratório..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout ca.key -out ca.crt -subj "/CN=CA do Laboratorio TCC" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
fi

# ---------- Certificado do servidor (Nginx) ----------
if [ ! -f server.crt ]; then
  echo "Gerando certificado do servidor (localhost)..."
  openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr -subj "/CN=localhost"
  cat > server.ext << EXT
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 365 -out server.crt -extfile server.ext
  rm -f server.csr server.ext
fi

# ---------- Certificados das estações de trabalho (dispositivos) ----------
# Cada estação recebe um certificado com um identificador próprio (CN).
# A chave privada (.key) representa o que fica guardado apenas naquela máquina.
for estacao in estacao-operador1 estacao-operador2; do
  if [ ! -f "$estacao.crt" ]; then
    echo "Gerando certificado do dispositivo $estacao..."
    openssl req -newkey rsa:2048 -nodes \
      -keyout "$estacao.key" -out "$estacao.csr" -subj "/CN=$estacao"
    cat > client.ext << EXT
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT
    openssl x509 -req -in "$estacao.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 365 -out "$estacao.crt" -extfile client.ext
    rm -f "$estacao.csr" client.ext
  fi
done

chmod 644 *.crt *.key
echo "Certificados prontos."
