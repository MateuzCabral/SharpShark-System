#!/bin/bash
set -e

ENV_FILE=".env"
ENV_EXAMPLE_FILE=".env-example"

# --- 1. SETUP DO .env E SECRET_KEY ---
if [ ! -f "$ENV_FILE" ]; then
    echo "Arquivo .env não encontrado. Criando a partir do $ENV_EXAMPLE_FILE..."
    cp "$ENV_EXAMPLE_FILE" "$ENV_FILE"
    
    echo "Gerando nova SECRET_KEY..."
    KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    echo "" >> "$ENV_FILE"
    echo "# Chave gerada automaticamente" >> "$ENV_FILE"
    echo "SECRET_KEY=$KEY" >> "$ENV_FILE"
    echo "Nova SECRET_KEY gerada e salva no .env."
else
    echo ".env já existe. Pulando geração de chave."
fi

# --- 2. SETUP DO BANCO DE DADOS ---
echo "Inicializando o banco de dados (criando tabelas se não existirem)..."
python3 -m cli init-db
echo "Banco de dados pronto."

# --- 3. INICIA O SERVIDOR ---
echo "Iniciando servidor Uvicorn em 0.0.0.0:8000..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 