# Em: SharpShark-System/Dockerfile

FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Copia o requirements.txt de dentro da pasta 'app'
COPY app/requirements.txt .

# 2. Instala as dependências
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copia o CONTEÚDO da sua pasta 'app/' para o WORKDIR ('/app')
COPY app/ .

# 4. Copia os arquivos da raiz do projeto (entrypoint e .env-example) para o WORKDIR
COPY entrypoint.sh .
COPY .env-example .

# 5. CORREÇÃO: Corrigido o typo e o caminho.
#    Como o WORKDIR é /app, o arquivo está em 'entrypoint.sh'
RUN chmod +x entrypoint.sh

# 6. Define as variáveis de ambiente que o Docker vai usar
ENV INGEST_BASE_DIRECTORY=/data/ingest
ENV UPLOAD_DIRECTORY=/app/uploads

# 7. Garante que a pasta de uploads padrão exista
RUN mkdir -p /app/uploads

EXPOSE 8000

# 8. O entrypoint agora está em /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]