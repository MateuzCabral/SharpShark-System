import time
import asyncio
from collections import defaultdict
from core.config import LOGIN_RATE_LIMIT, LOGIN_RATE_PERIOD, UPLOAD_RATE_LIMIT, UPLOAD_RATE_PERIOD

class RateLimiter:
    """
    Implementação de um 'rate limiter' (limitador de taxa) assíncrono
    e em memória. Usa um dicionário para rastrear timestamps de tentativas.
    """
    def __init__(self, limit: int, period: int):
        self.limit = limit # Nº máximo de tentativas
        self.period = period # Período em segundos
        # Dicionário que armazena listas de timestamps para cada chave (key)
        self.attempts = defaultdict(list)
        # Lock assíncrono para garantir 'thread safety' (neste caso, 'coroutine safety')
        self.lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> bool:
        """
        Verifica se uma tentativa (identificada pela 'key', ex: IP ou username)
        é permitida.
        """
        now = time.time() # Tempo atual em segundos
        async with self.lock:
            timestamps = self.attempts[key]

            # 1. Limpa timestamps antigos (mais velhos que o período)
            self.attempts[key] = [t for t in timestamps if now - t < self.period]

            # 2. Verifica se o limite foi atingido
            if len(self.attempts[key]) >= self.limit:
                return False # Bloqueia a tentativa

            # 3. Registra a nova tentativa
            self.attempts[key].append(now)
            return True # Permite a tentativa

    async def cleanup(self):
        """
        Função de limpeza (opcional) para remover chaves antigas do dicionário
        e liberar memória.
        """
        now = time.time()
        async with self.lock:
            # Encontra chaves onde *todos* os timestamps expiraram
            to_delete = [
                key for key, timestamps in self.attempts.items()
                if all(now - t > self.period for t in timestamps)
            ]
            for key in to_delete:
                del self.attempts[key]

# Instâncias globais dos rate limiters, usando as configurações do config.py
login_rate_limiter = RateLimiter(limit=LOGIN_RATE_LIMIT, period=LOGIN_RATE_PERIOD)
upload_rate_limiter = RateLimiter(limit=UPLOAD_RATE_LIMIT, period=UPLOAD_RATE_PERIOD)