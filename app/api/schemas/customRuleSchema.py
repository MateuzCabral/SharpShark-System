from pydantic import BaseModel, Field, model_validator
from typing import Literal

# 'Literal' restringe os valores permitidos para um campo
SeverityType = Literal["low", "medium", "high", "critical"]
RuleType = Literal["payload", "port"]

class CustomRuleBase(BaseModel):
    """ Schema base para regras customizadas, com validação. """
    name: str = Field(..., min_length=3, max_length=100)
    rule_type: RuleType
    value: str = Field(..., min_length=1, max_length=1000)
    alert_type: str = Field(..., min_length=3, max_length=50)
    severity: SeverityType

    # Validador Pydantic que roda após a validação padrão
    @model_validator(mode='after')
    def validate_value_for_type(self):
        """
        Valida o campo 'value' com base no 'rule_type'.
        - Se 'port', 'value' deve ser um número de porta (1-65535).
        - Se 'payload', 'value' deve ter pelo menos 3 caracteres.
        """
        rule_type = self.rule_type
        value = self.value
        
        if rule_type == 'port':
            try:
                port_num = int(value)
                if not (1 <= port_num <= 65535):
                    raise ValueError("Porta deve estar entre 1 e 65535")
            except (ValueError, TypeError):
                raise ValueError("Para o tipo 'port', o valor deve ser um número de porta válido (1-65535)")
        
        elif rule_type == 'payload':
            if len(value) < 3:
                raise ValueError("Para o tipo 'payload', o valor (assinatura) deve ter pelo menos 3 caracteres")
        
        return self

class CustomRuleCreate(CustomRuleBase):
    """ Schema usado para criar uma nova regra (herda a validação). """
    pass

class CustomRuleRead(CustomRuleBase):
    """ Schema usado para 'ler' uma regra (inclui IDs). """
    id: str
    user_id: str

    class Config:
        from_attributes = True