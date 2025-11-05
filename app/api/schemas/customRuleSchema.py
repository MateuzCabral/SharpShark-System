from pydantic import BaseModel, Field, model_validator
from typing import Literal, Optional

SeverityType = Literal["low", "medium", "high", "critical"]
RuleType = Literal["payload", "port"]

class CustomRuleBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    rule_type: RuleType
    value: str = Field(..., min_length=1, max_length=1000)
    alert_type: str = Field(..., min_length=3, max_length=50)
    severity: SeverityType

    @model_validator(mode='after')
    def validate_value_for_type(self):
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
    pass

class CustomRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    rule_type: Optional[RuleType] = None
    value: Optional[str] = Field(None, min_length=1, max_length=1000)
    alert_type: Optional[str] = Field(None, min_length=3, max_length=50)
    severity: Optional[SeverityType] = None

class CustomRuleRead(CustomRuleBase):
    id: str
    user_id: str

    class Config:
        from_attributes = True