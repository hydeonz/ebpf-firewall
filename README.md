### POST /add-rule  
Content-Type: application/json

Структура:
```json
{
  "interface": "string (required)",
  "ip": "string (required)",
  "protocol": "string (required) [tcp|udp|icmp|all]",
  "direction": "string (required) [src|dst]",
  "port": "string (optional, default='any')",
  "action": "string (required) [block|allow]"
}
```

Пример:
```json
{
  "interface": "eth0",
  "ip": "192.168.1.100",
  "protocol": "tcp",
  "direction": "src",
  "port": "443",
  "action": "block"
}
```

Ответы:  
**а) 200**
```json
{
  "success": true,
  "message": "Successfully blocked src tcp traffic for IP: 192.168.1.100, port: 443 on interface eth0",
  "data": {
    "interface": "eth0",
    "ip": "192.168.1.100",
    "protocol": "tcp",
    "direction": "src",
    "port": "443",
    "action": "block"
  }
}
```

**б) 400**
```json
{
  "success": false,
  "message": "ip, protocol, direction and action parameters are required"
}
```

---

### POST /remove-rule  
Content-Type: application/json

Структура:
```json
{
  "ip": "string (required)",
  "protocol": "string (required) [tcp|udp|icmp|all]",
  "direction": "string (required) [src|dst]",
  "port": "string (optional, default='any')",
  "action": "string (required) [block|allow]",
  "interface": "string (optional)"
}
```

Пример:
```json
{
  "ip": "192.168.1.100",
  "protocol": "tcp",
  "direction": "src",
  "port": "443",
  "action": "block"
}
```

Ответы:  
**а) 200**
```json
{
  "success": true,
  "message": "Successfully removed block rule for src tcp traffic for IP: 192.168.1.100, port: 443"
}
```

**б) 400**
```json
{
  "success": false,
  "message": "rule not found in block rules"
}
```

---

### POST /global-block  
Content-Type: application/json

Структура:
```json
{
  "enable": "boolean (required)"
}
```

Пример:
```json
{
  "enable": true
}
```

Ответ:  
**а) 200**
```json
{
  "success": true,
  "message": "Global block enabled",
  "data": {
    "enabled": true,
    "type": "block"
  }
}
```

---

### POST /global-allow  
Content-Type: application/json

Структура:
```json
{
  "enable": "boolean (required)"
}
```

Пример:
```json
{
  "enable": false
}
```

Ответ:  
**а) 200**
```json
{
  "success": true,
  "message": "Global allow disabled",
  "data": {
    "enabled": false,
    "type": "allow"
  }
}
```

---

### GET /list-rules  
Content-Type: application/json

Ответ:  
**а) 200**
```json
{
  "success": true,
  "message": "Rules loaded successfully",
  "data": {
    "global_block": false,
    "global_allow": true,
    "rules": [
      {
        "interface": "eth0",
        "ip": "10.0.0.5",
        "protocol": "udp",
        "direction": "dst",
        "port": "any",
        "action": "allow"
      }
    ]
  }
}
```
