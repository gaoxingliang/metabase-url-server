# Metabase URL Server - 安全认证机制

## 概述

本服务已升级为使用HMAC-SHA256签名认证机制，替代了之前不安全的明文传输app_secret的方式。新的认证机制提供了更高的安全性，防止重放攻击和中间人攻击。

## 认证机制

### 1. 签名算法

使用HMAC-SHA256算法生成请求签名，签名过程如下：

1. **构建待签名字符串**：
   ```
   HTTP方法\n
   请求路径\n
   时间戳\n
   随机数\n
   请求体内容
   ```

2. **生成签名**：
   - 使用app_secret作为密钥
   - 对待签名字符串进行HMAC-SHA256计算
   - 将结果进行Base64编码

举例：
待签名字符串:
```
POST
/api/metabase/urls
1755827031
0ac4ddd0-d300-4168-8083-e356d1d79e13
{"resource": "dashboard", "id": 123}
```
生成的签名: Fsz/qbnQDM3HKEvfGR9Y0O2dOeV1QrNGs55N4AxpyPA=

### 2. 请求头要求

每个API请求必须包含以下认证头：

- `X-AppKey`: 应用标识符
- `X-Timestamp`: Unix时间戳（秒）
- `X-Nonce`: 随机数（UUID格式）
- `Authorization`: 签名头，格式为 `Signature {base64_signature}`

### 3. 安全特性

- **防重放攻击**: 使用时间戳和随机数防止请求重放
- **时间窗口**: 请求时间戳必须在服务器时间的5分钟内
- **随机数唯一性**: 每个nonce只能使用一次
- **常量时间比较**: 使用`hmac.compare_digest`防止时序攻击

## 客户端实现示例

### Python客户端

```python
import hashlib
import hmac
import base64
import time
import uuid
import requests
import json

def generate_signature(http_method, uri_path, timestamp, nonce, request_body, app_secret):
    """生成HMAC-SHA256签名"""
    string_to_sign = (
        f"{http_method}\n"
        f"{uri_path}\n"
        f"{timestamp}\n"
        f"{nonce}\n"
        f"{request_body}"
    )
    
    signature = hmac.new(
        app_secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    return base64.b64encode(signature).decode('utf-8')

def make_authenticated_request(url, app_key, app_secret, data=None):
    """发送认证请求"""
    http_method = "POST"
    uri_path = "/api/metabase/urls"
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    request_body = json.dumps(data) if data else ''
    
    signature = generate_signature(
        http_method, uri_path, timestamp, nonce, request_body, app_secret
    )
    
    headers = {
        'Content-Type': 'application/json',
        'X-AppKey': app_key,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'Authorization': f'Signature {signature}'
    }
    
    return requests.post(url, json=data, headers=headers)
```

### JavaScript客户端

```javascript
const crypto = require('crypto');

function generateSignature(httpMethod, uriPath, timestamp, nonce, requestBody, appSecret) {
    const stringToSign = `${httpMethod}\n${uriPath}\n${timestamp}\n${nonce}\n${requestBody}`;
    
    const signature = crypto
        .createHmac('sha256', appSecret)
        .update(stringToSign)
        .digest('base64');
    
    return signature;
}

function makeAuthenticatedRequest(url, appKey, appSecret, data = null) {
    const httpMethod = 'POST';
    const uriPath = '/api/metabase/urls';
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = require('uuid').v4();
    const requestBody = data ? JSON.stringify(data) : '';
    
    const signature = generateSignature(
        httpMethod, uriPath, timestamp, nonce, requestBody, appSecret
    );
    
    const headers = {
        'Content-Type': 'application/json',
        'X-AppKey': appKey,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'Authorization': `Signature ${signature}`
    };
    
    return fetch(url, {
        method: 'POST',
        headers: headers,
        body: requestBody
    });
}
```

### Java 客户端

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import com.fasterxml.jackson.databind.ObjectMapper;

public class MetabaseUrlClient {
    private final String appKey;
    private final String appSecret;
    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    public MetabaseUrlClient(String appKey, String appSecret, String baseUrl) {
        this.appKey = appKey;
        this.appSecret = appSecret;
        this.baseUrl = baseUrl;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * 生成HMAC-SHA256签名
     */
    private String generateSignature(String httpMethod, String uriPath, 
                                   String timestamp, String nonce, String requestBody) throws Exception {
        String stringToSign = String.format("%s\n%s\n%s\n%s\n%s", 
            httpMethod, uriPath, timestamp, nonce, requestBody);
        
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(
            appSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        
        byte[] signatureBytes = mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
    
    /**
     * 发送认证请求
     */
    public String makeAuthenticatedRequest(Object requestData) throws Exception {
        String httpMethod = "POST";
        String uriPath = "/api/metabase/urls";
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String nonce = UUID.randomUUID().toString();
        String requestBody = requestData != null ? objectMapper.writeValueAsString(requestData) : "";
        
        String signature = generateSignature(httpMethod, uriPath, timestamp, nonce, requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + uriPath))
            .header("Content-Type", "application/json")
            .header("X-AppKey", appKey)
            .header("X-Timestamp", timestamp)
            .header("X-Nonce", nonce)
            .header("Authorization", "Signature " + signature)
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();
        
        HttpResponse<String> response = httpClient.send(request, 
            HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new RuntimeException("Request failed with status: " + response.statusCode() + 
                ", body: " + response.body());
        }
        
        return response.body();
    }
    
    /**
     * 使用示例
     */
    public static void main(String[] args) {
        try {
            MetabaseUrlClient client = new MetabaseUrlClient(
                "dev_app_key_123", 
                "dev_secret_key_456", 
                "http://localhost:7070"
            );
            
            // 创建请求数据
            RequestData requestData = new RequestData("question", 123);
            
            // 发送请求
            String response = client.makeAuthenticatedRequest(requestData);
            System.out.println("Response: " + response);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * 请求数据类
 */
class RequestData {
    private String resource;
    private int id;
    
    public RequestData(String resource, int id) {
        this.resource = resource;
        this.id = id;
    }
    
    // Getters and setters
    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
}
```

**Maven依赖**：

```xml
<dependencies>
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.15.2</version>
    </dependency>
</dependencies>
```

**Gradle依赖**：

```gradle
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.2'
}
```

## 配置说明

### 服务端配置

在`conf/config.yml`中配置认证组：

```yaml
auth_groups:
  dev_team:
    app_key: "dev_app_key_123"
    app_secret: "dev_secret_key_456"
    description: "Development team access"
    enabled: true
    
  prod_team:
    app_key: "prod_app_key_789"
    app_secret: "prod_secret_key_012"
    description: "Production team access"
    enabled: true
```

### 客户端配置

客户端需要配置对应的app_key和app_secret：

```python
APP_KEY = "dev_app_key_123"
APP_SECRET = "dev_secret_key_456"
```

## API调用示例

### 请求示例

```bash
curl -X POST http://localhost:7070/api/metabase/urls \
  -H "Content-Type: application/json" \
  -H "X-AppKey: dev_app_key_123" \
  -H "X-Timestamp: 1640995200" \
  -H "X-Nonce: 550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Signature dGVzdF9zaWduYXR1cmU=" \
  -d '{"resource": "question", "id": 123}'
```

### 响应示例

```json
{
  "url": "http://metabase.example.com/embed/question/eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in_minutes": 30
}
```

## 错误处理

### 常见错误码

- `401 Unauthorized`: 认证失败
  - 缺少必需的认证头
  - 无效的AppKey
  - 签名不匹配
  - 时间戳过期
  - 重复的nonce（重放攻击）

### 错误响应示例

```json
{
  "error": "Missing required authentication headers"
}
```

## 安全最佳实践

1. **密钥管理**：
   - 使用强随机生成的密钥
   - 定期轮换密钥
   - 不要在代码中硬编码密钥

2. **时间同步**：
   - 确保客户端和服务器时间同步
   - 考虑网络延迟，适当调整时间窗口

3. **随机数生成**：
   - 使用加密安全的随机数生成器
   - 确保nonce的唯一性

4. **HTTPS传输**：
   - 在生产环境中使用HTTPS
   - 验证SSL证书

5. **日志记录**：
   - 记录认证失败事件
   - 监控异常访问模式

## 迁移指南

### 从旧版本迁移

1. 更新客户端代码，实现HMAC签名
2. 配置新的认证头
3. 测试认证流程
4. 部署新版本服务端
5. 更新所有客户端

### 兼容性

新版本不再支持旧的明文认证方式，需要所有客户端都升级到新的认证机制。

## 故障排除

### 常见问题

1. **签名不匹配**：
   - 检查待签名字符串格式
   - 确认app_secret正确
   - 验证请求体编码

2. **时间戳过期**：
   - 检查客户端时间同步
   - 调整时间窗口设置

3. **重复nonce**：
   - 确保每次请求生成新的nonce
   - 检查客户端UUID生成

### 调试模式

启用详细日志记录：

```yaml
server:
  log_level: "DEBUG"
```

查看服务器日志以获取详细的认证信息。
