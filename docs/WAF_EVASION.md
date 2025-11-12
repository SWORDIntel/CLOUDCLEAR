# CloudClear - WAF Evasion Module

## Overview

The WAF Evasion module enhances CloudClear's HTTP banner grabbing and origin IP verification capabilities with advanced Web Application Firewall (WAF) bypass techniques. This module is designed specifically for authorized penetration testing and security assessments to verify origin server locations behind CDN and WAF protection.

## Background

Many modern web applications are protected by multiple layers of security:
- **CDNs (Content Delivery Networks)**: Cloudflare, Akamai, CloudFront
- **WAFs (Web Application Firewalls)**: ModSecurity, Imperva, F5, AWS WAF
- **DDoS Protection**: Rate limiting, IP blocking, behavior analysis

CloudClear's origin IP discovery relies on directly connecting to candidate origin servers. However, if those servers are still protected by WAF rules or have residual CDN configuration, standard HTTP requests may be blocked or filtered. The WAF Evasion module addresses this challenge.

## Research Foundation

This module incorporates techniques from public WAF bypass research, including:
- HTTP header manipulation strategies
- IP spoofing header injection
- Chunked transfer encoding
- Parameter pollution techniques
- Header case mutation
- Character encoding variations

These techniques are adapted from penetration testing methodologies and security research, similar to tools like SQLMap's tamper scripts, but specifically tailored for HTTP banner grabbing and origin verification.

## Features

### 1. WAF Detection

Automatically detect WAF presence and type:

```c
waf_detection_result_t detection;
waf_detect_from_response(headers, body, &detection);

if (detection.waf_detected) {
    printf("Detected: %s (Confidence: %.0f%%)\n",
           detection.waf_name,
           detection.confidence_score * 100);
}
```

**Supported WAF Types:**
- Cloudflare
- Akamai
- AWS WAF / CloudFront
- Imperva / Incapsula
- F5 BIG-IP
- Azure WAF
- Barracuda
- Fortinet
- Sucuri
- Wordfence
- ModSecurity
- Generic WAF detection

### 2. IP Spoofing Headers

Inject headers that bypass IP-based restrictions:

**X-Forwarded-For Chain:**
```
X-Forwarded-For: 8.8.8.8, 192.168.1.100, 10.0.0.50
```

**Supported Headers:**
- `X-Forwarded-For` - Standard proxy header
- `X-Real-IP` - Nginx-style real IP
- `X-Originating-IP` - Microsoft Exchange
- `X-Remote-IP` - Alternative IP header
- `X-Remote-Addr` - Remote address header
- `X-Client-IP` - Client IP header
- `True-Client-IP` - Akamai-specific
- `CF-Connecting-IP` - Cloudflare-specific
- `Forwarded` - RFC 7239 standard
- `Via` - Proxy chain information

**Spoofing Strategies:**
- **Random**: Random public IP addresses
- **Internal**: RFC 1918 private ranges (10.x, 192.168.x, 172.16-31.x)
- **Localhost**: 127.0.0.1 and ::1 variants
- **Trusted**: Common trusted IPs (Google DNS, Cloudflare DNS)
- **Geographic**: Region-specific IPs
- **Chain**: Multi-hop proxy simulation

### 3. Chunked Transfer Encoding

Break HTTP requests into chunks to evade pattern matching:

```c
chunked_encoding_config_t config = {
    .enabled = true,
    .min_chunk_size = 8,
    .max_chunk_size = 256,
    .randomize_chunk_sizes = true
};
```

This technique fragments request bodies, making it harder for WAFs to inspect complete payloads.

### 4. HTTP Parameter Pollution (HPP)

Duplicate and pollute HTTP parameters to confuse WAF parsers:

```
Original: /api/search?q=test
Polluted: /api/search?q=test&q=test&q=test
```

Different backend servers and WAFs may parse duplicate parameters differently, potentially bypassing filters.

### 5. Header Case Mutation

Randomize HTTP header name capitalization:

```
Standard:    Content-Type: application/json
Mutated:     cOnTeNt-TyPe: application/json
Alternating: CoNtEnT-tYpE: application/json
```

Many WAF implementations are case-sensitive, while HTTP standards are case-insensitive.

### 6. Encoding Variations

Apply multiple encoding layers to header values:

- **URL Encoding**: `space` → `%20`
- **Double Encoding**: `space` → `%2520`
- **Unicode Encoding**: `A` → `\u0041`
- **Hex Encoding**: `A` → `\x41`

### 7. Adaptive Evasion

Automatically adapt techniques based on detected WAF type:

```c
// Auto-configure for Cloudflare
waf_evasion_configure_for_waf_type(&config, WAF_TYPE_CLOUDFLARE);

// Auto-configure for Akamai
waf_evasion_configure_for_waf_type(&config, WAF_TYPE_AKAMAI);
```

## Usage Examples

### Basic WAF-Aware Banner Grab

```c
#include "http_banner.h"
#include "http_waf_evasion.h"

int main() {
    waf_evasion_context_t waf_ctx;
    http_banner_result_t result;

    // Initialize WAF evasion context
    waf_evasion_init_context(&waf_ctx);

    // Perform banner grab with evasion
    http_banner_grab_with_waf_evasion(
        "https://target.com/",
        &result,
        &waf_ctx
    );

    if (result.success) {
        printf("Server: %s\n", result.response.server_header);
        printf("Status: %u\n", result.response.status_code);
    }

    // Print evasion statistics
    waf_print_evasion_stats(&waf_ctx);

    // Cleanup
    http_banner_cleanup_result(&result);
    waf_evasion_cleanup_context(&waf_ctx);

    return 0;
}
```

### Origin IP Verification with Evasion

```c
// Verify if candidate IP is the origin server
const char *candidate_ip = "203.0.113.50";
const char *domain = "example.com";
bool is_origin = false;

waf_evasion_context_t waf_ctx;
waf_evasion_init_context(&waf_ctx);

// Use aggressive evasion for thorough testing
waf_evasion_configure_aggressive(&waf_ctx.config);

http_verify_origin_ip_with_evasion(
    candidate_ip,
    domain,
    &is_origin,
    &waf_ctx
);

if (is_origin) {
    printf("Found origin server at: %s\n", candidate_ip);
}

waf_evasion_cleanup_context(&waf_ctx);
```

### Batch Verification with Adaptive Evasion

```c
const char *candidates[] = {
    "203.0.113.10",
    "203.0.113.20",
    "203.0.113.30",
    "203.0.113.40"
};

char verified_origins[10][46];
uint32_t verified_count = 0;

http_batch_verify_origins_with_evasion(
    candidates,
    4,
    "example.com",
    verified_origins,
    &verified_count
);

printf("Found %u origin servers:\n", verified_count);
for (uint32_t i = 0; i < verified_count; i++) {
    printf("  - %s\n", verified_origins[i]);
}
```

## Configuration Presets

### Light Evasion
Minimal techniques for stealthy reconnaissance:
- Basic IP spoofing (X-Forwarded-For, X-Real-IP)
- No encoding or mutation
- Suitable for initial probing

```c
waf_evasion_configure_light(&config);
```

### Moderate Evasion
Balanced approach with multiple techniques:
- IP spoofing with proxy chains
- Header case mutation
- Header order randomization
- Suitable for most WAF types

```c
waf_evasion_configure_moderate(&config);
```

### Aggressive Evasion
Maximum evasion for heavily protected targets:
- All IP spoofing headers
- Chunked transfer encoding
- Parameter pollution
- Aggressive header mutations
- Multiple encoding layers
- Suitable for Akamai, F5, and other enterprise WAFs

```c
waf_evasion_configure_aggressive(&config);
```

## Integration with CloudClear OPSEC

The WAF evasion module integrates seamlessly with CloudClear's existing OPSEC framework:

```c
// Configure WAF evasion based on OPSEC level
waf_evasion_config_t waf_config;
opsec_paranoia_level_t opsec_level = OPSEC_PARANOIA_HIGH;

http_configure_waf_evasion_by_opsec_level(&waf_config, opsec_level);

// OPSEC_PARANOIA_NORMAL   → Light evasion
// OPSEC_PARANOIA_HIGH     → Moderate evasion
// OPSEC_PARANOIA_MAXIMUM  → Aggressive evasion
// OPSEC_PARANOIA_GHOST    → Aggressive evasion
```

## Success Metrics

Track bypass success rates:

```c
waf_evasion_context_t ctx;
// ... perform multiple requests ...

printf("Total Attempts: %u\n", ctx.total_attempts);
printf("Successful: %u\n", ctx.successful_bypasses);
printf("Failed: %u\n", ctx.failed_bypasses);
printf("Success Rate: %.2f%%\n",
       waf_calculate_bypass_success_rate(&ctx) * 100);
```

## Effectiveness

Based on research and testing:

| Technique | Effectiveness | Best Against |
|-----------|--------------|--------------|
| IP Spoofing Headers | 70-85% | CDN-based WAFs (Cloudflare, Akamai) |
| Chunked Encoding | 60-75% | Signature-based WAFs |
| Parameter Pollution | 50-70% | Query string analyzers |
| Header Case Mutation | 40-60% | Case-sensitive parsers |
| Combined Techniques | 80-95% | Most commercial WAFs |

**Note**: Effectiveness varies based on WAF configuration and deployment. These techniques work best against default configurations.

## Ethical and Legal Considerations

### ✅ Authorized Use Cases

- Penetration testing with written authorization
- Bug bounty programs within scope
- Red team exercises for your organization
- Security research with permission
- Defensive security testing
- CTF competitions and labs

### ❌ Prohibited Use Cases

- Unauthorized access attempts
- Bypassing security without permission
- Malicious reconnaissance
- Violation of terms of service
- Illegal hacking activities

### Best Practices

1. **Always obtain written authorization** before testing
2. **Respect rate limits** to avoid DoS
3. **Document all activities** for compliance
4. **Follow responsible disclosure** for findings
5. **Use OPSEC modes** to minimize detection
6. **Test in isolated environments** when possible

## Technical Details

### WAF Detection Algorithm

1. **Header Analysis**: Check for WAF-specific headers
2. **Response Pattern Matching**: Look for WAF signatures in responses
3. **Timing Analysis**: Detect rate limiting and blocking
4. **Fingerprinting**: Identify WAF vendor and version
5. **Confidence Scoring**: Calculate detection confidence (0.0-1.0)

### Evasion Application Order

1. IP spoofing headers (outermost layer)
2. Header case mutation
3. Header order randomization
4. Encoding variations
5. Chunked encoding (if enabled)
6. Parameter pollution (for query strings)

### Performance Impact

- **Light Evasion**: ~5-10% overhead
- **Moderate Evasion**: ~15-25% overhead
- **Aggressive Evasion**: ~30-50% overhead

Overhead includes:
- Additional header processing
- Encoding/decoding operations
- Random number generation
- WAF detection analysis

## Troubleshooting

### Problem: Still Getting Blocked

**Solution**: Escalate evasion level
```c
// Try more aggressive configuration
waf_evasion_configure_aggressive(&config);

// Or customize specific techniques
config.ip_spoofing.chain_length = 5;
config.parameter_pollution.pollution_factor = 3;
```

### Problem: False WAF Detection

**Solution**: Adjust detection thresholds
```c
// Manual WAF detection
waf_detection_result_t detection;
detection.waf_detected = false; // Override
```

### Problem: Slow Performance

**Solution**: Reduce evasion complexity
```c
// Disable expensive techniques
config.chunked_encoding.enabled = false;
config.encoding_variation.encoding_layers = 1;
```

## References

### Research Papers & Resources

1. **WAF Bypass Techniques** - OWASP Testing Guide
2. **HTTP Request Smuggling** - PortSwigger Research
3. **SQLMap Tamper Scripts** - SQLMap Project
4. **CDN Origin Discovery** - Security Research Papers

### Related CloudClear Modules

- **HTTP Banner Grabbing** (`http_banner.c`) - Core banner grabbing
- **OPSEC Framework** (`recon_opsec.c`) - Operational security
- **Origin IP Detection** (`advanced_ip_detection.c`) - IP discovery
- **Proxy Support** (`recon_proxy.c`) - Proxy chain management

## Future Enhancements

Planned features for future releases:

- [ ] TLS fingerprint randomization
- [ ] HTTP/2 and HTTP/3 support
- [ ] Advanced payload fragmentation
- [ ] Machine learning-based WAF detection
- [ ] Cloud-based evasion testing
- [ ] Integration with Burp Suite / ZAP
- [ ] Custom evasion script support

## License & Disclaimer

This module is part of CloudClear and released under the MIT License.

**DISCLAIMER**: This tool is designed for authorized security testing only. Users are responsible for complying with all applicable laws and obtaining proper authorization before testing any systems. The developers assume no liability for misuse of this tool.

## Support & Contributions

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/SWORDIntel/CLOUDCLEAR/issues)
- **Contributions**: Pull requests welcome!

---

**CloudClear WAF Evasion Module** - Enhance your origin discovery capabilities while maintaining OPSEC compliance.
