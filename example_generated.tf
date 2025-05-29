# __generated__ by Terraform
resource "fastly_service_vcl" "frontend_vcl_service_ngwaf_edge_deploy_bcunning_ngwaf_lab_global_ssl_fastly_net" {
  activate           = null
  comment            = "Managed by Terraform"
  default_host       = null
  default_ttl        = 3600
  force_destroy      = null
  http3              = false
  name               = "Frontend VCL Service - NGWAF edge deploy bcunning-ngwaf-lab.global.ssl.fastly.net"
  reuse              = null
  stage              = null
  stale_if_error     = false
  stale_if_error_ttl = 43200
  version_comment    = null
  backend {
    address               = "graphql-devhub-demo.edgecompute.app"
    auto_loadbalance      = false
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "graphql_backend"
    override_host         = "graphql-devhub-demo.edgecompute.app"
    port                  = 443
    request_condition     = "graphql backend condition"
    share_key             = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = "graphql-devhub-demo.edgecompute.app"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "graphql-devhub-demo.edgecompute.app"
    use_ssl               = true
    weight                = 100
  }
  backend {
    address               = "http-me.glitch.me"
    auto_loadbalance      = false
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "HTTPMESHIELD"
    override_host         = "http-me.glitch.me"
    port                  = 443
    request_condition     = "http-me backend condition"
    share_key             = null
    shield                = "sjc-ca-us"
    ssl_ca_cert           = null
    ssl_cert_hostname     = "http-me.glitch.me"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "http-me.glitch.me"
    use_ssl               = true
    weight                = 100
  }
  backend {
    address               = "http.edgecompute.app"
    auto_loadbalance      = false
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "vcl_service_origin"
    override_host         = "http.edgecompute.app"
    port                  = 443
    request_condition     = null
    share_key             = null
    shield                = "yyz-on-ca"
    ssl_ca_cert           = null
    ssl_cert_hostname     = "http.edgecompute.app"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "http.edgecompute.app"
    use_ssl               = true
    weight                = 100
  }
  backend {
    address               = "super-dynamic-backend.edgecompute.app"
    auto_loadbalance      = false
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "SUPERDYNAMICBACKEND"
    override_host         = "super-dynamic-backend.edgecompute.app"
    port                  = 443
    request_condition     = "SUPERDYNAMICBACKEND backend condition"
    share_key             = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = "super-dynamic-backend.edgecompute.app"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "super-dynamic-backend.edgecompute.app"
    use_ssl               = true
    weight                = 100
  }
  condition {
    name      = "SUPERDYNAMICBACKEND backend condition"
    priority  = 10
    statement = "std.strlen(req.http.cookie:fsly_domain) > 0 || req.url.path ~ \"/static/domain_form.html\" || req.url.path ~ \"/dynamic_backend/submit\" || req.url.path ~ \"/callback\""
    type      = "REQUEST"
  }
  condition {
    name      = "graphql backend condition"
    priority  = 10
    statement = "std.tolower(req.http.host) == \"bcunning-ngwaf-graphql.global.ssl.fastly.net\""
    type      = "REQUEST"
  }
  condition {
    name      = "http-me backend condition"
    priority  = 10
    statement = "std.strlen(req.http.httpme-alt) > 0"
    type      = "REQUEST"
  }
  dictionary {
    force_destroy = false
    name          = "Edge_Security"
    write_only    = false
  }
  domain {
    comment = "demo domain"
    name    = "*.livewaflove.com"
  }
  domain {
    comment = "demo domain"
    name    = "bcunning-ngwaf-graphql.global.ssl.fastly.net"
  }
  domain {
    comment = "demo domain"
    name    = "bcunning-ngwaf-lab.global.ssl.fastly.net"
  }
  domain {
    comment = "demo domain"
    name    = "livewaflove.com"
  }
  dynamicsnippet {
    content  = null
    name     = "ngwaf_config_deliver"
    priority = 9000
    type     = "deliver"
  }
  dynamicsnippet {
    content  = null
    name     = "ngwaf_config_init"
    priority = 0
    type     = "init"
  }
  dynamicsnippet {
    content  = null
    name     = "ngwaf_config_miss"
    priority = 9000
    type     = "miss"
  }
  dynamicsnippet {
    content  = null
    name     = "ngwaf_config_pass"
    priority = 9000
    type     = "pass"
  }
  product_enablement {
    bot_management        = true
    brotli_compression    = false
    domain_inspector      = true
    image_optimizer       = false
    log_explorer_insights = true
    name                  = null
    origin_inspector      = true
    websockets            = false
    ddos_protection {
      enabled = true
      mode    = "block"
    }
  }
  snippet {
    content  = "# Only needed in miss because the method is a POST\nif (req.url.path ~ \"/csp-reporting-endpoint\") {\n    set req.http.csp-report = req.body;\n}\n"
    name     = "content security policy report handler"
    priority = 120
    type     = "recv"
  }
  snippet {
    content  = "# Use the IP from RandomHack\nif (fastly.ff.visits_this_service == 0) {\n    if (req.http.X-Source-Ip) {\n        set req.http.Fastly-Client-IP = req.http.X-Source-Ip;\n    } else {\n        set req.http.Fastly-Client-IP = client.ip;\n    }\n    set client.geo.ip_override = req.http.Fastly-Client-IP;\n}\n  "
    name     = "Use RandomHack IP from X-Source-IP Header"
    priority = 1
    type     = "recv"
  }
  snippet {
    content  = "# vcl recv\n\n# enable ngwaf logging headers\nif (req.restarts == 0 && fastly.ff.visits_this_service == 0) {\n    set req.http.X-Sigsci-Response-Headers = \"true\";\n}\n\n"
    name     = "Add ngwaf log headers"
    priority = 100
    type     = "recv"
  }
  snippet {
    content  = "# vcl_deliver\n\nif (req.restarts == 0 && fastly.ff.visits_this_service == 0) {\n    if (req.url.qs ~ \"apex\") {    \n        # Capture the value of the FBM cookies.\n        # _fs_ch_cp_79UUvfpJ5mWYtLQv\n        # _fs_ch_st_FSBmUei20MqUiJb9\n        if (req.http.Cookie:_fs_ch_cp_79UUvfpJ5mWYtLQv) {\n            declare local var.fs_ch_cp STRING;\n            set var.fs_ch_cp = req.http.Cookie:_fs_ch_cp_79UUvfpJ5mWYtLQv;\n        }\n\n        if (req.http.Cookie:_fs_ch_st_FSBmUei20MqUiJb9) {\n            declare local var.fs_ch_st STRING;\n            set var.fs_ch_st = req.http.Cookie:_fs_ch_st_FSBmUei20MqUiJb9;\n        } \n\n        # Use a another filter or implementation for other apex domains\n        if (fastly_info.host_header ~ \"livewaflove.com\") {\n            declare local var.new_cookie_domain STRING;\n            set var.new_cookie_domain = \"livewaflove.com\";\n        }\n    \n        # Set the new cookie with the captured value, scoped to foo.xyz.\n        if (std.strlen(var.fs_ch_cp) > 0) {\n            # add resp.http.fbm-debug-2 = \"_fs_ch_cp_79UUvfpJ5mWYtLQv exists\";\n            add resp.http.Set-Cookie = \"_fs_ch_cp_79UUvfpJ5mWYtLQv=\" + var.fs_ch_cp + \"; Domain=\" + var.new_cookie_domain + \"; \" + \"Path=/; HttpOnly; SameSite=Lax; Max-Age=3600\";\n        }\n\n        if (std.strlen(var.fs_ch_st) > 0) {\n            # add resp.http.fbm-debug-2 = \"_fs_ch_st_FSBmUei20MqUiJb9 exists\";\n            add resp.http.Set-Cookie = \"_fs_ch_st_FSBmUei20MqUiJb9=\" + var.fs_ch_st + \"; Domain=\" + var.new_cookie_domain + \"; \" + \"Path=/; HttpOnly; SameSite=Lax; Max-Age=3600\";\n        }\n    \n        # Unsetting the cookies should only run at the initial workflow where the client first sets the cookies.\n        # Expire the original FBM cookie by setting Max-Age to 0.\n        if (fastly_info.host_header ~ \"www.livewaflove.com\") {\n\n            if (req.http.Cookie:_fs_ch_cp_79UUvfpJ5mWYtLQv) {\n                declare local var.cookie_domain STRING;\n                declare local var.cookie_path STRING;\n\n                # expire the other cookies to avoid duplicates.\n                # add resp.http.Set-Cookie = \"_fs_ch_cp_79UUvfpJ5mWYtLQv=deleted; Domain=\" + fastly_info.host_header + \"; Path=/; HttpOnly; SameSite=Lax; expires=Thu, 01 Jan 1970 00:00:00 GMT\";\n                add resp.http.Set-Cookie = \"_fs_ch_cp_79UUvfpJ5mWYtLQv=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0\";\n                add resp.http.Set-Cookie = \"_fs_ch_st_FSBmUei20MqUiJb9=deleted; Path=/; HttpOnly; Max-Age=0\";\n            }\n        }\n    }\n}"
    name     = "FBM cookie scope"
    priority = 100
    type     = "deliver"
  }
  snippet {
    content  = "# vcl_recv\nif (req.http.waf-bypass == \"secretvalue\") {\n    set req.http.x-sigsci-no-inspection = \"Disable NGWAF inspection\";\n}\n"
    name     = "Disable NGWAF Inspection"
    priority = 90
    type     = "recv"
  }
  snippet {
    content  = "#vcl_miss and vcl_pass\n\nif (std.strlen(req.http.httpme) > 0){\n    set req.backend = HTTPMESHIELD;\n    set bereq.http.x-fastly-ngwaf:backend = regsub(req.backend, \"^[a-zA-Z0-9]+--(?:F_)?\", \"\");\n    set bereq.http.x-fastly-ngwaf:backend-info = req.backend.connect_info;\n\n    set bereq.http.x-fastly-ngwaf:dynamic-backend-token = table.lookup(Edge_Security, \"DYNAMIC_BACKEND_TOKEN\", \"notoken\");\n    set bereq.http.x-fastly-ngwaf:host = bereq.http.host;\n    if (!bereq.http.x-fastly-ngwaf:ip-address) {\n            set bereq.http.x-fastly-ngwaf:ip-address = req.http.fastly-client-ip;\n    }\n    set bereq.http.x-fastly-ngwaf:serviceid = req.service_id;\n    set bereq.http.x-fastly-ngwaf:response-headers = \"true\";\n    set bereq.http.x-fastly-ngwaf:edgemodule = \"vcl 2.7.0;backendtoken\";\n    set waf.executed = true;\n}\n"
    name     = "Set to httpme backend - miss"
    priority = 9200
    type     = "miss"
  }
  snippet {
    content  = "#vcl_miss and vcl_pass\n\nif (std.strlen(req.http.httpme) > 0){\n    set req.backend = HTTPMESHIELD;\n    set bereq.http.x-fastly-ngwaf:backend = regsub(req.backend, \"^[a-zA-Z0-9]+--(?:F_)?\", \"\");\n    set bereq.http.x-fastly-ngwaf:backend-info = req.backend.connect_info;\n\n    set bereq.http.x-fastly-ngwaf:dynamic-backend-token = table.lookup(Edge_Security, \"DYNAMIC_BACKEND_TOKEN\", \"notoken\");\n    set bereq.http.x-fastly-ngwaf:host = bereq.http.host;\n    if (!bereq.http.x-fastly-ngwaf:ip-address) {\n            set bereq.http.x-fastly-ngwaf:ip-address = req.http.fastly-client-ip;\n    }\n    set bereq.http.x-fastly-ngwaf:serviceid = req.service_id;\n    set bereq.http.x-fastly-ngwaf:response-headers = \"true\";\n    set bereq.http.x-fastly-ngwaf:edgemodule = \"vcl 2.7.0;backendtoken\";\n    set waf.executed = true;\n}\n"
    name     = "Set to httpme backend - pass"
    priority = 9200
    type     = "pass"
  }
  snippet {
    content  = "#vcl_recv\n\nif(fastly.ff.visits_this_service == 0 && req.restarts == 0){\n    # set req.http.Fastly-Client-IP = client.ip;\n    set req.http.Client-JA3 = tls.client.ja3_md5;\n    set req.http.asn = client.as.number;\n    set req.http.as-name =  client.as.name;\n    set req.http.proxy-type = client.geo.proxy_type;\n    set req.http.proxy-desc = client.geo.proxy_description;\n    # set req.http.original-host = fastly_info.host_header;\n}\n"
    name     = "cdn enrichment"
    priority = 110
    type     = "recv"
  }
  snippet {
    content  = "set beresp.cacheable = false;"
    name     = "Disable caching"
    priority = 220
    type     = "fetch"
  }
  snippet {
    content  = "set resp.http.vcl-version = req.http.vcl-version ;"
    name     = "response debug headers"
    priority = 100
    type     = "deliver"
  }
  snippet {
    content  = "sub vcl_recv {\n    if (req.url ~ \"/fastly/logo\") {\n        set req.url = \"/static-assets/challenge-robot.jpg\";\n    }\n}"
    name     = "Update for custom logo"
    priority = 100
    type     = "init"
  }
}

