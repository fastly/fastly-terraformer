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
      mode    = "blocking"
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

# __generated__ by Terraform from "DcOdWNfZXYSXegRLYWRmE7/HnAOjhUzFHe2klOfjfZAm1"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_miss_dcodwnfzxysxegrlywrme7_hnaojhuzfhe2klofjfzam1" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\n\tcall edge_security;\n"
  manage_snippets = null
  service_id      = "DcOdWNfZXYSXegRLYWRmE7"
  snippet_id      = "HnAOjhUzFHe2klOfjfZAm1"
}

# __generated__ by Terraform from "5mLVmHgke4grHXUE8EcUV0/0H1qhKzeZ6guGK4cPUaDB1"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_pass_tf_5mlvmhgke4grhxue8ecuv0_0h1qhkzez6gugk4cpuadb1" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\n\tcall edge_security;\n"
  manage_snippets = null
  service_id      = "5mLVmHgke4grHXUE8EcUV0"
  snippet_id      = "0H1qhKzeZ6guGK4cPUaDB1"
}

# __generated__ by Terraform from "FChohPn3blvaq2yQifHWE4/cs91Ynh0dI2qiiQog995F6"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_pass_fchohpn3blvaq2yqifhwe4_cs91ynh0di2qiiqog995f6" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\n\tcall edge_security;\n"
  manage_snippets = null
  service_id      = "FChohPn3blvaq2yQifHWE4"
  snippet_id      = "cs91Ynh0dI2qiiQog995F6"
}

# __generated__ by Terraform from "DcOdWNfZXYSXegRLYWRmE7/asMNM2QBtXoXZ9rMLKETJ6"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_init_dcodwnfzxysxegrlywrme7_asmnm2qbtxoxz9rmlketj6" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\nbackend F_sigsci_waf {\n\t.always_use_host_header = true;\n\t.between_bytes_timeout = 60s; # real timeouts are in waf\n\t.connect_timeout = 1s;\n\t.dynamic = true;\n\t.first_byte_timeout = 600s; # real timeouts are in waf\n\t.host = \"se--brooks-cunningham-lab--67d058144c468e0dfd14a59b.edgecompute.app\";\n\t.host_header = \"se--brooks-cunningham-lab--67d058144c468e0dfd14a59b.edgecompute.app\";\n\t.max_connections = 800;\n\t.port = \"443\";\n\t.share_key = \"DcOdWNfZXYSXegRLYWRmE7\";\n\t.ssl = true;\n\t.ssl_cert_hostname = \"se--brooks-cunningham-lab--67d058144c468e0dfd14a59b.edgecompute.app\";\n\t.ssl_check_cert = always;\n\t.ssl_sni_hostname = \"se--brooks-cunningham-lab--67d058144c468e0dfd14a59b.edgecompute.app\";\n\t.probe = {\n\t\t.dummy = false; # this is a real healthcheck for fail open\n\t\t.initial = 1;\n\t\t.interval = 12s;\n\t\t.request = \"HEAD / HTTP/1.1\" \"Host: se--brooks-cunningham-lab--67d058144c468e0dfd14a59b.edgecompute.app\" \"Connection: close\" \"x-fastly-ngwaf: backend=health check,host=host health check,siteid=\";\n\t\t.expected_response = 200;\n\t\t.threshold = 1;\n\t\t.timeout = 2s;\n\t\t.window = 5;\n\t}\n}\n\nsub edge_security {\n\tif (!req.backend.is_origin) {\n\t\treturn;\n\t}\n\n\tif (!backend.F_sigsci_waf.healthy) {\n\t\tset bereq.http.x-sigsci-no-inspection = \"unhealthy_waf\";\n\t}\n\tif (!req.backend.healthy) {\n\t\tset bereq.http.x-sigsci-no-inspection = \"unhealthy_req.backend\";\n\t}\n\n\tif (bereq.http.x-sigsci-skip-inspection-once) {\n\t\tunset bereq.http.x-sigsci-skip-inspection-once;\n\t\treturn;\n\t}\n\n\tif (bereq.http.x-sigsci-no-inspection) {\n\t\tcall unset_preinspection_vars;\n\t\treturn;\n\t}\n\n\tif (!waf.executed) {\n\t\tset bereq.http.x-fastly-ngwaf:backend = regsub(req.backend, \"^[a-zA-Z0-9]+--(?:F_)?\", \"\");\n\t\tset bereq.http.x-fastly-ngwaf:backend-info = req.backend.connect_info;\n\t\tif (std.strlen(bereq.http.x-fastly-ngwaf:backend-info) == 0) {\n\t\t\tcall unset_preinspection_vars;\n\t\t\treturn;\n\t\t}\n\t\t\n\t\tset bereq.http.x-fastly-ngwaf:dynamic-backend-token = table.lookup(Edge_Security, \"DYNAMIC_BACKEND_TOKEN\", \"notoken\");\n\t\tset bereq.http.x-fastly-ngwaf:host = bereq.http.host;\n\t\tif (!bereq.http.x-fastly-ngwaf:ip-address) {\n\t\t\tset bereq.http.x-fastly-ngwaf:ip-address = req.http.fastly-client-ip;\n\t\t}\n\t\tset bereq.http.x-fastly-ngwaf:serviceid-prod = \"DcOdWNfZXYSXegRLYWRmE7\";\n\t\tset bereq.http.x-fastly-ngwaf:serviceid = req.service_id;\n\t\tset bereq.http.x-fastly-ngwaf:response-headers = \"true\";\n\t\tset bereq.http.x-fastly-ngwaf:edgemodule = \"vcl 2.11.1;backendtoken\";\n\t\tset bereq.http.x-fastly-ngwaf:siteid = \"\";\n\t\tset req.backend = F_sigsci_waf;\n\t\tset waf.executed = true;\n\t}\n}\n\nsub unset_preinspection_vars {\n\tunset bereq.http.x-fastly-ngwaf:sec-data;\n\tunset bereq.http.x-fastly-ngwaf:backend-info;\n\tunset bereq.http.x-fastly-ngwaf:backend;\n\tunset bereq.http.x-fastly-ngwaf:protocol;\n\tunset bereq.http.x-fastly-ngwaf:requestid;\n\tunset bereq.http.x-fastly-ngwaf:scheme;\n\tunset bereq.http.x-fastly-ngwaf:tlscipher;\n\tunset bereq.http.x-fastly-ngwaf:tlsprotocol;\n}\n\nsub vcl_recv {\n\tif (req.restarts == 0) {\n\t\tif (fastly.ff.visits_this_service == 0) {\n\t\t\t# if the Enabled key is absent then default to Enabled=0%\n\t\t\tif (!(std.strlen(req.http.x-sigsci-force-inspection) > 0 || randombool(std.atoi(table.lookup(Edge_Security, \"Enabled\", \"0\")), 100))) {\n\t\t\t\tset req.http.x-sigsci-no-inspection = \"disabled\";\n\t\t\t} else {\n\t\t\t\tif (table.contains(enabled_products, \"origin_inspector\")) {\n\t\t\t\t\tset req.http.fastly-origin-inspector = \"true\";\n\t\t\t\t} else {\n\t\t\t\t\tunset req.http.fastly-origin-inspector;\n\t\t\t\t}\n\t\t\t\tunset req.http.x-sigsci-no-inspection;\n\t\t\t\tunset req.http.x-sigsci-skip-inspection-once;\n\t\t\t\t\n\t\t\t\tset req.http.fastly-client-ip = client.ip;\n\t\t\t\t\n\t\t\t\tset req.http.x-fastly-ngwaf:sec-data = fastly_info.sec_data;\n\t\t\t\tset req.http.x-fastly-ngwaf:protocol = req.proto;\n\t\t\t\tset req.http.x-fastly-ngwaf:requestid = fastly_info.request_id;\n\t\t\t\tset req.http.x-fastly-ngwaf:scheme = req.protocol;\n\t\t\t\tset req.http.x-fastly-ngwaf:tlscipher = tls.client.cipher;\n\t\t\t\tset req.http.x-fastly-ngwaf:tlsprotocol = tls.client.protocol;\n\t\t\t}\n\t\t}\n\n\t\tunset req.http.x-fastly-ngwaf:ip-address;\n\t}\n}\n"
  manage_snippets = null
  service_id      = "DcOdWNfZXYSXegRLYWRmE7"
  snippet_id      = "asMNM2QBtXoXZ9rMLKETJ6"
}

# __generated__ by Terraform
resource "fastly_service_compute" "hibp_enrichment_demo" {
  activate        = null
  comment         = "Check the HIBP API for pwned passwords and send enriched information to the origin"
  force_destroy   = null
  name            = "hibp_enrichment_demo"
  reuse           = null
  stage           = null
  version_comment = null
  backend {
    address               = "api.pwnedpasswords.com"
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "api.pwnedpasswords.com"
    override_host         = null
    port                  = 443
    share_key             = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = "api.pwnedpasswords.com"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "api.pwnedpasswords.com"
    use_ssl               = true
    weight                = 100
  }
  backend {
    address               = "f1b41fc7-35d7-4636-bf54-06291d49cc0d.sigscicloudwaf.com"
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "nextgenwaf"
    override_host         = null
    port                  = 443
    share_key             = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = "f1b41fc7-35d7-4636-bf54-06291d49cc0d.sigscicloudwaf.com"
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = "f1b41fc7-35d7-4636-bf54-06291d49cc0d.sigscicloudwaf.com"
    use_ssl               = true
    weight                = 100
  }
  backend {
    address               = "httpbin.org"
    between_bytes_timeout = 10000
    connect_timeout       = 1000
    error_threshold       = 0
    first_byte_timeout    = 15000
    healthcheck           = null
    keepalive_time        = 0
    max_conn              = 200
    max_tls_version       = null
    min_tls_version       = null
    name                  = "httpbin.org"
    override_host         = null
    port                  = 443
    share_key             = null
    shield                = null
    ssl_ca_cert           = null
    ssl_cert_hostname     = null
    ssl_check_cert        = true
    ssl_ciphers           = null
    ssl_client_cert       = null
    ssl_client_key        = null
    ssl_sni_hostname      = null
    use_ssl               = true
    weight                = 100
  }
  domain {
    comment = null
    name    = "legally-free-kodiak.edgecompute.app"
  }
  domain {
    comment = null
    name    = "pwnedly-waf.webbots.page"
  }
  domain {
    comment = null
    name    = "pwnedly.edgecompute.app"
  }
  package {
    content          = null
    filename         = null
    source_code_hash = null
  }
}

# __generated__ by Terraform from "iV6wJ8uiR7iKyOHdnQSOD4/qfNm1XscFbXM4Db35TZq11"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_miss_iv6wj8uir7ikyohdnqsod4_qfnm1xscfbxm4db35tzq11" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\n\tcall edge_security;\n"
  manage_snippets = null
  service_id      = "iV6wJ8uiR7iKyOHdnQSOD4"
  snippet_id      = "qfNm1XscFbXM4Db35TZq11"
}

# __generated__ by Terraform
resource "fastly_service_compute" "webhook_compute_receiver_with_object_store" {
  activate        = null
  comment         = "Managed by Terraform"
  force_destroy   = null
  name            = "Webhook Compute Receiver with object store"
  reuse           = null
  stage           = null
  version_comment = null
  domain {
    comment = "Webhook Compute Receiver with object store"
    name    = "siem-webhook.global.ssl.fastly.net"
  }
  package {
    content          = null
    filename         = null
    source_code_hash = null
  }
  resource_link {
    name        = "siem-store"
    resource_id = "3bafyj55ur1crf8h0peikt"
  }
}