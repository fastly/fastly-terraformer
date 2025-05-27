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
  backend {} # sensitive
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

# __generated__ by Terraform from "KclUymQNIHIoswD9mRpXR6/FB2c6F7MbrDI6s0yA67NB2"
resource "fastly_service_dynamic_snippet_content" "ngwaf_config_pass_kcluymqnihioswd9mrpxr6_fb2c6f7mbrdi6s0ya67nb2" {
  content         = "\n# DO NOT EDIT OR COPY - this dynamic snippet is managed by fastly\n\tcall edge_security;\n"
  manage_snippets = null
  service_id      = "KclUymQNIHIoswD9mRpXR6"
  snippet_id      = "FB2c6F7MbrDI6s0yA67NB2"
}

# __generated__ by Terraform
resource "fastly_service_vcl" "edge_rate_limiting_terraform_erl_tf_global_ssl_fastly_net" {
  activate           = null
  comment            = "Managed by Terraform"
  default_host       = null
  default_ttl        = 3600
  force_destroy      = null
  http3              = false
  name               = "edge-rate-limiting-terraform erl-tf.global.ssl.fastly.net"
  reuse              = null
  stage              = null
  stale_if_error     = false
  stale_if_error_ttl = 43200
  version_comment    = null
  backend {} # sensitive
  dictionary {
    force_destroy = false
    name          = "rl_user_agents"
    write_only    = false
  }
  dictionary {
    force_destroy = false
    name          = "login_edge_rate_limit_config"
    write_only    = false
  }
  dictionary {
    force_destroy = false
    name          = "login_paths"
    write_only    = false
  }
  dictionary {
    force_destroy = false
    name          = "erl_config"
    write_only    = false
  }
  domain {
    comment = "demo for configuring edge rate limiting with terraform"
    name    = "erl-tf.global.ssl.fastly.net"
  }
  product_enablement {
    bot_management        = false
    brotli_compression    = false
    domain_inspector      = true
    image_optimizer       = false
    log_explorer_insights = false
    name                  = null
    origin_inspector      = true
    websockets            = false
  }
  snippet {
    content  = "# Snippet rate-limiter-v1-origin_waf_response-init-init : 100\n# Begin rate-limiter Fastly Edge Rate Limiting\npenaltybox rl_origin_waf_response_pb {}\nratecounter rl_origin_waf_response_rc {}\n\ntable rl_origin_waf_response_methods {\n  \"GET\": \"true\",\n  \"PUT\": \"true\",\n  \"TRACE\": \"true\",\n  \"POST\": \"true\",\n  \"HEAD\": \"true\",\n  \"DELETE\": \"true\",\n  \"PATCH\": \"true\",\n  \"OPTIONS\": \"true\",\n}\n\n#### Start rate-limiter Fastly Edge Rate Limiting\nsub vcl_recv {\n    # call rl_origin_waf_response_process;\n      if (req.restarts == 0 && fastly.ff.visits_this_service == 0\n      && table.contains(rl_origin_waf_response_methods, req.method)\n      ) {\n        if (ratelimit.penaltybox_has(rl_origin_waf_response_pb, client.ip)) {\n            error 829 \"Rate limiter: Too many requests for origin_waf_response\";\n        }\n      }\n}\n#### End rate-limiter Fastly Edge Rate Limiting\n\n#### Start check backend response status code\nsub vcl_fetch {\n    # perform check based on the origin response. 206 status makes for easier testing and reporting\n    if (beresp.status == 406 || beresp.status == 206) {\n        log \"406 or 206 response\";\n        ratelimit.penaltybox_add(rl_origin_waf_response_pb, client.ip, 10m);\n    }\n}\n##### End check backend response status code\n\n# Useful troubleshooting based on the response - Start\n/* sub vcl_deliver {\n  if (req.http.fastly-debug == \"1\"){\n    set resp.http.X-ERL-PenaltyBox-has = ratelimit.penaltybox_has(rl_origin_waf_response_pb, client.ip);\n  }\n} */\n# Useful troubleshooting based on the response - End\n\nsub vcl_error {\n    # Snippet rate-limiter-v1-origin_waf_response-error-error : 100\n    # Begin rate-limiter Fastly Edge Rate Limiting - default edge rate limiting error - origin_waf_response\n  if (obj.status == 829 && obj.response == \"Rate limiter: Too many requests for origin_waf_response\") {\n    set obj.status = 429;\n    set obj.response = \"Too Many Requests\";\n    set obj.http.Content-Type = \"text/html\";\n    synthetic.base64 \"PGh0bWw+Cgk8aGVhZD4KCQk8dGl0bGU+VG9vIE1hbnkgUmVxdWVzdHM8L3RpdGxlPgoJPC9oZWFkPgoJPGJvZHk+CgkJPHA+VG9vIE1hbnkgUmVxdWVzdHMgdG8gdGhlIHNpdGU8L3A+Cgk8L2JvZHk+CjwvaHRtbD4=\";\n    return(deliver);\n  }\n    # End rate-limiter Fastly Edge Rate Limiting - default edge rate limiting error - origin_waf_response\n}\n"
    name     = "Origin Response Penalty Box"
    priority = 130
    type     = "init"
  }
  snippet {
    content  = "# https://docs.fastly.com/en/guides/temporarily-disabling-caching\nreturn(pass);\n"
    name     = "Disable caching"
    priority = 100
    type     = "recv"
  }
  snippet {
    content  = "\n# Snippet rate-limiter-v1-low_volume-init\npenaltybox rl_low_volume_pb {}\nratecounter rl_low_volume_rc {}\ntable rl_low_volume_methods {\n  \"GET\": \"true\",\n  \"PUT\": \"true\",\n  \"TRACE\": \"true\",\n  \"POST\": \"true\",\n  \"HEAD\": \"true\",\n  \"DELETE\": \"true\",\n  \"PATCH\": \"true\",\n  \"OPTIONS\": \"true\",\n}\n\n# use a seperate table for the ERL tuning\n\nsub rl_low_volume_process {\n  /* declare local var.rl_low_volume_window INTEGER; */\n  declare local var.rl_low_volume_limit INTEGER;\n  declare local var.rl_low_volume_entry STRING;\n  declare local var.rl_low_volume_delta INTEGER;\n  declare local var.rl_low_volume_60_sec_bucket_limit INTEGER;\n\n  # Check if the entry is greater than 0\n  /* if (table.lookup(login_edge_rate_limit_config, \"rl_low_volume_60_sec_bucket_limit\") > 0) { */\n  if (std.atoi(table.lookup(login_edge_rate_limit_config, \"rl_low_volume_60_sec_bucket_limit\")) > 0) {\n    set var.rl_low_volume_60_sec_bucket_limit = std.atoi(table.lookup(login_edge_rate_limit_config, \"rl_low_volume_60_sec_bucket_limit\"));\n  } else {\n    set var.rl_low_volume_60_sec_bucket_limit = 10 ;\n  }\n\n  set req.http.rl-limit = var.rl_low_volume_60_sec_bucket_limit;\n\n  # Set for debugging\n  set req.http.rl-low-volume-delta = var.rl_low_volume_delta;\n\n  set var.rl_low_volume_entry = req.http.rl-key;\n  if (req.restarts == 0 && fastly.ff.visits_this_service == 0\n      && table.contains(rl_low_volume_methods, req.method)\n      && table.contains(login_paths, std.tolower(req.url.path))\n      && std.strlen(var.rl_low_volume_entry) > 0\n      ) {\n\n    # https://developer.fastly.com/reference/vcl/functions/rate-limiting/ratelimit-ratecounter-increment/\n    # high risk\n    declare local var.rl_last_60_sec_bucket INTEGER;\n    if (req.http.high-risk || client.geo.proxy_description ~ \"^tor-\")  {\n      set var.rl_last_60_sec_bucket = ratelimit.ratecounter_increment(rl_low_volume_rc, var.rl_low_volume_entry, 3);\n    } else {\n      # not high risk\n      set var.rl_last_60_sec_bucket = ratelimit.ratecounter_increment(rl_low_volume_rc, var.rl_low_volume_entry, 1);\n    }\n   \n    if (ratecounter.rl_low_volume_rc.bucket.60s > var.rl_low_volume_60_sec_bucket_limit\n      && table.lookup(login_edge_rate_limit_config, \"blocking\") == \"true\") {\n      /* set req.http.Fastly-SEC-RateLimit = \"true\"; # Use for debugging */\n      /* set req.http.Fastly-erl-60-sec-bucket = ratecounter.rl_low_volume_rc.bucket.60s;  */\n      /* set req.http.Fastly-login-erl-limit = table.lookup(login_edge_rate_limit_config, \"login_edge_rate_limit_config\"); */\n      error 829 \"Rate limiter: Too many requests for low_volume\";\n    }\n  }\n}\n\nsub vcl_miss {\n    # Snippet rate-limiter-v1-low_volume-miss\n    call rl_low_volume_process;\n}\n\nsub vcl_pass {\n    # Snippet rate-limiter-v1-low_volume-pass\n    call rl_low_volume_process;\n}\n\n#### Debug Rate limit with lower volume traffic - ONLY USE FOR DEBUGGING SINCE THIS SENDS RATE COUNT INFORMATION BACK TO THE CLIENT\nsub vcl_deliver {\n  if(fastly.ff.visits_this_service == 0 && req.http.fastly-debug){\n    set resp.http.rl-limit = req.http.rl-limit;\n    set resp.http.rl-bucket-60 = ratecounter.rl_low_volume_rc.bucket.60s;\n    set resp.http.rl-delta = req.http.rl-low-volume-delta;\n  }  \n}\n\nsub vcl_error {\n    # Snippet rate-limiter-v1-low_volume-error\n    if (obj.status == 829 && obj.response == \"Rate limiter: Too many requests for low_volume\") {\n        set obj.status = 429;\n        set obj.response = \"Too Many Requests\";\n        set obj.http.Content-Type = \"text/html\";\n        synthetic.base64 \"PGh0bWw+CiAgICAgICAgPGhlYWQ+CiAgICAgICAgICAgICAgICA8dGl0bGU+VG9vIE1hbnkgUmVxdWVzdHM8L3RpdGxlPgogICAgICAgIDwvaGVhZD4KICAgICAgICA8Ym9keT4KICAgICAgICAgICAgICAgIDxwPlRvbyBNYW55IFJlcXVlc3RzIHRvIHRoZSBzaXRlLiBMViBFUkw8L3A+CiAgICAgICAgPC9ib2R5Pgo8L2h0bWw+\";\n        return(deliver);\n    }\n}"
    name     = "Low Volume Login Edge Rate Limiting"
    priority = 90
    type     = "init"
  }
  snippet {
    content  = "\n# Snippet rate-limiter-v1-orange_frodo-init\npenaltybox rl_orange_frodo_pb {}\nratecounter rl_orange_frodo_rc {}\ntable rl_orange_frodo_methods {\n  \"GET\": \"true\",\n  \"PUT\": \"true\",\n  \"TRACE\": \"true\",\n  \"POST\": \"true\",\n  \"HEAD\": \"true\",\n  \"DELETE\": \"true\",\n  \"PATCH\": \"true\",\n  \"OPTIONS\": \"true\",\n}\n\nsub rl_orange_frodo_process {\n  declare local var.rl_orange_frodo_limit INTEGER;\n  declare local var.rl_orange_frodo_window INTEGER;\n  declare local var.rl_orange_frodo_ttl TIME;\n  declare local var.rl_orange_frodo_entry STRING;\n  set var.rl_orange_frodo_limit = 10;\n  set var.rl_orange_frodo_window = 10;\n  set var.rl_orange_frodo_ttl = 4m;\n  \n  # Use the request header user-id for the rate limit key\n  set var.rl_orange_frodo_entry = req.http.user-id;\n  \n  if (req.restarts == 0 && fastly.ff.visits_this_service == 0\n      && table.contains(rl_orange_frodo_methods, req.method)\n      && req.http.user-id\n      ) {\n      #check rate for the request header user-id\n        if (ratelimit.check_rate(var.rl_orange_frodo_entry\n        , rl_orange_frodo_rc, 1\n        , var.rl_orange_frodo_window\n        , var.rl_orange_frodo_limit\n        , rl_orange_frodo_pb\n        , var.rl_orange_frodo_ttl)\n        ) {\n      set req.http.Fastly-SEC-RateLimit = \"true\";\n      error 829 \"Rate limiter: Too many requests for orange_frodo\";\n      }\n  }\n}\n\nsub vcl_miss {\n    # Snippet rate-limiter-v1-orange_frodo-miss\n    call rl_orange_frodo_process;\n}\n\nsub vcl_pass {\n    # Snippet rate-limiter-v1-orange_frodo-pass\n    call rl_orange_frodo_process;\n}\n\n# Only set response headers when debugging to avoid giving attackers additional information\n/* sub vcl_deliver {\n  set resp.http.rate = ratecounter.rl_orange_frodo_rc.rate.60s;\n  set resp.http.rate-counter = ratecounter.rl_orange_frodo_rc.bucket.60s;\n} */\n\nsub vcl_error {\n    # Snippet rate-limiter-v1-orange_frodo-error\n    if (obj.status == 829 && obj.response == \"Rate limiter: Too many requests for orange_frodo\") {\n        set obj.status = 429;\n        set obj.response = \"Too Many Requests\";\n        set obj.http.Content-Type = \"text/html\";\n        synthetic.base64 \"PGh0bWw+Cgk8aGVhZD4KCQk8dGl0bGU+VG9vIE1hbnkgUmVxdWVzdHM8L3RpdGxlPgoJPC9oZWFkPgoJPGJvZHk+CgkJPHA+VG9vIE1hbnkgUmVxdWVzdHMgdG8gdGhlIHNpdGU8L3A+Cgk8L2JvZHk+CjwvaHRtbD4=\";\n        return(deliver);\n    }\n}\n"
    name     = "Edge Rate Limit by user-id request header"
    priority = 110
    type     = "init"
  }
}

# __generated__ by Terraform
resource "fastly_service_vcl" "bot_detect" {
  activate           = null
  comment            = "Managed by Terraform"
  default_host       = null
  default_ttl        = 3600
  force_destroy      = null
  http3              = false
  name               = "bot-detect"
  reuse              = null
  stage              = null
  stale_if_error     = false
  stale_if_error_ttl = 43200
  version_comment    = null
  backend {} # sensitive
  condition {
    name      = "always_false"
    priority  = 10
    statement = "false"
    type      = "REQUEST"
  }
  domain {
    comment = null
    name    = "bot-detect.global.ssl.fastly.net"
  }
  domain {
    comment = "demo for bot detection"
    name    = "bot-detect.webbots.page"
  }
  snippet {
    content  = "    # Make sure we set proper content-type for the FST BSCAN\n    if (req.url.path == \"/fst_bscan.js\") {\n        set resp.http.Content-type = \"application/javascript; charset=utf-8\";\n    }\n    if (resp.http.Fastly-deny-check) {\n        set req.http.Fastly-deny-check = \"COMPLETED\";\n        if (resp.http.Fastly-deny-check-fingerprint) {\n            set req.http.Fastly-deny-check-fingerprint = resp.http.Fastly-deny-check-fingerprint;\n        }\n        if (resp.http.Fastly-deny-check-host) {\n            set req.http.Fastly-deny-check-host = resp.http.Fastly-deny-check-host;\n        }\n        if (resp.http.Fastly-wl-check-host) {\n            set req.http.Fastly-allow-check-host = resp.http.Fastly-allow-check-host;\n        }\n        return (restart);\n    }\n"
    name     = "botdetect_deliver"
    priority = 100
    type     = "deliver"
  }
  snippet {
    content  = "    if (obj.status == 701) {\n        call bot_deliver_work_unit;\n        return (deliver);\n    } else if (obj.status == 702) {\n        call bot_set_token;\n        return (deliver);\n    } else if (obj.status == 703) {\n        call bot_redirect;\n        return (deliver);\n    }"
    name     = "botdetect_error"
    priority = 100
    type     = "error"
  }
  snippet {
    content  = "# Don't restrict access for Googlebot\nif ( table.lookup(default_variables, \"search_engine_bot_bypass\", \"YES\") == \"YES\" &&\n    req.http.User-Agent ~ \"(?i)googlebot\" ) {\n\n  set req.http.botdetect-passed = \"1\";\n\n} else if ( req.http.User-Agent ~ \"(?i)fastlybot\" ) {\n\n  set req.http.botdetect-passed = \"1\";\n\n} else if ( req.http.Fastly-Client-IP ~ bad_reputation ) {\n  error 403;\n} else if ( table.lookup(default_variables, \"block_requests_from_public_clouds\", \"YES\") == \"YES\"\n        && table.lookup(public_clouds, client.as.number ) ) {\n  error 403;\n\n}\n"
    name     = "blocking"
    priority = 100
    type     = "recv"
  }
  snippet {
    content  = "# set the defaul variables\n\ntable default_variables {\n  \"block_requests_from_public_clouds\":  \"YES\",\n  \"seconds_to_solve_challenge\":         \"30\",\n  \"shared_secret\":                      \"mysuper-duper-secret-string\",\n  \"search_engine_bot_bypass\":           \"YES\",\n  \"static_assets_bot_bypass\":           \"YES\",\n  \"token_ttl\":                          \"3600\"\n}\n\n\nsub bot_set_token {\n    declare local var.token_data STRING;\n    declare local var.token_csum STRING;\n    declare local var.expire INTEGER;\n    declare local var.bytes STRING;\n\n    /*\n     * Our token conists of:\n     *\n     * expire time : browser fingerprint : client ip : random bytes\n     */\n    set var.expire = now;\n    /*\n     * NB: expire after 3600  seconds. We will want to increase this in !testing\n     */\n    set var.expire += std.atoi(table.lookup(default_variables, \"token_ttl\"));\n    set var.bytes = randomstr(10);\n    set var.token_data = var.expire + \":\" + req.http.X-bot-detect-browser-finger-print +\n        \":\" client.ip + \":\" + var.bytes;\n    set var.token_csum = digest.hmac_sha256(table.lookup(default_variables, \"shared_secret\"), var.token_data);\n    add obj.http.Set-Cookie = \"Fastly-bot-token=\" + var.expire \":\" +\n        req.http.X-bot-detect-browser-finger-print + \":\" + var.bytes + \":\" + var.token_csum;\n    set obj.http.Content-Type = \"text/json\";\n    set obj.status = 200;\n    set obj.http.Cache-control = \"max-age=0, no-cache, no-store, must-revalidate\";\n    synthetic {\" { \"url\" : \"\"} req.http.Referer {\"\" }\"};\n}\n\n/*\n * Extract some data from the cookie.  In this case the cookie doesn't have client.ip and\n * obviously the secret key required for the HMAC operation.\n */\nsub bot_validate_token {\n    declare local var.fingerprint STRING;\n    declare local var.timestamp INTEGER;\n    declare local var.bytes STRING;\n    declare local var.hmac STRING;\n    declare local var.csum STRING;\n\n    /*\n     * Make sure the cookie is in the format that we set.\n     */\n    if (req.http.Cookie:Fastly-bot-token !~ \"^(\\d+):([a-f0-9]+):([A-Za-z0-9_-]+):([a-f0-9x]+)\") {\n        set req.http.X-bot-detect-token-valid = \"FALSE\";\n        return;\n    }\n    set var.timestamp = std.atoi(re.group.1);\n    set var.fingerprint = re.group.2;\n    set var.bytes = re.group.3;\n    set var.hmac = re.group.4;\n    set var.csum = digest.hmac_sha256(table.lookup(default_variables, \"shared_secret\"), var.timestamp + \":\" +\n        var.fingerprint + \":\" + client.ip + \":\" var.bytes);\n    if (var.csum != var.hmac) {\n        set req.http.X-bot-detect-token-valid = \"FALSE\";\n        return;\n    }\n    if (time.is_after(now, std.integer2time(var.timestamp))) {\n        set req.http.X-bot-detect-token-valid = \"FALSE\";\n        return;\n    }\n    set req.http.X-bot-detect-token-valid = \"TRUE\";\n}\n\nsub bot_validate_work_unit {\n    declare local var.pow_expire INTEGER;\n\n    /*\n     * Validate the the proof of work solution matches the format that we are\n     * expecting. If not, immediately fail this request.\n     *\n     * Then we move on to check the expirey time, and make sure that the answer\n     * and supplied expirey were produced by us.\n     */\n    if (req.http.X-bot-detect-proof-of-work !~ \"^([A-Za-z0-9_-]+):(\\d+):([a-f0-9x]+)\") {\n        set req.http.X-work-unit-validated = \"FALSE\";\n        return;\n    }\n    set var.pow_expire = std.atoi(re.group.2);\n    if (digest.hmac_sha256(table.lookup(default_variables, \"shared_secret\"), re.group.1 + \":\" + re.group.2) != re.group.3) {\n        set req.http.X-work-unit-validated = \"FALSE\";\n        return;\n    }\n    if (time.is_after(now, std.integer2time(var.pow_expire))) {\n        set req.http.X-work-unit-validated = \"FALSE\";\n        return;\n    }\n    set req.http.X-work-unit-validated = \"TRUE\";\n}\n\nsub bot_deliver_work_unit {\n    declare local var.emit_challenge STRING;\n    declare local var.pow_hmac_data STRING;\n    declare local var.base_string STRING;\n    declare local var.full_string STRING;\n    declare local var.pow_hmac STRING;\n    declare local var.expire INTEGER;\n    declare local var.secret STRING;\n    declare local var.sum STRING;\n\n    set var.expire = now;\n    /*\n     * Give the user 5 seconds to solve this challenge. This should be ample\n     * time. In fact I think we should reduce this to 1-2 seconds.\n     */\n    set var.expire += std.atoi(table.lookup(default_variables, \"seconds_to_solve_challenge\", \"5\"));\n    /*\n     * Set the string that the user will have to find in order to calculate\n     * it's checksum.\n     */\n    set var.base_string = randomstr(10);\n    /*\n     * Make the challenge 2 bytes. Again, the point isn't necessarily to make this\n     * a difficult problem to solve, it's to prove that there is a javascript\n     * runtime which solved the problem. However, we need to add a counter to the\n     * cookie (or some other method) to identify brute force attacks.\n     */\n    set var.secret = randomstr(2);          /* Make the user brute force 2 bytes */\n    set var.full_string = var.base_string + var.secret;\n    set var.sum = digest.hash_sha256(var.full_string);\n    /*\n     * HMAC the answer and the expire time so we can ensure it hasn't been\n     * forged within the timeout period.\n     */\n    set var.pow_hmac_data = var.secret + \":\" var.expire;\n    set var.pow_hmac = digest.hmac_sha256(table.lookup(default_variables, \"shared_secret\"), var.pow_hmac_data);\n    /*\n     * This is the object that we will be inserting into the Javascript.\n     */\n    set var.emit_challenge = \"      var challenge = { expire: '\" + var.expire + \"', \" +\n        \"string: '\" + var.base_string + \"', \" +\n        \"hash: '\" + var.sum + \"', \" +\n        \"hmac: '\" + var.pow_hmac + \"' };\";\n    set obj.http.Content-Type = \"application/javascript; charset=utf-8\";\n    set obj.http.Cache-control = \"max-age=0, no-cache, no-store, must-revalidate\";\n    set obj.status = 200;\n    synthetic {\"\n    /*\n     * Bootstrap the fingerprint and proof of work javascript.\n     */\n    function brute_force(base_str, targ_hash) {\n        var lcase = \"abcdefghijklmnopqrstuvwxyz\";\n        var ucase = \"ABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n        var nums = \"0123456789\";\n        var charset = lcase + ucase + nums + \"_-\";\n\n        for (i = 0; i < charset.length; i++) {\n            for (k = 0; k < charset.length; k++) {\n                target = base_str + charset[i] + charset[k];\n                hash = sjcl.hash.sha256.hash(target);\n                hash_str = sjcl.codec.hex.fromBits(hash);\n                if (hash_str == targ_hash) {\n                    answer = charset[i] + charset[k];\n                    return (answer);\n                }\n            }\n        }\n        return (null);\n    }\n\n    function loadTest(x) {\n        new Fingerprint2().get(function(result, components){\n            console.log(result); //a hash, representing your device fingerprint\n            console.log(components); // an array of FP components\n        });\n        var fp = new Fingerprint2();\n        \"}        + var.emit_challenge + {\"\n        var answer = brute_force(challenge.string, challenge.hash);\n\n        fp.get(function(result, components) {\n            var req = new XMLHttpRequest();\n            req.open(\"GET\", '/dna.html');\n            req.setRequestHeader(\"X-bot-detect-browser-finger-print\", result);\n            pow_hdr_data = answer + \":\" + challenge.expire + \":\" + challenge.hmac;\n            req.setRequestHeader(\"X-bot-detect-proof-of-work\", pow_hdr_data);\n            for (var index in components) {\n                var obj = components[index];\n                var key = obj.key;\n                if (key === 'canvas') {\n                    req.setRequestHeader(\"X-bot-detect-canvas-set\", \"true\");\n                    continue;\n                }\n                if (key === 'webgl') {\n                    req.setRequestHeader(\"X-bot-detect-webgl-set\", \"true\");\n                    continue;\n                }\n                var value = obj.value;\n                new_header = 'X-bot-detect-' + key;\n                req.setRequestHeader(new_header, value.toString());\n            }\n            req.onreadystatechange = function() {\n                if (req.readyState == XMLHttpRequest.DONE && req.status == 200) {\n                    var obj = JSON.parse(this.responseText);\n                    rd_url = obj['url'];\n                    /*\n                     * If the Referer is /botcheck.html, do nothing otherwise\n                     * this will result in a loop.\n                     */\n                    /* NB: this check is probably bogus now. */\n                    if (!rd_url.endsWith(\"/botcheck.html\")) {\n                        window.location.replace(obj[\"url\"]);\n                    } else {\n                        document.write('<html><h1>Hi</h1></html>');\n                    }\n                }\n            }\n            req.send()\n        });\n    }\n    window.onload = loadTest;\n\"};\n}\n\nsub bot_redirect {\n    set obj.http.Content-Type = \"text/html; charset=utf-8\";\n    set obj.http.Cache-control = \"max-age=0, no-cache, no-store, must-revalidate\";\n    set obj.status = 505;\n    synthetic {\"<!DOCTYPE html>\n<script src=\"/sjcl.js\"></script>\n<script src=\"/b-bootstrap\" type=\"application/javascript\"></script>\n<script src=\"/fst_bscan.js\" type=\"application/javascript\"></script>\n<noscript>\nYou need Javascript enabled to use this site.\n</noscript>\n<html>\n<body>\n<p>Validating your browser... </p>\n</body>\n</html>\n    \"};\n}\n\n/*\n * This is the main validation sub routine. This function will check for the\n * following data-points:\n *\n * - Is the IP address associated with this request allow listed\n * - Is the IP address associated with this request deny listed\n * - Is the fingerprint associated with this host deny listed\n * - Is the fingerprint a hash\n * - Does the reported User Agent the same as the user agent as detected\n *   by the javascript runtime\n * - Has the color depth been detected in the javascript runtime, and is\n *   it an integer\n * - Does the User agent match our list of \"standard\" browsers\n * - Is the reported time zone offset appropriate based on the TZ associated\n *   with known GEO IP data\n */\nsub bot_validate_dna {\n    declare local var.bot_threshold INTEGER;\n    declare local var.bot_score INTEGER;\n    declare local var.ip_tz INTEGER;\n    declare local var.h_tz INTEGER;\n\n    set req.http.X-bot-detected = \"FALSE\";\n    /*\n     * NB: These variables should be tunable.\n     */\n    set var.bot_threshold = 30;\n    set var.bot_score = 0;\n    /*\n     * First check to see if this client has been white listed. If so\n     * immediately return.\n     */\n    if (req.http.Fastly-allow-check-host && req.http.Fastly-allow-check-host == \"FOUND\") {\n        set req.http.X-bot-detected = \"FALSE\";\n        return;\n    }\n    /*\n     * A match of any deny list item is an immediate drop.\n     */\n    if (req.http.Fastly-deny-check-fingerprint &&\n      req.http.Fastly-deny-check-fingerprint == \"FOUND\") {\n        set var.bot_score += var.bot_threshold;\n    }\n    if (req.http.Fastly-deny-check-host &&\n      req.http.Fastly-deny-check-host == \"FOUND\") {\n        set var.bot_score += var.bot_threshold;\n    }\n    /*\n     * Check to make sure the checksum field contains only hex characters.\n     * We could probably be more specific based on which algorithm is used.\n     */\n    if (!req.http.X-bot-detect-browser-finger-print ~ \"^[[:xdigit:]]+$\") {\n        set var.bot_score += var.bot_threshold;\n    }\n    /*\n     * If the User-Agent header is not the same X-bot-detect-user_agent\n     * increment the score by 5 (this is sort of arbitrary for now).\n     */\n    if (req.http.User-Agent != req.http.X-bot-detect-user_agent) {\n        set var.bot_score += 5;\n    }\n    /*\n     * Check to see if the color depth header has been specified.\n     */\n    if (!req.http.X-bot-detect-color_depth) {\n        set var.bot_score += 5;\n    }\n    /*\n     * Check for canvas and web GL related data picked up by the fingerprinting process.\n     */\n    if (!req.http.X-bot-detect-canvas-set) {\n        set var.bot_score += 15;\n    }\n    if (!req.http.X-bot-detect-webgl-set) {\n        set var.bot_score += 15;\n    }\n    /*\n     * Make sure this is numeric, ideally we should constrain this to the\n     * standard color depths.\n     */\n    if (req.http.X-bot-detect-color_depth !~ \"^[0-9]+$\") {\n        set var.bot_score += 5;\n    }\n    /*\n     * Check to see if the standard browsers are reported in the user-agent\n     */\n    if (req.http.X-bot-detect-user_agent !~ \"(Windows NT|Safari|Chrome|Firefox)\") {\n        set var.bot_score += 10;\n    }\n    /*\n     * Finally check the reported timezone against where this device currently resides.\n     *\n     * the DE database will represent CST as 600 (6 hour offset). Convert it to the\n     * number of hours.  The browser reports time zone offset in units of minutes, so\n     * we will also have to convert this to hours.\n     */\n    set var.ip_tz = std.atoi(client.geo.gmt_offset);\n    set var.ip_tz /= 100;\n    set var.h_tz = std.atoi(req.http.X-bot-detect-timezone_offset);\n    set var.h_tz /= 60;\n    if (var.h_tz != var.ip_tz) {\n        /*\n         * NB:\n         * It's possible that the direction isn't specified by the browser.\n         * If this is the case, take the ABS of the database supplied value and\n         * use that instead.\n         */\n        if (var.ip_tz < 0) {\n            set var.ip_tz *= -1;\n            if (var.h_tz != var.ip_tz) {\n                set var.bot_score += 5;\n\n            }\n        } else {\n            set var.bot_score += 5;\n        }\n    }\n    if (var.bot_score >= var.bot_threshold) {\n        set req.http.X-bot-detected = \"TRUE\";\n\n    }\n}\n\nsub bot_check_init {\n    /*\n     * Fetch the fingerprinting and sha256 code right away.\n     */\n    if (req.url.path == \"/fst_bscan.js\") {\n        return;\n    }\n    if (req.url.path == \"/b-bootstrap\") {\n        error 701 \"OK\";\n    }\n    # if (req.request == \"GET\" && req.url.path == \"/dna.html\" && !req.http.Fastly-deny-check) {\n    #if (req.request == \"GET\" && req.url.path == \"/dna.html\") {\n    #    set req.http.get-dna = \"1\";\n    #    return;\n    #}\n    #if (req.http.X-bot-detect-proof-of-work && req.request == \"GET\" && req.url.path == \"/dna.html\") {\n    if (req.request == \"GET\" && req.url.path == \"/dna.html\") {\n        /*\n         * Check to see if the supplied work unit was solved.\n         */\n        call bot_validate_work_unit;\n        if (req.http.X-work-unit-validated == \"FALSE\") {\n            error 703 \"VALIDATE_WORK_UNIT\";\n        }\n        call bot_validate_dna;\n        if (req.http.X-bot-detected == \"TRUE\") {\n            error 703 \"VALIDATE_DNA\";\n            return;\n        }\n        error 702 \"OK\";\n    }\n    if (req.http.Cookie:Fastly-bot-token) {\n        call bot_validate_token;\n        if (req.http.X-bot-detect-token-valid == \"FALSE\") {\n            set req.http.anything-else = \"bot token called\";\n            error 703 \"VALIDATE_TOKEN\";\n        }\n    } else {\n        if (req.url.path != \"/dna.html\" && req.url.path != \"/botcheck.html\" && req.url.path != \"/fst_bscan.js\") {\n            set req.http.anything-else = \"703\";\n            error 703 \"ANYTHING_ELSE\";\n        }\n    }\n}\n"
    name     = "botdetect_init"
    priority = 100
    type     = "init"
  }
  snippet {
    content  = "#acl bots {\n#\t\"1.2.3.4\"/24;\n#\t\"10.0.0.0\"/8;\n#}\n\nacl bad_reputation {\n\"1.192.128.23\";\n\"1.214.119.227\";\n\"1.234.20.151\";\n\"1.34.22.39\";\n\"101.251.205.250\";\n\"101.254.149.143\";\n\"101.99.70.200\";\n\"103.1.112.232\";\n\"103.196.100.66\";\n\"103.249.28.142\";\n\"104.128.144.130\";\n\"104.128.144.131\";\n\"104.192.0.18\";\n\"104.192.0.226\";\n\"104.192.103.3\";\n\"104.193.9.236\";\n\"104.194.26.204\";\n\"104.194.26.205\";\n\"104.208.237.78\";\n\"104.219.250.4\";\n\"104.238.223.126\";\n\"104.243.129.210\";\n\"104.243.129.98\";\n\"104.243.24.211\";\n\"104.243.47.26\";\n\"104.245.97.236\";\n\"104.255.65.207\";\n\"104.255.68.139\";\n\"104.42.122.55\";\n\"106.184.3.122\";\n\"106.187.39.193\";\n\"106.187.47.170\";\n\"106.240.247.220\";\n\"106.39.95.194\";\n\"106.7.248.207\";\n\"107.150.45.106\";\n\"107.23.190.198\";\n\"108.170.62.10\";\n\"108.175.8.214\";\n\"109.163.234.2\";\n\"109.201.154.170\";\n\"109.228.29.175\";\n\"109.75.185.95\";\n\"110.228.91.64\";\n\"110.93.14.68\";\n\"111.12.13.225\";\n\"112.124.115.185\";\n\"113.204.53.134\";\n\"114.97.77.139\";\n\"115.230.124.201\";\n\"116.211.0.90\";\n\"117.18.73.66\";\n\"117.21.226.160\";\n\"118.46.132.81\";\n\"118.81.102.118\";\n\"118.98.104.21\";\n\"119.145.148.211\";\n\"119.188.4.3\";\n\"119.59.122.169\";\n\"119.97.146.76\";\n\"120.132.72.217\";\n\"120.132.77.5\";\n\"120.26.221.37\";\n\"121.14.5.125\";\n\"121.196.232.155\";\n\"121.207.230.74\";\n\"121.237.195.33\";\n\"121.40.129.82\";\n\"123.184.16.88\";\n\"123.220.251.190\";\n\"124.90.52.42\";\n\"125.253.123.194\";\n\"125.64.35.67\";\n\"125.64.35.68\";\n\"130.0.233.146\";\n\"130.185.155.10\";\n\"130.185.155.74\";\n\"130.185.155.82\";\n\"132.248.44.99\";\n\"134.249.55.157\";\n\"137.226.113.7\";\n\"14.139.82.140\";\n\"14.63.160.219\";\n\"140.117.53.39\";\n\"141.138.168.124\";\n\"141.212.121.10\";\n\"141.212.122.112\";\n\"141.212.122.129\";\n\"141.212.122.160\";\n\"141.212.122.177\";\n\"141.212.122.209\";\n\"141.212.122.64\";\n\"141.212.122.96\";\n\"141.212.122.98\";\n\"141.85.227.117\";\n\"142.54.184.181\";\n\"142.54.186.26\";\n\"144.168.45.117\";\n\"146.0.36.43\";\n\"146.185.239.100\";\n\"146.185.253.103\";\n\"149.202.52.100\";\n\"149.202.60.88\";\n\"151.217.177.200\";\n\"151.236.57.57\";\n\"151.248.0.118\";\n\"151.80.22.111\";\n\"151.80.96.140\";\n\"157.55.39.235\";\n\"158.85.125.245\";\n\"159.122.222.194\";\n\"159.8.93.184\";\n\"161.202.41.12\";\n\"162.144.87.81\";\n\"162.213.251.154\";\n\"162.243.239.246\";\n\"162.246.61.20\";\n\"162.247.72.200\";\n\"162.253.66.50\";\n\"163.172.13.173\";\n\"163.47.75.50\";\n\"166.78.185.218\";\n\"167.114.247.58\";\n\"168.63.60.33\";\n\"169.229.3.91\";\n\"169.50.3.171\";\n\"169.53.185.151\";\n\"169.55.151.117\";\n\"171.25.193.20\";\n\"171.25.193.77\";\n\"171.8.63.71\";\n\"172.82.149.130\";\n\"172.82.149.234\";\n\"173.193.12.5\";\n\"173.193.157.42\";\n\"173.208.177.59\";\n\"173.208.182.149\";\n\"173.208.194.98\";\n\"173.242.118.66\";\n\"173.254.236.58\";\n\"174.120.70.217\";\n\"175.102.9.100\";\n\"175.126.111.78\";\n\"176.10.104.243\";\n\"176.10.99.205\";\n\"176.103.48.38\";\n\"176.58.100.98\";\n\"176.8.88.197\";\n\"177.129.90.37\";\n\"177.43.63.141\";\n\"177.81.201.200\";\n\"178.137.160.226\";\n\"178.137.81.70\";\n\"178.137.84.60\";\n\"178.137.85.67\";\n\"178.162.214.34\";\n\"178.20.55.18\";\n\"178.239.50.139\";\n\"178.239.50.140\";\n\"178.33.189.175\";\n\"179.43.134.2\";\n\"179.99.200.39\";\n\"180.150.227.242\";\n\"180.150.227.246\";\n\"180.153.127.23\";\n\"180.186.121.254\";\n\"180.97.106.162\";\n\"180.97.106.36\";\n\"180.97.106.37\";\n\"181.177.20.14\";\n\"181.177.20.15\";\n\"181.214.92.100\";\n\"182.118.53.176\";\n\"182.118.53.198\";\n\"182.118.54.58\";\n\"183.60.243.187\";\n\"183.60.243.188\";\n\"183.60.243.189\";\n\"183.60.243.190\";\n\"183.60.244.29\";\n\"183.60.244.30\";\n\"183.60.244.37\";\n\"183.60.244.44\";\n\"183.60.244.46\";\n\"183.60.244.49\";\n\"184.154.150.120\";\n\"184.169.148.148\";\n\"184.172.196.102\";\n\"184.172.196.106\";\n\"184.73.254.168\";\n\"185.103.252.98\";\n\"185.106.92.36\";\n\"185.106.92.47\";\n\"185.106.94.2\";\n\"185.106.94.91\";\n\"185.112.102.222\";\n\"185.124.85.162\";\n\"185.129.148.205\";\n\"185.130.5.207\";\n\"185.130.5.208\";\n\"185.130.5.224\";\n\"185.130.5.235\";\n\"185.130.5.244\";\n\"185.130.5.247\";\n\"185.23.21.17\";\n\"185.25.148.240\";\n\"185.25.151.159\";\n\"185.26.122.13\";\n\"185.35.62.11\";\n\"185.49.14.190\";\n\"185.49.15.23\";\n\"185.5.222.171\";\n\"185.62.189.162\";\n\"185.62.190.55\";\n\"185.93.187.46\";\n\"187.45.193.161\";\n\"187.63.160.3\";\n\"188.132.230.14\";\n\"188.138.1.218\";\n\"188.138.17.205\";\n\"188.138.56.180\";\n\"188.138.9.49\";\n\"188.138.9.50\";\n\"188.143.233.136\";\n\"188.143.234.53\";\n\"188.165.248.41\";\n\"188.165.61.65\";\n\"188.227.200.2\";\n\"188.39.46.35\";\n\"188.42.240.119\";\n\"190.121.21.211\";\n\"190.145.38.2\";\n\"190.147.34.47\";\n\"190.214.21.185\";\n\"190.78.49.210\";\n\"192.129.227.26\";\n\"192.157.201.202\";\n\"192.168.1.199\";\n\"192.168.105.36\";\n\"192.185.4.97\";\n\"192.187.110.98\";\n\"192.187.123.109\";\n\"192.3.207.66\";\n\"192.42.116.16\";\n\"192.99.149.88\";\n\"193.105.21.30\";\n\"193.109.69.251\";\n\"193.189.117.62\";\n\"193.201.224.130\";\n\"193.201.227.139\";\n\"193.201.227.21\";\n\"193.239.80.37\";\n\"193.25.195.151\";\n\"193.34.144.188\";\n\"194.102.125.196\";\n\"194.150.168.95\";\n\"194.90.160.133\";\n\"195.114.18.146\";\n\"195.122.2.196\";\n\"195.142.3.116\";\n\"195.154.102.211\";\n\"195.154.199.235\";\n\"195.154.232.169\";\n\"195.154.235.55\";\n\"195.154.240.146\";\n\"195.154.240.184\";\n\"195.154.240.246\";\n\"195.154.241.119\";\n\"195.154.241.166\";\n\"195.154.241.35\";\n\"195.154.241.43\";\n\"195.154.251.120\";\n\"195.154.251.17\";\n\"195.206.253.146\";\n\"195.211.155.156\";\n\"195.211.155.184\";\n\"195.22.126.220\";\n\"195.228.45.176\";\n\"195.242.155.100\";\n\"195.246.192.46\";\n\"195.3.144.124\";\n\"195.3.144.125\";\n\"195.3.144.84\";\n\"195.3.144.88\";\n\"195.3.144.92\";\n\"195.62.53.168\";\n\"197.231.221.211\";\n\"198.1.110.182\";\n\"198.12.87.151\";\n\"198.12.87.153\";\n\"198.154.63.131\";\n\"198.20.69.74\";\n\"198.20.69.98\";\n\"198.20.70.114\";\n\"198.20.99.130\";\n\"198.204.252.252\";\n\"198.23.176.210\";\n\"198.55.103.19\";\n\"198.57.247.144\";\n\"199.115.117.88\";\n\"199.180.112.34\";\n\"199.180.114.150\";\n\"199.180.114.241\";\n\"199.187.124.84\";\n\"199.188.195.53\";\n\"199.21.112.162\";\n\"199.48.147.139\";\n\"2.115.68.148\";\n\"2.139.237.110\";\n\"2.238.115.47\";\n\"2.51.79.62\";\n\"200.178.96.86\";\n\"201.139.224.7\";\n\"201.166.181.230\";\n\"201.27.147.112\";\n\"201.99.46.26\";\n\"202.100.219.52\";\n\"202.109.143.18\";\n\"202.183.165.42\";\n\"202.191.57.118\";\n\"203.162.15.233\";\n\"203.191.48.209\";\n\"203.195.163.188\";\n\"203.195.184.151\";\n\"203.72.116.27\";\n\"204.15.135.116\";\n\"204.8.156.142\";\n\"205.186.157.81\";\n\"207.239.189.5\";\n\"208.100.26.230\";\n\"208.101.2.227\";\n\"208.115.111.75\";\n\"208.52.154.240\";\n\"208.52.154.243\";\n\"208.52.161.177\";\n\"208.52.161.99\";\n\"208.66.72.154\";\n\"208.83.121.3\";\n\"209.126.230.71\";\n\"209.17.114.78\";\n\"209.92.176.24\";\n\"210.72.142.101\";\n\"211.152.36.135\";\n\"211.172.232.163\";\n\"211.22.149.31\";\n\"211.220.63.148\";\n\"212.172.221.89\";\n\"212.200.246.24\";\n\"212.234.152.117\";\n\"212.48.68.133\";\n\"212.48.87.19\";\n\"212.59.30.110\";\n\"212.82.217.9\";\n\"212.83.149.123\";\n\"212.83.181.236\";\n\"212.83.182.10\";\n\"213.128.67.90\";\n\"213.128.81.66\";\n\"213.135.93.46\";\n\"213.136.69.149\";\n\"213.136.71.178\";\n\"213.202.212.166\";\n\"213.208.191.70\";\n\"213.251.182.102\";\n\"213.251.182.105\";\n\"213.251.182.107\";\n\"213.251.182.110\";\n\"213.251.182.111\";\n\"213.251.182.113\";\n\"213.251.182.115\";\n\"213.30.120.214\";\n\"213.56.130.38\";\n\"216.17.102.64\";\n\"216.18.231.50\";\n\"216.55.186.43\";\n\"216.70.91.214\";\n\"217.114.212.26\";\n\"217.144.201.243\";\n\"217.31.48.30\";\n\"217.71.50.24\";\n\"217.79.62.98\";\n\"218.152.216.82\";\n\"218.36.126.226\";\n\"218.59.238.92\";\n\"218.59.238.93\";\n\"218.77.79.43\";\n\"219.223.252.93\";\n\"219.232.247.108\";\n\"220.128.102.223\";\n\"220.133.59.53\";\n\"220.133.85.35\";\n\"220.134.5.148\";\n\"220.167.100.13\";\n\"220.170.89.93\";\n\"220.178.252.141\";\n\"221.11.92.253\";\n\"221.143.48.160\";\n\"221.231.6.246\";\n\"221.3.153.172\";\n\"222.141.64.65\";\n\"222.178.90.21\";\n\"222.186.15.200\";\n\"222.186.21.115\";\n\"222.186.21.179\";\n\"222.186.21.70\";\n\"222.186.30.225\";\n\"222.186.31.57\";\n\"222.186.34.23\";\n\"222.186.34.94\";\n\"222.216.28.248\";\n\"222.236.47.141\";\n\"222.66.95.253\";\n\"222.73.18.162\";\n\"222.74.212.77\";\n\"222.75.33.167\";\n\"222.76.242.219\";\n\"223.105.1.104\";\n\"23.21.128.200\";\n\"23.21.146.201\";\n\"23.238.187.66\";\n\"23.94.150.226\";\n\"23.94.17.82\";\n\"23.94.97.41\";\n\"23.95.12.210\";\n\"27.255.81.146\";\n\"27.255.94.166\";\n\"31.184.194.114\";\n\"31.184.195.114\";\n\"31.192.108.62\";\n\"31.193.239.215\";\n\"31.204.152.111\";\n\"35.0.127.52\";\n\"37.130.227.133\";\n\"37.187.114.171\";\n\"37.187.129.166\";\n\"37.187.135.6\";\n\"37.187.159.92\";\n\"37.187.173.167\";\n\"37.187.243.209\";\n\"37.187.48.15\";\n\"37.187.78.222\";\n\"37.239.46.26\";\n\"37.48.73.19\";\n\"37.57.231.112\";\n\"37.58.75.46\";\n\"37.59.232.247\";\n\"40.114.43.252\";\n\"43.240.30.141\";\n\"45.35.20.199\";\n\"45.41.87.190\";\n\"45.41.92.66\";\n\"45.43.239.2\";\n\"45.43.239.3\";\n\"46.118.118.215\";\n\"46.119.117.47\";\n\"46.148.18.122\";\n\"46.148.18.162\";\n\"46.148.22.18\";\n\"46.148.22.26\";\n\"46.151.212.26\";\n\"46.165.220.215\";\n\"46.172.71.251\";\n\"46.174.191.28\";\n\"46.183.221.142\";\n\"46.25.29.221\";\n\"46.28.105.88\";\n\"46.28.206.148\";\n\"46.4.73.171\";\n\"5.10.68.248\";\n\"5.10.68.254\";\n\"5.153.233.130\";\n\"5.153.234.154\";\n\"5.189.140.14\";\n\"5.189.171.97\";\n\"5.196.109.77\";\n\"5.39.220.3\";\n\"5.8.66.78\";\n\"50.22.0.250\";\n\"50.23.69.44\";\n\"50.243.11.125\";\n\"50.30.35.150\";\n\"50.62.208.106\";\n\"51.254.126.85\";\n\"54.164.191.103\";\n\"54.170.156.84\";\n\"54.204.47.156\";\n\"54.207.20.82\";\n\"54.213.13.85\";\n\"54.217.236.195\";\n\"54.235.163.229\";\n\"54.67.38.74\";\n\"58.118.96.33\";\n\"58.177.86.10\";\n\"58.213.123.107\";\n\"58.220.25.99\";\n\"58.26.128.114\";\n\"59.120.146.182\";\n\"59.174.47.194\";\n\"59.46.12.28\";\n\"60.12.119.200\";\n\"60.13.214.247\";\n\"60.164.173.49\";\n\"61.138.252.235\";\n\"61.147.103.173\";\n\"61.147.103.184\";\n\"61.147.107.107\";\n\"61.160.213.56\";\n\"61.160.222.61\";\n\"61.160.224.128\";\n\"61.160.247.153\";\n\"61.160.247.7\";\n\"61.161.130.242\";\n\"61.178.42.254\";\n\"61.182.202.57\";\n\"61.183.118.225\";\n\"61.19.246.190\";\n\"61.216.2.13\";\n\"61.216.2.14\";\n\"61.91.45.50\";\n\"62.109.22.253\";\n\"62.149.143.72\";\n\"62.210.162.209\";\n\"62.210.162.37\";\n\"62.210.185.3\";\n\"62.210.69.173\";\n\"62.210.74.47\";\n\"62.210.84.109\";\n\"62.210.88.201\";\n\"63.131.141.125\";\n\"64.111.126.33\";\n\"64.15.155.177\";\n\"64.16.209.152\";\n\"64.34.173.227\";\n\"64.38.225.100\";\n\"64.95.98.10\";\n\"64.95.98.11\";\n\"64.95.98.210\";\n\"64.95.98.214\";\n\"65.223.61.122\";\n\"65.39.211.243\";\n\"66.117.2.30\";\n\"66.135.38.206\";\n\"66.240.192.138\";\n\"66.240.236.119\";\n\"66.71.247.94\";\n\"67.159.16.2\";\n\"67.176.111.74\";\n\"67.207.202.9\";\n\"68.67.61.254\";\n\"69.12.77.220\";\n\"69.162.105.66\";\n\"69.174.245.163\";\n\"69.197.148.68\";\n\"69.197.148.87\";\n\"69.197.148.92\";\n\"69.64.46.86\";\n\"70.196.199.221\";\n\"71.189.24.112\";\n\"71.6.135.131\";\n\"71.6.165.200\";\n\"71.6.167.142\";\n\"72.18.138.178\";\n\"72.251.234.218\";\n\"72.251.243.50\";\n\"72.4.143.205\";\n\"72.46.141.58\";\n\"72.9.231.226\";\n\"73.51.25.178\";\n\"74.208.125.220\";\n\"74.208.173.136\";\n\"74.208.70.95\";\n\"75.98.36.146\";\n\"76.164.201.226\";\n\"76.65.198.63\";\n\"77.109.141.138\";\n\"77.221.130.7\";\n\"77.236.97.247\";\n\"77.247.181.162\";\n\"77.247.181.163\";\n\"77.247.181.165\";\n\"78.110.50.106\";\n\"78.129.148.77\";\n\"78.153.217.212\";\n\"78.158.180.106\";\n\"79.96.13.179\";\n\"79.96.220.97\";\n\"80.29.126.199\";\n\"80.73.9.164\";\n\"80.80.161.88\";\n\"80.82.64.145\";\n\"80.82.64.68\";\n\"80.82.65.186\";\n\"80.82.70.106\";\n\"80.82.70.112\";\n\"80.82.78.170\";\n\"80.82.78.87\";\n\"81.17.16.170\";\n\"81.177.24.60\";\n\"81.213.206.174\";\n\"81.248.4.225\";\n\"81.89.96.88\";\n\"82.146.36.221\";\n\"82.165.15.29\";\n\"82.213.78.2\";\n\"82.220.38.16\";\n\"82.221.105.6\";\n\"82.221.105.7\";\n\"82.223.22.211\";\n\"82.69.59.67\";\n\"83.240.166.127\";\n\"83.96.132.85\";\n\"84.240.9.6\";\n\"85.113.38.80\";\n\"85.114.141.217\";\n\"85.128.142.48\";\n\"85.128.142.49\";\n\"85.131.207.5\";\n\"85.204.118.142\";\n\"85.214.137.45\";\n\"85.214.149.179\";\n\"85.25.103.119\";\n\"85.25.103.50\";\n\"85.25.43.94\";\n\"85.31.185.2\";\n\"85.52.193.116\";\n\"85.65.3.186\";\n\"87.117.204.95\";\n\"88.198.14.171\";\n\"88.202.224.162\";\n\"89.161.195.11\";\n\"89.163.209.4\";\n\"89.163.251.200\";\n\"89.187.142.208\";\n\"89.221.250.27\";\n\"89.234.157.254\";\n\"89.248.160.132\";\n\"89.248.160.196\";\n\"89.248.160.212\";\n\"89.248.168.192\";\n\"89.248.171.139\";\n\"89.248.171.167\";\n\"89.248.171.2\";\n\"89.248.172.169\";\n\"89.248.172.175\";\n\"89.248.172.27\";\n\"89.248.172.35\";\n\"89.248.174.4\";\n\"89.46.100.144\";\n\"91.121.133.87\";\n\"91.121.18.214\";\n\"91.121.202.95\";\n\"91.142.209.68\";\n\"91.196.50.33\";\n\"91.197.32.185\";\n\"91.200.12.11\";\n\"91.200.12.114\";\n\"91.200.12.127\";\n\"91.200.12.139\";\n\"91.200.12.14\";\n\"91.200.12.18\";\n\"91.200.12.22\";\n\"91.200.12.26\";\n\"91.200.12.29\";\n\"91.200.12.4\";\n\"91.200.12.52\";\n\"91.200.12.53\";\n\"91.200.12.54\";\n\"91.200.12.55\";\n\"91.200.12.56\";\n\"91.200.12.61\";\n\"91.200.12.63\";\n\"91.200.12.65\";\n\"91.200.12.7\";\n\"91.200.12.71\";\n\"91.200.12.8\";\n\"91.200.12.9\";\n\"91.200.12.92\";\n\"91.200.12.95\";\n\"91.200.13.64\";\n\"91.207.5.222\";\n\"91.207.7.178\";\n\"91.208.99.2\";\n\"91.212.124.160\";\n\"91.217.90.49\";\n\"91.218.125.66\";\n\"91.224.160.13\";\n\"91.227.100.17\";\n\"91.229.76.13\";\n\"91.236.75.4\";\n\"91.238.134.154\";\n\"91.239.67.141\";\n\"91.90.15.118\";\n\"92.222.15.140\";\n\"92.243.29.148\";\n\"92.63.133.65\";\n\"93.104.208.162\";\n\"93.113.125.11\";\n\"93.115.92.169\";\n\"93.120.27.62\";\n\"93.158.200.15\";\n\"93.158.200.34\";\n\"93.158.200.40\";\n\"93.174.93.119\";\n\"93.174.93.129\";\n\"93.174.93.146\";\n\"93.174.93.149\";\n\"93.174.93.192\";\n\"93.174.93.241\";\n\"93.174.93.33\";\n\"93.174.95.55\";\n\"93.174.95.64\";\n\"93.174.95.81\";\n\"93.180.68.68\";\n\"94.102.49.168\";\n\"94.102.49.169\";\n\"94.102.49.31\";\n\"94.102.49.79\";\n\"94.102.49.82\";\n\"94.102.51.30\";\n\"94.102.60.183\";\n\"94.102.63.155\";\n\"94.138.219.186\";\n\"94.185.83.100\";\n\"94.228.215.83\";\n\"94.23.12.209\";\n\"94.23.247.86\";\n\"94.23.28.193\";\n\"94.231.108.221\";\n\"94.242.246.23\";\n\"94.73.142.106\";\n\"94.73.148.218\";\n\"95.111.68.120\";\n\"95.172.83.162\";\n\"95.172.83.90\";\n\"95.211.229.158\";\n\"96.44.179.242\";\n}\n"
    name     = "bad_reputation"
    priority = 100
    type     = "init"
  }
  snippet {
    content  = "if (req.restarts == 0) { \n    unset req.http.bot-detect-passed;\n}\n\nif ( table.lookup(public_clouds, client.as.number ) ) {\n    error 770 \"botdetect:public_clouds\";\n}\n\nif ( req.http.User-Agent ~ \"(?i)googlebot\" && req.http.Fastly-Client-IP ~ \"googlebot\" ) {\n    set req.http.botdetect-passed = \"1\";\n} else if ( req.http.User-Agent ~ \"(?i)bingbot\" && client.as.number == 8075 ) {\n    set req.http.botdetect-passed = \"1\";\n}\n\nif (req.url.path == \"/fst_bscan.js\" || req.url.path == \"/sjcl.js\") {\n   set req.backend = F_fingerprint_storage;\n   set req.http.host = \"fastly-bot-detection.global.ssl.fastly.net\";\n   return(lookup);\n}\n\nunset req.http.get-dna;\n\nset req.http.visits_this_service = fastly.ff.visits_this_service;\n\nif ( fastly.ff.visits_this_service == 0 ) {\n  # set req.http.1-bot-visits-is-zero = \"zero\";\n\n  # Things that are in the long cache are static assets and should not be checked\n  # if (req.http.x-long-cache || req.url.path ~ \"^/(pub/)?(media|static)/.*\") {\n  #    set req.http.1-botdetect-passed = \"1\";\n  # }\n#############################################################################################\n  # Should we bypass bot detection for static files. This is useful is people are embedding \n  # your URL from external sources\n  if ( table.lookup(default_variables, \"static_assets_bot_bypass\", \"YES\") == \"YES\"\n    && req.url.ext ~ \"(?i)(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)\") {\n    # do nothing\n    # set req.http.1-bot-do-nothing = \"recv\";\n  } else {\n\n    if ( !req.http.botdetect-passed ) {\n      # set req.http.1-bot-check-init = \"calling_in_recv\";\n      call bot_check_init;\n    }\n  }\n}"
    name     = "botdetect_recv"
    priority = 100
    type     = "recv"
  }
  snippet {
    content  = "table public_clouds {\n\"16509\": \"1\",\n\"8075\": \"1\",\n\"20473\": \"1\",\n\"202109\": \"1\",\n\"202018\": \"1\",\n\"201229\": \"1\",\n\"200130\": \"1\",\n\"135340\": \"1\",\n\"133165\": \"1\",\n\"14061\": \"1\",\n\"62567\": \"1\",\n\"393406\": \"1\",\n\"37153\": \"1\",\n\"24940\": \"1\",\n\"63949\": \"1\",\n\"48337\": \"1\",\n\"36351\": \"1\"}"
    name     = "public_clouds"
    priority = 100
    type     = "init"
  }
}

# __generated__ by Terraform
resource "fastly_service_compute" "ngwaf_compute_integration" {
  activate        = null
  comment         = null
  force_destroy   = null
  name            = "ngwaf-compute-integration"
  reuse           = null
  stage           = null
  version_comment = null
  backend {} # sensitive
  domain {
    comment = null
    name    = "ngwaf-compute.edgecompute.app"
  }
  package {
    content          = null
    filename         = null
    source_code_hash = "f02bae8f5c21bc0a8fda138849b05d5270ac6624c2942d89d0215c6bf9048d5c9440b5567dc9e4fefc7c7e31e950c024dd6b4b14fece4a74e4784d0f1535c808"
  }
  resource_link {
    name        = "ngwaf"
    resource_id = "NntAREFv0Lv1xYkYvzaDK7"
  }
}
