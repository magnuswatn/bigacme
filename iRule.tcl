when HTTP_REQUEST {
    if { [HTTP::path] starts_with "/.well-known/acme-challenge/" } {
        set datagroup "acme_responses_dg"

        if {! [class exists $datagroup]} {
            log local0.error "Responding with 500 to ACME challenge on virtal server [virtual name] because the datagroup $datagroup does not exist"
            HTTP::respond 500 -version 1.1 noserver Connection Close
            event disable
            return
        }

        set token [getfield [HTTP::host] : 1]:[string map {"/.well-known/acme-challenge/" ""} [HTTP::path]]
        set response [class match -value -- $token equals $datagroup]

        if { $response != "" } {
            log local0.info "Responding to ACME challenge $token with response $response on virtual server [virtual name]"
            HTTP::respond 200 -version 1.1 content $response noserver "Content-Type" "text/plain; charset=utf-8" Connection Close
            event disable
        } else {
            log local0.warning "Responding with 404 to ACME challenge on virtual server [virtual name] because the token did not match any known token" 
            HTTP::respond 404 -version 1.1 noserver Connection Close
            event disable
        }
    }
}
