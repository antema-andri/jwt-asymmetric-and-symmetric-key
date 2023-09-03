package com.security.apps.encrypter;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.stereotype.Service;

@Service
public interface Encrypter {
    JwtEncoder encoder();
    JwtDecoder decoder();
}
