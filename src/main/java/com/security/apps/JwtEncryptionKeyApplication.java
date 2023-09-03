package com.security.apps;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.security.apps.config.RsaKeysConfig;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class JwtEncryptionKeyApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtEncryptionKeyApplication.class, args);
	}

}
