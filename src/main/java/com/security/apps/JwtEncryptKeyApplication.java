package com.security.apps;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.security.apps.config.RsaKeysConfig;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class JwtEncryptKeyApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtEncryptKeyApplication.class, args);
	}

}
