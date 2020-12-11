package com.ryan.springsecurity.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtProvider implements InitializingBean {

    public static final String AUTHORITIES_KEY = "auth";
    private JwtParser jwtParser;
    private JwtBuilder jwtBuilder;

    /**
     * 由包含的{@code BeanFactory}设置所有bean属性并满足BeanFactoryAware  ApplicationContextAware}等之后调用。<p>此方法允许bean实例执行其整体配置的验证和最终初始化。 设置了所有bean属性后。 @throws发生配置错误（例如无法设置
     *   必要属性）或由于其他任何原因导致初始化失败
     *
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {

        // 配置使用至少88位base64对令牌进行编码
        String secret = "ZmQ0ZGI5NjQ0MDQwY2I4MjMxY2Y3ZmI3MjdhN2ZmMjNhODViOTg1ZGE0NTBjMGM4NDA5NzYxMjdjOWMwYWRmZTBlZjlhNGY3ZTg4Y2U3YTE1ODVkZDU5Y2Y3OGYwZWE1NzUzNWQ2YjFjZDc0NGMxZWU2MmQ3MjY1NzJmNTE0MzI=";
        byte[] decode = Decoders.BASE64.decode(secret);
        // 初始化 JWT 签名密钥
        Key secretKey = Keys.hmacShaKeyFor(decode);
        jwtParser = Jwts.parserBuilder().setSigningKey(secretKey).build();
        jwtBuilder = Jwts.builder().signWith(secretKey, SignatureAlgorithm.HS512);
    }

    /**
     * 产生jwt token
     *
     * @param authentication
     * @return
     */
    public String createToken(Authentication authentication) {


        // 获取权限列表
        String authorities  = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        return jwtBuilder
                // 加入ID确保生成的 Token 都不一致
                .setId(UUID.randomUUID().toString())
                // 权限列表
                .claim(AUTHORITIES_KEY, authorities)
                // username
                .setSubject(authentication.getName())
                // 过期时间
                .setExpiration(DateUtils.addDays(new Date(), 1))
                .compact();
    }


    /**
     * 获取令牌信息
     *
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        Claims body = jwtParser.parseClaimsJws(token).getBody();
        Object authoritiesStr = body.get(AUTHORITIES_KEY);
        Collection<? extends GrantedAuthority> authorities = null;
        if (null != authoritiesStr) {
            authorities = (Collection<? extends GrantedAuthority>) Arrays.stream(authoritiesStr.toString().split(",")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        } else {
            authorities = Collections.emptyList();
        }
        User principal = new User(body.getSubject(), "****", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
}
